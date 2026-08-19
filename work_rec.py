import contextlib
import hashlib
import hmac
import os
import socket
import subprocess
import sys
import threading
import time

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from receiver_detection import detect_receiver_host

from cnft_protocol import (
    MSG_ACK,
    MSG_DATA,
    MSG_RESUME_BITMAP,
    MSG_RESUME_QUERY,
    recv_header,
    send_header,
)
from transfer_resume import (
    DEFAULT_CHUNK_SIZE,
    bitmap_all_set,
    bitmap_has_chunk,
    chunk_offset,
    chunk_size_for_id,
    compute_file_hash,
    derive_chunk_key,
    derive_session_key,
    empty_bitmap,
    ensure_manifest,
    ensure_part_file,
    finalize_manifest,
    manifest_bitmap,
    received_bytes_from_bitmap,
    recv_exact,
    recv_transfer_metadata,
    recv_uint32,
    save_manifest,
    send_uint32,
    update_manifest_bitmap,
    bitmap_mark_chunk,
)
from transfer_security import (
    can_attempt_auth,
    record_auth_failure,
    record_auth_success,
    mark_session_completed,
    register_or_reject_session,
)

lock = threading.Lock()
password_global = None
session_key_global = None
session_salt_global = None
active_transfer_id = None
last_activity_ts = None
transfer_completed = False
CHUNK_SIZE = DEFAULT_CHUNK_SIZE


def get_preset_code():
    """Get and store the preset code for this receiver session."""
    print("🔐 Setup Authentication")
    code = input("Enter preset code for this session: ").strip()
    return code


def reset_state():
    global password_global, session_key_global, session_salt_global
    global active_transfer_id, last_activity_ts, transfer_completed
    with lock:
        password_global = None
        session_key_global = None
        session_salt_global = None
        active_transfer_id = None
        last_activity_ts = None
        transfer_completed = False


def authenticate_sender(client, preset_code):
    """
    Perform challenge-response authentication with sender.
    Returns True if authenticated, False otherwise.
    """
    key = preset_code.encode()

    try:
        challenge = get_random_bytes(32)
        client.sendall(challenge)

        received_response = recv_exact(client, 32)
        expected_response = hmac.new(key, challenge, hashlib.sha256).digest()
        if not hmac.compare_digest(received_response, expected_response):
            client.sendall(b"AUTH_FAIL")
            return False

        counter_challenge = get_random_bytes(32)
        client.sendall(counter_challenge)

        received_counter = recv_exact(client, 32)
        expected_counter = hmac.new(key, counter_challenge, hashlib.sha256).digest()
        if not hmac.compare_digest(received_counter, expected_counter):
            client.sendall(b"AUTH_FAIL")
            return False

        client.sendall(b"AUTH_SUCCESS")
        return True
    except (ConnectionError, OSError):
        try:
            client.sendall(b"AUTH_FAIL")
        except OSError:
            pass
        return False


def _record_activity(transfer_id):
    global active_transfer_id, last_activity_ts
    with lock:
        active_transfer_id = transfer_id
        last_activity_ts = time.time()


def _load_or_create_manifest(save_dir, metadata):
    manifest = ensure_manifest(
        save_dir,
        metadata["transfer_id"],
        metadata["filename"],
        metadata["file_size"],
        metadata["chunk_size"],
    )
    return manifest, manifest_bitmap(manifest)


def _security_metadata(metadata):
    return {
        "transfer_id": metadata["transfer_id"],
        "filename": metadata["filename"],
        "file_size": metadata["file_size"],
        "chunk_size": metadata["chunk_size"],
        "total_chunks": metadata["total_chunks"],
        "session_id": metadata["session_id"],
        "session_started_at": metadata["session_ts"],
    }


def _prompt_password(filename):
    global password_global
    with lock:
        if password_global is None:
            password_global = input(f"Enter password for {filename}: ").encode()
        return password_global


def _cache_session_key(password, session_salt):
    """Derive and cache the session key from password and salt."""
    global session_key_global, session_salt_global
    with lock:
        if session_salt_global == session_salt and session_key_global is not None:
            return
        session_key_global = derive_session_key(password, session_salt)
        session_salt_global = session_salt


def _get_session_key(session_salt, filename):
    """Retrieve the cached session key, or derive it if necessary."""
    with lock:
        if session_key_global is not None and session_salt_global == session_salt:
            return session_key_global
    password = _prompt_password(filename)
    _cache_session_key(password, session_salt)
    with lock:
        return session_key_global


def _verify_file_integrity(manifest):
    """Verify the SHA-256 hash of the completed file against the sender's hash."""
    expected_hash = manifest.get("file_hash")
    if not expected_hash:
        print("⚠️  No file hash received — skipping integrity verification")
        return
    actual_hash = compute_file_hash(manifest["final_path"])
    if actual_hash == expected_hash:
        print(f"✅ Integrity verified: SHA-256 matches for {manifest['filename']}")
    else:
        print(f"❌ INTEGRITY FAILURE: SHA-256 mismatch for {manifest['filename']}")
        print(f"   Expected: {expected_hash}")
        print(f"   Got:      {actual_hash}")


def handle_resume_query(client, save_dir):
    metadata = recv_transfer_metadata(client)
    _record_activity(metadata["transfer_id"])

    allowed, reason, _, _ = register_or_reject_session(
        save_dir, _security_metadata(metadata)
    )
    if not allowed:
        raise ValueError(f"Rejected resume session: {reason}")

    manifest, bitmap = _load_or_create_manifest(save_dir, metadata)

    if metadata.get("file_hash") and not manifest.get("file_hash"):
        manifest["file_hash"] = metadata["file_hash"]
        save_manifest(save_dir, manifest)

    if len(bitmap) == 0 and manifest["total_chunks"]:
        bitmap = empty_bitmap(manifest["total_chunks"])

    password = _prompt_password(metadata["filename"])
    _cache_session_key(password, metadata["session_salt"])
    print(f"🔑 Session key derived (PBKDF2 → HKDF per-chunk)")
    print(f"🔏 File SHA-256: {metadata.get('file_hash', 'N/A')[:16]}...")

    received_bytes = received_bytes_from_bitmap(
        bitmap, manifest["file_size"], manifest["chunk_size"]
    )
    send_header(client, MSG_RESUME_BITMAP)
    send_uint32(client, len(bitmap))
    client.sendall(bitmap)

    print(
        f"♻️  Resume query for {metadata['filename']}: "
        f"{received_bytes}/{manifest['file_size']} bytes already stored"
    )


def handle_chunk_data(client, save_dir):
    metadata = recv_transfer_metadata(client)
    _record_activity(metadata["transfer_id"])

    allowed, reason, _, _ = register_or_reject_session(
        save_dir, _security_metadata(metadata)
    )
    if not allowed:
        raise ValueError(f"Rejected chunk session: {reason}")

    chunk_id = recv_uint32(client)
    if chunk_id >= metadata["total_chunks"]:
        raise ValueError(f"Chunk {chunk_id} is out of range")

    expected_size = chunk_size_for_id(
        metadata["file_size"], metadata["chunk_size"], chunk_id
    )
    nonce = recv_exact(client, 16)
    tag = recv_exact(client, 16)
    encrypted = recv_exact(client, expected_size)

    session_key = _get_session_key(metadata["session_salt"], metadata["filename"])
    chunk_key = derive_chunk_key(session_key, chunk_id)

    with lock:
        manifest = ensure_manifest(
            save_dir,
            metadata["transfer_id"],
            metadata["filename"],
            metadata["file_size"],
            metadata["chunk_size"],
        )
        bitmap = manifest_bitmap(manifest)

        if manifest.get("completed") or bitmap_has_chunk(bitmap, chunk_id):
            send_header(client, MSG_ACK)
            return

        cipher = AES.new(chunk_key, AES.MODE_EAX, nonce)
        decrypted = cipher.decrypt_and_verify(encrypted, tag)

        ensure_part_file(manifest)
        with open(manifest["part_path"], "r+b") as handle:
            handle.seek(chunk_offset(chunk_id, metadata["chunk_size"]))
            handle.write(decrypted)

        bitmap_mark_chunk(bitmap, chunk_id)
        update_manifest_bitmap(save_dir, manifest, bitmap)

        if bitmap_all_set(bitmap, manifest["total_chunks"]):
            os.replace(manifest["part_path"], manifest["final_path"])
            finalize_manifest(save_dir, manifest, bitmap)
            mark_session_completed(save_dir, _security_metadata(metadata))

            _verify_file_integrity(manifest)

            global transfer_completed
            transfer_completed = True

    print(
        f"⬇ Received chunk {chunk_id + 1}/{manifest['total_chunks']} for {metadata['filename']}"
    )
    send_header(client, MSG_ACK)


def receive_connection(client, preset_code, save_dir):
    try:
        client.settimeout(10)
        peer_ip = client.getpeername()[0]

        allowed, reason = can_attempt_auth(save_dir, peer_ip)
        if not allowed:
            print(f"🚫 Auth rate limit for {peer_ip}: {reason}")
            return

        if not authenticate_sender(client, preset_code):
            record_auth_failure(save_dir, peer_ip)
            print("❌ Authentication failed for chunk connection")
            return

        record_auth_success(save_dir, peer_ip)

        _, msg_type = recv_header(client)
        print(f"📡 CNFT/1.0 ← {msg_type}")
        if msg_type == MSG_RESUME_QUERY:
            handle_resume_query(client, save_dir)
        elif msg_type == MSG_DATA:
            handle_chunk_data(client, save_dir)
        else:
            raise ValueError(f"Unknown message type: {msg_type}")
    except Exception as e:
        print(f"❌ Error handling connection: {e}")
    finally:
        client.close()


def receive_one_file(server, preset_code, save_dir):
    """Receive a single chunked file session; returns True if successful."""
    reset_state()

    server.settimeout(2)
    idle_grace = 8

    while True:
        with lock:
            if transfer_completed:
                break

        try:
            client, addr = server.accept()
        except socket.timeout:
            with lock:
                if transfer_completed:
                    break
                if active_transfer_id and last_activity_ts:
                    if (time.time() - last_activity_ts) > idle_grace:
                        break
            continue
        except OSError:
            return False

        print(f"🔗 Connection from {addr}")
        worker = threading.Thread(
            target=receive_connection, args=(client, preset_code, save_dir)
        )
        worker.daemon = True
        worker.start()

    with lock:
        if transfer_completed:
            print("✅ File received and reconstructed from resumable chunks.")
            return True

    print("⚠️  Incomplete transfer. The manifest was saved for later resume.")
    return False


def start_server(host="0.0.0.0", port=1205, save_dir=".", preset_code=None):
    """Start the server to receive chunked files."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(50)

    print(f"📡 Listening on {host}:{port} (waiting for sender)...")

    try:
        while True:
            ok = receive_one_file(server, preset_code, save_dir)

            if ok:
                print("🎉 Transfer complete.")
            else:
                print("⚠️  Transfer ended without full success.")

            choice = input("Receive another file? (y/n): ").strip().lower()
            if choice != "y":
                break

            print("📡 Ready for next file. Waiting for sender...")

    except KeyboardInterrupt:
        print("\n🛑 Server stopped")
    finally:
        with contextlib.suppress(Exception):
            server.close()
        print("👋 Receiver closed")


if __name__ == "__main__":
    print("📥 Secure File Transfer - Receiver")

    preset_code = get_preset_code()
    if not preset_code:
        print("❌ Error: Preset code cannot be empty.")
        sys.exit(1)

    host = detect_receiver_host()

    port_str = input("Enter port (default: 1205): ").strip()
    if not port_str:
        port = 1205
    else:
        try:
            port = int(port_str)
            if not (1 <= port <= 65535):
                raise ValueError
        except ValueError:
            print("❌ Invalid port. Must be 1-65535. Exiting.")
            sys.exit(1)

    print(f"📡 Auto-detected receiver host: {host}")

    print("📂 Opening folder picker for save directory...")
    code = (
        "import tkinter as tk; from tkinter import filedialog; "
        "root = tk.Tk(); root.withdraw(); root.attributes('-topmost', True); "
        "d = filedialog.askdirectory(title='Select save directory'); "
        "print(d if d else '')"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
    )
    save_dir = result.stdout.strip()

    if not save_dir:
        save_dir = "."
        print("📁 No folder selected. Using current directory.")
    else:
        print(f"📁 Save directory: {save_dir}")

    if not os.path.exists(save_dir):
        os.makedirs(save_dir)

    sys.exit(start_server(host, port, save_dir, preset_code))
