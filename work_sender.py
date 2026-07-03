import hashlib
import hmac
import os
import socket
import struct
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import tqdm
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

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
    build_transfer_id,
    chunk_count,
    chunk_offset,
    chunk_size_for_id,
    compute_file_hash,
    derive_chunk_key,
    derive_session_key,
    list_missing_chunks,
    received_bytes_from_bitmap,
    recv_exact,
    recv_uint32,
    send_transfer_metadata,
)
from transfer_security import current_timestamp, generate_session_id

CHUNK_SIZE = DEFAULT_CHUNK_SIZE
MAX_RETRIES = 3
MAX_RESUME_ROUNDS = 3


def authenticate_with_receiver(client, preset_code):
    """
    Perform challenge-response authentication with receiver.
    Returns True if successful, False otherwise.
    """
    key = preset_code.encode()

    try:
        challenge = recv_exact(client, 32)
        response = hmac.new(key, challenge, hashlib.sha256).digest()
        client.sendall(response)

        counter_challenge = recv_exact(client, 32)
        counter_response = hmac.new(key, counter_challenge, hashlib.sha256).digest()
        client.sendall(counter_response)

        status = client.recv(32)
        return status == b"AUTH_SUCCESS"
    except (ConnectionError, OSError):
        return False


def get_preset_code():
    preset_code = input("Enter preset code: ").strip()
    if not preset_code:
        print("❌ Error: Preset code cannot be empty.")
        raise SystemExit(1)
    return preset_code


def request_resume_bitmap(file_path, file_hash, session_salt, server_ip, server_port, preset_code):
    filename = os.path.basename(file_path)
    file_size = os.path.getsize(file_path)
    total_chunks = chunk_count(file_size, CHUNK_SIZE)
    transfer_id = build_transfer_id(file_path, file_size, CHUNK_SIZE)
    session_id = generate_session_id()
    session_started_at = current_timestamp()

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect((server_ip, server_port))

        if not authenticate_with_receiver(client, preset_code):
            raise ConnectionError("Authentication failed while requesting resume state")

        send_header(client, MSG_RESUME_QUERY)
        send_transfer_metadata(
            client,
            filename,
            file_size,
            CHUNK_SIZE,
            total_chunks,
            transfer_id,
            session_id,
            session_started_at,
            file_hash,
            session_salt,
        )

        _, msg_type = recv_header(client)
        if msg_type != MSG_RESUME_BITMAP:
            raise ConnectionError(f"Expected RESUME_BITMAP, got {msg_type}")
        bitmap_length = recv_uint32(client)
        bitmap = bytearray(recv_exact(client, bitmap_length))
        return transfer_id, session_id, session_started_at, bitmap
    finally:
        client.close()


def send_chunk(
    file_path,
    session_key,
    file_hash,
    session_salt,
    server_ip,
    server_port,
    preset_code,
    filename,
    file_size,
    total_chunks,
    transfer_id,
    session_id,
    session_started_at,
    chunk_id,
    offset,
    size,
):
    """Encrypt and send one chunk. Returns bytes sent on success, 0 on failure."""

    for attempt in range(1, MAX_RETRIES + 1):
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client.connect((server_ip, server_port))

            if not authenticate_with_receiver(client, preset_code):
                raise ConnectionError("Authentication failed with receiver")

            send_header(client, MSG_DATA)
            send_transfer_metadata(
                client,
                filename,
                file_size,
                CHUNK_SIZE,
                total_chunks,
                transfer_id,
                session_id,
                session_started_at,
                file_hash,
                session_salt,
            )
            client.sendall(struct.pack("!I", chunk_id))

            with open(file_path, "rb") as f:
                f.seek(offset)
                chunk_data = f.read(size)

            chunk_key = derive_chunk_key(session_key, chunk_id)
            nonce = get_random_bytes(16)

            cipher = AES.new(chunk_key, AES.MODE_EAX, nonce)
            ciphertext, tag = cipher.encrypt_and_digest(chunk_data)

            client.sendall(nonce)
            client.sendall(tag)
            client.sendall(ciphertext)

            _, msg_type = recv_header(client)
            if msg_type != MSG_ACK:
                raise ConnectionError(f"Expected ACK, got {msg_type}")

            return len(chunk_data)

        except (
            ConnectionRefusedError,
            TimeoutError,
            BrokenPipeError,
            ConnectionError,
        ) as e:
            print(f"❌ Chunk {chunk_id}: {e} (attempt {attempt}/{MAX_RETRIES})")
            time.sleep(0.5 * attempt)
        except Exception as e:
            print(f"❌ Chunk {chunk_id}: {e} (attempt {attempt}/{MAX_RETRIES})")
            break
        finally:
            client.close()

    return 0


def send_file(file_path, password, server_ip, server_port, preset_code):
    """Send a file in encrypted chunks to the server."""

    filename = os.path.basename(file_path)
    file_size = os.path.getsize(file_path)
    total_chunks = chunk_count(file_size, CHUNK_SIZE)
    threads = min(8, max(1, total_chunks))

    print("🔒 Computing file hash...")
    file_hash = compute_file_hash(file_path)
    session_salt = get_random_bytes(32)
    session_key = derive_session_key(password, session_salt)

    transfer_id, session_id, session_started_at, bitmap = request_resume_bitmap(
        file_path, file_hash, session_salt, server_ip, server_port, preset_code
    )
    received_bytes = received_bytes_from_bitmap(bitmap, file_size, CHUNK_SIZE)
    missing_chunks = list_missing_chunks(bitmap, total_chunks)

    print(f"\n📤 Sending {filename}")
    print(f"📡 Protocol: CNFT/1.0")
    print(f"🔑 Session key derived (PBKDF2 → HKDF per-chunk)")
    print(f"🔏 File SHA-256: {file_hash[:16]}...")
    print(f"📦 Total chunks: {total_chunks}, Threads: {threads}")
    print(f"🧭 Transfer ID: {transfer_id}")
    if received_bytes:
        print(f"♻️  Receiver already has {received_bytes} bytes")

    progress = tqdm.tqdm(
        total=file_size,
        unit="B",
        unit_scale=True,
        unit_divisor=1024,
        initial=received_bytes,
    )

    try:
        resume_round = 0

        while missing_chunks and resume_round < MAX_RESUME_ROUNDS:
            print(
                f"📦 Resuming {len(missing_chunks)} missing chunks (round {resume_round + 1})"
            )
            bytes_sent = 0
            failed_chunks = []

            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {
                    executor.submit(
                        send_chunk,
                        file_path,
                        session_key,
                        file_hash,
                        session_salt,
                        server_ip,
                        server_port,
                        preset_code,
                        filename,
                        file_size,
                        total_chunks,
                        transfer_id,
                        session_id,
                        session_started_at,
                        chunk_id,
                        chunk_offset(chunk_id, CHUNK_SIZE),
                        chunk_size_for_id(file_size, CHUNK_SIZE, chunk_id),
                    ): chunk_id
                    for chunk_id in missing_chunks
                }

                try:
                    for future in as_completed(futures):
                        chunk_id = futures[future]
                        sent_now = future.result()
                        if sent_now:
                            bytes_sent += sent_now
                            progress.update(sent_now)
                        else:
                            failed_chunks.append(chunk_id)
                except KeyboardInterrupt:
                    print(
                        "\n🛑 Cancelled by user. Waiting for active chunk sends to finish..."
                    )

            if failed_chunks:
                refreshed_transfer_id, _, _, bitmap = request_resume_bitmap(
                    file_path, file_hash, session_salt, server_ip, server_port, preset_code
                )
                if refreshed_transfer_id != transfer_id:
                    transfer_id = refreshed_transfer_id

                current_received = received_bytes_from_bitmap(
                    bitmap, file_size, CHUNK_SIZE
                )
                if current_received > progress.n:
                    progress.update(current_received - progress.n)

                missing_chunks = list_missing_chunks(bitmap, total_chunks)
                resume_round += 1

                if not missing_chunks:
                    break

                print(f"⚠️  Pending retries for chunks: {sorted(set(failed_chunks))}")
            else:
                missing_chunks = []
                break

        if missing_chunks:
            print(
                f"❌ Failed chunks after resume attempts: {missing_chunks[:10]}"
                + (" ..." if len(missing_chunks) > 10 else "")
            )
            print(f"⚠️  File {filename} not fully sent.")
            return False

    finally:
        progress.close()

    print(f"✅ File {filename} sent successfully ({file_size} bytes).")
    return True


def pick_file():
    """Open a native file picker in an isolated subprocess to avoid Tcl conflicts."""
    code = (
        "import tkinter as tk; from tkinter import filedialog; "
        "root = tk.Tk(); root.withdraw(); root.attributes('-topmost', True); "
        "f = filedialog.askopenfilename(title='Select a file to send'); "
        "print(f if f else '')"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


if __name__ == "__main__":
    print("📤 Secure File Transfer - Sender")

    PRESET_CODE = get_preset_code()

    # Get server details
    server_ip = (
        input("Enter receiver's IP address (default: 172.20.10.3): ").strip()
        or "172.20.10.3"
    )
    server_port = int(
        input("Enter receiver's port (default: 1205): ").strip() or "1205"
    )

    while True:
        print("\n📂 Opening file picker...")
        file_path = pick_file()

        if not file_path:
            print("🚪 No file selected. Exiting.")
            break

        if not os.path.exists(file_path):
            print(f"❌ Error: File '{file_path}' not found.")
            continue

        password = input("Enter unique password for this file: ").strip()
        if not password:
            print("❌ Error: Password cannot be empty.")
            continue

        print(f"\n📤 Sending {os.path.basename(file_path)}...")
        send_file(file_path, password, server_ip, server_port, PRESET_CODE)

        continue_sending = input("\nSend another file? (y/n): ").strip().lower()
        if continue_sending != "y":
            break

    print("👋 File transfer session ended.")
