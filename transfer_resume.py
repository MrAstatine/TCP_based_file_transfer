import hashlib
import hmac
import json
import os
import struct
import time
import tqdm

from Crypto.Protocol.KDF import PBKDF2

DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024
PBKDF2_ROUNDS = 200_000
RESUME_DIR_NAME = ".p2p_resume"
RESUME_QUERY = b"Q"
CHUNK_DATA = b"D"
CHUNK_ACK = b"ACK"


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection lost")
        data += chunk
    return data


def send_uint32(sock, value):
    sock.sendall(struct.pack("!I", value))


def recv_uint32(sock):
    return struct.unpack("!I", recv_exact(sock, 4))[0]


def send_uint64(sock, value):
    sock.sendall(struct.pack("!Q", value))


def recv_uint64(sock):
    return struct.unpack("!Q", recv_exact(sock, 8))[0]


def send_blob(sock, data):
    send_uint32(sock, len(data))
    sock.sendall(data)


def recv_blob(sock):
    return recv_exact(sock, recv_uint32(sock))


def send_transfer_metadata(
    sock,
    filename,
    file_size,
    chunk_size,
    total_chunks,
    transfer_id,
    session_id,
    session_ts,
    file_hash,
    session_salt,
):
    send_blob(sock, filename.encode("utf-8"))
    send_uint64(sock, file_size)
    send_uint32(sock, chunk_size)
    send_uint32(sock, total_chunks)
    send_blob(sock, transfer_id.encode("ascii"))
    send_blob(sock, session_id.encode("ascii"))
    send_uint64(sock, session_ts)
    send_blob(sock, file_hash.encode("ascii"))
    send_blob(sock, session_salt)


def recv_transfer_metadata(sock):
    filename = recv_blob(sock).decode("utf-8")
    file_size = recv_uint64(sock)
    chunk_size = recv_uint32(sock)
    total_chunks = recv_uint32(sock)
    transfer_id = recv_blob(sock).decode("ascii")
    session_id = recv_blob(sock).decode("ascii")
    session_ts = recv_uint64(sock)
    file_hash = recv_blob(sock).decode("ascii")
    session_salt = recv_blob(sock)
    return {
        "filename": filename,
        "file_size": file_size,
        "chunk_size": chunk_size,
        "total_chunks": total_chunks,
        "transfer_id": transfer_id,
        "session_id": session_id,
        "session_ts": session_ts,
        "file_hash": file_hash,
        "session_salt": session_salt,
    }


def chunk_count(file_size, chunk_size=DEFAULT_CHUNK_SIZE):
    return (file_size + chunk_size - 1) // chunk_size


def chunk_offset(chunk_id, chunk_size=DEFAULT_CHUNK_SIZE):
    return chunk_id * chunk_size


def chunk_size_for_id(file_size, chunk_size, chunk_id):
    start = chunk_offset(chunk_id, chunk_size)
    remaining = file_size - start
    return min(chunk_size, remaining)


def build_transfer_id(file_path, file_size, chunk_size=DEFAULT_CHUNK_SIZE):
    stat = os.stat(file_path)
    identity = "|".join(
        [
            os.path.normcase(os.path.abspath(file_path)),
            str(file_size),
            str(stat.st_mtime_ns),
            str(chunk_size),
        ]
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:32]


def bitmap_length(total_chunks):
    return (total_chunks + 7) // 8


def empty_bitmap(total_chunks):
    return bytearray(bitmap_length(total_chunks))


def bitmap_has_chunk(bitmap, chunk_id):
    return bool(bitmap[chunk_id // 8] & (1 << (chunk_id % 8)))


def bitmap_mark_chunk(bitmap, chunk_id):
    bitmap[chunk_id // 8] |= 1 << (chunk_id % 8)


def bitmap_all_set(bitmap, total_chunks):
    for chunk_id in range(total_chunks):
        if not bitmap_has_chunk(bitmap, chunk_id):
            return False
    return True


def list_missing_chunks(bitmap, total_chunks):
    return [
        chunk_id
        for chunk_id in range(total_chunks)
        if not bitmap_has_chunk(bitmap, chunk_id)
    ]


def received_bytes_from_bitmap(bitmap, file_size, chunk_size):
    received = 0
    total_chunks = chunk_count(file_size, chunk_size)
    for chunk_id in range(total_chunks):
        if bitmap_has_chunk(bitmap, chunk_id):
            received += chunk_size_for_id(file_size, chunk_size, chunk_id)
    return received


def bitmap_to_hex(bitmap):
    return bytes(bitmap).hex()


def hex_to_bitmap(value):
    return bytearray.fromhex(value) if value else bytearray()


def resume_directory(base_dir):
    path = os.path.join(base_dir, RESUME_DIR_NAME)
    os.makedirs(path, exist_ok=True)
    return path


def manifest_path(base_dir, transfer_id):
    return os.path.join(resume_directory(base_dir), f"{transfer_id}.json")


def part_path(base_dir, transfer_id):
    return os.path.join(resume_directory(base_dir), f"{transfer_id}.part")


def final_path(base_dir, filename):
    return os.path.join(base_dir, f"received_{filename}")


def load_manifest(base_dir, transfer_id):
    path = manifest_path(base_dir, transfer_id)
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def save_manifest(base_dir, manifest):
    path = manifest_path(base_dir, manifest["transfer_id"])
    manifest["updated_at"] = time.time()
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)


def build_manifest(base_dir, transfer_id, filename, file_size, chunk_size):
    total_chunks = chunk_count(file_size, chunk_size)
    manifest = {
        "transfer_id": transfer_id,
        "filename": filename,
        "file_size": file_size,
        "chunk_size": chunk_size,
        "total_chunks": total_chunks,
        "bitmap_hex": bitmap_to_hex(empty_bitmap(total_chunks)),
        "final_path": final_path(base_dir, filename),
        "part_path": part_path(base_dir, transfer_id),
        "completed": False,
        "created_at": time.time(),
        "updated_at": time.time(),
    }
    return manifest


def ensure_manifest(base_dir, transfer_id, filename, file_size, chunk_size):
    existing = load_manifest(base_dir, transfer_id)
    if existing is not None:
        expected = {
            "transfer_id": transfer_id,
            "filename": filename,
            "file_size": file_size,
            "chunk_size": chunk_size,
            "total_chunks": chunk_count(file_size, chunk_size),
            "final_path": final_path(base_dir, filename),
            "part_path": part_path(base_dir, transfer_id),
        }
        for key, value in expected.items():
            if existing.get(key) != value:
                raise ValueError(f"Transfer manifest mismatch for {transfer_id}: {key}")
        return existing

    manifest = build_manifest(base_dir, transfer_id, filename, file_size, chunk_size)
    save_manifest(base_dir, manifest)
    return manifest


def manifest_bitmap(manifest):
    return hex_to_bitmap(manifest.get("bitmap_hex", ""))


def update_manifest_bitmap(base_dir, manifest, bitmap):
    manifest["bitmap_hex"] = bitmap_to_hex(bitmap)
    save_manifest(base_dir, manifest)


def ensure_part_file(manifest):
    part_file = manifest["part_path"]
    if not os.path.exists(part_file):
        with open(part_file, "wb") as handle:
            handle.truncate(manifest["file_size"])


def finalize_manifest(base_dir, manifest, bitmap):
    manifest["bitmap_hex"] = bitmap_to_hex(bitmap)
    manifest["completed"] = True
    save_manifest(base_dir, manifest)


def compute_file_hash(file_path):
    """Compute SHA-256 hash of a file, reading in chunks to support large files."""
    sha256 = hashlib.sha256()
    file_size = os.path.getsize(file_path)
    with open(file_path, "rb") as f, tqdm.tqdm(
        total=file_size,
        unit="B",
        unit_scale=True,
        desc="Hashing",
        leave=False,
    ) as pbar:
        while True:
            data = f.read(DEFAULT_CHUNK_SIZE)
            if not data:
                break
            sha256.update(data)
            pbar.update(len(data))
    return sha256.hexdigest()


def derive_session_key(password, salt):
    """Derive a 256-bit session key from a password and salt using PBKDF2."""
    if isinstance(password, str):
        password = password.encode()
    return PBKDF2(password, salt, dkLen=32, count=PBKDF2_ROUNDS)


def derive_chunk_key(session_key, chunk_id):
    """Derive a per-chunk encryption key from the session key (HKDF-Expand style).

    Uses HMAC-SHA256 with a domain-separated context string and the chunk ID.
    """
    context = b"CNFT/1.0-chunk-key" + struct.pack("!I", chunk_id)
    return hmac.new(session_key, context, hashlib.sha256).digest()
