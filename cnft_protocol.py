"""CNFT/1.0 -- Application-layer protocol framing for P2P file transfer.

Defines a lightweight header-based protocol that wraps every post-authentication
message.  Each message starts with a single ASCII line:

    CNFT/1.0 <TYPE>\n

followed by a type-specific binary payload.
"""

PROTO_VERSION = "CNFT/1.0"

# Message type constants
MSG_AUTH = "AUTH"
MSG_METADATA = "METADATA"
MSG_DATA = "DATA"
MSG_ACK = "ACK"
MSG_ERROR = "ERROR"
MSG_RESUME_QUERY = "RESUME_QUERY"
MSG_RESUME_BITMAP = "RESUME_BITMAP"

_MAX_HEADER_LENGTH = 64  # Safety limit for header line length


def send_header(sock, msg_type):
    """Send a protocol header: ``CNFT/1.0 <TYPE>\n``."""
    sock.sendall(f"{PROTO_VERSION} {msg_type}\n".encode("ascii"))


def recv_header(sock):
    """Read a protocol header and return *(version, msg_type)*.

    Raises :class:`ValueError` on malformed headers or unsupported versions.
    Raises :class:`ConnectionError` if the connection drops mid-read.
    """
    buf = b""
    while True:
        byte = sock.recv(1)
        if not byte:
            raise ConnectionError("Connection lost while reading protocol header")
        buf += byte
        if byte == b"\n":
            break
        if len(buf) > _MAX_HEADER_LENGTH:
            raise ValueError("Protocol header exceeds maximum length")

    line = buf.decode("ascii").strip()
    parts = line.split(" ", 1)
    if len(parts) != 2:
        raise ValueError(f"Malformed protocol header: {line!r}")

    version, msg_type = parts
    if version != PROTO_VERSION:
        raise ValueError(f"Unsupported protocol version: {version}")

    return version, msg_type


def send_error(sock, message):
    """Send an ERROR message with a human-readable description."""
    send_header(sock, MSG_ERROR)
    encoded = message.encode("utf-8")
    sock.sendall(len(encoded).to_bytes(4, "big"))
    sock.sendall(encoded)
