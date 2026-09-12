"""
ztr_stream.py — a simple video-streaming target app.

Same shape as ztr_requests.py: runs on a machine you control, deployed
alongside the rest of package/. Serves video files out of a `videos/`
directory next to this script, in fixed-size chunks, over the tunnel —
rather than buffering a whole file in memory the way ztr_requests.py's
request/response does, which doesn't scale to video-sized payloads.

Two commands: `list` (what's available) and `stream` (send one file).
No transcoding, no adaptive bitrate, no seeking — this is deliberately
the simplest thing that lets a client pull a video through an authorized
tunnel and either save it or pipe it straight into a player.
"""
import socket
import struct
import sys
import os
import json
import logging
import threading


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(SCRIPT_DIR), "ztrclient", "utils"))
import crypt_bot as AR

VIDEO_DIR = os.path.join(SCRIPT_DIR, "videos")
CHUNK_SIZE = 64 * 1024

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stdout
)
logger = logging.getLogger("ztr_stream")

crypt = AR.CryptBot(
    pathPrivateKey=os.path.join(SCRIPT_DIR, "privateKey.pem"),
    pathPublicKey=os.path.join(SCRIPT_DIR, "publicKey.pem"),
    pathRecipientPublicKey=os.path.join(SCRIPT_DIR, "boss_pub.pem"),
)
crypt.create_keys(rsa_size=2048, reuse=True)
try:
    crypt._load_recipient_pub_key()
except FileNotFoundError:
    logger.warning(
        f"{crypt.pathRecipientPublicKey} not found yet — will load it on the first "
        "request instead. Drop the boss's public key there before connecting."
    )

os.makedirs(VIDEO_DIR, exist_ok=True)


def _recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed connection")
        buf.extend(chunk)
    return bytes(buf)

# length(4 bytes) + encrypted payload — no compression flag byte like
# ztr_requests.py's framing, since video chunks are already-compressed
# binary (h264/mp4/etc); gzip on top would just burn CPU for no size win.
# Wrapped in the same header send_HTH/recv_HTH use (4-byte length + 64-byte
# marker) with the marker zeroed out, so the exit hop can tell this reply
# came from the target rather than from elsewhere in the hop chain.
def _send_frame(conn: socket.socket, payload: bytes) -> None:
    encrypted = crypt.encrypt_sign_BytesPayload(payload)
    frame = struct.pack(">I", len(encrypted)) + encrypted
    envelope = struct.pack(">I64s", len(frame), b"0" * 64)
    conn.sendall(envelope + frame)

def _recv_frame(conn: socket.socket) -> bytes:
    (length,) = struct.unpack(">I", _recv_exact(conn, 4))
    encrypted = _recv_exact(conn, length)
    payload = crypt.decrypt_msg_verifyBytesPayload(encrypted, as_="bytes")
    if payload is None:
        raise ValueError("signature verification failed")
    return payload

def _safe_path(name: str) -> str:
    # Only a bare filename, never a path — closes the obvious traversal
    # ("../../etc/passwd") a client-supplied name would otherwise open.
    return os.path.join(VIDEO_DIR, os.path.basename(name))


def _handle_client(conn: socket.socket, addr) -> None:
    logger.info(f"connected: {addr}")
    try:
        while True:
            req = json.loads(_recv_frame(conn).decode("utf-8"))
            cmd = req.get("cmd")

            if cmd == "list":
                names = sorted(
                    f for f in os.listdir(VIDEO_DIR)
                    if os.path.isfile(os.path.join(VIDEO_DIR, f))
                )
                _send_frame(conn, json.dumps({"videos": names}).encode("utf-8"))
                continue

            if cmd == "stream":
                path = _safe_path(req.get("video", ""))
                if not os.path.isfile(path):
                    _send_frame(conn, json.dumps({"error": "not found", "size": 0}).encode("utf-8"))
                    continue

                size = os.path.getsize(path)
                _send_frame(conn, json.dumps({"error": None, "size": size}).encode("utf-8"))

                with open(path, "rb") as f:
                    sent = 0
                    while sent < size:
                        chunk = f.read(CHUNK_SIZE)
                        _send_frame(conn, chunk)
                        sent += len(chunk)
                logger.info(f"streamed {path} ({size} bytes) to {addr}")
                continue

            _send_frame(conn, json.dumps({"error": f"unknown cmd {cmd!r}"}).encode("utf-8"))

    except (ConnectionError, OSError, struct.error, ValueError) as e:
        logger.warning(f"client {addr} disconnected: {e}")
    except Exception as e:
        logger.exception(f"unhandled error for {addr}: {e}")
    finally:
        conn.close()
        logger.info(f"closed: {addr}")


def server(host: str = "0.0.0.0", port: int = 9998) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(64)
    logger.info(f"listening on {host}:{port}, serving videos from {VIDEO_DIR}")
    try:
        while True:
            try:
                conn, addr = sock.accept()
            except OSError as e:
                logger.warning(f"accept() failed: {e}")
                continue
            threading.Thread(target=_handle_client, args=(conn, addr), daemon=True).start()
    finally:
        sock.close()


if __name__ == "__main__":
    server()
