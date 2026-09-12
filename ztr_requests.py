import socket
import gzip
import struct
import sys
import os
import json
import requests
import logging
import threading
import base64


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# crypt_bot.py isn't bundled next to this file — it's the same module the
# ztrclient package ships, resolved relative to __file__ (not CWD) so this
# still works no matter how the app is launched (systemd, a different
# working directory, a symlink, etc). Deploy the whole package/ directory
# on the target machine, not just apps/ztr_requests.py on its own.
sys.path.insert(0, os.path.join(os.path.dirname(SCRIPT_DIR), "ztrclient", "utils"))
import crypt_bot as AR

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stdout
)
logger = logging.getLogger("ztr_requests")

crypt = AR.CryptBot(
    pathPrivateKey=os.path.join(SCRIPT_DIR, "privateKey.pem"),
    pathPublicKey=os.path.join(SCRIPT_DIR, "publicKey.pem"),
    pathRecipientPublicKey=os.path.join(SCRIPT_DIR, "boss_pub.pem"),
)
crypt.create_keys(rsa_size=2048, reuse=True)
# Force the recipient (boss) public key to load now, single-threaded,
# instead of on whichever request thread happens to arrive first. Every
# connection is handled on its own thread (see server()) and would
# otherwise race to lazily populate this same cached attribute on their
# first message — harmless (idempotent), but wasted duplicate work under
# concurrent first connections. Pre-warming here avoids that without
# putting a lock around every encrypt/decrypt call, which would serialize
# the one part of request handling (RSA) that's actually worth running
# concurrently. Best-effort only: on first-ever setup boss_pub.pem won't
# exist yet (the operator needs this service's freshly-generated
# publicKey.pem before they can hand back a boss_pub.pem to match it), and
# the server should still come up and wait rather than refuse to start.
try:
    crypt._load_recipient_pub_key()
except FileNotFoundError:
    logger.warning(
        f"{crypt.pathRecipientPublicKey} not found yet — will load it on the first "
        "request instead. Drop the boss's public key there before connecting."
    )

# One shared Session gives connection pooling/keep-alive across requests to
# the same origin instead of a fresh TCP+TLS handshake every time — plain
# requests.request() opens and tears down a connection per call.
_session = requests.Session()

# Headers describing the on-the-wire encoding of r.content no longer apply
# once we've already decoded it and are re-framing it ourselves — forwarding
# them verbatim would tell whoever reads the response to gunzip
# already-decompressed bytes, or trust a Content-Length that no longer
# matches.
_DROP_RESPONSE_HEADERS = {"content-encoding", "content-length", "transfer-encoding"}


def _recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed connection")
        buf.extend(chunk)
    return bytes(buf)

def _send_framed(conn: socket.socket, data_str: str, size_threshold=200) -> None:
    data = data_str.encode("utf-8")
    if len(data) >= size_threshold:
        compressed = gzip.compress(data)
        if len(compressed) < len(data):
            flag = 1
            payload = compressed
        else:
            flag = 0
            payload = data
    else:
        flag = 0
        payload = data
    logger.info(f"[send({flag})] = {len(payload)} bytes")
    encrypted_payload = crypt.encrypt_sign_BytesPayload(payload)
    # flag (1 byte) + payload length (4 bytes) + payload — our own inner
    # framing. The exit hop expects every reply on this socket wrapped in
    # the same header send_HTH/recv_HTH use (4-byte length + 64-byte
    # marker), with the marker zeroed out instead of holding a session id —
    # that's how it tells a target-originated reply apart from a message
    # from elsewhere in the hop chain.
    frame = struct.pack(">BI", flag, len(encrypted_payload)) + encrypted_payload
    envelope = struct.pack(">I64s", len(frame), b"0" * 64)
    conn.sendall(envelope + frame)

def _recv_framed(conn: socket.socket) -> bytes:
    header = _recv_exact(conn, 5)
    flag, length = struct.unpack(">BI", header)

    encrypted_payload = _recv_exact(conn, length)

    payload = crypt.decrypt_msg_verifyBytesPayload(encrypted_payload, as_="bytes")
    if payload is None:
        # Wrong/missing signature — decrypt_msg_verify() returns None
        # instead of raising, so this has to be checked explicitly or the
        # gzip/len() calls below fail on None with a confusing TypeError
        # instead of a clear reason for closing the connection.
        raise ValueError("signature verification failed")

    if flag == 1:
        payload = gzip.decompress(payload)
    logger.info(f"[recv({flag})] {length} bytes -> {len(payload)} bytes")
    return payload.decode("utf-8")

def _execute(req: dict) -> dict:
    method  = req.get("method", "GET").upper()
    url     = req.get("url")
    headers = req.get("headers", {})
    body    = req.get("body") or req.get("data")
    timeout = req.get("timeout", 30)
    cookies = req.get("cookies", {})

    if not url:
        return {
            "error": "missing url",
            "status_code": 0,
            "headers": {},
            "body": "",
            "is_base64": False
        }
    try:
        if req.get("is_base64") and isinstance(body, str):
            body = base64.b64decode(body)

        r = _session.request(
            method,
            url,
            headers=headers,
            data=body.encode() if isinstance(body, str) else body,
            timeout=timeout,
            allow_redirects=True,
            cookies=cookies
        )
        response_headers = {k: v for k, v in r.headers.items() if k.lower() not in _DROP_RESPONSE_HEADERS}

        # Send text bodies as plain JSON strings and only pay base64's ~33%
        # size tax for genuinely binary content — most HTTP responses
        # (JSON, HTML, anything text-ish) decode cleanly and this also lets
        # gzip in _send_framed compress the real text instead of its
        # base64 blow-up.
        try:
            return {
                "status_code": r.status_code,
                "headers": response_headers,
                "body": r.content.decode("utf-8"),
                "is_base64": False
            }
        except UnicodeDecodeError:
            return {
                "status_code": r.status_code,
                "headers": response_headers,
                "body": base64.b64encode(r.content).decode("utf-8"),
                "is_base64": True
            }
    except requests.RequestException as e:
        return {
            "error": str(e),
            "status_code": 0,
            "headers": {},
            "body": "",
            "is_base64": False
        }


def _handle_client(conn: socket.socket, addr) -> None:
    logger.info(f"connected: {addr}")
    try:
        while True:
            data_str = _recv_framed(conn)

            data    = json.loads(data_str)
            result  = _execute(data["request"])

            response = json.dumps(result)
            _send_framed(conn, response)

    except (ConnectionError, OSError, struct.error, ValueError) as e:
        logger.warning(f"client {addr} disconnected: {e}")
    except Exception as e:
        logger.exception(f"unhandled error for {addr}: {e}")
    finally:
        conn.close()
        logger.info(f"closed: {addr}")


def server(host: str = "0.0.0.0", port: int = 9999) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(64)
    logger.info(f"listening on {host}:{port}")
    try:
        while True:
            try:
                conn, addr = sock.accept()
            except OSError as e:
                logger.warning(f"accept() failed: {e}")
                continue
            threading.Thread(
                target=_handle_client,
                args=(conn, addr),
                daemon=True,
            ).start()
    finally:
        sock.close()


if __name__ == "__main__":
    server()
