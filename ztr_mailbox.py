"""
ztr_mailbox.py — a simple SecureDrop-style async drop-box target app.

Generic example throughout: Bob wants to send Alice something without
either of them having a prior identity relationship. Deliberately not
framed around a specific real-world use case in code/docs — this is an
unaudited reference implementation of a pattern, not a vetted tool, and
naming it after a specific high-stakes scenario risks someone treating
it as ready for that scenario without doing their own review first (see
the security note in this app's docs section).

Different shape from ztr_requests.py/ztr_stream.py: those assume one
pre-authenticated identity on each side, exchanged once before the first
connection. A drop-box needs the opposite — Bob should be able to submit
without a prior relationship, and the mailbox itself should never be
able to read what it stores. So there's no crypt_bot identity/signing
layer on the wire here at all: the relay tunnel's own encryption covers
transport, and every submission/reply is *separately* end-to-end
encrypted (Bob -> Alice's pubkey, Alice -> Bob's one-time ephemeral
pubkey) using crypt_bot's standalone encrypt_msg()/decrypt_msg()
functions, which don't require any pre-shared identity the way the
CryptBot class does.

This process never holds any of Alice's keys at all, public or private —
not even her public key. Alice publishes her pubkey (and this mailbox's
port) as public services metadata on the target's own alias instead (see
the platform docs' Aliases section); Bob looks that up himself before
ever contacting this process, the same way he'd look up any other
alias's metadata. Even a fully compromised mailbox server can't decrypt
a single submission or reply it's storing, and it isn't a place Alice's
key material could leak from even by accident.

No usernames, no accounts, no persistent identity for either side.
Losing your claim token (or Bob's saved reply key) loses that submission
for good — there's no recovery, by design.

Known limitation, not solved here: `check` does a real filesystem lookup
keyed by token hash, so response timing could in principle distinguish a
valid-but-unanswered token from a nonexistent one on a sufficiently
loaded/observed server. A production deployment wanting to fully close
that would need constant-time lookup regardless of hit/miss.
"""
import json
import os
import secrets
import struct
import socket
import sys
import hashlib
import threading
import logging
from datetime import datetime, timezone


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

SUBMISSIONS_DIR = os.path.join(SCRIPT_DIR, "submissions")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stdout
)
logger = logging.getLogger("ztr_mailbox")

os.makedirs(SUBMISSIONS_DIR, exist_ok=True)


def _recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed connection")
        buf.extend(chunk)
    return bytes(buf)

# Plain length-prefixed JSON — no crypt_bot signing layer, deliberately
# (see module docstring). length(4 bytes) + JSON bytes.
def _send(conn: socket.socket, obj: dict) -> None:
    data = json.dumps(obj).encode("utf-8")
    conn.sendall(struct.pack(">I", len(data)) + data)

def _recv(conn: socket.socket) -> dict:
    (length,) = struct.unpack(">I", _recv_exact(conn, 4))
    return json.loads(_recv_exact(conn, length).decode("utf-8"))


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def _submission_path(submission_id: str) -> str:
    # submission_id is always our own sha256 hexdigest (from _token_hash or
    # directly off disk in list_new) — never client-supplied free text, so
    # this can't be used for path traversal the way a filename could.
    return os.path.join(SUBMISSIONS_DIR, submission_id + ".json")


def _handle_submit(req: dict) -> dict:
    blob = req.get("blob")
    if not blob:
        return {"error": "missing blob"}

    token = secrets.token_hex(32)
    record = {
        "blob": blob,
        "reply": None,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    # Stored keyed by hash(token), never the raw token itself — if this
    # storage is ever seized or leaked, claim tokens aren't recoverable
    # from it, only their hashes.
    with open(_submission_path(_token_hash(token)), "w") as f:
        json.dump(record, f)

    logger.info("new submission received")
    return {"token": token}

def _handle_list_new(req: dict) -> dict:
    out = []
    for name in os.listdir(SUBMISSIONS_DIR):
        if not name.endswith(".json"):
            continue
        submission_id = name[: -len(".json")]
        with open(_submission_path(submission_id)) as f:
            record = json.load(f)
        if record["reply"] is not None:
            continue  # already answered — not "new" anymore
        out.append({"id": submission_id, "blob": record["blob"], "created_at": record["created_at"]})
    return {"submissions": out}

def _handle_reply(req: dict) -> dict:
    submission_id = req.get("id", "")
    blob = req.get("blob")
    # submission_id here IS client-supplied (Alice's client echoes back an
    # id list_new gave it) — validate it's a bare hex-digest before it
    # ever touches a path, same reasoning as ztr_stream.py's basename()
    # guard on a client-supplied filename.
    if not blob or not submission_id or not all(c in "0123456789abcdef" for c in submission_id):
        return {"error": "unknown submission"}

    path = _submission_path(submission_id)
    if not os.path.isfile(path):
        return {"error": "unknown submission"}

    with open(path) as f:
        record = json.load(f)
    record["reply"] = blob
    with open(path, "w") as f:
        json.dump(record, f)

    logger.info(f"reply stored for submission {submission_id}")
    return {"ok": True}

def _handle_check(req: dict) -> dict:
    token = req.get("token", "")
    path = _submission_path(_token_hash(token))
    if not os.path.isfile(path):
        # Same response shape as "no reply yet" on purpose — see module
        # docstring's note on this not being fully timing-safe.
        return {"reply": None}
    with open(path) as f:
        record = json.load(f)
    return {"reply": record["reply"]}

_HANDLERS = {
    "submit": _handle_submit,
    "list_new": _handle_list_new,
    "reply": _handle_reply,
    "check": _handle_check,
}


def _handle_client(conn: socket.socket, addr) -> None:
    logger.info(f"connected: {addr}")
    try:
        while True:
            req = _recv(conn)
            handler = _HANDLERS.get(req.get("cmd"))
            resp = handler(req) if handler else {"error": f"unknown cmd {req.get('cmd')!r}"}
            _send(conn, resp)
    except (ConnectionError, OSError, struct.error, json.JSONDecodeError) as e:
        logger.warning(f"client {addr} disconnected: {e}")
    except Exception as e:
        logger.exception(f"unhandled error for {addr}: {e}")
    finally:
        conn.close()
        logger.info(f"closed: {addr}")


def server(host: str = "0.0.0.0", port: int = 9997) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(64)
    logger.info(f"listening on {host}:{port}, submissions in {SUBMISSIONS_DIR}")
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
