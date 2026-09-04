import argparse
import base64
import json
import os
import socket
import struct
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_ZTR_CLIENT_DIR = os.path.join(os.path.dirname(SCRIPT_DIR), "ztrclient")
sys.path.insert(0, _ZTR_CLIENT_DIR)
sys.path.insert(0, os.path.join(_ZTR_CLIENT_DIR, "utils"))
from ztrClient import RelayClient
from Crypto.PublicKey import RSA
import crypt_bot as CB  # standalone encrypt_msg()/decrypt_msg() — no CryptBot identity needed for this app


def _encode_blob(plaintext: bytes, pubkey: RSA.RsaKey) -> dict:
    ciphertext, encrypted_aes_key, iv = CB.encrypt_msg(plaintext, pubkey)
    return {
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode("ascii"),
        "iv": base64.b64encode(iv).decode("ascii"),
    }

def _decode_blob(blob: dict, privkey: RSA.RsaKey) -> bytes:
    return CB.decrypt_msg(
        base64.b64decode(blob["ciphertext"]),
        base64.b64decode(blob["encrypted_aes_key"]),
        base64.b64decode(blob["iv"]),
        privkey,
        as_="bytes",
    )


class _MailboxConnection:
    """Low-level transport to ztr_mailbox.py — plain length-prefixed JSON
    over the tunnel (send_HTH/recv_HTH), no extra encryption layer at
    this level; see ztr_mailbox.py's module docstring for why."""

    def __init__(self, config_file: str, relay_name: str, relay_port: int = 9997):
        self._client = RelayClient(target_host=relay_name, port=relay_port, config_file=config_file)
        self._sock = None

    def connect(self) -> "_MailboxConnection":
        result = self._client.set_tunnel()
        if not result or not result.get("status"):
            raise ConnectionError(f"failed to establish tunnel: {result}")
        self._sock = socket.create_connection((self._client.entry_hop, self._client.ra_port))
        return self

    def close(self) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    def __enter__(self) -> "_MailboxConnection":
        return self.connect()

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def call(self, cmd: str, **kwargs) -> dict:
        req = {"cmd": cmd, **kwargs}
        data = json.dumps(req).encode("utf-8")
        frame = struct.pack(">I", len(data)) + data
        self._client.send_HTH(self._sock, frame, self._client.session_id)

        resp_frame, _session_id = self._client.recv_HTH(self._sock)
        (length,) = struct.unpack(">I", resp_frame[:4])
        return json.loads(resp_frame[4:4 + length].decode("utf-8"))


class BobClient:
    """
    For Bob — the anonymous sender, no persistent keys of his own.
    submit() generates a fresh, one-time RSA keypair for this single
    submission and hands back (claim_token, ephemeral_private_key_pem).
    Save BOTH somewhere safe: the token is how you check for a reply
    later, the private key is how you decrypt it. Neither is recoverable
    if lost — that's deliberate, not a bug (see ztr_mailbox.py's
    docstring).

    Bob is responsible for looking up Alice's pubkey himself before
    calling submit() — the mailbox target doesn't serve it (never held
    any of Alice's keys, and no longer needs a get_alice_pubkey command
    to prove it). Alice publishes it as public services metadata on the
    mailbox's own alias; look it up with the dashboard's Alias lookup
    tool, or `python3 access.py get_domain_data <alias>` directly.
    """

    def __init__(self, config_file: str, relay_name: str, relay_port: int = 9997):
        self._config_file = config_file
        self._relay_name = relay_name
        self._relay_port = relay_port

    def submit(self, message: str, alice_pubkey: "RSA.RsaKey") -> tuple:
        ephemeral = RSA.generate(2048)
        ephemeral_pub_pem = ephemeral.publickey().export_key().decode("ascii")
        ephemeral_priv_pem = ephemeral.export_key().decode("ascii")

        payload = json.dumps({"message": message, "reply_pubkey": ephemeral_pub_pem}).encode("utf-8")
        blob = _encode_blob(payload, alice_pubkey)

        with _MailboxConnection(self._config_file, self._relay_name, self._relay_port) as conn:
            resp = conn.call("submit", blob=blob)
        if resp.get("error"):
            raise RuntimeError(resp["error"])

        return resp["token"], ephemeral_priv_pem

    def check_reply(self, token: str, ephemeral_private_key_pem: str):
        with _MailboxConnection(self._config_file, self._relay_name, self._relay_port) as conn:
            resp = conn.call("check", token=token)
        if not resp.get("reply"):
            return None
        privkey = RSA.import_key(ephemeral_private_key_pem)
        return _decode_blob(resp["reply"], privkey).decode("utf-8")


class AliceClient:
    """
    For Alice — the fixed recipient, using her own long-lived RSA
    keypair (generate with `genkey` below, once, kept private, never
    given to the mailbox target — see ztr_mailbox.py's docstring).
    list_new() and reply() both encrypt/decrypt locally with this key;
    the mailbox process itself never sees plaintext.
    """

    def __init__(self, config_file: str, relay_name: str, private_key_pem_path: str, relay_port: int = 9997):
        self._config_file = config_file
        self._relay_name = relay_name
        self._relay_port = relay_port
        with open(private_key_pem_path) as f:
            self._privkey = RSA.import_key(f.read())

    def list_new(self) -> list:
        with _MailboxConnection(self._config_file, self._relay_name, self._relay_port) as conn:
            resp = conn.call("list_new")

        out = []
        for item in resp.get("submissions", []):
            plaintext = json.loads(_decode_blob(item["blob"], self._privkey).decode("utf-8"))
            out.append({
                "id": item["id"],
                "created_at": item["created_at"],
                "message": plaintext["message"],
                "reply_pubkey": plaintext["reply_pubkey"],
            })
        return out

    def reply(self, submission_id: str, message: str, reply_pubkey_pem: str) -> None:
        reply_pubkey = RSA.import_key(reply_pubkey_pem)
        blob = _encode_blob(message.encode("utf-8"), reply_pubkey)

        with _MailboxConnection(self._config_file, self._relay_name, self._relay_port) as conn:
            resp = conn.call("reply", id=submission_id, blob=blob)
        if resp.get("error"):
            raise RuntimeError(resp["error"])


def _cli() -> None:
    parser = argparse.ArgumentParser(
        description="Bob-to-Alice async mailbox client, over an authorized ZTRelay tunnel."
    )
    parser.add_argument("--config-file", default=None, help="your downloaded .ztr route config (not needed for genkey)")
    parser.add_argument("--relay-name", default=None, help="the ._ztr alias (or address) of the target running ztr_mailbox.py (not needed for genkey)")
    parser.add_argument("--relay-port", type=int, default=9997)

    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("genkey", help="Alice: run once, offline, to generate her keypair")
    p.add_argument("--out-prefix", default="alice", help="writes <prefix>_priv.pem (keep this off the target) and <prefix>_pub.pem (paste its contents into the alias's services metadata via the dashboard)")

    p = sub.add_parser("submit", help="Bob: submit a message anonymously")
    p.add_argument("message")
    p.add_argument("--alice-pubkey", required=True, help="path to Alice's public key PEM — look it up yourself first (dashboard's Alias lookup tool, or `access.py get_domain_data <alias>`)")

    p = sub.add_parser("check", help="Bob: check for a reply to a previous submission")
    p.add_argument("token")
    p.add_argument("--key-file", required=True, help="the ephemeral private key PEM saved from submit")

    p = sub.add_parser("list", help="Alice: list submissions awaiting a reply")
    p.add_argument("--key-file", required=True, help="Alice's own private key PEM")

    p = sub.add_parser("reply", help="Alice: reply to a submission")
    p.add_argument("submission_id")
    p.add_argument("message")
    p.add_argument("reply_pubkey_file", help="the reply_pubkey PEM `list` saved for this submission")
    p.add_argument("--key-file", required=True, help="Alice's own private key PEM")

    args = parser.parse_args()

    if args.cmd == "genkey":
        key = RSA.generate(2048)
        priv_path, pub_path = f"{args.out_prefix}_priv.pem", f"{args.out_prefix}_pub.pem"
        with open(priv_path, "w") as f:
            f.write(key.export_key().decode("ascii"))
        with open(pub_path, "w") as f:
            f.write(key.publickey().export_key().decode("ascii"))
        print(f"Wrote {priv_path} (keep this OFF the target machine) and {pub_path}.")
        print(f"Paste {pub_path}'s contents into the mailbox alias's services metadata (dashboard DNS panel) as encryptions.pubkey — Bob looks it up from there, this target never serves it.")
        return

    if not args.config_file or not args.relay_name:
        parser.error("--config-file and --relay-name are required for this command")

    if args.cmd == "submit":
        client = BobClient(args.config_file, args.relay_name, args.relay_port)
        pubkey = RSA.import_key(open(args.alice_pubkey).read())
        token, ephemeral_priv_pem = client.submit(args.message, pubkey)
        key_path = f"mailbox_{token[:12]}.pem"
        with open(key_path, "w") as f:
            f.write(ephemeral_priv_pem)
        print("Submitted. SAVE THESE — there is no recovery if you lose them:")
        print(f"  claim token: {token}")
        print(f"  reply key:   {key_path}")

    elif args.cmd == "check":
        client = BobClient(args.config_file, args.relay_name, args.relay_port)
        reply = client.check_reply(args.token, open(args.key_file).read())
        print(reply if reply else "(no reply yet)")

    elif args.cmd == "list":
        client = AliceClient(args.config_file, args.relay_name, args.key_file, args.relay_port)
        submissions = client.list_new()
        if not submissions:
            print("(nothing new)")
        for item in submissions:
            print(f"[{item['id']}] {item['created_at']}")
            print(f"  {item['message']}")
            reply_key_path = f"reply_pubkey_{item['id'][:12]}.pem"
            with open(reply_key_path, "w") as f:
                f.write(item["reply_pubkey"])
            print(f"  (reply pubkey saved to {reply_key_path} — pass it to `reply`)")

    elif args.cmd == "reply":
        client = AliceClient(args.config_file, args.relay_name, args.key_file, args.relay_port)
        client.reply(args.submission_id, args.message, open(args.reply_pubkey_file).read())
        print("Reply sent.")


if __name__ == "__main__":
    _cli()
