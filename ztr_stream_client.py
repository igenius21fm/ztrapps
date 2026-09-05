import argparse
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
import crypt_bot as AR


class ZtrStreamClient:
    """
    Talks to a ztr_stream.py target service through an authorized ZTRelay
    tunnel. One instance = one tunnel session: connect() once, then call
    list_videos() / stream_video() as many times as you like.

    Same key-exchange requirement as ZtrRequestsClient: your own keypair
    plus the target's public key (see ztr_stream.py's module docstring
    and ztr_requests.py's setup docs — the exchange is identical).
    Defaults to privateKey.pem / publicKey.pem / target_pub.pem next to
    this script.
    """

    def __init__(
        self,
        config_file: str,
        relay_name: str,
        relay_port: int = 9998,
        own_private_key: str = None,
        own_public_key: str = None,
        target_public_key: str = None,
        worker_id: str = None,
        worker_prefix: str = "",
    ):
        self._client = RelayClient(target_host=relay_name, port=relay_port, config_file=config_file)
        if worker_id is not None:
            self._client.with_worker_id(f"{worker_prefix}{worker_id}")
        self._sock = None

        self._crypt = AR.CryptBot(
            pathPrivateKey=own_private_key or os.path.join(SCRIPT_DIR, "privateKey.pem"),
            pathPublicKey=own_public_key or os.path.join(SCRIPT_DIR, "publicKey.pem"),
            pathRecipientPublicKey=target_public_key or os.path.join(SCRIPT_DIR, "target_pub.pem"),
        )
        self._crypt.create_keys(rsa_size=2048, reuse=True)

    def connect(self) -> "ZtrStreamClient":
        result = self._client.set_tunnel()
        if not result or not result.get("status"):
            raise ConnectionError(f"failed to establish tunnel: {result}")
        self._sock = socket.create_connection((self._client.entry_hop, self._client.PORT))
        return self

    def close(self) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    def __enter__(self) -> "ZtrStreamClient":
        return self.connect()

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    # ------------------------------------------------------------------

    def list_videos(self) -> list:
        self._send(json.dumps({"cmd": "list"}).encode("utf-8"))
        return json.loads(self._recv().decode("utf-8"))["videos"]

    def stream_video(self, name: str, out) -> int:
        """
        Requests `name` and writes it to `out` (any writable binary
        file-like object — an open file, or sys.stdout.buffer to pipe
        straight into a player like ffplay/vlc) as chunks arrive, instead
        of buffering the whole video in memory first. Returns bytes
        written; raises FileNotFoundError if the target doesn't have it.
        """
        self._send(json.dumps({"cmd": "stream", "video": name}).encode("utf-8"))
        meta = json.loads(self._recv().decode("utf-8"))
        if meta.get("error"):
            raise FileNotFoundError(meta["error"])

        size = meta["size"]
        received = 0
        while received < size:
            chunk = self._recv()
            out.write(chunk)
            received += len(chunk)
        return received

    # ------------------------------------------------------------------
    # Same length(4) + encrypted-payload framing as ztr_stream.py's
    # _send_frame/_recv_frame — this is the inner, end-to-end encrypted
    # layer. send_HTH/recv_HTH is the separate outer layer that actually
    # moves bytes through the authorized tunnel; that layer is already
    # gone by the time a message reaches ztr_stream.py's raw socket.

    def _send(self, payload: bytes) -> None:
        encrypted = self._crypt.encrypt_sign_BytesPayload(payload)
        frame = struct.pack(">I", len(encrypted)) + encrypted
        self._client.send_HTH(self._sock, frame, self._client.session_id)

    def _recv(self) -> bytes:
        frame, _session_id = self._client.recv_HTH(self._sock)
        (length,) = struct.unpack(">I", frame[:4])
        encrypted = frame[4:4 + length]
        payload = self._crypt.decrypt_msg_verifyBytesPayload(encrypted, as_="bytes")
        if payload is None:
            raise ValueError(
                "signature verification failed — check target_pub.pem matches "
                "this target's actual publicKey.pem"
            )
        return payload


def _cli() -> None:
    parser = argparse.ArgumentParser(
        description="List or stream a video from a ztr_stream.py target, over an authorized ZTRelay tunnel."
    )
    parser.add_argument("--config-file", required=True, help="your downloaded .ztr route config")
    parser.add_argument("--relay-name", required=True, help="the ._ztr alias (or address) of the target running ztr_stream.py")
    parser.add_argument("--relay-port", type=int, default=9998)

    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="list videos available on the target")
    p_get = sub.add_parser("get", help="stream one video to a file (or - for stdout)")
    p_get.add_argument("video")
    p_get.add_argument("-o", "--output", default=None, help="output path (default: same name as the video)")

    args = parser.parse_args()

    with ZtrStreamClient(args.config_file, args.relay_name, args.relay_port) as client:
        if args.cmd == "list":
            for name in client.list_videos():
                print(name)
            return

        out_path = args.output or args.video
        if out_path == "-":
            written = client.stream_video(args.video, sys.stdout.buffer)
        else:
            with open(out_path, "wb") as f:
                written = client.stream_video(args.video, f)
        print(f"{written} bytes -> {out_path}", file=sys.stderr)


if __name__ == "__main__":
    _cli()
