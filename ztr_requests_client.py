import argparse
import base64
import gzip
import json
import os
import socket
import struct
import sys


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# Same reasoning as ztr_requests.py: resolve relative to __file__, not CWD,
# and pull ztrClient.py + crypt_bot.py from their real home in the
# ztrclient package rather than duplicating them here.
_ZTR_CLIENT_DIR = os.path.join(os.path.dirname(SCRIPT_DIR), "ztrclient")
sys.path.insert(0, _ZTR_CLIENT_DIR)
sys.path.insert(0, os.path.join(_ZTR_CLIENT_DIR, "utils"))
from ztrClient import RelayClient
import crypt_bot as AR


class ZtrResponse:
    """What ztr_requests.py's _execute() sent back, unpacked. Mirrors just
    enough of `requests.Response` to be a drop-in for simple call sites."""

    __slots__ = ("status_code", "headers", "error", "_body", "_is_base64")

    def __init__(self, result: dict):
        self.status_code = result.get("status_code", 0)
        self.headers = result.get("headers", {})
        self.error = result.get("error")
        self._body = result.get("body", "")
        self._is_base64 = result.get("is_base64", False)

    @property
    def ok(self) -> bool:
        return self.error is None and 200 <= self.status_code < 400

    @property
    def content(self) -> bytes:
        if self._is_base64:
            return base64.b64decode(self._body)
        return self._body.encode("utf-8")

    @property
    def text(self) -> str:
        if self._is_base64:
            return self.content.decode("utf-8", errors="replace")
        return self._body

    def json(self):
        return json.loads(self.text)

    def __repr__(self):
        return f"<ZtrResponse [{self.status_code or self.error}]>"


class ZtrRequestsClient:
    """
    Talks to a ztr_requests.py target service through an authorized ZTRelay
    tunnel. One instance = one tunnel session: connect() once, then call
    request() (or get/post/...) as many times as you like — same
    one-socket-many-requests shape as ztr_requests.py's own connection loop.

    Needs its own RSA keypair plus the target's public key, same as
    ztr_requests.py needs yours (see that file's module docstring for the
    key exchange). Defaults to privateKey.pem / publicKey.pem / target_pub.pem
    next to this script; pass the own_*/target_public_key args to use
    different ones (e.g. one keypair per target).
    """

    def __init__(
        self,
        config_file: str,
        target_host: str,
        worker_prefix: str,
        port: int = 9999,
        target_port: int = None,
        own_private_key: str = None,
        own_public_key: str = None,
        target_public_key: str = None,
        timeout: int = 30,
        timing_defense: bool = False,
        secure_transport: bool = False,
        worker_id: str = None,
    ):
        self._timeout = timeout
        self._client = RelayClient(target_host=target_host, port=port, config_file=config_file)
        # port and target_port are not the same thing — port is this
        # tunnel's own listening_port; target_port (only set if given —
        # RelayClient otherwise defaults it to `port`) is where the exit
        # hop actually connects at target_host. See ztrClient.py.
        if target_port is not None:
            self._client.set_target_port(target_port)
        # create_tunnel_id() hashes worker_id in — without setting a distinct
        # one per instance, pooling several ZtrRequestsClients against the
        # same route/target would all compute the same tunnel_id and end up
        # sharing one cached session instead of each getting its own.
        # worker_prefix just saves the caller writing f"{prefix}{i}"
        # themselves, and keeps two separate pools from colliding with each
        # other too — same idea as (and required for the same reason as)
        # RCWorkers' worker_prefix, even when worker_id itself is unused.
        if worker_id is not None:
            self._client.with_worker_id(f"{worker_prefix}{worker_id}")
        self._client.with_timing_defense(timing_defense)
        # Keyword, not positional — with_encryption()'s first positional
        # arg is now recipient_pubkey_path (opt-in end-to-end encryption on
        # RelayClient itself), which this class doesn't use: it already
        # runs its own separate crypto layer below (self._crypt) for the
        # actual target-facing encryption. This just sets the unrelated
        # secure_transport flag — the hop chain's own final-leg encryption.
        self._client.with_encryption(enabled=secure_transport)
        self._sock = None

        self._crypt = AR.CryptBot(
            pathPrivateKey=own_private_key or os.path.join(SCRIPT_DIR, "privateKey.pem"),
            pathPublicKey=own_public_key or os.path.join(SCRIPT_DIR, "publicKey.pem"),
            pathRecipientPublicKey=target_public_key or os.path.join(SCRIPT_DIR, "target_pub.pem"),
        )
        self._crypt.create_keys(rsa_size=2048, reuse=True)

    def connect(self) -> "ZtrRequestsClient":
        result = self._client.set_tunnel()
        if not result or not result.get("status"):
            raise ConnectionError(f"failed to establish tunnel: {result}")
        self._sock = socket.create_connection(
            (self._client.entry_hop, self._client.PORT), timeout=self._timeout
        )
        return self

    def close(self) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    def __enter__(self) -> "ZtrRequestsClient":
        return self.connect()

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    # ------------------------------------------------------------------

    def request(
        self,
        method: str,
        url: str,
        headers: dict = None,
        body=None,
        is_base64: bool = False,
        cookies: dict = None,
        timeout: int = 30,
    ) -> ZtrResponse:
        if self._sock is None:
            raise RuntimeError("not connected — call connect() first, or use `with ZtrRequestsClient(...) as client:`")

        req = {
            "method": method,
            "url": url,
            "headers": headers or {},
            "cookies": cookies or {},
            "timeout": timeout,
        }
        if body is not None:
            if isinstance(body, (bytes, bytearray)):
                req["body"] = base64.b64encode(body).decode("ascii")
                req["is_base64"] = True
            else:
                req["body"] = body
                req["is_base64"] = is_base64

        self._send(json.dumps({"request": req}))
        return ZtrResponse(json.loads(self._recv()))

    def get(self, url: str, **kwargs) -> ZtrResponse:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> ZtrResponse:
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs) -> ZtrResponse:
        return self.request("PUT", url, **kwargs)

    def delete(self, url: str, **kwargs) -> ZtrResponse:
        return self.request("DELETE", url, **kwargs)

    def patch(self, url: str, **kwargs) -> ZtrResponse:
        return self.request("PATCH", url, **kwargs)

    # ------------------------------------------------------------------
    # Same flag(1) + length(4) + encrypted-payload framing as
    # ztr_requests.py's _send_framed/_recv_framed — this is the inner,
    # end-to-end encrypted layer. send_HTH/recv_HTH below is the separate
    # outer layer that actually moves bytes through the authorized tunnel;
    # by the time a message reaches ztr_requests.py's raw socket, that
    # outer layer is already gone and this inner frame is all that's left.

    def _send(self, data_str: str, size_threshold: int = 200) -> None:
        data = data_str.encode("utf-8")
        if len(data) >= size_threshold:
            compressed = gzip.compress(data)
            flag, payload = (1, compressed) if len(compressed) < len(data) else (0, data)
        else:
            flag, payload = 0, data
        encrypted = self._crypt.encrypt_sign_BytesPayload(payload)
        frame = struct.pack(">BI", flag, len(encrypted)) + encrypted
        self._client.send_HTH(self._sock, frame, self._client.session_id)

    def _recv(self) -> str:
        frame, _session_id = self._client.recv_HTH(self._sock)
        flag, length = struct.unpack(">BI", frame[:5])
        encrypted = frame[5:5 + length]

        payload = self._crypt.decrypt_msg_verifyBytesPayload(encrypted, as_="bytes")
        if payload is None:
            raise ValueError(
                "signature verification failed — check target_pub.pem matches "
                "this target's actual publicKey.pem"
            )
        if flag == 1:
            payload = gzip.decompress(payload)
        return payload.decode("utf-8")


def _cli() -> None:
    parser = argparse.ArgumentParser(
        description="Make one HTTP request through a ztr_requests.py target service, over an authorized ZTRelay tunnel."
    )
    parser.add_argument("method", help="HTTP method (GET, POST, ...)")
    parser.add_argument("url", help="URL for the target service to request on your behalf")
    parser.add_argument("--config-file", required=True, help="your downloaded .ztr route config")
    parser.add_argument("--target-host", required=True, help="the ._ztr alias (or address) of the target running ztr_requests.py")
    parser.add_argument("--port", type=int, default=9999, help="this tunnel's own listening_port (see ztrClient.py)")
    parser.add_argument("--target-port", type=int, default=None, help="exit hop's real destination port, if different from --port")
    parser.add_argument("-H", "--header", action="append", default=[], metavar="Name:Value")
    parser.add_argument("-d", "--data", help="request body")
    parser.add_argument(
        "--timing-correlation-defense",
        action="store_true",
        help="ask the hop chain for delay-jitter and decoy traffic on this tunnel",
    )
    parser.add_argument(
        "--secure-transport",
        action="store_true",
        help="ask the hop chain to also encrypt the final leg to the target — redundant for "
        "already-encrypted protocols (HTTPS), useful if the target service itself doesn't encrypt",
    )
    args = parser.parse_args()

    headers = {}
    for h in args.header:
        name, _, value = h.partition(":")
        headers[name.strip()] = value.strip()

    with ZtrRequestsClient(
        args.config_file,
        args.target_host,
        worker_prefix="",  # single one-shot CLI client, never pooled
        port=args.port,
        target_port=args.target_port,
        timing_defense=args.timing_correlation_defense,
        secure_transport=args.secure_transport,
    ) as client:
        resp = client.request(args.method.upper(), args.url, headers=headers, body=args.data)

    print(f"HTTP {resp.status_code or resp.error}")
    for k, v in resp.headers.items():
        print(f"{k}: {v}")
    print()
    print(resp.text)
    sys.exit(0 if resp.ok else 1)


if __name__ == "__main__":
    _cli()
