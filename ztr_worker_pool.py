import os
import socket
import sys
import threading
import time
from typing import Callable, Optional


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(SCRIPT_DIR), "ztrclient"))
sys.path.insert(0, os.path.join(os.path.dirname(SCRIPT_DIR), "ztrclient", "utils"))
from ztrClient import RelayClient, TunnelError, NetworkError

# Minimum time between reauthorization attempts for the same worker, so a
# broken worker isn't retried on every single loop iteration.
HEAL_COOLDOWN_SECONDS = 5.0


class RCTimer(RelayClient):
    """A RelayClient that tracks its own busy/free/broken state and the time
    of its last state change, so a pool can pick the least-recently-used
    free worker and detect/heal broken ones."""

    def __init__(self, target_host: str, port: int = None, config_file: str = None):
        super().__init__(target_host, port, config_file=config_file)
        self.clock = 0.0
        self.state = "free"
        self.last_heal_attempt = 0.0

    def __repr__(self):
        return (
            f"<ZTRC hops_len<{len(self.chain)}>, session<{self.session_id}>,"
            f" tunnel<{self.tunnel_id}>, clock<{self.clock}>,"
            f" state<{self.state}>>"
        )

    def send_HTH(self, sock: socket.socket, payload: bytes, session_id: str, encrypt_payload: bool = False):
        self.tap().__busy__()
        try:
            return super().send_HTH(sock, payload, session_id, encrypt_payload=encrypt_payload)
        except Exception:
            self.__broken__()
            raise

    def recv_HTH(self, sock: socket.socket, decrypt_payload: bool = False):
        self.tap().__busy__()
        try:
            r = super().recv_HTH(sock, decrypt_payload=decrypt_payload)
            self.__free__()
            return r
        except Exception:
            self.__broken__()
            raise

    def __busy__(self):
        self.state = "busy"

    def __free__(self):
        self.state = "free"

    def __broken__(self):
        self.state = "broken"

    def tap(self):
        self.clock = time.monotonic()
        return self


class RCWorkers:
    def __init__(
        self,
        target_host: str,
        config_file: str,
        worker_prefix: str,
        port: int = None,
        n: int = 2,
        target_port: int = None,
        override: Optional[Callable[["RCTimer"], None]] = None,
    ):
        self.lock = threading.Lock()
        self.condition = threading.Condition(self.lock)
        self.target_host = target_host
        self.port = port
        self.target_port = target_port
        self.config_file = config_file

        # Workers that fail to authorize here stay in the pool as "broken"
        # rather than being dropped, so they still get a chance to heal.
        self.workers = [RCTimer(target_host, port, config_file) for _ in range(n)]
        for i, w in enumerate(self.workers):
            # worker_prefix (required) plus index keeps tunnel_ids distinct
            # across workers and across separate pools on the same route.
            w.with_worker_id(f"{worker_prefix}{i}")
            # Runs before _authorize() — e.g. override=lambda w: w.with_timing_defense().with_encryption("target_pub.pem")
            if override:
                override(w)
            # Must happen before _authorize() — TARGET_PORT is read at
            # authorization time, so setting it afterward would have no effect.
            if target_port is not None:
                w.set_target_port(target_port)
            self._authorize(w)
        ready = sum(1 for w in self.workers if w.state == "free")
        print(f"{ready}/{n} worker(s) ready")

    def _authorize(self, w: RCTimer) -> bool:
        """Runs set_tunnel() and only marks the worker free if it actually
        succeeded — set_tunnel() can fail without raising (it returns None
        or {"status": False, ...} on a rejected/failed authorization), so
        checking only for exceptions here would mark a still-broken worker
        free and hand it back out to the next caller."""
        try:
            r = w.set_tunnel()
        except Exception as e:
            print(f"[WORKER AUTH FAILED] {w}: {e}")
            w.__broken__()
            return False

        if r and r.get("status"):
            w.tap().__free__()
            return True

        print(f"[WORKER AUTH REJECTED] {w}: {r}")
        w.__broken__()
        return False

    def acquire_worker(self, wait_timeout: float = None) -> RCTimer:
        """Blocks until a worker is free, marks it as busy, and returns it.
        Retries healing broken workers periodically even with no other
        thread around to wake it — pass wait_timeout to also bound how long
        this can block overall (raises TimeoutError past that point)."""
        deadline = None if wait_timeout is None else time.monotonic() + wait_timeout

        with self.condition:
            while True:
                self._heal_broken_workers()

                free_workers = [w for w in self.workers if w.state == "free"]
                if free_workers:
                    worker = sorted(free_workers, key=lambda k: k.clock)[0]
                    worker.tap().__busy__()
                    return worker

                if deadline is not None and time.monotonic() >= deadline:
                    raise TimeoutError("no worker became available in time")

                # Bounded, not indefinite — if every worker is broken and no
                # other thread wakes this, healing still gets retried.
                remaining = None if deadline is None else max(0.0, deadline - time.monotonic())
                self.condition.wait(timeout=min(HEAL_COOLDOWN_SECONDS, remaining) if remaining is not None else HEAL_COOLDOWN_SECONDS)

    def release_worker(self, worker: RCTimer):
        """Releases a worker back to the pool and notifies waiting threads."""
        with self.condition:
            if worker.state != "broken":
                worker.__free__()
            self.condition.notify_all()

    def _heal_broken_workers(self):
        """Attempts recovery on broken workers, at most once per worker per
        HEAL_COOLDOWN_SECONDS."""
        now = time.monotonic()
        for i, w in enumerate(self.workers):
            if w.state != "broken":
                continue
            if now - w.last_heal_attempt < HEAL_COOLDOWN_SECONDS:
                continue
            w.last_heal_attempt = now
            print(f"[WORKER HEAL] Attempting to reconnect broken worker #{i}...")
            if self._authorize(w):
                print(f"[WORKER HEAL] Worker #{i} successfully restored!")


def rc_task(rcw: RCWorkers, _start, on_failure=None, on_success=None, *args, **kwargs):
    """Runs _start(worker, *args, **kwargs) on a pool worker, retrying on a
    different worker (up to once per worker in the pool) if it fails with a
    tunnel-level error. Every worker in the pool gets exactly one chance
    before giving up — bounded by pool size, not by "have I seen this
    worker object before", which can misfire and give up early if the pool
    hands back an already-tried worker while a fresh one is still becoming
    free."""
    max_attempts = len(rcw.workers)
    failures = {}
    worker = None

    for attempt in range(max_attempts):
        try:
            worker = rcw.acquire_worker(wait_timeout=2)
        except TimeoutError as e:
            failures["pool"] = str(e)
            break

        try:
            r = _start(worker, *args, **kwargs)
        except (TunnelError, NetworkError) as e:
            # Network/protocol-level failure — this worker's cached
            # authorization may now be stale, so clear it (it re-authorizes
            # from scratch next time) and let another worker take a shot.
            failures[worker.worker_id] = str(e)
            worker.tunnel_cache.delete(worker.tunnel_id)
            print(f"[rc_task] attempt {attempt + 1}/{max_attempts} failed on {worker.worker_id}: {e}")
        except Exception as e:
            # Not tunnel-level (e.g. a bug in _start itself) — another
            # worker won't fix that, so stop instead of burning the pool.
            failures[worker.worker_id] = str(e)
            print(f"[rc_task] non-retryable error on {worker.worker_id}: {e}")
            rcw.release_worker(worker)
            break
        else:
            rcw.release_worker(worker)
            if r and on_success:
                on_success(worker, r)
            return r
        rcw.release_worker(worker)

    if on_failure:
        on_failure(worker, failures)
    return None
