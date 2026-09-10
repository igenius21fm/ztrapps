import os
import socket
import sys
import threading
import time


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(SCRIPT_DIR), "ztrclient"))
sys.path.insert(0, os.path.join(os.path.dirname(SCRIPT_DIR), "ztrclient", "utils"))
from ztrClient import RelayClient

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

    def send_HTH(self, sock: socket.socket, payload: bytes, session_id: str):
        self.tap().__busy__()
        try:
            return super().send_HTH(sock, payload, session_id)
        except Exception:
            self.__broken__()
            raise

    def recv_HTH(self, sock: socket.socket):
        self.tap().__busy__()
        try:
            r = super().recv_HTH(sock)
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
        timing_defense: bool = False,
        secure_transport: bool = False,
        target_port: int = None,
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
            w.with_timing_defense(timing_defense)
            w.with_encryption(enabled=secure_transport)
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
    worker = rcw.acquire_worker()
    try:
        r = _start(worker, *args, **kwargs)
        if r:
            on_success and on_success(worker, r)
        return r
    except Exception as e:
        print(f"Task failed on worker {worker}: {e}")
        if on_failure:
            on_failure(worker, str(e))
        return None
    finally:
        rcw.release_worker(worker)
