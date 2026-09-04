import os
import socket
import sys
import threading
import time


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(SCRIPT_DIR), "ztrclient"))
sys.path.insert(0, os.path.join(os.path.dirname(SCRIPT_DIR), "ztrclient", "utils"))
from ztrClient import RelayClient

# Minimum time between reauthorization attempts for the same worker — without
# this, every thread that finds no free worker retries healing on every loop
# iteration, hammering the hop chain with repeated reauth attempts for a
# worker that just failed moments ago.
HEAL_COOLDOWN_SECONDS = 5.0


class RCTimer(RelayClient):
    """A RelayClient that tracks its own busy/free/broken state and the time
    of its last state change, so a pool can pick the least-recently-used
    free worker and detect/heal broken ones."""

    def __init__(self, target_host: str, port: int, config_file: str):
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
        port: int,
        config_file: str,
        n: int = 2,
        timing_defense: bool = False,
        secure_transport: bool = False,
        worker_prefix: str = "",
    ):
        self.lock = threading.Lock()
        self.condition = threading.Condition(self.lock)
        self.target_host = target_host
        self.port = port
        self.config_file = config_file

        # Workers that fail to authorize here are kept in the pool (state
        # "broken") rather than dropped — otherwise a worker that just
        # happened to fail at startup would never get a chance to heal, and
        # the pool would silently run under capacity for its whole lifetime.
        self.workers = [RCTimer(target_host, port, config_file) for _ in range(n)]
        for i, w in enumerate(self.workers):
            # Distinct worker_id per worker — create_tunnel_id() hashes it
            # in, so without this every worker here (same target/route/ttl)
            # would compute the *same* tunnel_id and could end up sharing
            # one cached session instead of each getting its own. Set once;
            # it's stored on the instance and stays put across the
            # re-authorization attempts _heal_broken_workers() makes later.
            # A string id (optionally prefixed) is just as unique as an int
            # here — create_tunnel_id() stringifies it either way — but
            # reads a lot better in logs across multiple pools than a bare
            # "0", "1", "2" that could be any pool's worker #0.
            w.with_worker_id(f"{worker_prefix}{i}")
            # Pool-wide toggles applied uniformly — every worker here
            # shares the same target/route, so there's no reason one
            # worker's tunnel would want these on while another's didn't.
            w.with_timing_defense(timing_defense)
            w.with_encryption(secure_transport)
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

                # Bounded wait, not indefinite — if every worker is broken
                # and no other thread currently holds one, nothing would
                # ever call notify_all() to wake this up otherwise, and
                # healing would never get retried.
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


def task(rcw: RCWorkers, _start, on_failure=None, on_success=None, *args, **kwargs):
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
