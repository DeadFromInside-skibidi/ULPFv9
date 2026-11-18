"""
Host dispatcher: journal batches → worker processes, completion tracking.

* Each journal block becomes one work item. ``affinity='source'`` pins a
  source to one worker (stateful formats: W3C headers, CSV headers,
  multiline); ``'none'`` spreads batches round-robin.
* Worker queues are bounded; a full queue blocks the caller, which is how
  backpressure reaches the inputs.
* A worker that dies is restarted and its in-flight batches are resubmitted.
  Segment names are fixed by the journal range, so resubmission cannot
  duplicate anything already buffered.
* ``CommitTracker`` turns out-of-order completions into a contiguous commit
  watermark.
"""
from __future__ import annotations

import logging
import multiprocessing as mp
import queue
import threading
import time
import zlib
from collections import deque

logger = logging.getLogger(__name__)


class CommitTracker:
    """Contiguous completion watermark over journal sequence ranges."""

    def __init__(self, committed: int = 0):
        self._lock = threading.Lock()
        self._pending: dict[int, int] = {}      # first -> last, registered but not done
        self._done: set[int] = set()            # firsts completed out of order
        self._order: deque[int] = deque()       # firsts in registration (= sequence) order
        self.committed = committed

    def register(self, first: int, count: int) -> None:
        with self._lock:
            self._pending[first] = first + count - 1
            self._order.append(first)

    def complete(self, first: int) -> bool:
        """Mark a range done; returns True if the watermark advanced."""
        with self._lock:
            if first not in self._pending:
                return False
            self._done.add(first)
            advanced = False
            while self._order and self._order[0] in self._done:
                f = self._order.popleft()
                self._done.discard(f)
                self.committed = self._pending.pop(f)
                advanced = True
            return advanced

    @property
    def in_flight(self) -> int:
        with self._lock:
            return len(self._pending)


class Dispatcher:
    def __init__(self, cfg: dict, node: str, workers: int, tracker: CommitTracker,
                 on_result=None, queue_batches: int = 64):
        self.cfg = cfg
        self.node = node
        self.n = max(1, workers)
        self.tracker = tracker
        self.on_result = on_result
        self.ctx = mp.get_context("spawn")
        self.stop_flag = self.ctx.Event()
        self.out_q = self.ctx.Queue()
        self.queue_batches = queue_batches
        self.in_qs = [self.ctx.Queue(maxsize=queue_batches) for _ in range(self.n)]
        self.procs: list = [None] * self.n
        self._rr = 0
        self._lock = threading.Lock()
        self._inflight: dict[int, tuple[int, tuple]] = {}   # first -> (worker, msg)
        self._collector = None
        self._monitor = None
        self._closing = False
        self.batches_done = 0
        self.errors = 0
        self.worker_restarts = 0
        self.counts = {"records": 0, "events": 0, "skipped": 0, "failed": 0,
                       "raw_fallback": 0, "auto_parsed": 0, "derived": 0}
        self.written: dict[str, int] = {}
        self.dropped: dict[str, int] = {}
        self.aborted = 0
        self._ready = threading.Event()
        self._ready_n = 0
        self.fatal: str | None = None

    # ------------------------------------------------------------------

    def _spawn(self, i: int) -> None:
        from ulpf.runtime.worker import worker_main
        p = self.ctx.Process(target=worker_main, name=f"ulpf-worker-{i}",
                             args=(i, self.cfg, self.node, self.in_qs[i], self.out_q, self.stop_flag),
                             daemon=True)
        p.start()
        self.procs[i] = p

    def start(self, timeout: float = 120.0) -> None:
        for i in range(self.n):
            self._spawn(i)
        self._collector = threading.Thread(target=self._collect, name="ulpf-dispatch-collector", daemon=True)
        self._collector.start()
        deadline = time.monotonic() + timeout
        while self._ready_n < self.n:
            if self.fatal:
                raise RuntimeError(f"worker failed to start:\n{self.fatal}")
            if time.monotonic() > deadline:
                raise RuntimeError("workers did not start in time")
            self._ready.wait(0.1)
        self._monitor = threading.Thread(target=self._watch, name="ulpf-dispatch-monitor", daemon=True)
        self._monitor.start()

    def submit(self, input_name: str, source: str, affinity: str, first: int, raws: list[bytes],
               digests: list[bytes], recv_ts: float) -> None:
        if affinity == "source":
            i = zlib.crc32(f"{input_name}\x00{source}".encode()) % self.n
        else:
            with self._lock:
                i = self._rr = (self._rr + 1) % self.n
        # The commit watermark lets workers erase row-MAC keys no uncommitted record needs
        msg = ("batch", input_name, source, first, raws, digests, recv_ts, self.tracker.committed)
        with self._lock:
            self._inflight[first] = (i, msg)
        self._put(i, msg)

    def broadcast(self, kind: str, payload=None) -> None:
        """Send a control message (e.g. ``reload_parsers``) to every worker; best effort, never blocks long."""
        msg = (kind,) if payload is None else (kind, payload)
        for q in self.in_qs:
            try:
                q.put(msg, timeout=1.0)
            except queue.Full:
                logger.warning(f"dispatcher: worker queue full, {kind} not delivered (workers re-poll on their own)")

    def _put(self, i: int, msg) -> None:
        while True:
            try:
                self.in_qs[i].put(msg, timeout=0.5)
                return
            except queue.Full:
                if self._closing and self.stop_flag.is_set():
                    raise RuntimeError("dispatcher stopped while queue full")

    # ------------------------------------------------------------------

    def _collect(self) -> None:
        while True:
            try:
                msg = self.out_q.get(timeout=0.5)
            except queue.Empty:
                if self._closing and not any(p is not None and p.is_alive() for p in self.procs):
                    return
                continue
            t = msg.get("t")
            if t == "ready":
                self._ready_n += 1
                self._ready.set()
            elif t == "fatal":
                self.fatal = msg.get("error")
                self._ready.set()
            elif t in ("done", "error"):
                with self._lock:
                    self._inflight.pop(msg["first"], None)
                if t == "done":
                    self.batches_done += 1
                    for k, v in msg["counts"].items():
                        self.counts[k] = self.counts.get(k, 0) + v
                    for k, v in msg["written"].items():
                        self.written[k] = self.written.get(k, 0) + v
                    for k, v in msg["dropped"].items():
                        if v:
                            self.dropped[k] = self.dropped.get(k, 0) + v
                else:
                    self.errors += 1
                    logger.error(f"worker {msg.get('worker')} failed on records "
                                 f"{msg['first']}..{msg['last']}:\n{msg.get('error')}")
                if self.on_result:
                    try:
                        self.on_result(msg)
                    except Exception:
                        logger.exception("result handler failed")
                self.tracker.complete(msg["first"])
            elif t == "aborted":
                # Shutdown interrupted the batch (e.g. waiting for a full sink buffer). It is not
                # completed, so the commit watermark stays before it and the next start replays it.
                with self._lock:
                    self._inflight.pop(msg["first"], None)
                self.aborted += 1
            elif t == "exit":
                pass

    def _watch(self) -> None:
        while not self._closing:
            time.sleep(1.0)
            for i, p in enumerate(self.procs):
                if self._closing:
                    return
                if p is not None and not p.is_alive():
                    self.worker_restarts += 1
                    logger.error(f"worker {i} exited unexpectedly (code {p.exitcode}); restarting "
                                 "and resubmitting its batches")
                    self._spawn(i)
                    with self._lock:
                        mine = [m for (w, m) in self._inflight.values() if w == i]
                    for m in sorted(mine, key=lambda m: m[3]):
                        self._put(i, m)

    # ------------------------------------------------------------------

    def drain(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                if not self._inflight:
                    return True
            time.sleep(0.05)
        return False

    def stop(self, timeout: float = 30.0) -> None:
        self._closing = True
        for q in self.in_qs:
            try:
                q.put(None, timeout=1)
            except queue.Full:
                pass
        deadline = time.monotonic() + timeout
        for p in self.procs:
            if p is None:
                continue
            p.join(max(0.1, deadline - time.monotonic()))
            if p.is_alive():
                self.stop_flag.set()
                p.join(2)
                if p.is_alive():
                    p.terminate()
        if self._collector:
            self._collector.join(3)

    def stats(self) -> dict:
        with self._lock:
            inflight = len(self._inflight)
        return {"workers": self.n, "alive": sum(1 for p in self.procs if p is not None and p.is_alive()),
                "in_flight_batches": inflight, "batches_done": self.batches_done, "errors": self.errors,
                "worker_restarts": self.worker_restarts, "counts": dict(self.counts),
                "written": dict(self.written), "dropped": dict(self.dropped)}
