# -*- coding: utf-8 -*-
"""طابور مهام الفحص: خيط عامل واحد، إيقاف عبر أعلام، وتنظيف الفحوص اليتيمة."""
from __future__ import annotations

import queue
import threading
import time

from . import db, scanner


class JobQueue:
    def __init__(self):
        self._q: queue.Queue[int] = queue.Queue()
        self._positions: dict[int, float] = {}
        self._stop_flags: dict[int, threading.Event] = {}
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._running = False

    def enqueue(self, sid: int) -> int:
        with self._lock:
            self._stop_flags[sid] = threading.Event()
            self._positions[sid] = time.time()
            self._q.put(sid)
            return sorted(self._positions.values()).index(self._positions[sid]) + 1

    def request_stop(self, sid: int) -> bool:
        with self._lock:
            flag = self._stop_flags.get(sid)
            if flag:
                flag.set()
                return True
            return False

    def position(self, sid: int) -> int | None:
        with self._lock:
            if sid not in self._positions:
                return None
            return sorted(self._positions.values()).index(self._positions[sid]) + 1

    def snapshot(self) -> dict:
        with self._lock:
            return {"queued": sorted(self._positions, key=self._positions.get),
                    "size": len(self._positions)}

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, name="th-ghost-worker", daemon=True)
        self._thread.start()

    def _loop(self):
        while True:
            sid = self._q.get()
            with self._lock:
                self._positions.pop(sid, None)
            flag = self._stop_flags.get(sid, threading.Event())
            db.set_scan_status(sid, "running")
            try:
                scanner.scan_project(sid, stop_flag=flag.is_set)
            except Exception:
                try:
                    db.finish_scan(sid, {"error": "worker"}, status="error")
                except Exception:
                    pass
            finally:
                with self._lock:
                    self._stop_flags.pop(sid, None)
            self._q.task_done()


QUEUE = JobQueue()


def start_worker():
    QUEUE.start()


def mark_orphan_scans():
    """عند الإقلاع: أي فحص عالق running/queued من جلسة سابقة يُعلَّم متوقفاً."""
    for s in db.running_scans():
        db.set_scan_status(s["id"], "stopped")
        db.finish_scan(s["id"], {"note": "أُوقف عند إعادة تشغيل الخادم."}, status="stopped")
