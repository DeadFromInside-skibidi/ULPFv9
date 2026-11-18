"""
Windows Event Log input (live channels) via ``wevtutil``, no extra packages.

Each channel is polled for events with ``EventRecordID`` above the
checkpoint; each event is journaled as its rendered XML (the XML parser maps
``EventData``/``Data Name=`` fields). Reading ``Security`` needs an account
with "Manage auditing and security log" rights (e.g. Administrators or Event
Log Readers).
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
import threading

from ulpf.runtime.inputs.base import Input

_EVENT = re.compile(rb"<Event[ >].*?</Event>", re.S)
_RID = re.compile(rb"<EventRecordID>(\d+)</EventRecordID>")


class EvtxInput(Input):
    def _query(self, channel: str, after: int, count: int = 500) -> list[bytes]:
        # ``query`` is an extra condition on System, e.g. "Level<=3" or "EventID=4625"
        cond = self.opts.get("query")
        extra = f" and ({cond})" if cond not in (None, "", "*") else ""
        q = f"*[System[(EventRecordID>{after}){extra}]]"
        r = subprocess.run([self.exe, "qe", channel, f"/q:{q}", "/f:xml", "/rd:false", f"/c:{count}"],
                           capture_output=True, timeout=120)
        if r.returncode != 0:
            msg = r.stderr.decode(errors="replace").strip() or r.stdout.decode(errors="replace").strip()
            raise PermissionError(f"wevtutil {channel}: {msg[:300]}")
        return _EVENT.findall(r.stdout)

    def run(self, stop: threading.Event) -> None:
        if sys.platform != "win32":
            raise RuntimeError("the evtx input reads live Windows event channels (Windows only)")
        self.exe = shutil.which("wevtutil") or "wevtutil"
        channels = self.opts.get("channels") or ["System"]
        last: dict[str, int] = {}
        for ch in channels:
            ck = self.ctx.checkpoints.durable(f"evtx:{self.name}:{ch}")
            if ck is not None:
                last[ch] = int(ck["value"])
            else:   # start at the newest event: do not backfill whole channels on first run
                newest = self._query_newest(ch)
                last[ch] = newest
        interval = self.opts.get("poll_interval_ms", 1000) / 1000.0
        while not stop.is_set():
            for ch in channels:
                events = self._query(ch, last[ch])
                while events:
                    ids = [int(_RID.search(e).group(1)) for e in events]
                    self.accept(ch, events, block=True)
                    last[ch] = max(ids)
                    self.ctx.checkpoints.set(f"evtx:{self.name}:{ch}", last[ch], self.last_seq)
                    events = self._query(ch, last[ch]) if len(events) >= 500 else []
            stop.wait(interval)

    def _query_newest(self, channel: str) -> int:
        r = subprocess.run([self.exe, "qe", channel, "/f:xml", "/rd:true", "/c:1"], capture_output=True, timeout=60)
        m = _RID.search(r.stdout)
        if r.returncode != 0:
            msg = r.stderr.decode(errors="replace").strip()
            raise PermissionError(f"wevtutil {channel}: {msg[:300]}")
        return int(m.group(1)) if m else 0
