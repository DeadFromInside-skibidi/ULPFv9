"""
Record decoders applied in the workers before parsing (container log formats).

The journal keeps the original bytes (forensics); the decoder hands the
pipeline the application's own message and returns metadata for the event.
"""
from __future__ import annotations

import json
import os
import re

_K8S_NAME = re.compile(r"^(?P<pod>[^_]+)_(?P<namespace>[^_]+)_(?P<container>.+)-(?P<id>[0-9a-f]{64})\.log$")


class ContainerDecoder:
    def __init__(self, mode: str, data_dir: str):
        self.mode = mode
        self.data_dir = data_dir
        self._labels: dict[str, dict] = {}

    def _docker_labels(self, source: str) -> dict:
        cid = os.path.basename(os.path.dirname(source))
        info = self._labels.get(cid)
        if info is None:
            try:
                with open(os.path.join(self.data_dir, "containers", f"{cid}.json"), "r", encoding="utf-8") as f:
                    info = json.load(f)
            except (OSError, ValueError):
                info = {"id": cid, "runtime": "docker"}
            self._labels[cid] = info
        return info

    def _cri_labels(self, source: str) -> dict:
        info = self._labels.get(source)
        if info is None:
            m = _K8S_NAME.match(os.path.basename(source))
            info = {"runtime": self.mode}
            if m:
                info.update(pod=m["pod"], namespace=m["namespace"], name=m["container"], id=m["id"])
            self._labels[source] = info
        return info

    def decode(self, raw: bytes, source: str) -> tuple[str, dict]:
        """Return (message text for the parsers, container metadata)."""
        if self.mode == "docker":
            msgs, stream, ts = [], None, None
            for line in raw.split(b"\n"):
                try:
                    d = json.loads(line)
                except ValueError:
                    msgs.append(line.decode("utf-8", "replace"))
                    continue
                msgs.append(str(d.get("log", "")))
                stream = stream or d.get("stream")
                ts = ts or d.get("time")
            meta = {**self._docker_labels(source), "stream": stream, "time": ts}
            return "".join(msgs).rstrip("\r\n"), meta
        # CRI: "<RFC3339Nano> <stream> <P|F> <message>" per line
        msgs, stream, ts = [], None, None
        for line in raw.split(b"\n"):
            parts = line.decode("utf-8", "replace").split(" ", 3)
            if len(parts) == 4:
                ts = ts or parts[0]
                stream = stream or parts[1]
                msgs.append(parts[3])
            else:
                msgs.append(line.decode("utf-8", "replace"))
        return "".join(msgs).rstrip("\r\n"), {**self._cri_labels(source), "stream": stream, "time": ts}


_JOURNALD_KEEP = ("_SYSTEMD_UNIT", "SYSLOG_IDENTIFIER", "_PID", "_UID", "PRIORITY", "_HOSTNAME",
                  "_COMM", "_EXE", "_BOOT_ID", "__REALTIME_TIMESTAMP")


class JournaldDecoder:
    """journald JSON entry -> its MESSAGE for the parsers, selected fields as metadata."""

    def decode(self, raw: bytes, source: str) -> tuple[str, dict]:
        try:
            d = json.loads(raw)
        except ValueError:
            return raw.decode("utf-8", "replace"), {}
        msg = d.get("MESSAGE", "")
        if isinstance(msg, list):          # binary messages arrive as byte arrays
            msg = bytes(msg).decode("utf-8", "replace")
        return str(msg), {"journald": {k: d[k] for k in _JOURNALD_KEEP if k in d}}


def build_decoders(inputs: list[dict], data_dir: str) -> dict:
    out: dict = {}
    for i in inputs:
        if i.get("type") == "file" and i.get("container", "none") != "none":
            out[i["name"]] = ContainerDecoder(i["container"], data_dir)
        elif i.get("type") == "journald":
            out[i["name"]] = JournaldDecoder()
        elif i.get("type") == "syslog" and i.get("telemetry", "none") != "none":
            from ulpf.runtime.telemetry import TelemetryDecoder
            out[i["name"]] = TelemetryDecoder(i["telemetry"], i)
    return out
