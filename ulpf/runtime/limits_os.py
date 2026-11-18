"""
Hard memory ceilings enforced by the operating system (``limits.hard_memory_mb``).

``limits.max_rss_mb`` only warns. For tactical edge hardware the kernel must
guarantee the bound, for the host *and* every worker process it spawns:

* **Windows**: the process is placed in a Job Object with
  ``JOB_OBJECT_LIMIT_JOB_MEMORY`` (committed memory of all processes in the job;
  children inherit the job). An allocation beyond the ceiling fails
  (``MemoryError`` in Python, ``nullptr`` in native code) instead of paging the
  machine to death; nothing is killed by the OS.
* **Linux**: cgroup v2 ``memory.max`` (hard) and ``memory.high`` (reclaim/throttle
  point, default 90 %) on the process's cgroup when it is delegated and
  writable (systemd ``Delegate=yes`` or a container), else a child cgroup the
  process moves into. When neither is possible the result says why and gives
  the systemd ``MemoryMax=`` / ``MemoryHigh=`` lines to use instead.

``apply_memory_ceiling`` returns a status dict (recorded in the audit log);
``memory_status`` reports current usage against the ceiling.
"""
from __future__ import annotations

import ctypes
import os
import sys

JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x100
JOB_OBJECT_LIMIT_JOB_MEMORY = 0x200
JobObjectExtendedLimitInformation = 9
_job_handle = None


class _IoCounters(ctypes.Structure):
    _fields_ = [(n, ctypes.c_ulonglong) for n in ("ReadOperationCount", "WriteOperationCount",
                                                    "OtherOperationCount", "ReadTransferCount",
                                                    "WriteTransferCount", "OtherTransferCount")]


class _BasicLimit(ctypes.Structure):
    _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong), ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", ctypes.c_uint32), ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", ctypes.c_uint32),
                ("Affinity", ctypes.c_size_t), ("PriorityClass", ctypes.c_uint32),
                ("SchedulingClass", ctypes.c_uint32)]


class _ExtendedLimit(ctypes.Structure):
    _fields_ = [("BasicLimitInformation", _BasicLimit), ("IoInfo", _IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]


def _k32():
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateJobObjectW.restype = ctypes.c_void_p
    k.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
    k.SetInformationJobObject.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    k.QueryInformationJobObject.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32,
                                            ctypes.c_void_p]
    k.AssignProcessToJobObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    k.OpenProcess.restype = ctypes.c_void_p
    k.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    k.GetCurrentProcess.restype = ctypes.c_void_p
    k.CloseHandle.argtypes = [ctypes.c_void_p]
    return k


def windows_job_limit(limit_mb: int, pid: int | None = None, per_process: bool = False) -> dict:
    """Put ``pid`` (default: this process) in a new Job Object limited to ``limit_mb`` committed MiB."""
    global _job_handle
    k = _k32()
    job = k.CreateJobObjectW(None, None)
    if not job:
        return {"applied": False, "mechanism": "job_object", "error": f"CreateJobObject: {ctypes.get_last_error()}"}
    info = _ExtendedLimit()
    flag = JOB_OBJECT_LIMIT_PROCESS_MEMORY if per_process else JOB_OBJECT_LIMIT_JOB_MEMORY
    info.BasicLimitInformation.LimitFlags = flag
    if per_process:
        info.ProcessMemoryLimit = int(limit_mb) * 2**20
    else:
        info.JobMemoryLimit = int(limit_mb) * 2**20
    if not k.SetInformationJobObject(job, JobObjectExtendedLimitInformation, ctypes.byref(info),
                                     ctypes.sizeof(info)):
        err = ctypes.get_last_error()
        k.CloseHandle(job)
        return {"applied": False, "mechanism": "job_object", "error": f"SetInformationJobObject: {err}"}
    if pid is None:
        proc, close = k.GetCurrentProcess(), False
    else:
        proc, close = k.OpenProcess(0x0100 | 0x0001, False, int(pid)), True    # SET_QUOTA | TERMINATE
    ok = k.AssignProcessToJobObject(job, proc)
    err = ctypes.get_last_error()
    if close and proc:
        k.CloseHandle(proc)
    if not ok:
        k.CloseHandle(job)
        return {"applied": False, "mechanism": "job_object", "error": f"AssignProcessToJobObject: {err}"}
    if pid is None:
        _job_handle = job              # keep the job alive for this process's lifetime
    return {"applied": True, "mechanism": "job_object", "limit_mb": int(limit_mb),
            "scope": "process" if per_process else "job (host + workers)", "handle": int(job)}


def _job_usage() -> dict:
    if _job_handle is None:
        return {}
    k = _k32()
    info = _ExtendedLimit()
    if k.QueryInformationJobObject(_job_handle, JobObjectExtendedLimitInformation, ctypes.byref(info),
                                   ctypes.sizeof(info), None):
        return {"peak_job_mb": round(info.PeakJobMemoryUsed / 2**20, 1),
                "limit_mb": round(info.JobMemoryLimit / 2**20, 1)}
    return {}


def _own_cgroup() -> str | None:
    try:
        with open("/proc/self/cgroup", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("0::"):
                    return "/sys/fs/cgroup" + line[3:].strip()
    except OSError:
        return None
    return None


def cgroup_limit(limit_mb: int, high_mb: int | None = None) -> dict:
    cg = _own_cgroup()
    high = int(high_mb or limit_mb * 0.9)
    systemd = [f"MemoryMax={int(limit_mb)}M", f"MemoryHigh={high}M", "MemorySwapMax=0"]
    if cg is None or not os.path.exists(os.path.join(cg, "memory.max")) and \
            not os.path.exists(os.path.join(cg, "cgroup.subtree_control")):
        return {"applied": False, "mechanism": "cgroup_v2", "error": "cgroup v2 not mounted or no own cgroup",
                "systemd": systemd}

    def write(path, value):
        with open(path, "w", encoding="ascii") as f:
            f.write(str(value))
    try:
        target = cg
        if not os.access(os.path.join(cg, "memory.max"), os.W_OK):
            target = os.path.join(cg, "ulpf-runtime")
            os.makedirs(target, exist_ok=True)
            write(os.path.join(target, "cgroup.procs"), os.getpid())
        write(os.path.join(target, "memory.max"), int(limit_mb) * 2**20)
        write(os.path.join(target, "memory.high"), high * 2**20)
        try:
            write(os.path.join(target, "memory.swap.max"), 0)
        except OSError:
            pass
        return {"applied": True, "mechanism": "cgroup_v2", "cgroup": target, "limit_mb": int(limit_mb),
                "high_mb": high, "scope": "cgroup (host + workers)"}
    except OSError as e:
        return {"applied": False, "mechanism": "cgroup_v2", "error": str(e), "systemd": systemd,
                "hint": "run under systemd with the MemoryMax/MemoryHigh lines, or Delegate=yes"}


def apply_memory_ceiling(limit_mb: int, high_mb: int | None = None, include_children: bool = True) -> dict:
    if limit_mb <= 0:
        return {"applied": False, "error": "limit must be positive"}
    if sys.platform == "win32":
        return windows_job_limit(limit_mb, per_process=not include_children)
    if sys.platform.startswith("linux"):
        return cgroup_limit(limit_mb, high_mb)
    return {"applied": False, "error": f"no hard memory ceiling mechanism on {sys.platform}"}


def memory_status() -> dict:
    out: dict = {}
    try:
        import psutil
        p = psutil.Process()
        rss = p.memory_info().rss + sum(c.memory_info().rss for c in p.children(recursive=True))
        out["rss_mb"] = round(rss / 2**20, 1)
    except Exception:
        pass
    if sys.platform == "win32":
        out.update(_job_usage())
    else:
        cg = _own_cgroup()
        for name in ("memory.current", "memory.max", "memory.high"):
            for base in (cg, os.path.join(cg or "", "ulpf-runtime")):
                try:
                    with open(os.path.join(base, name), "r", encoding="ascii") as f:
                        v = f.read().strip()
                    out[name] = v if v == "max" else round(int(v) / 2**20, 1)
                except (OSError, ValueError, TypeError):
                    continue
    return out
