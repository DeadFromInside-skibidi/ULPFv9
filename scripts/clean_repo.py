"""
Remove build, cache and benchmark artifacts from the source tree.

    python scripts/clean_repo.py            # list what would be removed (nothing is deleted)
    python scripts/clean_repo.py --yes      # remove it

Benchmark result JSON files are kept (the docs cite them); only the raw
corpora (corpus_*.log), archives (*.zip) and plots are removed. The bundled
interpreter (python311/) and runtime data outside the tree are never touched.
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# (path relative to ROOT, glob-free) directories removed whole
DIRS = [
    "native/ulpf_core/target",
    "build",
    "dist",
    ".hypothesis",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    "ulpf.egg-info",
]

# (directory, predicate on file name) files removed inside a tree
FILE_RULES = [
    ("benchmarks/results", lambda n: n.startswith("corpus_") and n.endswith(".log")),
    ("benchmarks/results", lambda n: n.endswith(".zip")),
    ("benchmarks", lambda n: n.endswith(".zip")),
    ("ulpf", lambda n: n.startswith("ulpf_core") and n.endswith((".pyd", ".so", ".dylib"))),
]

SKIP = {"python311", ".git", ".venv", "venv"}


def _size(path: str) -> int:
    if os.path.isfile(path):
        return os.path.getsize(path)
    total = 0
    for dirpath, _dirs, files in os.walk(path):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(dirpath, f))
            except OSError:
                pass
    return total


def targets(root: str = ROOT) -> list[str]:
    out = [os.path.join(root, d) for d in DIRS if os.path.isdir(os.path.join(root, d))]
    for base, pred in FILE_RULES:
        base_dir = os.path.join(root, base)
        if not os.path.isdir(base_dir):
            continue
        # benchmarks/*.zip and ulpf/ulpf_core.* are top-level only; results/ is recursive
        recursive = base == "benchmarks/results"
        walker = os.walk(base_dir) if recursive else [(base_dir, [], os.listdir(base_dir))]
        for dirpath, _dirs, files in walker:
            for f in files:
                p = os.path.join(dirpath, f)
                if os.path.isfile(p) and pred(f):
                    out.append(p)
    for dirpath, dirs, _files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP and os.path.join(dirpath, d) not in out]
        for d in list(dirs):
            if d == "__pycache__":
                out.append(os.path.join(dirpath, d))
                dirs.remove(d)
    return sorted(set(out))


def remove(path: str) -> None:
    if os.path.isdir(path):
        shutil.rmtree(path)
    else:
        os.remove(path)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("--yes", action="store_true", help="Delete (default: only list)")
    ap.add_argument("--root", default=ROOT, help=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    found = targets(args.root)
    total = 0
    for p in found:
        n = _size(p)
        total += n
        print(f"{n / 2**20:9.1f} MB  {os.path.relpath(p, args.root)}")
    print(f"{total / 2**20:9.1f} MB  total in {len(found)} path(s)")
    if not args.yes:
        print("dry run: nothing deleted (pass --yes to delete)")
        return 0
    failed = 0
    for p in found:
        try:
            remove(p)
        except OSError as e:
            failed += 1
            print(f"could not remove {p}: {e}", file=sys.stderr)
    print(f"removed {len(found) - failed} path(s)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
