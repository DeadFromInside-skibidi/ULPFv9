"""
Schema registry: one JSON file per released unified-schema version.

    <version>.json = {"version": "1.1.0", "fields": {"source.ip": "IPv4/IPv6 string", ...}}

Rules (checked by ``diff`` and by the test suite):

* a minor or patch release may only add fields;
* removing a field or changing its type needs a new major version;
* the registry entry for ``SCHEMA_VERSION`` must equal the live catalogue,
  so a catalogue change without a version bump fails CI.

    ulpf schema diff 1.0.0 1.1.0      (versions or paths to exported files)
    ulpf schema export [FILE]         (the live catalogue in registry form)
"""
from __future__ import annotations

import json
import os

REGISTRY_DIR = os.path.dirname(os.path.abspath(__file__))


def current() -> dict:
    from ulpf.engine.schema import SCHEMA_DEFINITION, SCHEMA_VERSION
    fields = {f["name"]: f["type"] for g in SCHEMA_DEFINITION["groups"] for f in g["fields"]}
    return {"version": SCHEMA_VERSION, "fields": dict(sorted(fields.items()))}


def versions() -> list[str]:
    out = [n[:-5] for n in os.listdir(REGISTRY_DIR) if n.endswith(".json")]
    return sorted(out, key=_vkey)


def _vkey(v: str) -> tuple:
    try:
        return tuple(int(x) for x in v.split("."))
    except ValueError:
        return (0,)


def load(ref: str) -> dict:
    """A registry version ("1.0.0"), "current", or a path to an exported file."""
    if ref == "current":
        return current()
    path = ref if os.path.exists(ref) else os.path.join(REGISTRY_DIR, f"{ref}.json")
    if not os.path.exists(path):
        raise FileNotFoundError(f"unknown schema version {ref!r} (known: {', '.join(versions())})")
    with open(path, "r", encoding="utf-8") as f:
        doc = json.load(f)
    if "fields" not in doc and "groups" in doc:      # a SCHEMA_DEFINITION export
        doc = {"version": doc.get("version", "?"),
               "fields": {f["name"]: f["type"] for g in doc["groups"] for f in g["fields"]}}
    return doc


def diff(old: dict, new: dict) -> dict:
    o, n = old["fields"], new["fields"]
    added = sorted(set(n) - set(o))
    removed = sorted(set(o) - set(n))
    changed = sorted(k for k in set(o) & set(n) if o[k] != n[k])
    breaking = bool(removed or changed)
    ov, nv = _vkey(str(old.get("version"))), _vkey(str(new.get("version")))
    major_bumped = len(ov) >= 1 and len(nv) >= 1 and nv[0] > ov[0]
    problems = []
    if breaking and not major_bumped:
        problems.append(f"{len(removed)} removed and {len(changed)} retyped field(s) need a major version "
                        f"(got {old.get('version')} -> {new.get('version')})")
    if added and nv <= ov:
        problems.append(f"{len(added)} field(s) added without a version bump")
    return {"old": old.get("version"), "new": new.get("version"), "added": added, "removed": removed,
            "type_changed": [{"field": k, "old": o[k], "new": n[k]} for k in changed],
            "breaking": breaking, "compatible": not problems, "problems": problems}


def export(path: str | None = None) -> dict:
    doc = current()
    if path:
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(doc, f, indent=2)
            f.write("\n")
    return doc
