"""
Build ``ulpf/engine/standards/ocsf_1_3_0.json`` from the OCSF schema server's API
(https://schema.ocsf.io/api/1.3.0/...) responses saved in a directory:

    classes.json, objects.json, types.json       (list endpoints; types = data_types)
    cls/<name>.json                              (one per class; extension classes as <ext>_<name>.json)
    obj/<name>.json                              (one per object)

    python scripts/build_ocsf_schema.py <download dir>

The bundle keeps what ULPF's OCSF view and its conformance check need: per class
and object, each attribute as [requirement (r/R/o), type, object type, enum
{value: caption}, profile, is_array, sibling]; per class, its activities. OCSF is Apache-2.0 licensed (docs/SOURCES.md).
"""
from __future__ import annotations

import json
import os
import sys

REQ = {"required": "r", "recommended": "R", "optional": "o"}


def attrs(items) -> dict:
    out = {}
    for a in items:
        (name, v), = a.items()
        enum = v.get("enum")
        if enum and v.get("type") in ("integer_t", "long_t"):
            enum = {str(k): e.get("caption") for k, e in sorted(enum.items(), key=lambda kv: int(kv[0]))}
        elif enum:
            enum = {str(k): e.get("caption") for k, e in sorted(enum.items())}
        out[name] = [REQ.get(v.get("requirement"), "o"), v.get("type"), v.get("object_type"), enum or None,
                     v.get("profile"), bool(v.get("is_array")), v.get("sibling")]
    return out


def main(d: str) -> int:
    classes = json.load(open(os.path.join(d, "classes.json"), encoding="utf-8"))
    objects = json.load(open(os.path.join(d, "objects.json"), encoding="utf-8"))
    types = json.load(open(os.path.join(d, "types.json"), encoding="utf-8"))
    out = {"version": "1.3.0", "source": "https://schema.ocsf.io/api/1.3.0", "classes": {}, "objects": {},
           "types": {k: v.get("type") for k, v in types.items()}}
    for c in classes:
        fn = (c["extension"] + "_" if c.get("extension") else "") + c["name"]
        full = json.load(open(os.path.join(d, "cls", fn + ".json"), encoding="utf-8"))
        a = attrs(full["attributes"])
        act = {}
        for item in full["attributes"]:
            (name, v), = item.items()
            if name == "activity_id":
                act = {int(k): e["caption"] for k, e in v.get("enum", {}).items()}
        out["classes"][str(c["uid"])] = {"name": c["name"], "caption": c["caption"],
                                         "category_uid": c.get("category_uid", 0),
                                         "category_name": c.get("category_name"), "extension": c.get("extension"),
                                         "activities": dict(sorted(act.items())), "attributes": a}
    for o in objects:
        name = (o["extension"] + "/" if o.get("extension") else "") + o["name"]
        path = os.path.join(d, "obj", name.replace("/", "_") + ".json")
        if not os.path.exists(path):
            print(f"missing object {name}", file=sys.stderr)
            continue
        full = json.load(open(path, encoding="utf-8"))
        out["objects"][name] = {"attributes": attrs(full.get("attributes") or [])}
    dest = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "ulpf", "engine", "standards", "ocsf_1_3_0.json")
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(dest, "w", encoding="utf-8", newline="\n") as f:
        json.dump(out, f, separators=(",", ":"), sort_keys=True)
    print(f"{dest}: {len(out['classes'])} classes, {len(out['objects'])} objects")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
