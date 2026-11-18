"""
One-command offline forensic bundle (``ulpf bundle``): everything an investigator
needs to examine and verify a node's evidence away from it, in one signed pack.

    seals/                  every evidence seal (Ed25519, chained)
    events.parquet          stored events in the period (unified schema)
    detections.jsonl        Sigma detections and correlation groups in the period
    audit.log               the hash-chained audit log
    erasures/               DPDP Certificates of Erasure (they explain erased rows)
    config.yaml             the pipeline configuration (optional)
    journal/                raw journal segments (optional; encrypted ones stay encrypted)
    verify_pack.py, manifest.json, manifest.sig, signer.pub
"""
from __future__ import annotations

import io
import os
import time

from ulpf.compliance.packs import identity_key, write_pack


def write_bundle(data_dir: str, out_path: str, *, db=None, since: str | None = None, until: str | None = None,
                 include_journal: bool = False, config_path: str | None = None,
                 passphrase_env: str | None = None) -> dict:
    files: dict[str, bytes] = {}
    seal_dir = os.path.join(data_dir, "evidence", "seals")
    if os.path.isdir(seal_dir):
        for n in sorted(os.listdir(seal_dir)):
            if n.startswith("seal-") and n.endswith(".json"):
                with open(os.path.join(seal_dir, n), "rb") as f:
                    files[f"seals/{n}"] = f.read()
    audit = os.path.join(data_dir, "audit", "audit.log")
    if os.path.exists(audit):
        with open(audit, "rb") as f:
            files["audit.log"] = f.read()
    er = os.path.join(data_dir, "compliance", "erasures")
    if os.path.isdir(er):
        for n in sorted(os.listdir(er)):
            if n.endswith(".json") and not n.endswith(".receipt.json"):
                with open(os.path.join(er, n), "rb") as f:
                    files[f"erasures/{n}"] = f.read()
    if config_path:
        with open(config_path, "rb") as f:
            files["config.yaml"] = f.read()
    events = 0
    if db is not None:
        import pyarrow.parquet as pq
        from ulpf.storage.database import EVENT_COLUMNS
        where, params = [], []
        if since:
            where.append("timestamp >= ?")
            params.append(since)
        if until:
            where.append("timestamp <= ?")
            params.append(until)
        clause = (" WHERE " + " AND ".join(where)) if where else ""
        with db._conn_lock:
            table = db.conn.execute(f"SELECT {', '.join(EVENT_COLUMNS)} FROM events{clause}",
                                    params).arrow().read_all()
            det = db.conn.execute(
                f"SELECT normalised_json FROM events{clause}{' AND' if clause else ' WHERE'} "
                "json_extract_string(normalised_json, '$.event_kind') IN ('detection', 'correlation')", params).fetchall()
        buf = io.BytesIO()
        pq.write_table(table, buf, compression="zstd")
        files["events.parquet"] = buf.getvalue()
        files["detections.jsonl"] = "\n".join(r[0] for r in det).encode()
        events = table.num_rows
    if include_journal:
        jdir = os.path.join(data_dir, "journal")
        for n in sorted(os.listdir(jdir)) if os.path.isdir(jdir) else []:
            if n.endswith((".ulj", ".idx")) or n == "journal.state":
                with open(os.path.join(jdir, n), "rb") as f:
                    files[f"journal/{n}"] = f.read()
    node = ""
    try:
        with open(os.path.join(data_dir, "node_id"), "r", encoding="utf-8") as f:
            node = f.read().strip()
    except OSError:
        pass
    key = identity_key(data_dir, passphrase_env)
    manifest = write_pack(out_path, "forensic.bundle", files, key,
                          {"node": node, "period": {"from": since, "to": until}, "events": events,
                           "journal_included": include_journal,
                           "created_by": f"ulpf bundle at {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}"})
    return {"path": out_path, "files": len(manifest["files"]), "events": events,
            "seals": sum(1 for n in files if n.startswith("seals/"))}
