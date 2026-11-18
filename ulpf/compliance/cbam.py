"""
EU Carbon Border Adjustment Mechanism (CBAM): verifiable emissions data packs for exporters.

Records come from plant systems as CSV (ERP exports, meter readings, supplier
certificates). ``csv_to_jsonl`` turns a CSV file into JSON lines that carry
the source file's SHA-256 and the row number; a ``file`` input ingests them,
so every record is journaled and sealed like any log line. ``export_pack``
then builds ``cbam_datapack_<installation>_<period>.zip``: the records, the
calculation, the source file digests and, for every record, the Merkle
inclusion proof and seal that tie the figure to the bytes received, signed
with the installation's Ed25519 identity key and verifiable with only Python
(``verify_pack.py`` inside the pack).

Record types (``cbam_record_type``; templates: ``ulpf compliance cbam templates``)

    production   installation_id, period, cn_code, good_category, production_route,
                 quantity_t, direct_emissions_tco2e, verified, verification_id, batch_id
    electricity  installation_id, period, meter_id, electricity_mwh,
                 grid_factor_tco2_per_mwh, source, cn_code (optional allocation)
    precursor    installation_id, period, cn_code (the final good), precursor_cn_code,
                 quantity_t, see_direct_tco2e_per_t, supplier, country_of_origin,
                 verification_id (empty: the default value is used)
    shipment     installation_id, period, cn_code, quantity_t, importer_eori,
                 importer_name, destination_country

Calculation (per good, i.e. CN code, per installation and year)

* direct = production direct emissions + embedded direct emissions of precursors
* indirect = electricity MWh x grid factor, allocated to goods by production
  mass unless a meter row names the CN code
* specific embedded emissions SEE = emissions / tonnes produced
* chargeable SEE: direct only for iron and steel, aluminium and hydrogen;
  direct + indirect for cement, fertilisers and electricity
* default values (``--defaults`` CSV: cn_code, see_direct, see_indirect) are
  applied with the mark-up of the year (10 % in 2026, 20 % in 2027, 30 % from
  2028) where no verified actual value exists, and compared with actual values
* the chargeable share follows the phase-out of free allocation: 2.5 % (2026),
  5 % (2027), 10 % (2028), 22.5 % (2029), 48.5 % (2030), 61 % (2031),
  73.5 % (2032), 86 % (2033), 100 % from 2034
* importers below 50 tonnes of CBAM goods a year are below the de minimis
  threshold

Figures are estimates for preparing the declaration and the verifier's
review; mark-ups, phase-in and threshold are parameters (``PHASE_IN``,
``MARKUP``, ``THRESHOLD_T``) to keep in line with the regulation in force.
No EU default values are bundled: supply the values for your CN codes and
country of origin.
"""
from __future__ import annotations

import csv
import hashlib
import html
import io
import json
import os
from collections import defaultdict
from dataclasses import dataclass, field

from ulpf.compliance.packs import evidence_for, identity_key, write_pack

PHASE_IN = {2026: 0.025, 2027: 0.05, 2028: 0.10, 2029: 0.225, 2030: 0.485, 2031: 0.61, 2032: 0.735,
            2033: 0.86, 2034: 1.0}
MARKUP = {2026: 0.10, 2027: 0.20, 2028: 0.30}
THRESHOLD_T = 50.0
DIRECT_ONLY = {"iron_steel", "aluminium", "hydrogen"}
CATEGORIES = ("iron_steel", "aluminium", "cement", "fertilisers", "hydrogen", "electricity")

TEMPLATES = {
    "production.csv": ["cbam_record_type", "installation_id", "period", "cn_code", "good_category",
                       "production_route", "quantity_t", "direct_emissions_tco2e", "verified", "verification_id",
                       "batch_id"],
    "electricity.csv": ["cbam_record_type", "installation_id", "period", "meter_id", "electricity_mwh",
                        "grid_factor_tco2_per_mwh", "source", "cn_code"],
    "precursors.csv": ["cbam_record_type", "installation_id", "period", "cn_code", "precursor_cn_code", "quantity_t",
                       "see_direct_tco2e_per_t", "supplier", "country_of_origin", "verification_id"],
    "shipments.csv": ["cbam_record_type", "installation_id", "period", "cn_code", "quantity_t", "importer_eori",
                      "importer_name", "destination_country"],
}
_RTYPE = {"production.csv": "production", "electricity.csv": "electricity", "precursors.csv": "precursor",
          "shipments.csv": "shipment"}


def phase_in(year: int) -> float:
    if year < 2026:
        return 0.0
    return PHASE_IN.get(year, 1.0)


def markup(year: int) -> float:
    if year < 2026:
        return 0.0
    return MARKUP.get(year, max(MARKUP.values()))


def _num(v) -> float:
    if v is None or v == "":
        return 0.0
    return float(str(v).replace(",", "").strip())


def _year(period) -> int:
    return int(str(period).strip()[:4])


def write_templates(directory: str) -> list[str]:
    os.makedirs(directory, exist_ok=True)
    out = []
    for name, cols in TEMPLATES.items():
        path = os.path.join(directory, name)
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(cols)
        out.append(path)
    return out


def csv_to_jsonl(csv_path: str, out_path: str, record_type: str | None = None) -> int:
    """CSV rows -> JSON lines with the source file's SHA-256 and row number (for a file input)."""
    with open(csv_path, "rb") as f:
        data = f.read()
    digest = hashlib.sha256(data).hexdigest()
    rows = list(csv.DictReader(io.StringIO(data.decode("utf-8-sig"))))
    rtype = record_type or _RTYPE.get(os.path.basename(csv_path))
    n = 0
    with open(out_path, "a", encoding="utf-8") as out:
        for i, row in enumerate(rows, start=2):
            rec = {k.strip(): (v.strip() if isinstance(v, str) else v) for k, v in row.items() if k}
            if rtype and not rec.get("cbam_record_type"):
                rec["cbam_record_type"] = rtype
            if not rec.get("cbam_record_type"):
                raise ValueError(f"{csv_path}:{i}: cbam_record_type missing (name the file after a template "
                                 "or pass --record-type)")
            rec.update(cbam_source_file=os.path.basename(csv_path), cbam_source_sha256=digest, cbam_row=i)
            out.write(json.dumps(rec, separators=(",", ":")) + "\n")
            n += 1
    return n


def record_from_fields(fields: dict) -> dict | None:
    """A CBAM record from an event's parsed fields (None if it is not one)."""
    rtype = fields.get("cbam_record_type")
    if rtype not in ("production", "electricity", "precursor", "shipment"):
        return None
    cols = {"production": TEMPLATES["production.csv"], "electricity": TEMPLATES["electricity.csv"],
            "precursor": TEMPLATES["precursors.csv"], "shipment": TEMPLATES["shipments.csv"]}[rtype]
    rec = {c: fields.get(c) for c in cols}
    for k in ("cbam_source_file", "cbam_source_sha256", "cbam_row"):
        rec[k] = fields.get(k)
    return rec


def to_cbam_view(event: dict) -> dict:
    """The ``cbam`` output view: the CBAM record plus its evidence references."""
    rec = record_from_fields(event.get("parsed_fields") or {}) or {}
    ev = event.get("evidence") or {}
    return {"cbam": rec or None, "event_id": event.get("event_id"), "timestamp": event.get("timestamp"),
            "journal_seq": ev.get("journal_seq"), "raw_sha256": ev.get("raw_hash"), "node_id": ev.get("node_id")}


# ---------------------------------------------------------------------------
# Calculation
# ---------------------------------------------------------------------------

@dataclass
class Good:
    cn_code: str
    category: str = ""
    quantity_t: float = 0.0
    direct_t: float = 0.0
    precursor_direct_t: float = 0.0
    precursor_default_t: float = 0.0
    indirect_t: float = 0.0
    verified: bool = True
    routes: set = field(default_factory=set)


def load_defaults(path: str | None) -> dict[str, dict]:
    if not path:
        return {}
    with open(path, "r", encoding="utf-8-sig") as f:
        return {r["cn_code"].strip(): {"see_direct": _num(r.get("see_direct")),
                                       "see_indirect": _num(r.get("see_indirect"))}
                for r in csv.DictReader(f) if r.get("cn_code")}


def calculate(records: list[dict], installation: str, period: str, defaults: dict | None = None,
              price_eur: float | None = None) -> dict:
    """CBAM figures for one installation and reporting year."""
    year = _year(period)
    defaults = defaults or {}
    mk = markup(year)
    goods: dict[str, Good] = {}
    meters: list[dict] = []
    shipments: list[dict] = []
    issues: list[str] = []
    for r in records:
        if str(r.get("installation_id")) != installation or _year(r.get("period") or "0") != year:
            continue
        t = r["cbam_record_type"]
        if t == "production":
            g = goods.setdefault(str(r["cn_code"]), Good(str(r["cn_code"])))
            g.category = str(r.get("good_category") or g.category).lower()
            g.quantity_t += _num(r.get("quantity_t"))
            g.direct_t += _num(r.get("direct_emissions_tco2e"))
            g.verified = g.verified and str(r.get("verified", "")).lower() in ("true", "yes", "1", "y")
            if r.get("production_route"):
                g.routes.add(str(r["production_route"]))
        elif t == "precursor":
            g = goods.setdefault(str(r["cn_code"]), Good(str(r["cn_code"])))
            qty = _num(r.get("quantity_t"))
            if r.get("verification_id") and r.get("see_direct_tco2e_per_t") not in (None, ""):
                g.precursor_direct_t += qty * _num(r["see_direct_tco2e_per_t"])
            else:
                d = defaults.get(str(r.get("precursor_cn_code")))
                if d is None:
                    issues.append(f"precursor {r.get('precursor_cn_code')} for {r['cn_code']} has no verified value "
                                  "and no default value: not counted")
                    continue
                g.precursor_default_t += qty * d["see_direct"] * (1 + mk)
        elif t == "electricity":
            meters.append(r)
        elif t == "shipment":
            shipments.append(r)
    for g in goods.values():
        if g.category and g.category not in CATEGORIES:
            issues.append(f"{g.cn_code}: unknown good_category {g.category!r}")
    # indirect emissions: meters naming a CN code, the rest by production mass
    total_mass = sum(g.quantity_t for g in goods.values()) or 0.0
    for m in meters:
        tco2 = _num(m.get("electricity_mwh")) * _num(m.get("grid_factor_tco2_per_mwh"))
        cn = str(m.get("cn_code") or "")
        if cn and cn in goods:
            goods[cn].indirect_t += tco2
        elif total_mass:
            for g in goods.values():
                g.indirect_t += tco2 * g.quantity_t / total_mass
    out_goods = []
    for g in sorted(goods.values(), key=lambda x: x.cn_code):
        q = g.quantity_t
        direct = g.direct_t + g.precursor_direct_t + g.precursor_default_t
        see_d = direct / q if q else None
        see_i = g.indirect_t / q if q else None
        chargeable_see = (see_d if g.category in DIRECT_ONLY else (see_d or 0) + (see_i or 0)) if q else None
        d = defaults.get(g.cn_code)
        default_see = None
        if d is not None:
            dd = d["see_direct"] * (1 + mk)
            di = d["see_indirect"] * (1 + mk)
            default_see = dd if g.category in DIRECT_ONLY else dd + di
        out_goods.append({
            "cn_code": g.cn_code, "good_category": g.category, "production_routes": sorted(g.routes),
            "quantity_t": round(q, 6), "direct_emissions_tco2e": round(g.direct_t, 6),
            "precursor_emissions_tco2e": round(g.precursor_direct_t, 6),
            "precursor_default_emissions_tco2e": round(g.precursor_default_t, 6),
            "indirect_emissions_tco2e": round(g.indirect_t, 6),
            "see_direct_tco2e_per_t": None if see_d is None else round(see_d, 6),
            "see_indirect_tco2e_per_t": None if see_i is None else round(see_i, 6),
            "see_chargeable_tco2e_per_t": None if chargeable_see is None else round(chargeable_see, 6),
            "basis": "actual (verified)" if g.verified and not g.precursor_default_t else
                     "actual (unverified or with default precursors)",
            "default_see_with_markup_tco2e_per_t": None if default_see is None else round(default_see, 6),
            "actual_vs_default_tco2e_per_t": None if default_see is None or chargeable_see is None
            else round(chargeable_see - default_see, 6),
        })
    by_good = {g["cn_code"]: g for g in out_goods}
    importers: dict[str, dict] = defaultdict(lambda: {"mass_t": 0.0, "embedded_tco2e": 0.0, "default_tco2e": 0.0,
                                                       "name": None, "goods": set()})
    for s in shipments:
        key = str(s.get("importer_eori") or s.get("importer_name") or "unknown")
        imp = importers[key]
        imp["name"] = s.get("importer_name") or imp["name"]
        qty = _num(s.get("quantity_t"))
        imp["mass_t"] += qty
        g = by_good.get(str(s.get("cn_code")))
        imp["goods"].add(str(s.get("cn_code")))
        if g is None or g["see_chargeable_tco2e_per_t"] is None:
            issues.append(f"shipment of {s.get('cn_code')} to {key}: no production data for this good")
            continue
        imp["embedded_tco2e"] += qty * g["see_chargeable_tco2e_per_t"]
        if g["default_see_with_markup_tco2e_per_t"] is not None:
            imp["default_tco2e"] += qty * g["default_see_with_markup_tco2e_per_t"]
    share = phase_in(year)
    out_imp = []
    for key, imp in sorted(importers.items()):
        certs = imp["embedded_tco2e"] * share
        certs_default = imp["default_tco2e"] * share
        out_imp.append({
            "importer": key, "importer_name": imp["name"], "mass_t": round(imp["mass_t"], 6),
            "goods": sorted(imp["goods"]),
            "threshold": "above de minimis (CBAM obligations apply)" if imp["mass_t"] >= THRESHOLD_T
            else f"below the {THRESHOLD_T:g} t de minimis threshold",
            "embedded_emissions_tco2e": round(imp["embedded_tco2e"], 6),
            "certificates_estimate": round(certs, 6),
            "certificates_if_default_values": round(certs_default, 6) if imp["default_tco2e"] else None,
            "cost_estimate_eur": None if price_eur is None else round(certs * price_eur, 2),
            "cost_if_default_values_eur": None if price_eur is None or not imp["default_tco2e"]
            else round(certs_default * price_eur, 2),
        })
    return {"installation_id": installation, "period": str(period), "year": year,
            "chargeable_share": share, "default_value_markup": mk, "threshold_t": THRESHOLD_T,
            "price_eur_per_tco2e": price_eur, "goods": out_goods, "importers": out_imp, "issues": issues,
            "notes": ["Estimates for preparing the CBAM declaration and the verifier's review.",
                      "Chargeable emissions: direct only for iron/steel, aluminium and hydrogen; direct and "
                      "indirect for cement, fertilisers and electricity.",
                      "Certificate estimate = embedded emissions x chargeable share of the year; carbon prices "
                      "paid in the country of origin are not deducted."]}


# ---------------------------------------------------------------------------
# Records from the store or from files
# ---------------------------------------------------------------------------

def records_from_store(db, installation: str, period: str) -> list[dict]:
    year = str(_year(period))
    with db._conn_lock:
        rows = db.conn.execute(
            "SELECT event_id, parsed_fields, raw_hash, "
            "CAST(json_extract(normalised_json, '$.evidence.journal_seq') AS BIGINT) FROM events "
            "WHERE json_extract_string(parsed_fields, '$.cbam_record_type') IS NOT NULL "
            "AND json_extract_string(parsed_fields, '$.installation_id') = ? "
            "AND starts_with(json_extract_string(parsed_fields, '$.period'), ?)", [installation, year]).fetchall()
    out = []
    for eid, pf, rh, seq in rows:
        rec = record_from_fields(json.loads(pf))
        if rec:
            rec.update(event_id=eid, raw_sha256=rh, journal_seq=seq)
            out.append(rec)
    out.sort(key=lambda r: (r.get("journal_seq") or 0))
    return out


def records_from_files(paths: list[str]) -> list[dict]:
    """CSV or JSONL files read directly (no journal: the pack then has no inclusion proofs)."""
    out = []
    for p in paths:
        if p.lower().endswith(".csv"):
            with open(p, "rb") as f:
                data = f.read()
            digest = hashlib.sha256(data).hexdigest()
            for i, row in enumerate(csv.DictReader(io.StringIO(data.decode("utf-8-sig"))), start=2):
                rec = {k.strip(): (v.strip() if isinstance(v, str) else v) for k, v in row.items() if k}
                rec.setdefault("cbam_record_type", _RTYPE.get(os.path.basename(p)))
                rec.update(cbam_source_file=os.path.basename(p), cbam_source_sha256=digest, cbam_row=i)
                r = record_from_fields(rec)
                if r:
                    out.append(r)
        else:
            with open(p, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        r = record_from_fields(json.loads(line))
                        if r:
                            out.append(r)
    return out


def export_pack(out_dir: str, installation: str, period: str, *, data_dir: str, db=None, journal=None,
                files: list[str] | None = None, defaults_path: str | None = None, price_eur: float | None = None,
                passphrase_env: str | None = None) -> dict:
    """Write cbam_datapack_<installation>_<period>.zip. Returns {"path", "calculation"}."""
    records = records_from_store(db, installation, period) if db is not None else []
    if files:
        records += records_from_files(files)
    if not records:
        raise ValueError(f"no CBAM records for installation {installation!r} in {period}")
    defaults = load_defaults(defaults_path)
    calc = calculate(records, installation, period, defaults, price_eur)
    seqs = [r["journal_seq"] for r in records if r.get("journal_seq") is not None]
    seal_files, proofs = evidence_for(data_dir, journal, seqs) if seqs else ({}, [])
    sources: dict[str, dict] = {}
    for r in records:
        if r.get("cbam_source_sha256"):
            s = sources.setdefault(r["cbam_source_sha256"], {"file": r.get("cbam_source_file"), "rows": 0})
            s["rows"] += 1
    pack_files = {
        "records.json": json.dumps(records, indent=1, default=str).encode(),
        "calculation.json": json.dumps(calc, indent=1).encode(),
        "sources.json": json.dumps([{"sha256": k, **v} for k, v in sources.items()], indent=1).encode(),
        "proofs.json": json.dumps(proofs, indent=1).encode(),
        "summary.html": summary_html(calc, len(records), sum(1 for p in proofs if p.get("sealed"))).encode(),
        "README.txt": README.encode(),
        **seal_files,
    }
    if defaults_path:
        with open(defaults_path, "rb") as f:
            pack_files["default_values.csv"] = f.read()
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in f"{installation}_{period}")
    path = os.path.join(out_dir, f"cbam_datapack_{safe}.zip")
    key = identity_key(data_dir, passphrase_env)
    write_pack(path, "cbam.datapack", pack_files, key,
               {"installation_id": installation, "period": str(period), "records": len(records),
                "sealed_records": sum(1 for p in proofs if p.get("sealed"))})
    return {"path": path, "calculation": calc, "records": len(records)}


README = """CBAM data pack (ULPF)

records.json      every production, electricity, precursor and shipment record, with the
                  journal sequence and SHA-256 of the line as received (raw_sha256) and the
                  SHA-256 of the source file it came from (cbam_source_sha256)
calculation.json  embedded emissions per good, defaults with mark-up, certificate estimates
sources.json      the source files (SHA-256) and how many records each contributed
proofs.json       for each record: Merkle inclusion proof to an evidence seal
seals/            the seals (Ed25519-signed, chained)
manifest.json     SHA-256 of every file;  manifest.sig: Ed25519 signature;  signer.pub

Verify:  python verify_pack.py <this pack>.zip --pubkey <publisher key you received separately>
To tie a record to its source, hash the original CSV file and compare with cbam_source_sha256,
and the JSON line it was ingested as with raw_sha256.
"""


def summary_html(calc: dict, n_records: int, n_sealed: int) -> str:
    e = html.escape
    goods = "".join(
        f"<tr><td>{e(g['cn_code'])}</td><td>{e(g['good_category'])}</td><td>{g['quantity_t']}</td>"
        f"<td>{g['see_direct_tco2e_per_t']}</td><td>{g['see_indirect_tco2e_per_t']}</td>"
        f"<td>{g['see_chargeable_tco2e_per_t']}</td><td>{g['default_see_with_markup_tco2e_per_t']}</td>"
        f"<td>{e(g['basis'])}</td></tr>" for g in calc["goods"])
    imps = "".join(
        f"<tr><td>{e(i['importer'])}</td><td>{i['mass_t']}</td><td>{e(i['threshold'])}</td>"
        f"<td>{i['embedded_emissions_tco2e']}</td><td>{i['certificates_estimate']}</td>"
        f"<td>{i['cost_estimate_eur']}</td></tr>" for i in calc["importers"])
    issues = "".join(f"<li>{e(x)}</li>" for x in calc["issues"]) or "<li>none</li>"
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>CBAM data pack {e(calc['installation_id'])} {e(calc['period'])}</title>
<style>body{{font-family:system-ui,sans-serif;max-width:1100px;margin:2em auto;padding:0 1em}}
table{{border-collapse:collapse;width:100%;font-size:13px}}td,th{{border:1px solid #ccc;padding:4px 6px}}</style></head><body>
<h1>CBAM data pack</h1><p>Installation {e(calc['installation_id'])} · period {e(calc['period'])} ·
chargeable share {calc['chargeable_share']:.1%} · default mark-up {calc['default_value_markup']:.0%}</p>
<p>{n_records} records, {n_sealed} with Merkle inclusion proofs.</p>
<h2>Goods</h2><table><tr><th>CN code</th><th>Category</th><th>Tonnes</th><th>SEE direct</th><th>SEE indirect</th>
<th>SEE chargeable</th><th>Default + mark-up</th><th>Basis</th></tr>{goods}</table>
<h2>Importers</h2><table><tr><th>Importer</th><th>Tonnes</th><th>Threshold</th><th>Embedded tCO2e</th>
<th>Certificates (est.)</th><th>Cost EUR (est.)</th></tr>{imps}</table>
<h2>Issues</h2><ul>{issues}</ul><h2>Notes</h2><ul>{''.join(f'<li>{e(n)}</li>' for n in calc['notes'])}</ul>
</body></html>"""
