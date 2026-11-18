"""
Arithmetic behind the incubation pack: ROI, sizing, TAM/SAM/SOM and the
3-year plan. Every input is either a measurement (with its result file) or a
labelled assumption; change an input here and re-run generate_proposal_docs.py.

    python incubation_pack/model.py        # prints every table as JSON
"""
from __future__ import annotations

import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ---------------------------------------------------------------- measurements
MEASURED = {
    # benchmarks/results/latency/encoded_size_20261023_023215.json
    "raw_bytes_per_event": 183.1,
    "encoded_vs_raw": {"raw (format: raw)": 1.02, "CEF syslog": 2.55, "LEEF syslog": 2.46, "OCSF JSON": 9.12,
                       "ECS JSON": 10.51, "unified JSON": 14.25},
    # benchmarks/results/latency/latency_footprint_20261023_023101.json
    "journal_vs_raw": 1.359, "duckdb_vs_raw": 7.5, "parquet_vs_raw": 2.002,
    "synthetic_forward_share_pct": 40.59,
    # benchmarks/results/live/runtime_tcp_20261022_024737.json (6 workers, laptop)
    "node_eps_measured": 26_952,
}

# ---------------------------------------------------------------- assumptions
ASSUME = {
    "usd_inr": 88.0,                      # assumption: planning exchange rate
    "sentinel_payg_usd_per_gb": 4.30,     # third-party reported East-US PAYG analytics rate (Microsoft: estimates vary by region/agreement)
    "sentinel_100gb_tier_usd_per_gb": 2.96,  # third-party: ~$296/day for the 100 GB/day commitment tier
    "customer_gb_per_day": 100,
    "ulpf_pro_inr_per_node_year": 360_000,
    "node_planning_fraction": 0.60,       # plan nodes at 60 % of the measured rate
    "retention_days": 180,                # CERT-In direction (April 2022)
    "disk_inr_per_tb": 6_000,             # assumption: usable NAS-class capacity incl. redundancy; get customer quotes
}


def roi(forward_share: float, rate_usd_per_gb: float, upstream_format: str = "raw (format: raw)") -> dict:
    a, m = ASSUME, MEASURED
    gb = a["customer_gb_per_day"]
    before = gb * rate_usd_per_gb * 365 * a["usd_inr"]
    upstream_gb = gb * forward_share * m["encoded_vs_raw"][upstream_format]
    after = upstream_gb * rate_usd_per_gb * 365 * a["usd_inr"]
    events_per_s = gb * 1e9 / m["raw_bytes_per_event"] / 86_400
    nodes = max(1, -(-events_per_s // (m["node_eps_measured"] * a["node_planning_fraction"])))
    archive_tb = gb * m["journal_vs_raw"] * a["retention_days"] / 1000
    disk = archive_tb * a["disk_inr_per_tb"]
    license_ = nodes * a["ulpf_pro_inr_per_node_year"]
    saving = before - after - license_ - disk / 3      # disk amortised over 3 years
    return {"forward_share_pct": round(100 * forward_share, 1), "upstream_format": upstream_format,
            "siem_rate_usd_per_gb": rate_usd_per_gb, "siem_cost_before_inr": round(before),
            "upstream_gb_per_day": round(upstream_gb, 1), "siem_cost_after_inr": round(after),
            "avg_events_per_s": round(events_per_s), "ulpf_nodes": int(nodes), "ulpf_license_inr": int(license_),
            "archive_tb_180d": round(archive_tb, 1), "archive_disk_inr_once": round(disk),
            "net_saving_inr_per_year": round(saving),
            "saving_per_license_rupee": round(saving / license_, 1)}


ROI_SCENARIOS = [roi(f, r, fmt) for f, r, fmt in (
    (0.10, ASSUME["sentinel_payg_usd_per_gb"], "raw (format: raw)"),
    (0.25, ASSUME["sentinel_payg_usd_per_gb"], "raw (format: raw)"),
    (0.406, ASSUME["sentinel_payg_usd_per_gb"], "raw (format: raw)"),
    (0.10, ASSUME["sentinel_100gb_tier_usd_per_gb"], "raw (format: raw)"),
    (0.10, ASSUME["sentinel_payg_usd_per_gb"], "CEF syslog"),
    (0.10, ASSUME["sentinel_payg_usd_per_gb"], "ECS JSON"),
)]

# ---------------------------------------------------------------- market sizing (India, bottom-up)
SEGMENTS = [
    # name, entities, source, nodes per entity, price per node (INR/yr), SAM share, SAM basis
    ("NBFCs registered with RBI", 9_291, "RBI list as of 31-Dec-2024", 1, 360_000, 0.10,
     "assumption: the ~10 % with in-house IT and a SIEM"),
    ("Urban co-operative banks", 1_457, "RBI Annual Report, end-March 2025", 1, 360_000, 0.425,
     "Tier 2-4 UCBs (42.5 %; 57.5 % are Tier 1, RBI)"),
    ("CERT-In empanelled audit organisations (as channel)", 231, "PIB, January 2026", 20, 252_000, 0.20,
     "assumption: 20 % run managed SOC/log services; 20 client nodes each at 70 % of list"),
    ("Defence / PSU / critical-infrastructure sites", 300, "assumption (no public count found)", 1, 1_500_000, 0.30,
     "assumption: sites with air-gap requirements reachable via iDEX/PSU tenders"),
]


def market() -> dict:
    rows, tam, sam = [], 0, 0
    for name, n, src, nodes, price, share, basis in SEGMENTS:
        t = n * nodes * price
        s = t * share
        tam += t
        sam += s
        rows.append({"segment": name, "entities": n, "source": src, "nodes_per_entity": nodes,
                     "price_inr": price, "tam_inr": t, "sam_share": share, "sam_basis": basis, "sam_inr": round(s)})
    return {"rows": rows, "tam_inr": tam, "sam_inr": round(sam)}


# ---------------------------------------------------------------- 3-year plan (planning assumptions, not forecasts)
PLAN = {
    "Y1": {"pro_nodes": 5, "sovereign_sites": 1, "sovereign_price": 1_200_000, "mssp_partners": 2, "nodes_per_partner": 5,
           "team": 4, "monthly_burn": 600_000},
    "Y2": {"pro_nodes": 20, "sovereign_sites": 3, "sovereign_price": 1_500_000, "mssp_partners": 6, "nodes_per_partner": 10,
           "team": 9, "monthly_burn": 1_800_000},
    "Y3": {"pro_nodes": 50, "sovereign_sites": 8, "sovereign_price": 1_800_000, "mssp_partners": 15, "nodes_per_partner": 15,
           "team": 18, "monthly_burn": 4_000_000},
}
UNIT = {"pro_price": 360_000, "mssp_net_per_node": 252_000, "gross_margin": 0.85, "annual_churn": 0.15,
        "cac_pro": 150_000, "cac_sovereign": 600_000, "cac_mssp_partner": 300_000}


def plan() -> dict:
    out = {}
    for y, p in PLAN.items():
        pro = p["pro_nodes"] * UNIT["pro_price"]
        sov = p["sovereign_sites"] * p["sovereign_price"]
        mssp = p["mssp_partners"] * p["nodes_per_partner"] * UNIT["mssp_net_per_node"]
        arr = pro + sov + mssp
        cost = p["monthly_burn"] * 12
        out[y] = {**p, "arr_pro": pro, "arr_sovereign": sov, "arr_mssp": mssp, "arr_total": arr,
                  "gross_profit": round(arr * UNIT["gross_margin"]), "annual_cost": cost,
                  "net": round(arr * UNIT["gross_margin"] - cost)}
    ltv_pro = UNIT["pro_price"] * UNIT["gross_margin"] / UNIT["annual_churn"]
    ltv_sov = 1_500_000 * UNIT["gross_margin"] / 0.10
    ltv_mssp = 10 * UNIT["mssp_net_per_node"] * UNIT["gross_margin"] / 0.20
    out["unit"] = {"ltv_pro": round(ltv_pro), "ltv_cac_pro": round(ltv_pro / UNIT["cac_pro"], 1),
                   "ltv_sovereign": round(ltv_sov), "ltv_cac_sovereign": round(ltv_sov / UNIT["cac_sovereign"], 1),
                   "ltv_mssp_partner": round(ltv_mssp), "ltv_cac_mssp": round(ltv_mssp / UNIT["cac_mssp_partner"], 1),
                   **UNIT}
    return out


def cr(x: float) -> str:
    """INR in crore/lakh for tables."""
    return f"₹{x / 1e7:,.2f} Cr" if abs(x) >= 1e7 else f"₹{x / 1e5:,.1f} L"


if __name__ == "__main__":
    print(json.dumps({"roi": ROI_SCENARIOS, "market": market(), "plan": plan()}, indent=1, ensure_ascii=False))
