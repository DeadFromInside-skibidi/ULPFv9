"""
Pipeline configuration: load, validate, apply mode defaults, enforce mode rules.

    cfg = load_pipeline_config("pipeline.yaml")      # raises ConfigError
    report = describe(cfg)                           # startup / `ulpf config check` report

Mode rules have ids (for example ``defence.tls_listeners``). A rule can be
waived by listing its id under ``overrides:``; every waiver is reported at
startup and recorded in the audit log.
"""
from __future__ import annotations

import importlib.util
import ipaddress
import os
from dataclasses import dataclass, field
from typing import Any

from ulpf.config.components import INPUTS, OUTPUTS, component, remote_endpoints
from ulpf.config.schema import ConfigError, ConfigIssue, Opt, Validator, load_yaml_with_lines

MODES = ("defence", "industry")

WHEN_SPEC = {
    "kind_in": Opt(list, None, item=str),
    "input_in": Opt(list, None, item=str),
    "source_in": Opt(list, None, item=str),
    "raw_format_in": Opt(list, None, item=str),
    "category_in": Opt(list, None, item=str),
    "severity_gte": Opt(int, None, min=0),
    "severity_lte": Opt(int, None, min=0),
    "field_exists": Opt(list, None, item=str),
    "field_equals": Opt(dict, None),
}

PROFILES = ("default", "tactical_edge")

TOP_SPEC: dict[str, Opt] = {
    "mode": Opt(str, "industry", choices=MODES),
    "profile": Opt(str, "default", choices=PROFILES,
                   help="tactical_edge: a defence-mode appliance with fixed memory/disk quotas "
                        "(UAV ground stations, space and field systems)"),
    "limits": Opt(dict, spec={
        "max_rss_mb": Opt((int, float), 0, min=0, help="Warn and audit when host + workers exceed this RSS (0: off)"),
        "max_disk_mb": Opt((int, float), 0, min=0,
                           help="Retire the oldest store partitions while the data directory exceeds this (0: off)"),
        "duckdb_memory_mb": Opt((int, float), 0, min=0, help="DuckDB buffer pool cap (0: automatic)"),
        "hard_memory_mb": Opt((int, float), 0, min=0,
                              help="Hard RSS ceiling for host + workers: cgroup v2 memory.max (Linux) or a "
                                   "Job Object memory limit (Windows); 0: off"),
        "memory_high_mb": Opt((int, float), 0, min=0,
                              help="cgroup v2 memory.high throttle point (default 90% of hard_memory_mb)")}),
    "node": Opt(dict, spec={"id": Opt(str), "data_dir": Opt(str)}),
    "workers": Opt((int, str), "auto"),
    "journal": Opt(dict, spec={
        "sync": Opt(str, None, choices=("always", "interval", "never")),
        "sync_interval_ms": Opt(int, 200, min=1),
        "segment_mb": Opt(int, 64, min=1),
        "retention_days": Opt((int, float), None, min=0),
        "encrypt": Opt(bool, None),
        "key_file": Opt(str, help="AES-256 key file (default <data dir>/journal.key)")}),
    "inputs": Opt(list, [], item=dict),
    "outputs": Opt(list, [], item=dict),
    "routes": Opt(list, [], item={
        "name": Opt(str, required=True),
        "when": Opt(dict, spec=WHEN_SPEC),
        "to": Opt(list, required=True, item=str),
        "final": Opt(bool, False, help="Stop evaluating later routes when this one matches")}),
    "default_output": Opt(str),
    "airgap": Opt(dict, spec={
        "allow": Opt(list, [], item=str, help="Hostnames, IPs or CIDRs outputs/inputs may reach"),
        "allow_route": Opt(bool, False, help="Defence mode: permit a default route to exist"),
        "enforce": Opt(bool, None, help="Enforce the allow-list (always on in defence mode)"),
        "dns_refresh_seconds": Opt((int, float), 60, min=0,
                                   help="Re-resolve allowed host names this often (0: only at start)"),
        "dns_grace_seconds": Opt((int, float), 300, min=0,
                                 help="Keep an address a name stopped resolving to allowed this long")}),
    "evidence": Opt(dict, spec={
        "enabled": Opt(bool, None),
        "seal_every_events": Opt(int, None, min=1),
        "seal_every_seconds": Opt((int, float), None, min=0.1),
        "row_mac": Opt(bool, None, help="MAC every stored row so edits to any column are detected "
                                        "(default on in defence mode; costs ~10 % throughput)"),
        "row_key_epoch_records": Opt(int, None, min=1,
                                     help="Records per row-MAC key epoch; the key ratchets forward and "
                                          "earlier keys are erased (default: seal_every_events)"),
        "row_key_escrow": Opt(str, help="X25519 public key (PEM) the row-key K_0 is sealed to for verifiers "
                                        "(`ulpf evidence escrow-keygen`); without it K_0 is written to "
                                        "evidence/row_key.k0 to be moved off-box"),
        "key_provider": Opt(str, "file", choices=("file", "keyring", "pkcs11", "tpm"),
                            help="Where the Ed25519 signing keys live (pkcs11: HSM/token, tpm: TPM 2.0 sealed)"),
        "pkcs11": Opt(dict, {}, spec=None, help="PKCS#11 provider: module (library path), token_label | slot, "
                                                "key_label, pin_env (default ULPF_PKCS11_PIN), generate"),
        "tpm": Opt(dict, {}, spec=None, help="TPM provider: provider / key_name (Windows CNG), tcti (Linux)"),
        "key_passphrase_env": Opt(str, "ULPF_EVIDENCE_PASSPHRASE",
                                  help="Environment variable holding the passphrase that encrypts "
                                       "signing-key files")}),
    "analytics": Opt(dict, spec={
        "correlation": Opt(dict, spec={"enabled": Opt(bool, True),
                                       "window_seconds": Opt((int, float), 60, min=1),
                                       "max_groups": Opt(int, 2000, min=10,
                                                         help="Open correlation groups kept in memory"),
                                       "max_group_events": Opt(int, 1000, min=2,
                                                               help="Events kept per open group")}),
        "anomaly": Opt(dict, spec={"enabled": Opt(bool, True),
                                   "new_ip_warmup_events": Opt(int, 10_000, min=0,
                                                               help="Events before first-seen IP alerts start")}),
        "drift": Opt(dict, spec={"enabled": Opt(bool, True), "sample_lines": Opt(int, 500, min=20),
                                 "min_interval_seconds": Opt((int, float), 5, min=0)}),
        "sigma": Opt(dict, spec={
            "enabled": Opt(bool, True, help="Evaluate Sigma rules on every log event (workers) and tag "
                                            "correlation groups with MITRE ATT&CK techniques"),
            "builtin": Opt(bool, True, help="Load the bundled rule pack (ulpf/intelligence/sigma_rules)"),
            "rules": Opt(list, [], item=str, help="Sigma rule files or directories (*.yml)"),
            "dedupe_seconds": Opt((int, float), 60, min=0,
                                  help="One detection event per rule and source within this window")}),
        "yaral": Opt(dict, spec={
            "enabled": Opt(bool, True),
            "rules": Opt(list, [], item=str, help="YARA-L 2.0 rule files or directories (*.yaral)"),
            "inputs": Opt(list, [], item=str, help="Evaluate only events of these inputs (empty: all). Each event "
                                                   "is converted to UDM for YARA-L, about 0.2 ms per event")}),
        "ueba": Opt(dict, spec={
            "enabled": Opt(bool, True, help="User and entity behaviour analytics on the host (identities, assets, "
                                            "sessions, anomalies; state in <data dir>/ueba)"),
            "realm_aliases": Opt(list, [], item=list, help="Realms that are one organisation, e.g. "
                                                          "[[CORP, corp.com, CORP.COM]]"),
            "directory": Opt(str, help="Directory export (CSV id,aliases,department,title,... or JSON rows)"),
            "cmdb": Opt(str, help="Asset CSV: ip | cidr | hostname, owner, criticality, department, os, ..."),
            "zones": Opt(list, [], item=dict, help="Subnet zones: [{cidr, name, criticality}]"),
            "session_gap_minutes": Opt((int, float), 30, min=1),
            "travel_max_kmh": Opt((int, float), 900, min=1),
            "travel_min_km": Opt((int, float), 500, min=0),
            "warmup_events": Opt(int, 100, min=0),
            "warmup_logons": Opt(int, 30, min=0),
            "egress_min_bytes": Opt(int, 100 * 2**20, min=0),
            "profile_cache": Opt(int, 50_000, min=100), "identity_cache": Opt(int, 100_000, min=100)}),
        "risk": Opt(dict, spec={
            "enabled": Opt(bool, True, help="Risk-based alerting: detections add risk to users, hosts, IPs, "
                                            "domains; notable incidents when it crosses the threshold"),
            "half_life_days": Opt((int, float), 7, min=0.01),
            "thresholds": Opt(dict, {}, spec=None, help="entity type -> base threshold (default 100)"),
            "dynamic": Opt(bool, True, help="Raise thresholds to mean + k*stdev of the current scores"),
            "dynamic_sigma": Opt((int, float), 3, min=0),
            "tactic_threshold": Opt(int, 3, min=1, help="Distinct ATT&CK tactics that make an entity notable"),
            "suppress_hours": Opt((int, float), 24, min=0),
            "level_scores": Opt(dict, {}, spec=None, help="Sigma level -> risk score")})}),
    "plugins": Opt(dict, spec={
        "enabled": Opt(bool, True, help="Load installed ulpf.parsers entry-point plugins"),
        "allow": Opt(list, None, item=str,
                     help="SHA-256 package hashes allowed to load (required in defence mode; "
                          "see `ulpf plugins list`)")}),
    "learning": Opt(dict, spec={
        "autonomous": Opt(bool, True),
        "engine": Opt(str, "classic", choices=("classic", "streaming"),
                      help="Learning engine: classic batch clustering, or APG 2.0 streaming clustering"),
        "approval_required": Opt(bool, None),
        "max_parsers_per_source": Opt(int, 20, min=1)}),
    "intel": Opt(dict, spec={
        "enabled": Opt(bool, True, help="Threat-intelligence platform: IPs, CIDRs, domains (and *.wildcards), URLs, "
                                        "hashes, e-mail senders, mutexes and registry keys matched in every event "
                                        "(state in <data dir>/intel)"),
        "builtin": Opt(bool, True, help="Import config/iocs.json (source / destination IPs, no decay)"),
        "min_confidence": Opt((int, float), 0.2, min=0,
                              help="Indicators whose decayed confidence falls below this stop matching"),
        "half_life_days": Opt(dict, {}, spec=None, help="Indicator kind -> confidence half-life in days "
                                                        "(defaults: ip 14, domain 45, url 30, hashes 365, ...)"),
        "rebuild_minutes": Opt((int, float), 60, min=1, help="Re-apply decay and rebuild the match set"),
        "poll_seconds": Opt((int, float), 30, min=1),
        "max_indicators": Opt(int, 10_000_000, min=1000),
        "feeds": Opt(list, [], item=dict, help="[{name, type: stix_file | misp_file | otx_file | taxii | misp | "
                                               "otx, path | url, interval_minutes, token_env | key_env}] -- "
                                               "network feeds need their host on airgap.allow in defence mode")}),
    "query": Opt(dict, spec={
        "max_concurrent": Opt(int, 4, min=1, help="Queries running at once (KQL / SPL2 / HQL)"),
        "per_user": Opt(int, 2, min=1, help="Queries running at once per analyst (API key)"),
        "memory_mb": Opt(int, 1024, min=64, help="Memory reserved by all running queries together"),
        "query_memory_mb": Opt(int, 256, min=32, help="Memory limit of one query"),
        "timeout_seconds": Opt(int, 30, min=1, help="Default deadline (queue wait included)"),
        "max_queue": Opt(int, 64, min=1),
        "live": Opt(dict, spec={"max_tails": Opt(int, 32, min=1), "per_user": Opt(int, 4, min=1),
                                "queue_rows": Opt(int, 10_000, min=10), "idle_seconds": Opt(int, 120, min=5)})}),
    "api": Opt(dict, spec={
        "enabled": Opt(bool, True),
        "host": Opt(str, "127.0.0.1"),
        "port": Opt(int, 8000, min=0),
        "keys_file": Opt(str, help="YAML/JSON file of {key_sha256: role}"),
        "tls": Opt(dict, spec={"cert": Opt(str), "key": Opt(str), "client_ca": Opt(str)})}),
    "audit": Opt(dict, spec={"enabled": Opt(bool, True)}),
    "compliance": Opt(dict, spec={
        "dpdp": Opt(dict, spec={
            "enabled": Opt(bool, False, help="Scan log events for personal data (India DPDP Act)"),
            "mode": Opt(str, "detect", choices=("detect", "redact", "tokenize"),
                        help="detect: tag events pii:<type>; redact / tokenize: replace the values in the "
                             "store and every output (the journal keeps the bytes received)"),
            "types": Opt(list, [], item=str, help="PII types to look for (default: all)")})}),
    "dlq": Opt(dict, spec={"max_mb": Opt((int, float), 512, min=1),
                           "retention_days": Opt((int, float), 7, min=0)}),
    "cluster": Opt(dict, spec={
        "enabled": Opt(bool, False),
        "nodes": Opt(list, [], item={"id": Opt(str, required=True), "address": Opt(str, required=True)}),
        "shared_dir": Opt(str, help="Shared checkpoint/assignment store"),
        "heartbeat_seconds": Opt((int, float), 2, min=0.1),
        "failover_seconds": Opt((int, float), 10, min=1),
        "backend": Opt(str, "shared_dir", choices=("shared_dir", "raft"),
                       help="Lease coordinator: a shared directory with OS record locks, or embedded Raft"),
        "raft": Opt(dict, {}, spec=None, help="Raft: bind, peers {id: host:port}, tls {cert, key, ca}, "
                                              "election_ms, heartbeat_ms")}),
    "soar": Opt(dict, {}, spec=None, help="SOAR / case management (ulpf.soar.service)"),
    "copilot": Opt(dict, {}, spec=None, help="Offline SecOps copilot (ulpf.copilot)"),
    "fleet": Opt(dict, {}, spec=None, help="Forwarder fleet control plane (ulpf.fleet)"),
    "console": Opt(dict, {}, spec=None, help="Web console (ulpf.console)"),
    "overrides": Opt(list, [], item=str),
}

MODE_DEFAULTS = {
    "defence": {"journal.sync": "always", "journal.retention_days": 180, "journal.encrypt": True,
                "evidence.enabled": True, "evidence.seal_every_events": 1000,
                "evidence.seal_every_seconds": 60, "evidence.row_mac": True,
                "learning.approval_required": True, "airgap.enforce": True},
    "industry": {"journal.sync": "interval", "journal.retention_days": 30, "journal.encrypt": False,
                 "evidence.enabled": True, "evidence.seal_every_events": 10000,
                 "evidence.seal_every_seconds": 300, "evidence.row_mac": False,
                 "learning.approval_required": False, "airgap.enforce": False},
}

RULES = {
    "defence.no_cloud": "cloud connectors are disabled in defence mode",
    "defence.allowlist": "remote endpoint is not in airgap.allow",
    "defence.tls_listeners": "network listeners must use TLS in defence mode",
    "defence.tls_outputs": "remote outputs must use TLS in defence mode",
    "defence.journal_encrypt": "the raw journal must be encrypted in defence mode",
    "defence.evidence": "evidence sealing cannot be disabled in defence mode",
    "defence.approval": "learned parsers require operator approval in defence mode",
    "defence.api_mtls": "a non-loopback API requires mutual TLS (api.tls.client_ca) in defence mode",
    "defence.key_protection": "signing keys must be passphrase-encrypted or held in the OS keyring "
                              "in defence mode",
    "defence.lake_encryption": "lakehouse outputs must encrypt the cold tier (encryption.key_env) in defence mode",
}


@dataclass
class PipelineConfig:
    data: dict
    path: str | None = None
    warnings: list[str] = field(default_factory=list)
    waived: list[str] = field(default_factory=list)

    def __getitem__(self, key: str) -> Any:
        return self.data[key]

    @property
    def mode(self) -> str:
        return self.data["mode"]

    def get(self, dotted: str, default: Any = None) -> Any:
        cur: Any = self.data
        for part in dotted.split("."):
            if not isinstance(cur, dict) or part not in cur:
                return default
            cur = cur[part]
        return cur

    def outputs(self) -> list[dict]:
        return [o for o in self.data["outputs"] if o.get("enabled", True)]

    def inputs(self) -> list[dict]:
        return [i for i in self.data["inputs"] if i.get("enabled", True)]

    def overrides_unknown(self) -> list[str]:
        return [o for o in self.data.get("overrides", []) if o not in RULES]


def default_config(mode: str = "industry") -> dict:
    """The built-in pipeline: syslog TCP on 5514 into the local DuckDB store."""
    return {
        "mode": mode,
        "inputs": [{"type": "syslog", "name": "syslog", "protocol": "tcp", "host": "127.0.0.1",
                    "port": 5514}],
        "outputs": [{"type": "duckdb", "name": "store"}],
        "routes": [{"name": "everything", "to": ["store"]}],
        "default_output": "store",
    }


def load_pipeline_config(path: str | None = None, text: str | None = None,
                         data: dict | None = None) -> PipelineConfig:
    lines: dict[str, int] = {}
    if data is None:
        if text is None:
            with open(path, "r", encoding="utf-8") as f:
                text = f.read()
        data, lines = load_yaml_with_lines(text)
    data = _apply_profile(data or {})
    v = Validator(lines=lines)
    cfg = v.section(data, TOP_SPEC, "")
    cfg["inputs"] = [_component_section(v, "input", i, item) for i, item in enumerate(cfg.get("inputs") or [])]
    cfg["outputs"] = [_component_section(v, "output", i, item) for i, item in enumerate(cfg.get("outputs") or [])]
    structural = bool(v.issues)
    _apply_mode_defaults(cfg)
    pc = PipelineConfig(cfg, path)
    # Report every problem in one pass; later checks tolerate earlier errors
    try:
        _check_references(pc, v)
    except (KeyError, TypeError):
        pass
    if not structural:
        _check_mode_rules(pc, v)
    if v.issues:
        raise ConfigError(v.issues)
    return pc


def _apply_profile(data: dict) -> dict:
    """Profile defaults, applied before validation: anything set explicitly wins."""
    if not isinstance(data, dict) or data.get("profile") != "tactical_edge":
        return data
    import copy
    d = copy.deepcopy(data)
    d.setdefault("mode", "defence")
    d.setdefault("workers", 1)
    for section, values in (("journal", {"segment_mb": 16}), ("dlq", {"max_mb": 64}),
                            ("limits", {"max_rss_mb": 450, "duckdb_memory_mb": 128})):
        if isinstance(d.get(section, {}), dict):
            sec = d.setdefault(section, {})
            for k, val in values.items():
                sec.setdefault(k, val)
    for o in d.get("outputs") or []:
        if not isinstance(o, dict):
            continue
        buf = o.setdefault("buffer", {})
        if isinstance(buf, dict):
            buf.setdefault("max_mb", 64)
        if o.get("type") == "duckdb":
            o.setdefault("partition", "hourly")
            o.setdefault("partition_max_mb", 256)
            o.setdefault("retention_days", 30)
    return d


def _component_section(v: Validator, kind: str, i: int, item: Any) -> dict:
    path = f"{kind}s[{i}]"
    if not isinstance(item, dict):
        v.error(path, "expected a mapping")
        return {}
    comp = component(kind, item.get("type", ""))
    if comp is None:
        known = ", ".join(sorted(INPUTS if kind == "input" else OUTPUTS))
        v.error(f"{path}.type", f"unknown {kind} type {item.get('type')!r} (known: {known})")
        return {}
    out = v.section(item, comp.options, path)
    if out.get("affinity") == "auto":
        out["affinity"] = comp.default_affinity
    if out.get("enabled", True) and importlib.util.find_spec(comp.module) is None:
        v.error(f"{path}.type", f"{kind} type {comp.type!r} is not available in this build")
    for mod in comp.requires:
        try:
            ok = importlib.util.find_spec(mod) is not None
        except ModuleNotFoundError:
            ok = False
        if not ok and out.get("enabled", True):
            v.error(f"{path}.type", f"needs the {mod!r} package: pip install \"ulpf[{comp.extra}]\"")
    return out


def _apply_mode_defaults(cfg: dict) -> None:
    for dotted, value in MODE_DEFAULTS[cfg["mode"]].items():
        sec, key = dotted.split(".")
        if cfg[sec].get(key) is None:
            cfg[sec][key] = value
    if cfg.get("default_output") is None and cfg["outputs"]:
        cfg["default_output"] = cfg["outputs"][0].get("name")


def _check_references(pc: PipelineConfig, v: Validator) -> None:
    for kind in ("inputs", "outputs"):
        seen: set[str] = set()
        for i, c in enumerate(pc.data[kind]):
            name = c.get("name")
            if name in seen:
                v.error(f"{kind}[{i}].name", f"duplicate name {name!r}")
            seen.add(name)
    outputs = {o["name"] for o in pc.data["outputs"]}
    for i, r in enumerate(pc.data["routes"]):
        for j, target in enumerate(r["to"]):
            if target not in outputs:
                v.error(f"routes[{i}].to[{j}]", f"no output named {target!r}")
    d = pc.data.get("default_output")   # "" = drop events no route matches (counted)
    if d and d not in outputs:
        v.error("default_output", f"no output named {d!r}")
    if not outputs:
        v.error("outputs", "at least one output is required")
    if not pc.data["api"]["enabled"]:
        for i, c in enumerate(pc.data["inputs"]):
            if c.get("type") in ("http", "otlp") and c.get("enabled", True):
                v.error(f"inputs[{i}]", f"{c['type']} input is served by the API: set api.enabled: true")
    inputs = {c.get("name") for c in pc.data["inputs"]}
    for i, c in enumerate(pc.data["inputs"]):
        tls = c.get("tls") or {}
        if not (tls.get("sni_certs") or tls.get("sni_routes")):
            continue
        if c.get("engine") == "python":
            v.error(f"inputs[{i}].tls", "sni_certs / sni_routes need engine auto or native")
        for sni, target in tls.get("sni_routes", {}).items():
            if target not in inputs:
                v.error(f"inputs[{i}].tls.sni_routes.{sni}", f"no input named {target!r}")
    cl = pc.data["cluster"]
    if cl["enabled"]:
        if cl.get("backend", "shared_dir") == "shared_dir" and not cl.get("shared_dir"):
            v.error("cluster.shared_dir", "is required when cluster.enabled is true (backend shared_dir)")
        if cl.get("backend") == "raft" and not (cl.get("raft") or {}).get("peers"):
            v.error("cluster.raft.peers", "is required for the raft backend")
        if cl["failover_seconds"] <= cl["heartbeat_seconds"]:
            v.error("cluster.failover_seconds", "must be longer than cluster.heartbeat_seconds")
        ids = [n["id"] for n in cl.get("nodes") or []]
        if len(ids) != len(set(ids)):
            v.error("cluster.nodes", "duplicate node id")
    for o in pc.overrides_unknown():
        v.error("overrides", f"unknown rule id {o!r} (known: {', '.join(RULES)})")


def _host_allowed(host: str, allow: list[str]) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    for entry in allow:
        if entry == host or (entry.startswith("*.") and host.endswith(entry[1:])):
            return True
        if ip is not None:
            try:
                if ip in ipaddress.ip_network(entry, strict=False):
                    return True
            except ValueError:
                pass
    return host in ("127.0.0.1", "::1", "localhost")


def _uses_tls(comp, opts: dict) -> bool:
    if comp.type == "lakehouse":
        st = opts.get("storage") or {}
        kind = st.get("type", "local")
        url = str(st.get("endpoint") or st.get("account_url") or "")
        return kind == "local" or (kind == "s3" and not st.get("endpoint")) or url.startswith("https://")
    if opts.get("protocol") == "tls":
        return True
    for key in ("url", "endpoint"):
        if str(opts.get(key, "")).startswith("https://"):
            return True
    urls = opts.get("urls") or []
    if urls and all(str(u).startswith("https://") for u in urls):
        return True
    tls = opts.get("tls") or {}
    return bool(tls.get("ca") or tls.get("cert"))


def _check_mode_rules(pc: PipelineConfig, v: Validator) -> None:
    cfg = pc.data
    defence = cfg["mode"] == "defence"
    waive = set(cfg.get("overrides") or [])

    def violate(rule: str, path: str, detail: str) -> None:
        if rule in waive:
            pc.waived.append(f"{rule}: {detail}")
        else:
            v.error(path, f"{RULES[rule]}: {detail} (waive with overrides: [{rule}])")

    enforce = cfg["airgap"]["enforce"]
    allow = cfg["airgap"]["allow"]
    for kind, table in (("inputs", INPUTS), ("outputs", OUTPUTS)):
        for i, c in enumerate(cfg[kind]):
            if not c.get("enabled", True):
                continue
            comp = table[c["type"]]
            path = f"{kind}[{i}]"
            if defence and comp.cloud:
                violate("defence.no_cloud", path, f"{c['name']} ({c['type']})")
            if enforce:
                for host in remote_endpoints(comp, c):
                    if not _host_allowed(host, allow):
                        violate("defence.allowlist", path, f"{c['name']} -> {host}")
            if defence and comp.network_listener and not (c.get("protocol") == "tls"):
                violate("defence.tls_listeners", path, f"{c['name']} listens without TLS")
            if defence and comp.remote and kind == "outputs" and not _uses_tls(comp, c):
                violate("defence.tls_outputs", path, f"{c['name']} sends without TLS")
            if defence and comp.type == "lakehouse":
                if not (c.get("encryption") or {}).get("key_env"):
                    violate("defence.lake_encryption", path, c["name"])
                fl = c.get("flight") or {}
                if fl.get("enabled") and not (fl.get("tls") or {}).get("cert"):
                    violate("defence.tls_listeners", f"{path}.flight", f"{c['name']} Flight without TLS")
            if c.get("protocol") == "tls" and comp.network_listener:
                tls = c.get("tls") or {}
                if not (tls.get("cert") and tls.get("key")):
                    v.error(f"{path}.tls", "protocol tls needs tls.cert and tls.key")
    if defence:
        if cfg["journal"]["encrypt"] is False:
            violate("defence.journal_encrypt", "journal.encrypt", "set to false")
        if cfg["evidence"]["enabled"] is False:
            violate("defence.evidence", "evidence.enabled", "set to false")
        ev = cfg["evidence"]
        if ev["key_provider"] == "file" and not os.environ.get(ev["key_passphrase_env"] or ""):
            violate("defence.key_protection", "evidence.key_passphrase_env",
                    f"{ev['key_passphrase_env']} is not set")
        if cfg["learning"]["approval_required"] is False:
            violate("defence.approval", "learning.approval_required", "set to false")
        api = cfg["api"]
        if api["enabled"] and api["host"] not in ("127.0.0.1", "::1", "localhost") \
                and not (api["tls"].get("client_ca")):
            violate("defence.api_mtls", "api.host", f"API on {api['host']}")
    else:
        api = cfg["api"]
        if api["enabled"] and api["host"] not in ("127.0.0.1", "::1", "localhost") \
                and not api["tls"].get("cert"):
            pc.warnings.append(f"API listens on {api['host']} without TLS; use api.tls in production")


def describe(pc: PipelineConfig) -> dict:
    """What this config will open: listeners, remote destinations, waivers."""
    listeners, remotes = [], []
    for c in pc.inputs():
        comp = INPUTS[c["type"]]
        if comp.network_listener:
            listeners.append(f"{c['name']}: {c['type']} {c.get('protocol', 'udp')} "
                             f"{c.get('host')}:{c.get('port')}")
        remotes += [f"{c['name']} <- {h}" for h in remote_endpoints(comp, c)]
    for c in pc.outputs():
        remotes += [f"{c['name']} -> {h}" for h in remote_endpoints(OUTPUTS[c["type"]], c)]
    api = pc.data["api"]
    if api["enabled"]:
        listeners.append(f"api: http{'s' if api['tls'].get('cert') else ''} {api['host']}:{api['port']}")
    return {"mode": pc.mode, "listeners": listeners, "remote_destinations": remotes,
            "waived_rules": list(pc.waived), "warnings": list(pc.warnings),
            "inputs": [c["name"] for c in pc.inputs()], "outputs": [c["name"] for c in pc.outputs()]}


def format_issues(err: ConfigError, path: str | None = None) -> str:
    prefix = f"{path}: " if path else ""
    return "\n".join(f"{prefix}{i}" for i in err.issues)


__all__ = ["PipelineConfig", "ConfigError", "ConfigIssue", "load_pipeline_config", "describe",
           "default_config", "format_issues", "RULES", "MODES"]
