"""
Catalogue of pipeline inputs and outputs: option specs, implementation
module, and the properties mode rules need (network-facing, cloud, TLS).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ulpf.config.schema import Opt

TLS_SPEC = {
    "cert": Opt(str, help="PEM certificate (server side, or client cert for mutual TLS)"),
    "key": Opt(str, help="PEM private key"),
    "ca": Opt(str, help="CA bundle used to verify the peer"),
    "client_ca": Opt(str, help="Require client certificates signed by this CA (listeners)"),
    "verify": Opt(bool, True),
    "server_name": Opt(str),
    "sni_certs": Opt(list, [], item={"server_name": Opt(str, required=True), "cert": Opt(str, required=True),
                                     "key": Opt(str)},
                     help="Listeners (native engine): more certificates, chosen by the SNI name the client sends"),
    "sni_routes": Opt(dict, {}, spec=None,
                      help="Listeners (native engine): SNI name -> input name its records are journaled under"),
}

MULTILINE_SPEC = {
    "start_pattern": Opt(str, required=True, help="Regex matching the first line of an event"),
    "max_lines": Opt(int, 500, min=1),
    "timeout_ms": Opt(int, 1000, min=1),
}

BUFFER_SPEC = {
    "max_mb": Opt((int, float), 1024, min=1),
    "when_full": Opt(str, "block", choices=("block", "drop_oldest")),
}

BATCH_SPEC = {
    "max_events": Opt(int, 5000, min=1),
    "max_bytes": Opt(int, 5 * 1024 * 1024, min=1024),
}

RETRY_SPEC = {
    "max_attempts": Opt(int, 0, min=0, help="0 = retry forever (data stays buffered)"),
    "initial_ms": Opt(int, 500, min=1),
    "max_ms": Opt(int, 60_000, min=1),
}

COMMON_INPUT = {
    "type": Opt(str, required=True),
    "name": Opt(str, required=True),
    "enabled": Opt(bool, True),
    "rate_limit_eps": Opt((int, float), 0, min=0, help="Per-source events/s, 0 = unlimited"),
    "max_line_bytes": Opt(int, 1024 * 1024, min=64),
    "allow_sources": Opt(list, [], item=str, help="CIDRs allowed to send (network inputs)"),
    "affinity": Opt(str, "auto", choices=("auto", "source", "none")),
    "tags": Opt(list, [], item=str),
    "placement": Opt(str, "auto", choices=("auto", "all", "one"),
                     help="Cluster: run on every node (all) or on exactly one live node (one); "
                          "auto = one for cloud pull inputs, all otherwise"),
}

COMMON_OUTPUT = {
    "type": Opt(str, required=True),
    "name": Opt(str, required=True),
    "enabled": Opt(bool, True),
    "view": Opt(str, "unified", choices=("unified", "ecs", "ocsf", "udm", "asim", "cbam")),
    "buffer": Opt(dict, spec=BUFFER_SPEC),
    "batch": Opt(dict, spec=BATCH_SPEC),
    "retry": Opt(dict, spec=RETRY_SPEC),
}


@dataclass
class Component:
    kind: str                      # "input" or "output"
    type: str
    module: str                    # implementation module (imported lazily)
    cls: str
    options: dict
    network_listener: bool = False  # binds a port
    remote: bool = False            # connects to another host
    cloud: bool = False             # talks to a public cloud API (disabled in defence mode)
    tls_capable: bool = False
    extra: str | None = None        # pip extra needed, if any
    requires: tuple = ()            # importable modules needed at runtime
    default_affinity: str = "none"
    notes: str = ""
    remote_keys: tuple = field(default=("host", "url", "urls", "endpoint", "brokers"))


def _inp(type_, module, cls, opts, **kw) -> Component:
    return Component("input", type_, module, cls, {**COMMON_INPUT, **opts}, **kw)


def _out(type_, module, cls, opts, **kw) -> Component:
    return Component("output", type_, module, cls, {**COMMON_OUTPUT, **opts}, **kw)


_CRED = {"access_key_env": Opt(str), "secret_key_env": Opt(str), "session_token_env": Opt(str)}

# Network listeners that can run on the compiled core's Tokio runtime (ulpf.runtime.inputs.native)
_ENGINE = {
    "engine": Opt(str, "auto", choices=("auto", "native", "python"),
                  help="auto: the compiled core's listener when ulpf_core is built, else Python"),
    "threads": Opt(int, 2, min=1, help="Native engine: runtime threads (UDP: sockets with SO_REUSEPORT on Linux)"),
}

INPUTS: dict[str, Component] = {c.type: c for c in (
    _inp("syslog", "ulpf.runtime.inputs.syslog", "SyslogInput", {
        "protocol": Opt(str, "tcp", choices=("udp", "tcp", "tls")),
        "host": Opt(str, "0.0.0.0"), "port": Opt(int, 5514, min=1),
        "framing": Opt(str, "auto", choices=("auto", "newline", "octet")),
        "telemetry": Opt(str, "none", choices=("none", "mavlink", "ccsds"),
                         help="UDP: each datagram is one binary telemetry frame (MAVLink / CCSDS space packet)"),
        "mavlink": Opt(dict, {}, spec=None, help="MAVLink v2 signing: keys {sysid|'*': 'env:VAR'}, "
                                                 "require_signed, max_age_seconds"),
        "ccsds": Opt(dict, {}, spec=None, help="CCSDS: pus (c|a|none), time_coarse, time_fine, epoch_unix, pec"),
        "tls": Opt(dict, spec=TLS_SPEC), **_ENGINE},
        network_listener=True, tls_capable=True),
    _inp("file", "ulpf.runtime.inputs.file", "FileInput", {
        "paths": Opt(list, required=True, item=str, help="Files or glob patterns"),
        "exclude": Opt(list, [], item=str),
        "start_from": Opt(str, "end", choices=("beginning", "end")),
        "poll_interval_ms": Opt(int, 250, min=10),
        "encoding": Opt(str, "utf-8"),
        "multiline": Opt(dict, None, spec=None),
        "container": Opt(str, "none", choices=("none", "docker", "containerd", "kubernetes"),
                         help="Attach container/pod labels from the runtime's log layout")},
        default_affinity="source"),
    _inp("http", "ulpf.runtime.inputs.http", "HttpInput", {
        "sources": Opt(list, [], item=str, help="Allowed source names (empty = any)"),
        "api_key_env": Opt(str, help="Env var holding the key clients send as X-API-Key"),
        "max_body_mb": Opt((int, float), 16, min=0.001)},
        default_affinity="source"),
    _inp("otlp", "ulpf.runtime.inputs.http", "OtlpInput", {
        "api_key_env": Opt(str), "max_body_mb": Opt((int, float), 16, min=0.001)}),
    _inp("mqtt", "ulpf.runtime.inputs.mqtt", "MqttInput", {
        "host": Opt(str, required=True), "port": Opt(int, 8883, min=1),
        "topics": Opt(list, required=True, item=str), "qos": Opt(int, 1, choices=(0, 1, 2)),
        "client_id": Opt(str), "username": Opt(str), "password_env": Opt(str),
        "tls": Opt(dict, spec=TLS_SPEC)},
        remote=True, tls_capable=True, extra="mqtt", requires=("paho.mqtt",)),
    _inp("kafka", "ulpf.runtime.inputs.kafka", "KafkaInput", {
        "brokers": Opt(list, required=True, item=str), "topics": Opt(list, required=True, item=str),
        "group_id": Opt(str, "ulpf"), "tls": Opt(dict, spec=TLS_SPEC),
        "sasl_mechanism": Opt(str), "username": Opt(str), "password_env": Opt(str)},
        remote=True, tls_capable=True, extra="kafka", requires=("confluent_kafka",)),
    _inp("journald", "ulpf.runtime.inputs.journald", "JournaldInput", {
        "units": Opt(list, [], item=str)}),
    _inp("evtx", "ulpf.runtime.inputs.evtx", "EvtxInput", {
        "channels": Opt(list, ["Security", "System", "Application"], item=str),
        "query": Opt(str, "*", help='Extra System condition, e.g. "Level<=3" or "EventID=4625"'),
        "poll_interval_ms": Opt(int, 1000, min=100)},
        default_affinity="source"),
    _inp("netflow", "ulpf.runtime.inputs.netflow", "NetflowInput", {
        "host": Opt(str, "0.0.0.0"), "port": Opt(int, 2055, min=1), **_ENGINE},
        network_listener=True),
    _inp("snmp_trap", "ulpf.runtime.inputs.snmp", "SnmpTrapInput", {
        "host": Opt(str, "0.0.0.0"), "port": Opt(int, 162, min=1),
        "communities": Opt(list, ["public"], item=str),
        "v3_users": Opt(list, [], item={
            "name": Opt(str, required=True),
            "auth_protocol": Opt(str, "sha", choices=("none", "md5", "sha", "sha224", "sha256", "sha384",
                                                      "sha512")),
            "auth_key_env": Opt(str),
            "priv_protocol": Opt(str, "none", choices=("none", "aes", "aes128", "aes192", "aes256")),
            "priv_key_env": Opt(str)}), **_ENGINE},
        network_listener=True),
    _inp("otlp_grpc", "ulpf.runtime.inputs.native", "OtlpGrpcInput", {
        "host": Opt(str, "0.0.0.0"), "port": Opt(int, 4317, min=1), "api_key_env": Opt(str),
        "max_body_mb": Opt((int, float), 16, min=1), "tls": Opt(dict, spec=TLS_SPEC),
        "threads": Opt(int, 2, min=1)},
        network_listener=True, tls_capable=True, requires=("ulpf.ulpf_core",)),
    _inp("cloudtrail", "ulpf.runtime.inputs.cloud", "CloudTrailInput", {
        "region": Opt(str, required=True), "queue_url": Opt(str, required=True),
        "endpoint": Opt(str, help="Override for S3/SQS-compatible endpoints"),
        "poll_interval_ms": Opt(int, 5000, min=100), **_CRED},
        remote=True, cloud=True),
    _inp("eventhubs", "ulpf.runtime.inputs.cloud", "EventHubsInput", {
        "connection_string_env": Opt(str, required=True), "eventhub": Opt(str, required=True),
        "consumer_group": Opt(str, "$Default")},
        remote=True, cloud=True, extra="azure", requires=("azure.eventhub",)),
    _inp("pubsub", "ulpf.runtime.inputs.cloud", "PubSubInput", {
        "project": Opt(str, required=True), "subscription": Opt(str, required=True),
        "credentials_file": Opt(str, required=True), "endpoint": Opt(str),
        "poll_interval_ms": Opt(int, 2000, min=100)},
        remote=True, cloud=True),
    _inp("okta", "ulpf.runtime.inputs.cloud", "OktaInput", {
        "domain": Opt(str, required=True), "token_env": Opt(str, required=True),
        "poll_interval_s": Opt(int, 60, min=5), "endpoint": Opt(str)},
        remote=True, cloud=True),
    _inp("entra", "ulpf.runtime.inputs.cloud", "EntraInput", {
        "tenant_id": Opt(str, required=True), "client_id": Opt(str, required=True),
        "client_secret_env": Opt(str, required=True), "poll_interval_s": Opt(int, 60, min=5),
        "login_endpoint": Opt(str), "graph_endpoint": Opt(str)},
        remote=True, cloud=True),
)}
INPUTS["file"].options["multiline"] = Opt(dict, None, spec=MULTILINE_SPEC)

_ROTATE = {"rotate_mb": Opt((int, float), 128, min=1), "rotate_seconds": Opt(int, 300, min=1)}

OUTPUTS: dict[str, Component] = {c.type: c for c in (
    _out("duckdb", "ulpf.runtime.sinks.duckdb_sink", "DuckDBSink", {
        "path": Opt(str, help="Event store path (default <data dir>/ulpf.duckdb)"),
        "partition": Opt(str, "daily", choices=("none", "daily", "hourly"),
                         help="One DuckDB file per period; `events` is a view over all of them"),
        "partition_max_mb": Opt((int, float), 0, min=0,
                                help="Also start a new partition when the active one passes this size (0: off)"),
        "retention_days": Opt((int, float), None, min=0,
                              help="Retire partitions that ended this many days ago (whole files, no DELETE)"),
        "archive_dir": Opt(str, help="Retired partitions are moved/exported here instead of deleted"),
        "archive_format": Opt(str, "duckdb", choices=("duckdb", "parquet"))}),
    _out("file", "ulpf.runtime.sinks.files", "NdjsonFileSink", {
        "path": Opt(str, required=True, help="Directory"), "compress": Opt(str, "none", choices=("none", "gzip")),
        **_ROTATE}),
    _out("parquet", "ulpf.runtime.sinks.files", "ParquetSink", {
        "path": Opt(str, required=True, help="Directory (data lake root)"),
        "partition": Opt(list, ["dt"], item=str), **_ROTATE}),
    _out("s3", "ulpf.runtime.sinks.s3", "S3ParquetSink", {
        "bucket": Opt(str, required=True), "prefix": Opt(str, "ulpf"), "region": Opt(str, "us-east-1"),
        "endpoint": Opt(str, help="S3-compatible endpoint, e.g. MinIO"),
        "partition": Opt(list, ["dt"], item=str), **_ROTATE, **_CRED},
        remote=True, tls_capable=True),
    _out("lakehouse", "ulpf.runtime.sinks.lakehouse", "LakehouseSink", {
        "storage": Opt(dict, required=True, spec={
            "type": Opt(str, "local", choices=("local", "s3", "minio", "ceph", "azure")),
            "path": Opt(str, help="local: table directory"),
            "bucket": Opt(str), "prefix": Opt(str, ""), "region": Opt(str, "us-east-1"),
            "endpoint": Opt(str, help="MinIO / Ceph RGW endpoint URL"), "path_style": Opt(bool, None),
            "account_url": Opt(str, help="azure: https://<account>.blob.core.windows.net"),
            "container": Opt(str), "tenant_id": Opt(str), "client_id": Opt(str),
            "client_secret_env": Opt(str), "sas_env": Opt(str), "login_endpoint": Opt(str),
            "tls": Opt(dict, spec=None), **_CRED}),
        "hot": Opt(dict, spec={"path": Opt(str, help="Ring file on local NVMe (default under the data dir)"),
                               "capacity_mb": Opt(int, 1024, min=1)}),
        "encryption": Opt(dict, spec={"key_env": Opt(str, help="Env var holding the base64 32-byte master key "
                                                               "(AES-256-GCM, client side)")}),
        "tenant": Opt(str, "default"),
        "tenant_by_input": Opt(dict, {}, spec=None, help="input name -> tenant id"),
        "flush_seconds": Opt(int, 60, min=1), "flush_mb": Opt(int, 64, min=1),
        "compaction": Opt(dict, spec={"enabled": Opt(bool, True), "min_mb": Opt(int, 128, min=1),
                                      "max_mb": Opt(int, 512, min=1), "settle_minutes": Opt(int, 90, min=0),
                                      "interval_seconds": Opt(int, 300, min=1)}),
        "retention_days": Opt(int, 0, min=0), "vacuum_hours": Opt(int, 24, min=0),
        "cache_mb": Opt(int, 2048, min=16), "query_memory_mb": Opt(int, 256, min=32),
        "flight": Opt(dict, spec={"enabled": Opt(bool, False), "host": Opt(str, "127.0.0.1"),
                                  "port": Opt(int, 8815, min=1), "token_env": Opt(str),
                                  "tls": Opt(dict, spec=None)})},
        remote=True, tls_capable=True),
    _out("elasticsearch", "ulpf.runtime.sinks.http_sinks", "ElasticsearchSink", {
        "urls": Opt(list, required=True, item=str), "index": Opt(str, "ulpf-%Y.%m.%d"),
        "username": Opt(str), "password_env": Opt(str), "api_key_env": Opt(str),
        "pipeline": Opt(str), "tls": Opt(dict, spec=TLS_SPEC)},
        remote=True, tls_capable=True),
    _out("splunk_hec", "ulpf.runtime.sinks.http_sinks", "SplunkHecSink", {
        "url": Opt(str, required=True), "token_env": Opt(str, required=True),
        "index": Opt(str), "sourcetype": Opt(str, "ulpf:event"), "ack": Opt(bool, False),
        "tls": Opt(dict, spec=TLS_SPEC)},
        remote=True, tls_capable=True),
    _out("kafka", "ulpf.runtime.sinks.kafka_sink", "KafkaSink", {
        "brokers": Opt(list, required=True, item=str), "topic": Opt(str, required=True),
        "key_field": Opt(str, "source_ip"), "compression": Opt(str, "lz4"),
        "tls": Opt(dict, spec=TLS_SPEC), "sasl_mechanism": Opt(str), "username": Opt(str),
        "password_env": Opt(str)},
        remote=True, tls_capable=True, extra="kafka", requires=("confluent_kafka",)),
    _out("loki", "ulpf.runtime.sinks.http_sinks", "LokiSink", {
        "url": Opt(str, required=True), "labels": Opt(list, ["category", "raw_format"], item=str),
        "tenant_id": Opt(str), "tls": Opt(dict, spec=TLS_SPEC)},
        remote=True, tls_capable=True),
    _out("otlp", "ulpf.runtime.sinks.http_sinks", "OtlpSink", {
        "url": Opt(str, required=True), "headers": Opt(dict, {}), "tls": Opt(dict, spec=TLS_SPEC)},
        remote=True, tls_capable=True),
    _out("syslog", "ulpf.runtime.sinks.syslog_sink", "SyslogSink", {
        "host": Opt(str, required=True), "port": Opt(int, 514, min=1),
        "protocol": Opt(str, "tcp", choices=("udp", "tcp", "tls")),
        "format": Opt(str, "rfc5424", choices=("rfc5424", "leef", "cef", "json", "raw"),
                      help="raw = the original line as received (smallest upstream volume)"),
        "tls": Opt(dict, spec=TLS_SPEC)},
        remote=True, tls_capable=True),
    # Azure Monitor Logs Ingestion API (data collection rules); the older HTTP
    # Data Collector API is retired, so it is not offered.
    _out("azure_log_analytics", "ulpf.runtime.sinks.http_sinks", "AzureLogAnalyticsSink", {
        "endpoint": Opt(str, required=True, help="Data collection endpoint (DCE) URL"),
        "dcr_immutable_id": Opt(str, required=True), "stream_name": Opt(str, required=True),
        "tenant_id": Opt(str, required=True), "client_id": Opt(str, required=True),
        "client_secret_env": Opt(str, required=True), "login_endpoint": Opt(str)},
        remote=True, cloud=True, tls_capable=True),
    _out("chronicle", "ulpf.runtime.sinks.http_sinks", "ChronicleSink", {
        "customer_id": Opt(str, required=True), "credentials_file": Opt(str, required=True),
        "log_type": Opt(str, "UDM"), "endpoint": Opt(str, "https://malachiteingestion-pa.googleapis.com")},
        remote=True, cloud=True, tls_capable=True),
)}


def component(kind: str, type_: str) -> Component | None:
    return (INPUTS if kind == "input" else OUTPUTS).get(type_)


def remote_endpoints(comp: Component, opts: dict) -> list[str]:
    """Host[:port] strings a component will connect to, for allow-list checks."""
    from urllib.parse import urlparse
    found: list[str] = []
    if comp.type == "lakehouse":
        st = opts.get("storage") or {}
        kind = st.get("type", "local")
        if kind == "local":
            return found
        for key in ("endpoint", "account_url", "login_endpoint"):
            if st.get(key):
                found.append(urlparse(st[key]).hostname or st[key])
        if kind == "s3" and not st.get("endpoint"):
            found.append(f"{st.get('bucket')}.s3.{st.get('region', 'us-east-1')}.amazonaws.com")
        if kind == "azure" and st.get("client_secret_env") and not st.get("login_endpoint"):
            found.append("login.microsoftonline.com")
        return found
    if not comp.remote:
        return found
    for key in ("url", "endpoint", "login_endpoint", "graph_endpoint"):
        if opts.get(key):
            u = urlparse(opts[key])
            found.append(u.hostname or opts[key])
    for key in ("urls", "brokers"):
        for v in opts.get(key) or []:
            u = urlparse(v if "://" in v else f"//{v}")
            found.append(u.hostname or v)
    if opts.get("host"):
        found.append(opts["host"])
    if comp.type == "s3" and not opts.get("endpoint"):
        found.append(f"{opts.get('bucket')}.s3.{opts.get('region')}.amazonaws.com")
    if comp.type == "okta" and not opts.get("endpoint"):
        found.append(opts.get("domain", ""))
    if comp.type == "cloudtrail" and not opts.get("endpoint"):
        found.append(f"sqs.{opts.get('region')}.amazonaws.com")
    if comp.type == "pubsub" and not opts.get("endpoint"):
        found.append("pubsub.googleapis.com")
    if comp.type == "azure_log_analytics" and not opts.get("login_endpoint"):
        found.append("login.microsoftonline.com")
    if comp.type == "chronicle":
        found.append("oauth2.googleapis.com")
    if comp.type == "entra":
        found += [] if opts.get("login_endpoint") else ["login.microsoftonline.com"]
        found += [] if opts.get("graph_endpoint") else ["graph.microsoft.com"]
    return [f for f in found if f]
