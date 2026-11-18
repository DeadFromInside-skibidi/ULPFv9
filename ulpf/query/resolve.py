"""
Field names to SQL, per data source.

Analysts write the names of their own product: KQL ``TimeGenerated`` / ``SrcIpAddr``, Splunk
``_time`` / ``_raw`` / ``src``, LogScale ``@timestamp`` / ``@rawstring``, or the unified names
(``source.ip``, ``user.name``). Each resolver maps them onto its source's columns; any other
dotted name is read from the event JSON (and then from the parser's fields), so every field of
the unified event can be queried. Returns (sql, type) with type one of
str, int, float, bool, ts, json (text from JSON: cast on numeric use), list, any.
"""
from __future__ import annotations

_ALIASES = {
    "timestamp": ("@timestamp", "_time", "timegenerated", "time", "eventtime", "event.created", "@time"),
    "source.ip": ("src_ip", "src", "srcipaddr", "sourceip", "source_ip", "srcaddr", "src_addr", "client_ip",
                  "clientip", "ipaddress", "aip", "localip"),
    "destination.ip": ("dst_ip", "dest_ip", "dest", "dst", "dstipaddr", "destinationip", "destination_ip",
                       "dstaddr", "remoteip"),
    "source.port": ("src_port", "spt", "srcport", "sourceport", "source_port"),
    "destination.port": ("dest_port", "dst_port", "dpt", "dstport", "destinationport", "destination_port"),
    "network.protocol": ("protocol", "proto", "transport"),
    "device.vendor": ("vendor", "devicevendor", "device_vendor"),
    "device.product": ("product", "deviceproduct", "device_product"),
    "device.hostname": ("host", "hostname", "computer", "computername", "dvc", "dvchostname", "computer_name",
                        "devicename", "aid_hostname"),
    "user.name": ("user", "username", "accountname", "account", "targetusername", "user_name", "suser", "duser"),
    "event.category": ("category",),
    "event.action": ("action", "activity"),
    "event.severity": ("severity",),
    "severity_label": ("severity_label", "severitylabel"),
    "event.type": ("event_type", "eventtype"),
    "raw_format": ("raw_format", "sourcetype", "source_format"),
    "message": ("msg", "message"),
    "raw_event": ("_raw", "@rawstring", "rawdata", "raw", "syslogmessage"),
    "event_id": ("event_id", "eventid_ulpf", "@id", "_cd"),
    "hash.sha256": ("sha256", "filehash", "file.hash.sha256", "hash_sha256", "sha256hashdata"),
    "tenant_id": ("tenant", "tenantid", "#repo"),
}
_CANON = {}
for canon, alts in _ALIASES.items():
    _CANON[canon.lower()] = canon
    for a in alts:
        _CANON[a.lower()] = canon


def canonical(name: str) -> str:
    return _CANON.get(name.lower(), name)


def qident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def qstr(s: str) -> str:
    return "'" + str(s).replace("'", "''") + "'"


def json_path(name: str) -> str:
    return "$" + "".join("." + qident(p) for p in name.split("."))


class Resolver:
    physical: frozenset = frozenset()
    columns: dict = {}           # canonical name -> (sql, type)
    display: tuple = ()          # (output name, canonical) for rows of the source
    json_columns: tuple = ()     # JSON text columns searched for other names

    def resolve(self, name: str):
        c = canonical(name)
        if c in self.columns:
            return self.columns[c]
        if name in self.physical:
            return qident(name), "str"
        parts = [f"json_extract_string({col}, {qstr(json_path(c))})" for col in self.json_columns]
        parts += [f"json_extract_string({col}, {qstr('$.' + qident(name))})" for col in self.extra_json]
        return (parts[0] if len(parts) == 1 else f"COALESCE({', '.join(parts)})"), "json"

    extra_json: tuple = ()

    def time(self):
        return self.columns["timestamp"]


class StoreResolver(Resolver):
    """The DuckDB event store (``events``: storage.database.EVENT_COLUMNS) and live batches."""

    from ulpf.storage.database import EVENT_COLUMNS as _COLS
    physical = frozenset(_COLS)
    columns = {
        "timestamp": ('TRY_CAST("timestamp" AS TIMESTAMPTZ)', "ts"),
        "source.ip": ('"source_ip"', "str"), "destination.ip": ('"destination_ip"', "str"),
        "source.port": ('"source_port"', "int"), "destination.port": ('"destination_port"', "int"),
        "network.protocol": ('"protocol"', "str"), "device.vendor": ('"device_vendor"', "str"),
        "device.product": ('"device_product"', "str"), "event.category": ('"category"', "str"),
        "event.action": ('"action"', "str"), "event.severity": ('"severity"', "int"),
        "severity_label": ('"severity_label"', "str"), "event.type": ('"event_type"', "str"),
        "raw_format": ('"raw_format"', "str"), "message": ('"message"', "str"), "raw_event": ('"raw_event"', "str"),
        "event_id": ('"event_id"', "str"), "correlation_id": ('"correlation_id"', "str"),
        "tags": ('"tags"', "str"), "timestamp_original": ('"timestamp_original"', "str"),
        "user.name": ("json_extract_string(normalised_json, '$.user.name')", "json"),
        "device.hostname": ("json_extract_string(normalised_json, '$.device.hostname')", "json"),
        "hash.sha256": ("COALESCE(json_extract_string(normalised_json, '$.file.hash.sha256'), "
                        "json_extract_string(parsed_fields, '$.sha256'))", "json"),
        "tenant_id": ("NULL", "str"),
    }
    display = (("timestamp", "timestamp"), ("event_id", "event_id"), ("category", "event.category"),
               ("action", "event.action"), ("severity", "event.severity"), ("source.ip", "source.ip"),
               ("destination.ip", "destination.ip"), ("user.name", "user.name"),
               ("device.hostname", "device.hostname"), ("raw_format", "raw_format"), ("message", "message"),
               ("raw_event", "raw_event"))
    json_columns = ("normalised_json",)
    extra_json = ("parsed_fields",)


class LakeResolver(Resolver):
    """The lakehouse (``ulpf.lake.schema.SCHEMA``: flat columns plus ``event_json``)."""

    from ulpf.lake.schema import SCHEMA as _S
    physical = frozenset(f.name for f in _S)
    columns = {
        "timestamp": ('"timestamp"', "ts"), "source.ip": ('"source_ip"', "str"),
        "destination.ip": ('"destination_ip"', "str"), "source.port": ('"source_port"', "int"),
        "destination.port": ('"destination_port"', "int"), "network.protocol": ('"protocol"', "str"),
        "device.vendor": ('"device_vendor"', "str"), "device.product": ('"device_product"', "str"),
        "device.hostname": ('"device_hostname"', "str"), "user.name": ('"user_name"', "str"),
        "event.category": ('"category"', "str"), "event.action": ('"action"', "str"),
        "event.severity": ('"severity"', "int"), "severity_label": ('"severity_label"', "str"),
        "event.type": ('"event_type"', "str"), "raw_format": ('"raw_format"', "str"),
        "message": ('"message"', "str"), "raw_event": ('"raw_event"', "str"), "event_id": ('"event_id"', "str"),
        "hash.sha256": ('"hash_sha256"', "str"), "tenant_id": ('"tenant_id"', "str"),
        "network.bytes_in": ('"bytes_in"', "int"), "network.bytes_out": ('"bytes_out"', "int"),
        "rule.name": ('"rule_name"', "str"), "threat.category": ('"threat_category"', "str"),
    }
    display = (("timestamp", "timestamp"), ("tenant_id", "tenant_id"), ("event_id", "event_id"),
               ("category", "event.category"), ("action", "event.action"), ("severity", "event.severity"),
               ("source.ip", "source.ip"), ("destination.ip", "destination.ip"), ("user.name", "user.name"),
               ("device.hostname", "device.hostname"), ("message", "message"), ("raw_event", "raw_event"))
    json_columns = ("event_json",)
