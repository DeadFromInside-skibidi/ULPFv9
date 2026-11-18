"""
Events for the standard-view tests (OCSF, UDM, ASIM): ULPF's demo data and
generated lines, plus records that exercise every activity the views map —
Windows Security and Sysmon (XML), cloud audit (CloudTrail, GCP, Azure), EDR,
DNS, proxy, e-mail and derived detections.
"""
from __future__ import annotations

import glob
import json
import os
import random
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_SEC = "Microsoft-Windows-Security-Auditing"
_SYSMON = "Microsoft-Windows-Sysmon"


def _win(provider: str, eid: int, data: dict, computer: str = "ws01.corp.local",
         ts: str = "2026-10-21T10:00:00.000Z") -> str:
    d = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in data.items())
    return (f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
            f'<Provider Name="{provider}"/><EventID>{eid}</EventID><TimeCreated SystemTime="{ts}"/>'
            f'<Computer>{computer}</Computer></System><EventData>{d}</EventData></Event>')


def windows_lines(rnd: random.Random) -> list[str]:
    ip = lambda: f"{rnd.choice([10, 172, 203, 198])}.{rnd.randrange(256)}.{rnd.randrange(256)}.{rnd.randrange(1, 255)}"  # noqa: E731
    users = ["alice", "bob", "svc_backup", "administrator"]
    out = [
        _win(_SEC, 4624, {"TargetUserName": rnd.choice(users), "TargetDomainName": "CORP", "IpAddress": ip(),
                          "IpPort": rnd.randrange(1024, 65535), "LogonType": rnd.choice([2, 3, 10]),
                          "AuthenticationPackageName": rnd.choice(["Kerberos", "NTLM", "Negotiate"]),
                          "WorkstationName": "WS-17"}),
        _win(_SEC, 4625, {"TargetUserName": rnd.choice(users), "IpAddress": ip(), "LogonType": 3,
                          "FailureReason": "%%2313", "SubStatus": "0xc000006a"}),
        _win(_SEC, 4634, {"TargetUserName": rnd.choice(users), "LogonType": 3}),
        _win(_SEC, 4720, {"TargetUserName": "newuser", "SubjectUserName": "administrator", "SubjectDomainName": "CORP"}),
        _win(_SEC, 4726, {"TargetUserName": "olduser", "SubjectUserName": "administrator"}),
        _win(_SEC, 4723, {"TargetUserName": "alice", "SubjectUserName": "alice"}),
        _win(_SEC, 4740, {"TargetUserName": "bob", "SubjectUserName": "DC01$"}),
        _win(_SEC, 4767, {"TargetUserName": "bob", "SubjectUserName": "administrator"}),
        _win(_SEC, 4728, {"MemberName": "CN=bob,OU=Users", "TargetUserName": "Domain Admins",
                          "SubjectUserName": "administrator"}),
        _win(_SEC, 4733, {"MemberName": "CN=eve,OU=Users", "TargetUserName": "Administrators",
                          "SubjectUserName": "administrator"}),
        _win(_SEC, 4688, {"NewProcessName": "C:\\Windows\\System32\\cmd.exe", "NewProcessId": "0x1a4",
                          "CommandLine": "cmd.exe /c whoami", "ParentProcessName": "C:\\Windows\\explorer.exe",
                          "SubjectUserName": "alice", "TokenElevationType": "%%1936"}),
        _win(_SEC, 4689, {"ProcessName": "C:\\Windows\\System32\\cmd.exe", "ProcessId": "420", "SubjectUserName": "alice"}),
        _win(_SEC, 4663, {"ObjectName": "C:\\Finance\\q3.xlsx", "ProcessName": "C:\\Windows\\explorer.exe",
                          "SubjectUserName": "bob", "AccessMask": "0x1"}),
        _win(_SEC, 4657, {"ObjectName": "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                          "ObjectValueName": "Updater", "NewValue": "C:\\Users\\Public\\u.exe", "NewValueType": "REG_SZ",
                          "ProcessName": "C:\\Windows\\regedit.exe", "SubjectUserName": "alice"}),
        _win(_SEC, 4698, {"TaskName": "\\Microsoft\\Updater", "SubjectUserName": "alice"}),
        _win("Service Control Manager", 7045, {"ServiceName": "PSEXESVC", "ImagePath": "C:\\Windows\\PSEXESVC.exe",
                                               "AccountName": "LocalSystem"}),
        _win("Microsoft-Windows-Eventlog", 1102, {"SubjectUserName": "administrator"}),
        _win(_SYSMON, 1, {"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                          "CommandLine": "powershell -enc SQBFAFgA", "ProcessId": rnd.randrange(100, 9999),
                          "ProcessGuid": "{a1b2c3d4-0000-0000-0000-000000000001}",
                          "ParentImage": "C:\\Windows\\System32\\cmd.exe", "ParentProcessId": "4242",
                          "ParentCommandLine": "cmd.exe", "User": "CORP\\alice", "IntegrityLevel": "High",
                          "Hashes": "MD5=0123456789ABCDEF0123456789ABCDEF,SHA256=" + "AB" * 32}),
        _win(_SYSMON, 5, {"Image": "C:\\Windows\\System32\\notepad.exe", "ProcessId": "5150"}),
        _win(_SYSMON, 3, {"Image": "C:\\Windows\\System32\\rundll32.exe", "SourceIp": ip(), "SourcePort": "50123",
                          "DestinationIp": ip(), "DestinationPort": "443", "Protocol": "tcp", "User": "CORP\\bob"}),
        _win(_SYSMON, 6, {"ImageLoaded": "C:\\Windows\\System32\\drivers\\evil.sys", "Signed": "false"}),
        _win(_SYSMON, 7, {"Image": "C:\\Windows\\System32\\rundll32.exe", "ImageLoaded": "C:\\Temp\\x.dll"}),
        _win(_SYSMON, 11, {"Image": "C:\\Windows\\System32\\cmd.exe", "TargetFilename": "C:\\Temp\\payload.exe",
                           "ProcessId": "777"}),
        _win(_SYSMON, 23, {"Image": "C:\\Windows\\System32\\cmd.exe", "TargetFilename": "C:\\Temp\\log.txt"}),
        _win(_SYSMON, 12, {"EventType": "CreateKey", "Image": "C:\\Windows\\regedit.exe",
                           "TargetObject": "HKLM\\SOFTWARE\\Evil"}),
        _win(_SYSMON, 13, {"EventType": "SetValue", "Image": "C:\\Windows\\regedit.exe",
                           "TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Evil",
                           "Details": "C:\\Temp\\payload.exe"}),
        _win(_SYSMON, 22, {"Image": "C:\\Windows\\System32\\svchost.exe", "QueryName": "evil-c2.example",
                           "QueryStatus": "0", "QueryResults": "203.0.113.66"}),
    ]
    return out


def cloud_lines(rnd: random.Random) -> list[str]:
    trail = {"eventVersion": "1.08", "eventTime": "2026-10-21T10:00:00Z", "eventSource": "s3.amazonaws.com",
             "eventName": rnd.choice(["DeleteBucket", "GetObject", "PutBucketPolicy", "CreateUser"]),
             "awsRegion": "eu-west-1", "sourceIPAddress": "203.0.113.5", "userAgent": "aws-cli/2.15",
             "requestID": "REQ123", "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123456789012:user/bob",
                                                     "accountId": "123456789012", "userName": "bob"},
             "recipientAccountId": "123456789012"}
    trail_err = {**trail, "eventName": "ConsoleLogin", "eventSource": "signin.amazonaws.com", "errorCode": "AccessDenied"}
    gcp = {"protoPayload": {"methodName": "storage.buckets.delete", "serviceName": "storage.googleapis.com",
                            "authenticationInfo": {"principalEmail": "bob@example.com"},
                            "requestMetadata": {"callerIp": "198.51.100.7"}},
           "resource": {"labels": {"project_id": "prj-1"}}, "timestamp": "2026-10-21T10:00:01Z", "severity": "NOTICE"}
    azure = {"time": "2026-10-21T10:00:02Z", "operationName": "Microsoft.Compute/virtualMachines/delete",
             "resourceProviderName": "Microsoft.Compute", "caller": "alice@contoso.com", "callerIpAddress": "203.0.113.9",
             "subscriptionId": "sub-123", "level": "Warning", "resultSignature": "Succeeded"}
    return [json.dumps(trail), json.dumps(trail_err), json.dumps(gcp), json.dumps(azure)]


def app_lines(rnd: random.Random) -> list[str]:
    return [
        json.dumps({"timestamp": "2026-10-21T10:00:03Z", "event_type": "process", "message": "Process started",
                    "process": {"name": "mimikatz.exe", "pid": 1337, "command_line": "mimikatz sekurlsa::logonpasswords",
                                "parent": {"name": "cmd.exe", "pid": 100}}, "host": {"name": "ws02"}, "user": "eve",
                    "vendor": "Acme EDR", "category": "endpoint"}),
        json.dumps({"timestamp": "2026-10-21T10:00:04Z", "query": "updates.example.com", "qtype": "A",
                    "rcode": "NXDOMAIN", "src_ip": "10.0.0.8", "dst_ip": "10.0.0.53", "vendor": "Infoblox",
                    "product": "NIOS", "message": "dns query"}),
        json.dumps({"timestamp": "2026-10-21T10:00:05Z", "method": "POST", "url": "https://shop.example.com/login",
                    "status_code": 403, "user_agent": "curl/8.0", "src_ip": "198.51.100.23", "dst_ip": "10.0.1.5",
                    "action": "blocked", "vendor": "F5", "product": "ASM", "type": "waf"}),
        "date=2026-10-21 time=10:00:06 devname=FGT-1 type=utm subtype=email from=a@evil.example to=b@corp.example "
        "subject=Invoice srcip=203.0.113.4 dstip=10.0.0.25 action=blocked",
        "<14>Oct 21 10:00:07 web01 systemd[1]: Started nginx.service - A high performance web server.",
        "<86>Oct 21 10:00:08 web01 sshd[2211]: Accepted publickey for deploy from 10.1.2.3 port 52211 ssh2",
        "<38>Oct 21 10:00:09 vpn01 openvpn[311]: client alice connected, tunnel up from 203.0.113.80",
    ]


def lines(n_generated: int = 3000, seed: int = 9) -> list[str]:
    rnd = random.Random(seed)
    out: list[str] = []
    for path in sorted(glob.glob(os.path.join(ROOT, "demo_data", "*.log"))):
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            out += [l.rstrip("\n") for l in f if l.strip() and not l.startswith("#")]
    for _ in range(3):
        out += windows_lines(rnd) + cloud_lines(rnd) + app_lines(rnd)
    sys.path.insert(0, ROOT)
    from benchmarks.generator import DeterministicGenerator
    g = DeterministicGenerator(seed=seed)
    gens = [g.gen_syslog3164, g.gen_syslog5424, g.gen_cef, g.gen_leef, g.gen_json, g.gen_kv, g.gen_csv, g.gen_xml]
    out += [rnd.choice(gens)() for _ in range(n_generated)]
    return out


def events(n_generated: int = 3000, seed: int = 9) -> list[dict]:
    """Normalised events of ``lines`` plus derived events (anomaly, correlation, detection)."""
    from ulpf.engine.pipeline import Pipeline
    from ulpf.runtime.analytics import derived_event
    p = Pipeline(enable_auto_parser=False)
    out = []
    for i, l in enumerate(lines(n_generated, seed)):
        r = p.process_line(l, event_id=f"00000000-0000-8000-8000-{i:012d}")
        if r.get("success"):
            out.append(r["event"])
    out.append(derived_event("anomaly", "node-1", "1", 0, "Batch volume spike", 7,
                             {"anomaly_type": "volume_anomaly", "z": 4.2}, related=[out[0]["event_id"]]))
    det = derived_event("detection", "node-1", "r1", 0, "Sigma: Brute force", 7,
                        {"rule_id": "ulpf-0001", "techniques": ["T1110"], "tactics": ["credential_access"]},
                        category="ids_ips")
    det["rule"]["id"], det["rule"]["name"] = "ulpf-0001", "Brute force"
    out.append(det)
    return json.loads(json.dumps(out, default=str))
