# Long-running verification (run on the release / staging server)

The development machine ran only the short tests (`tests/test_v10_*.py` plus the regression suites the v10
changes touch). Everything below takes minutes to hours, needs special hardware (HSM, TPM, GPU, a Linux
kernel with BPF) or root/administrator rights, and has **not** been run yet. Run it before tagging 10.0.0 and
record the results in `benchmarks/results/` and `docs/DEFERRED_WORK.md`.

All commands run from the repository root with the project's Python (`python` below; on Windows the bundled
`python311\python.exe`). Install the test extras first: `pip install -e ".[dev,api]"`.

| # | What | Command | Pass criterion | Time |
|---|---|---|---|---|
| 1 | Full test suite (Linux **and** Windows) | `python -m pytest tests -q -x` | 0 failures | 20–40 min |
| 2 | v10 suites only | `python -m pytest tests/test_v10_*.py -q` | 0 failures | < 1 min |
| 3 | Raft safety, 500 seeds (Jepsen-style simulation) | `python -m scripts.long_tests.raft_chaos_long --seeds 500` | exit 0 | 30–60 min |
| 4 | Raft over TCP with kill -9 of random nodes | `python -m scripts.long_tests.raft_tcp_kill --nodes 5 --minutes 30` | exit 0; no lost acked checkpoint; leader within 5 s | 30 min |
| 5 | Fleet: 10,000 forwarders | `python -m scripts.long_tests.fleet_10k --agents 10000 --minutes 15` (load generator on a second host for the CPU figure) | 0 failed heartbeats; coordinator CPU < 2 % of a core | 20 min |
| 6 | Forensic verifier, 100 GB archive, one flipped bit | `python -m scripts.long_tests.forensic_large_archive --gb 100 --dir /data/ulpf-100g` | both verifiers name the exact segment, byte offset, bit and sequence | 2–4 h (disk bound) |
| 7 | PKCS#11 HSM (SoftHSM2, then the real YubiKey / Luna / CloudHSM module) | see §A | exit 0 | 5 min |
| 8 | TPM 2.0 sealing on real hardware | see §B | key unseals after reboot, not on another machine | 15 min |
| 9 | Linux eBPF egress enforcement | see §C | `ulpf airgap os-check` exits 0; allowed endpoints still work | 15 min |
| 10 | Windows WFP egress enforcement | see §D | same as 9 | 15 min |
| 11 | Hard memory ceiling under load (512 MB) | see §E | RSS never above the ceiling; no OOM kill; MemoryError handled | 1 h |
| 12 | MAVLink v2 signed telemetry at line rate | see §F | every spoofed command stored with `auth=rejected`, no genuine frame rejected | 10 min |
| 13 | Copilot with a real GGUF model (CPU and GPU) | `python -m scripts.long_tests.copilot_model_eval --model <gguf>` | 100 % of returned queries valid; p95 latency recorded | 15 min |
| 14 | 24 h soak with every v10 service on | see §G | RSS flat, no growth in open files/threads, audit chains valid | 24 h |
| 15 | Native core and forensic binary on Linux | `scripts/build_native.sh && (cd native/ulpf_forensic && cargo test --release && cargo build --release)` | builds, tests pass | 15 min |
| 16 | Package and container | `pip wheel . -w dist && pip install dist/ulpf-10.0.0-*.whl && ulpf --help && ulpf-forensic-verify --version`; `docker build -t ulpf:10.0.0 .` | installs, console served at `/console/` | 10 min |

## A. PKCS#11 (HSM / YubiKey / Nitrokey / CloudHSM / Luna)

```sh
# SoftHSM2 first (apt install softhsm2 | choco install softhsm)
softhsm2-util --init-token --free --label ULPF --pin 123456 --so-pin 12345678
ULPF_PKCS11_PIN=123456 python -m scripts.long_tests.pkcs11_softhsm --module /usr/lib/softhsm/libsofthsm2.so
# YubiKey 5 (ykcs11 from yubico-piv-tool): EdDSA needs firmware 5.7+
ULPF_PKCS11_PIN=<PIV PIN> python -m scripts.long_tests.pkcs11_softhsm --module /usr/lib/x86_64-linux-gnu/libykcs11.so --token-label "YubiKey PIV #<serial>"
```
Then run the runtime with `evidence.key_provider: pkcs11` and `evidence.pkcs11: {module: ..., token_label: ...}`
and verify seals with `ulpf evidence verify` and the standalone `ulpf-forensic-verify`.

## B. TPM 2.0

Windows (Platform Crypto Provider; the unit test used the software KSP):
```powershell
python -c "from ulpf.runtime.hwkeys import tpm_sealed_key; k=tpm_sealed_key(r'C:\ProgramData\ULPF\evidence\evidence.pem', {}); print(k.public_key().public_bytes_raw().hex())"
# reboot, run again: same public key. Copy evidence.pem.tpm to another PC: unsealing must fail.
```
Linux (`apt install tpm2-tools`, user in the `tss` group):
```sh
python -c "from ulpf.runtime.hwkeys import tpm_sealed_key; print(tpm_sealed_key('/var/lib/ulpf/evidence/evidence.pem', {}).public_key().public_bytes_raw().hex())"
```

## C. Linux eBPF egress (kernel >= 5.8, cgroup v2, clang, bpftool, root)

```sh
ulpf airgap os-policy --format ebpf -c pipeline.yaml --cgroup /sys/fs/cgroup/system.slice/ulpf.service > /tmp/ulpf-ebpf.sh
sudo sh /tmp/ulpf-ebpf.sh
sudo systemd-run --scope -p Slice=system.slice --unit ulpf.service ulpf airgap os-check   # must exit 0
# negative control from inside the cgroup with a native binary:
sudo cgexec -g :system.slice/ulpf.service curl -m 3 https://example.com   # must fail with EPERM
```

## D. Windows WFP egress (elevated PowerShell)

```powershell
ulpf airgap os-policy --format wfp -c pipeline.yaml > $env:TEMP\ulpf-wfp.ps1
powershell -ExecutionPolicy Bypass -File $env:TEMP\ulpf-wfp.ps1
ulpf airgap os-check --target 192.0.2.1:9          # must exit 0 (blocked)
Get-NetFirewallRule -Group "ULPF Egress" | Remove-NetFirewallRule   # cleanup
```

## E. Hard memory ceiling

```yaml
limits: {hard_memory_mb: 512}
```
Run `ulpf run -c pipeline.yaml` and drive it with `python scripts/log_sender.py --rate 50000 --minutes 60`
(or `benchmarks/soak.py`). Watch `GET /api/v1/console/overview` and the OS (`Get-Process`, `systemd-cgtop`).
The audit log records `limits.hard_memory` at start. Pass: no OOM kill, RSS ≤ 512 MB, ingest continues
(back-pressure) when allocations are refused.

## F. MAVLink line rate

Pipeline input: `{type: syslog, protocol: udp, port: 14550, telemetry: mavlink, mavlink: {keys: {"*": "env:MAV_KEY"}}}`.
```sh
export MAV_KEY=$(python -c "import os;print(os.urandom(32).hex())")
ulpf run -c pipeline.yaml &      # same MAV_KEY in its environment
python -m scripts.long_tests.mavlink_flood --rate 20000 --seconds 600
ulpf copilot ask "count of events by action in the last hour"     # then run the query in the console
```

## G. 24-hour soak with v10 services

`pipeline.yaml` with `soar.enabled`, `copilot.enabled`, `fleet.enabled`, `cluster.backend: raft` (3 nodes),
`evidence.row_mac: true`, `limits.hard_memory_mb`. Drive 5–20k EPS with `benchmarks/soak.py --hours 24`.
At the end: `ulpf soar audit-verify`, `ulpf evidence verify --check-store`, `ulpf-forensic-verify journal ...`,
`ulpf matrix run --no-ntp`. Record RSS / threads / file handles every 5 minutes (`benchmarks/soak.py` does).
