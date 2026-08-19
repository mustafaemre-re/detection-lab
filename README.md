# detection-lab

Malware analysis reports and the detection logic derived from them.

**Author:** Mustafa Emre

**Focus:** Static malware analysis · detection engineering · threat intelligence

---

## Repository layout

```
analysis/     Full analysis reports, one per sample
yara/         YARA rules, referenced back to their report
sigma/        Behavioural detections
scripts/      Analysis tooling
```

---

## Analyses

| Report | Sample | Summary |
|---|---|---|
| [XORTOR](analysis/xortor.md) | `4487762...bc2fd4a` | Tor-based modular crimeware: WordPress brute-force botnet + crypto clipper. Four obfuscation layers stripped statically; 12-byte XOR key recovered through frequency analysis without key material. |
| [SALAT](analysis/salat.md) | `1fce06b...9a66820` | Go infostealer targeting ~30 browsers, 16 wallets, Steam and messaging clients. Unpacked, but resolves C2 over DNS-over-HTTPS and transports over QUIC/HTTP3 — defeating DNS sinkholing and TLS inspection by design. Full capability set recovered from Go build metadata without disassembly. |
| [POLYDROP](analysis/polydrop.md) | `14bb4c8...6911a0d3` | Packed Windows implant with WebSocket C2 and a Polygon smart contract as fallback dead drop. Static analysis yielded nothing — full C2 infrastructure, persistence and contract address recovered dynamically against a simulated internet. Seizing the C2 domain does not disrupt the botnet. |

---

## Detection rules

| Rule | Target | Report |
|---|---|---|
| [`xortor.yar`](yara/xortor.yar) | XORTOR — encrypted payload, dropper, JScript modules, C2 fragments, screen capture | [XORTOR](analysis/xortor.md) |
| [`salat.yar`](yara/salat.yar) | SALAT — Go module path, dependency-intersection fingerprint, exact build ID | [SALAT](analysis/salat.md) |
| [`polydrop.yar`](yara/polydrop.yar) | POLYDROP — crypter section geometry (string-free, structural), camouflage import set | [POLYDROP](analysis/polydrop.md) |

### Behavioural (Sigma)

| Rule | Target | Report |
|---|---|---|
| [`polydrop_fake_programdata_path.yml`](sigma/polydrop_fake_programdata_path.yml) | Execution and file creation under `%LOCALAPPDATA%\ProgramData\` — a directory Windows does not have | [POLYDROP](analysis/polydrop.md) |
| [`polydrop_blockchain_deaddrop.yml`](sigma/polydrop_blockchain_deaddrop.yml) | Blockchain RPC lookups from non-browser processes; hijack of the Compatibility Appraiser task | [POLYDROP](analysis/polydrop.md) |

`UserInitMprLogonScript` persistence is deliberately **not** duplicated here — it
is already covered by *Potential Persistence Via Logon Scripts — Registry* (Tom
Ueltschi) in the Sigma Integrated Rule Set.

Mutex creation has no Sigma rule because Sysmon does not log it by default;
`Global\85B6839F7FF0A23D` remains an IOC for memory and handle enumeration only.

---

## Tooling

| Script | Purpose |
|---|---|
| [`polydrop_deaddrop_poll.py`](scripts/polydrop_deaddrop_poll.py) | Reads POLYDROP's C2 configuration from its Polygon dead-drop contract and reports when the operator rotates it. Read-only `eth_call` — no transaction, no trace, no sample needed. |

---

## How I work

**Static first.** Dynamic analysis tells you what a sample did on one run. Static analysis tells you what it can do. I reach for a sandbox when static analysis stops paying — not before.

**Document the dead ends.** A report that only contains what worked is a sales pitch. Failed hypotheses, corrections and unresolved questions belong in the report, because the next analyst needs to know where the ground is soft.

**Every rule declares its blind spots.** A rule shipped without a documented limitation is a rule nobody can reason about. Each one here carries its scope, its known false positives, and what defeats it.

**Test for false positives before shipping.** A rule that has never been run against a clean corpus is a hypothesis, not a detection.

---

## Scope

No samples are hosted here. Reports reference SHA-256 hashes; retrieve samples from MalwareBazaar or an equivalent source.

Everything published here is for defensive purposes: detection, threat intelligence, and incident response.
