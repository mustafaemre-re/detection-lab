# detection-lab

Malware analysis reports and the detection logic derived from them.

**Author:** Mustafa Emre

**Focus:** Static malware analysis · detection engineering · threat intelligence

---

## Repository layout

```
analysis/     Full analysis reports, one per sample
yara/         YARA rules, referenced back to their report (see yara/README.md)
sigma/        Behavioural detections
scripts/      Analysis tooling
```

---

## Analyses

| Report | Sample | Summary |
|---|---|---|
| [XORTOR](analysis/xortor.md) | `4487762...bc2fd4a` | Tor-based modular crimeware: WordPress brute-force botnet + crypto clipper. 12-byte XOR key recovered through frequency analysis without key material. Two of four obfuscation layers fully stripped — PyArmor and the obfuscator.io string array were not, and the C2 addresses were never recovered. Report revised 2026-08-19 after external review; see its §7.4. |
| [SALAT](analysis/salat.md) | `1fce06b...9a66820` | Go infostealer targeting ~30 browsers, 16 wallets, Steam and messaging clients. Unpacked, but resolves C2 over DNS-over-HTTPS and transports over QUIC/HTTP3 — defeating DNS sinkholing and TLS inspection by design. Full capability set recovered from Go build metadata without disassembly. |
| [POLYDROP](analysis/polydrop.md) | `14bb4c8...6911a0d3` | Packed Windows implant with WebSocket C2 and a Polygon smart contract as fallback dead drop. Static analysis yielded nothing — full C2 infrastructure, persistence and contract address recovered dynamically against a simulated internet. Seizing the C2 domain does not disrupt the botnet. |
| [BLOATDROP](analysis/bloatdrop.md) | `c9082f7...f3c32d37c` | Go loader in an 86 MB file, 96.9% of it random padding. Gates on a scored 13-check sandbox suite needing only 8 to pass, then resolves its C2 from a codeword posted on actor-controlled Telegram, Pinterest and Steam profiles. Carries no payload. Cracked by patching one byte in the PE subsystem field, which exposed the author’s own verbose debug log. |

---

## Detection rules

| Rule | Target | Report |
|---|---|---|
| [`xortor.yar`](yara/xortor.yar) | XORTOR — encrypted payload, dropper, JScript modules, C2 fragments, screen capture | [XORTOR](analysis/xortor.md) |
| [`salat.yar`](yara/salat.yar) | SALAT — Go module path, dependency-intersection fingerprint, exact build ID | [SALAT](analysis/salat.md) |
| [`polydrop.yar`](yara/polydrop.yar) | POLYDROP — crypter section geometry (string-free, structural), camouflage import set | [POLYDROP](analysis/polydrop.md) |
| [`bloatdrop.yar`](yara/bloatdrop.yar) | BLOATDROP — exact-mebibyte overlay padding on a Go PE64 (structural); dead-drop config and sandbox-gate labels (memory only) | [BLOATDROP](analysis/bloatdrop.md) |

### Behavioural (Sigma)

| Rule | Target | Report |
|---|---|---|
| [`polydrop_fake_programdata_path.yml`](sigma/polydrop_fake_programdata_path.yml) | Execution and file creation under `%LOCALAPPDATA%\ProgramData\` — a directory Windows does not have | [POLYDROP](analysis/polydrop.md) |
| [`polydrop_blockchain_deaddrop.yml`](sigma/polydrop_blockchain_deaddrop.yml) | Blockchain RPC lookups from non-browser processes; hijack of the Compatibility Appraiser task | [POLYDROP](analysis/polydrop.md) |
| [`bloatdrop_headless_browser_theft.yml`](sigma/bloatdrop_headless_browser_theft.yml) | Headless browser started against an empty throwaway profile with logging suppressed — the shape of an App-Bound Encryption bypass | [BLOATDROP](analysis/bloatdrop.md) |
| [`bloatdrop_social_deaddrop.yml`](sigma/bloatdrop_social_deaddrop.yml) | Telegram, Pinterest and Steam resolved by a non-browser process | [BLOATDROP](analysis/bloatdrop.md) |

`UserInitMprLogonScript` persistence is deliberately **not** duplicated here — it
is already covered by *Potential Persistence Via Logon Scripts — Registry* (Tom
Ueltschi) in the Sigma Integrated Rule Set.

Mutex creation has no Sigma rule because Sysmon does not log it by default;
`Global\85B6839F7FF0A23D` remains an IOC for memory and handle enumeration only.

BLOATDROP's self-delete is deliberately **not** duplicated here — `rmdir /s /q` is
already covered by *Directory Removal Via Rmdir* (frack113) in the Sigma
Integrated Rule Set, and `Glasikprostik` is a mutex, so the note above applies to
it too.

---

## Tooling

| Script | Purpose |
|---|---|
| [`polydrop_deaddrop_poll.py`](scripts/polydrop_deaddrop_poll.py) | Reads POLYDROP's C2 configuration from its Polygon dead-drop contract and reports when the operator rotates it. Read-only `eth_call` — no transaction, no trace, no sample needed. |
| [`xortor_xor_keyrecover.py`](scripts/xortor_xor_keyrecover.py) | Recovers a repeating-XOR key from ciphertext alone: Hamming-distance key length, then column frequency. Makes XORTOR §3.4–3.5 reproducible — it previously showed four hand-picked scan rows and a 15-line excerpt. |

---

## How I work

**Static first.** Dynamic analysis tells you what a sample did on one run. Static analysis tells you what it can do. I reach for a sandbox when static analysis stops paying — not before.

**Document the dead ends.** A report that only contains what worked is a sales pitch. Failed hypotheses, corrections and unresolved questions belong in the report, because the next analyst needs to know where the ground is soft.

**Every rule declares its blind spots.** A rule shipped without a documented limitation is a rule nobody can reason about. Each one here carries its scope, its known false positives, and what defeats it.

**Test for false positives before shipping.** A rule that has never been run against a clean corpus is a hypothesis, not a detection.


---

## Rule status

| Ruleset | Compiled | FP-tested | Corpus |
|---|---|---|---|
| [`polydrop.yar`](yara/polydrop.yar) | ✅ | ✅ | 6,977 PE files, incl. 1,464 Wine PE64 |
| [`salat.yar`](yara/salat.yar) | ✅ | ✅ | 2 Go Windows PE + 230,767 files |
| [`bloatdrop.yar`](yara/bloatdrop.yar) | ✅ | ⚠️ **partial** | 74,318 files, 0 hits — but only **14** cleared the rule's 50 MB floor, so the candidate set was 14. Large Go PE64 binaries with archive overlays, the population that would actually produce false positives, were absent from the corpus. The two memory-scoped rules are correctly negative on disk but untested against memory. |
| [`xortor.yar`](yara/xortor.yar) | ✅ | ⚠️ **partial** | Revised 2026-08-19; **not re-tested against the original samples**, which were unavailable. Corrections are verifiable by inspection. |
| [`sigma/`](sigma/) | ⚠️ **partial** | ❌ **untested** | No telemetry corpus was available. The POLYDROP rules were syntax-checked; the BLOATDROP pair was not. Treat all as `experimental`. |

Untested content is labelled rather than omitted, and labelled here rather than only in a commit message.

---

## Scope

No samples are hosted here. Reports reference SHA-256 hashes; retrieve samples from MalwareBazaar or an equivalent source.

Everything published here is for defensive purposes: detection, threat intelligence, and incident response.
