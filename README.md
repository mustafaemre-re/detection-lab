# detection-lab

Malware analysis reports and the detection logic derived from them.

Every rule in this repository traces back to a sample I took apart myself. Analysis first, detection second — a rule I cannot explain the origin of is a rule I do not ship.

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

---

## Detection rules

| Rule | Target | Report |
|---|---|---|
| [`xortor.yar`](yara/xortor.yar) | XORTOR — encrypted payload, dropper, JScript modules, C2 fragments, screen capture | [XORTOR](analysis/xortor.md) |

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
