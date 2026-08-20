# BLOATDROP — A Padded Go Loader with a Social-Media Dead Drop and Headless-Browser Credential Theft

**Author:** Mustafa Emre
**Date:** 2026-08-21
**TLP:** CLEAR
**Reviewed:** 2026-08-21 · rule status in [README](../README.md#rule-status)

**Sample analysed:**

| # | SHA-256 |
|---|---|
| 1 | `c9082f765b9d6580d20d56814b1edca52502b754e3553fae7387584f3c32d37c` |

**BLOATDROP is a local handle, not an attribution claim.** It is derived from
the sample's two defining characteristics — 84 MiB of **bloat** padding, and a
social-media dead **drop** resolver. **No attribution search was performed**
(§8.4), so this family may already have a published name. Do not propagate the
label until that is checked.

---

## 1. Executive summary

A 64-bit Go loader distributed as a fake application installer
(`NexomiaUI_v4.87.183.exe`). It gates execution behind a **scored
sandbox-detection suite** requiring 8 of 13 checks to pass, then resolves its
command-and-control address from **actor-controlled public social-media
profiles** — Telegram, Pinterest and Steam — before stealing browser
credentials and cookies and exfiltrating them over HTTPS.

Static analysis produced almost nothing of operational value. 96.9% of the file
is incompressible random padding, the strings are encrypted, the Go module path
is randomised, and the binary is built with `-trimpath`. An earlier reading of a
high-entropy `.rdata` blob as an embedded payload was **wrong** and is corrected
in §8.1 — the sample carries no payload at all. Everything it does, it fetches.

The finding worth carrying forward is the **resolution chain**. The loader holds
one hardcoded IP as its primary, and on failure walks three social-media profile
URLs looking for a five-character codeword. The C2 address is published in the
text around that codeword. Seizing the primary IP does not disrupt the botnet:
the operator edits a Pinterest bio and the estate migrates. Blocking
`telegram.me`, `pinterest.com` or `steamcommunity.com` is not an available
response in any normal environment, which is precisely why those three were
chosen. This is the same architecture as POLYDROP's Polygon contract
([polydrop.md](polydrop.md)) reimplemented on infrastructure that is even harder
to touch.

The single most productive step in this analysis was not a debugger. It was a
**one-byte patch to the PE subsystem field**, which converted a silent GUI
binary into a console binary and caused the sample to print its own decision
log — check names, thresholds, resolution attempts and failure reasons — in
plaintext (§3.4). The author had left verbose logging compiled in.

---

## 2. Sample information

| Field | Value |
|---|---|
| SHA-256 | `c9082f765b9d6580d20d56814b1edca52502b754e3553fae7387584f3c32d37c` |
| Filename as distributed | `NexomiaUI_v4.87.183.exe` |
| Type | PE32+ executable, x86-64, **GUI** (subsystem 2) |
| Size | 86.65 MB (VirusTotal-reported) |
| Overlay | **88,080,384 bytes — exactly 84 MiB**, ≈96.9% of the file |
| Compiler | Go **1.25.4** |
| Go module path | `yNjFRWkjrSgSHsEYcCU` — randomised, not a real import path |
| Build flags | `-trimpath=true` |
| Third-party dependencies | **none** — no `dep` lines in buildinfo |
| Symbol table | `.symtab` present (Go toolchain tell) |
| Signature | none |
| Resources / version info | none |
| Source | MalwareBazaar |

Fields not listed above — entry point, ImageBase, TimeDateStamp, full section
table — were not recorded during analysis and are deliberately omitted rather
than reconstructed after the fact.

### 2.1 The padding

The overlay is **84 MiB to the byte**. Not approximately:
`88,080,384 = 84 × 1,048,576` exactly. It does not compress (gzip returns it
essentially unchanged), contains no archive magic, no PE header, and no
structure of any kind. It is uniform random data appended to inflate the file.

The purpose is size-based evasion (**T1027.001, Binary Padding**). Many
automated pipelines, mail gateways and endpoint agents skip or truncate files
above a size threshold. A functionally small Go loader is thereby delivered
inside a file that a good deal of tooling will decline to open.

The exactness is itself an artefact. Padding drawn from a random length would
not land on a round mebibyte boundary, so this was produced by a build step that
appends a fixed number of megabytes. That gives a structural detection anchor
(§7.1) — and a fragile one, since a single line change in the actor's build
script removes it.

---

## 3. Analysis chain

### 3.1 Triage — static analysis stalls immediately

`file`, `pecheck`, `diec` and `strings` established a Go PE64 with a large
overlay and no recoverable configuration. `floss` runs took long enough to be
impractical against a file of this size and returned no C2 strings, no URLs and
no filesystem paths. The strings are encrypted in the binary and decrypted at
runtime.

`capa` reported anti-VM and anti-sandbox capabilities. **Those findings are
false positives** and are treated as such throughout this report — see §8.2.

### 3.2 Go build metadata

The `buildinfo` blob survives `-trimpath` and gave the toolchain version, the
module path and the dependency list:

```
go      go1.25.4
path    yNjFRWkjrSgSHsEYcCU
build   -trimpath=true
```

Three things follow. The module path is randomised per build, so it is a
per-sample artefact and not a family indicator — unlike SALAT, where the module
name `salat` was stable and became a rule ([salat.md](salat.md)). `-trimpath`
strips source paths, removing the developer's directory structure. And the
**absence of any `dep` line** means the loader uses only the Go standard
library: no HTTP framework, no crypto library, no third-party anything. There is
no dependency-intersection fingerprint to build here, which is what carried the
SALAT ruleset.

### 3.3 The `.rdata` blob — a correction

A high-entropy region in `.rdata` was initially read as an encrypted payload.
That was wrong. Two tests settled it:

- **gzip:** the region compresses by **78%**. Encrypted or compressed data does
  not compress. Structured data does.
- **Structure:** the header is a varint-delta sequence, matching Go's `pclntab`
  / `pctab` program-counter tables.

It is Go runtime metadata, not a payload. The full sequence of errors around
this is recorded in §8.1, because the wrong reading was stated more than once
before it was tested.

**The sample contains no embedded payload.** At that point static analysis was
finished: whatever it runs, it fetches.

### 3.4 The subsystem patch — the step that worked

Under x64dbg the sample terminated with **exit code `0x2`** after loading only
`bcryptprimitives`, `winmm`, `msvcrt`, `ucrtbase`, `powrprof`, `rpcrt4`,
`user32`, `gdi32`, `combase` and `bcrypt`. **No `ws2_32`, no `wininet`, no
`winhttp`, no `dnsapi`, no `mswsock`** — it never reached network code. Three Go
runtime threads spawned and exited.

The binary is compiled for the **GUI subsystem (2)**, so it has no console and
anything it writes to stdout or stderr is discarded. Changing the PE optional
header's `Subsystem` field from `2` to `3` (console) costs one byte and does not
alter a single instruction of code:

```python
import pefile
pe = pefile.PE('sample.exe')
pe.OPTIONAL_HEADER.Subsystem = 3
pe.write('sample_console.exe')
```

Run from `cmd.exe`, the patched binary printed a full, colourised, timestamped
decision log. The author had shipped a verbose build.

This is worth generalising: **a GUI-subsystem Go binary that terminates early
and silently is a candidate for the subsystem patch before it is a candidate for
a debugger.** Go's runtime writes panics, and many developers' own logging, to
stderr. A GUI subsystem hides all of it. The patch is reversible, did not trip
any integrity check in this sample, and cost minutes where the debugger had cost
hours.

### 3.5 The sandbox gate

The log opens with an environment survey and a scored check suite:

```
[*] === Sandbox Check ===
[*]   dll: ntdll.dll
[*]   dll: KERNEL32.DLL
      ... (20 loaded modules enumerated)
[*] AV: none detected
[*] sb: internet     skip
[*] sb: peb_flags    OK
[*] sb: ram          3 GB OK
[*] sb: modules      OK
[*] sb: av_sandbox   OK
[*] sb: cpus         2 OK
[*] sb: user         REM OK
[*] sb: rdtsc        1150 OK
[*] sb: disk         79 GB OK
[*] sb: pc           DESKTOP-2C3IQHO OK
[*] sb: debugger     OK
[*] sb: uptime       1h 56m 41s OK
[*] sb: score        13 / 13 (need 8)
[+] sb: passed
```

Twelve named checks were observed; the score line reports **13 / 13**. The
thirteenth was not identified — the `AV: none detected` line and the skipped
`internet` check are both candidates, and neither was confirmed. This
discrepancy is left open rather than resolved by assumption.

The threshold is the interesting part. **It needs 8 of 13, not 13 of 13.** A
single tell does not stop it. An analysis VM must fail six checks before the
sample declines to run, which means the common half-measures — renaming the
user, bumping the RAM — accomplish nothing individually.

| Check | Observed value | Reads |
|---|---|---|
| `internet` | *skipped* | Connectivity; skipped in this run |
| `peb_flags` | OK | `BeingDebugged` / `NtGlobalFlag` in the PEB |
| `ram` | 3 GB | Physical memory floor |
| `modules` | OK | Loaded-module list vs. analysis DLLs |
| `av_sandbox` | OK | Sandbox agent artefacts |
| `cpus` | 2 | Processor count floor |
| `user` | `REM` | Username against a blocklist |
| `rdtsc` | 1150 | Timing / instruction-cycle check |
| `disk` | 79 GB | Disk size floor |
| `pc` | `DESKTOP-2C3IQHO` | Hostname against a blocklist |
| `debugger` | OK | Debugger present |
| `uptime` | 1h 56m 41s | System uptime floor |

The lab passed all twelve. Two details earned that: the VM had been running for
nearly two hours before detonation, and the hostname was a genuine
Windows-style random name rather than something like `SANDBOX` or `MALWARE`.
The username `REM` — the SANS analysis-VM default, and a name any competent
blocklist would carry — **passed**, which is a useful negative result: this
sample's username check is narrower than expected.

**Exit code `0x2` under the debugger is now explained.** It is not a Go panic,
as first supposed (§8.3). The `debugger` check fails under x64dbg, the score
drops below 8, and the loader exits deliberately.

### 3.6 C2 resolution

With the gate passed, the loader began resolving:

```
[*] Direct: https://62.238.107.2
[!] Connect failed: https://62.238.107.2
[*] Dead drop: https://telegram.me/m1duus (sw: x4tte)
[*] Кодовое слово не найдено, пробуем напрямую: https://telegram.me/m1duus
[!] Connect failed: https://telegram.me/m1duus
[*] Dead drop: https://www.pinterest.com/m1duus (sw: x4tte)
[*] Кодовое слово не найдено, пробуем напрямую: https://www.pinterest.com/m1duus
[!] Connect failed: https://www.pinterest.com/m1duus
[*] Dead drop: https://steamcommunity.com/profiles/76561198657426610 (sw: x4tte)
[*] Кодовое слово не найдено, пробуем напрямую: https://steamcommunity.com/profiles/76561198657426610
[!] Connect failed: https://steamcommunity.com/profiles/76561198657426610
[!] C2 unavailable, attempt 1/473
[*] Direct: https://62.238.107.2
```

The algorithm, read directly off its own logging:

1. Try the hardcoded primary, `https://62.238.107.2`.
2. On failure, walk three dead-drop URLs in fixed order.
3. For each, fetch the page and search for the **codeword `x4tte`** (`sw:` in
   the log). The C2 address is published in the text around it.
4. If the codeword is absent, fall back to treating the profile URL itself as
   the C2 — this is what the Russian line reports (§3.7).
5. On total failure, sleep and restart the cycle. The counter reads
   **`attempt 1/473`**, so the loader will retry 473 times before giving up.

The lab is isolated, so every connection failed and the codeword was never
retrieved. VirusTotal's sandbox had real internet and **did** complete the
resolution; those results are in §11 and are not reproduced here as first-hand
findings.

`m1duus` appears as the account handle on both Telegram and Pinterest. A handle
reused across platforms is an operator artefact, not a generated string.

### 3.7 Language

```
Кодовое слово не найдено, пробуем напрямую
"Codeword not found, trying directly"
```

The debug strings are **Russian**, while the user-facing log lines (`Sandbox
Check`, `Dead drop`, `Connect failed`, `C2 unavailable`) are English. The
Russian appears in the line describing internal fallback logic — the kind of
message a developer writes for themselves. This is a developer-language
indicator. It is not attribution, and §8.4 records why it should not be treated
as one.

---

## 4. Capabilities

Confirmed first-hand from the console log:

- **Environment gating** — scored sandbox suite, 8 of 13 required (§3.5)
- **Module enumeration** — walks and logs the loaded-module list
- **AV detection** — reports installed AV before the check suite runs
- **Dead-drop C2 resolution** — codeword-keyed, three social platforms (§3.6)
- **Hardcoded primary C2** — `62.238.107.2`
- **Retry persistence** — 473 attempts before abandoning
- **Encrypted strings** — no configuration recoverable statically
- **Binary padding** — 84 MiB, exact (§2.1)

Reported by third-party sandboxes and recorded in §11, **not observed here**:
browser credential and cookie theft, headless-browser process injection,
multipart exfiltration, self-deletion, and UAC interaction.

---

## 5. Indicators of compromise

### 5.1 First-hand — observed in this analysis

| Type | Value | Note |
|---|---|---|
| SHA-256 | `c9082f765b9d6580d20d56814b1edca52502b754e3553fae7387584f3c32d37c` | |
| Filename | `NexomiaUI_v4.87.183.exe` | Fake installer lure |
| C2 (primary) | `62.238.107.2` | Hardcoded, HTTPS |
| Dead drop | `https://telegram.me/m1duus` | Actor-controlled profile |
| Dead drop | `https://www.pinterest.com/m1duus` | Actor-controlled profile |
| Dead drop | `https://steamcommunity.com/profiles/76561198657426610` | Actor-controlled profile |
| Codeword | `x4tte` | Marker delimiting the C2 in dead-drop page text |
| Handle | `m1duus` | Reused across Telegram and Pinterest |
| Go module | `yNjFRWkjrSgSHsEYcCU` | **Per-build, not a family indicator** |
| Overlay size | `88,080,384` bytes (84 MiB exact) | Structural |
| Retry budget | 473 | Behavioural |

**Do not blocklist `telegram.me`, `www.pinterest.com` or `steamcommunity.com`.**
They are the abused platforms, not the infrastructure. The detectable artefact
is *which process* contacts them (§7.3).

`62.238.107.2` was never reachable from the lab and was not verified as live.

### 5.2 Third-party — from VirusTotal, see §11

Resolved C2 endpoints, mutex, User-Agent, dropped paths and process behaviour
are listed in §11 and are **not** repeated here, so the boundary between what
this analysis established and what it did not stays visible.

---

## 6. MITRE ATT&CK mapping

Techniques supported by first-hand observation:

| ID | Technique | Evidence |
|---|---|---|
| T1027.001 | Obfuscated Files or Information: Binary Padding | 84 MiB exact overlay (§2.1) |
| T1027 | Obfuscated Files or Information | Encrypted strings; randomised module path; `-trimpath` |
| T1497.001 | Virtualization/Sandbox Evasion: System Checks | `ram`, `cpus`, `disk`, `pc`, `user`, `modules`, `av_sandbox` (§3.5) |
| T1497.003 | Virtualization/Sandbox Evasion: Time Based Evasion | `uptime` and `rdtsc` checks (§3.5) |
| T1622 | Debugger Evasion | `peb_flags` and `debugger` checks; exit `0x2` under x64dbg (§3.5) |
| T1102.001 | Web Service: Dead Drop Resolver | Codeword lookup on three social platforms (§3.6) |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTPS to primary and dead drops |
| T1008 | Fallback Channels | Primary → three dead drops → repeat, 473 times (§3.6) |
| T1036.005 | Masquerading: Match Legitimate Name or Location | `NexomiaUI_v4.87.183.exe` |

Techniques reported only by third-party sandboxes — process injection, APC
injection, credential access from password stores, browser session hijacking,
indicator removal — are mapped in §11.3 and deliberately not mixed in here.

---

## 7. Detection opportunities

### 7.1 Structural — the padded Go binary

The exact 84 MiB overlay on a Go PE64 is machine-checkable and does not depend
on any string surviving encryption. This is the basis of
`BLOATDROP_Padded_Go_Loader` in [`yara/bloatdrop.yar`](../yara/bloatdrop.yar).

The discriminator that makes it usable is **exactness**. Legitimate Go binaries
with large high-entropy overlays exist — self-extracting installers are the
obvious case — but a compressed archive appended to a stub does not land on a
round mebibyte. Requiring `overlay.size % 1048576 == 0` separates deliberate
padding from a payload that merely happens to be large.

**This is fragile by construction.** One line in the actor's build script — pad
to a random length instead of a fixed one — defeats it entirely. It is shipped
because it costs nothing and works today, not because it will last.

### 7.2 Runtime strings — memory scanning only

The configuration is encrypted on disk and present in memory only after
decryption. `BLOATDROP_Runtime_Config` and `BLOATDROP_Sandbox_Gate` are
therefore **memory-scoped rules** and should not be expected to fire on a file
at rest. Whether any of these strings also exist in plaintext in the binary was
**not tested** — the sample was not reachable from the host at the time of
writing — and the rules are marked accordingly.

### 7.3 Social platforms contacted by a non-browser process

The dead-drop platforms cannot be blocked. The caller can be scrutinised. A
process that is not a browser, a messaging client or a game launcher resolving
`telegram.me`, `pinterest.com` **and** `steamcommunity.com` within a short
window is a strong signal — the *combination* is far more distinctive than any
one of them. This is
[`sigma/bloatdrop_social_deaddrop.yml`](../sigma/bloatdrop_social_deaddrop.yml).

### 7.4 Headless browser with a throwaway profile

Reported by VirusTotal, not observed here (§11.2). Covered by
[`sigma/bloatdrop_headless_browser_theft.yml`](../sigma/bloatdrop_headless_browser_theft.yml),
which carries a note recording that it is written against third-party
observation.

### 7.5 What is deliberately not shipped

- **No rule on the Go module path.** `yNjFRWkjrSgSHsEYcCU` is randomised per
  build. A rule keyed on it detects exactly one file, which the hash already
  does.
- **No rule on `62.238.107.2`.** A single IP in a design explicitly built to
  survive losing it. It is an IOC, not a detection.
- **No dependency-intersection rule.** The loader has no third-party
  dependencies, so the technique that carried SALAT does not apply.

### 7.6 Rule status

**Nothing in this ruleset has been false-positive tested.** The sample and the
clean corpus live inside the analysis VMs and were not reachable from the host
when the rules were written. They are written to compile; they have not been
compiled or run against a corpus. See the
[rule status table](../README.md#rule-status). Test command in
[`yara/README.md`](../yara/README.md).

---

## 8. Gaps, dead ends and corrections

### 8.1 The `.rdata` blob was called a payload, twice, before it was tested

A high-entropy region in `.rdata` was described as an encrypted payload, then
revised, then described that way again. None of those statements rested on a
test. Two cheap tests settled it in minutes once they were actually run: it
compresses 78% under gzip, and its header is a varint-delta sequence — Go
`pclntab` metadata (§3.3).

The lesson is specific and worth stating plainly: **high entropy alone does not
mean encrypted.** Compressed data, packed metadata and structured tables all
read as high entropy. A gzip pass distinguishes them and takes seconds.

### 8.2 capa's anti-VM findings on this sample are false positives

`capa` reported anti-VM and anti-sandbox capabilities. The sample **does**
perform sandbox checks (§3.5), so the findings are accidentally correct — but
they are not correctly derived. They come from pattern matches inside the 84 MiB
of random overlay data. A case-sensitive `grep` for `QEMU`, `Xen` and `VMware`
across the file returned **zero** hits.

This generalises: **against a heavily padded sample, any tool that scans the
whole file will manufacture findings from the padding.** Random data of that
volume will contain short byte sequences matching almost any signature. Scope
such tools to the PE sections, not the file, or discount their output.

### 8.3 Exit code `0x2` was attributed to a Go panic

Under the debugger the sample exited `0x2`, and Go's runtime does exit `2` on an
unrecovered panic, so that was the stated hypothesis. It was wrong. The console
patch showed the sandbox gate failing its `debugger` check and the loader
exiting deliberately (§3.5). The hypothesis was reasonable and the evidence
overrode it; it is recorded because the reasoning that produced it looked sound
at the time.

### 8.4 No attribution search was performed

The Russian debug strings, the handle `m1duus` and the codeword `x4tte` are all
searchable. None were searched. The dead-drop profiles were not viewed.

This is a deliberate omission, not an oversight. Viewing actor-controlled
profiles from an attributable address risks alerting the operator, who would
then rotate the infrastructure and invalidate every indicator in §5.1 — for
everyone, not only for this report. Archived copies and third-party enrichment
carry no such risk and are the correct route if this is picked up later.

Consequently: **this family may already have a published name.** `BLOATDROP` is
a local handle and nothing more.

### 8.5 The thirteenth check is unidentified

Twelve checks were observed; the score reports 13 (§3.5). The remaining one was
not identified and is not guessed at here.

### 8.6 The codeword was never retrieved

The lab is isolated by design, so no dead-drop page was ever fetched and the
**format of the C2 record around the `x4tte` marker is unknown** — whether it is
plaintext, encoded, or encrypted. Recovering that format is what would make an
independent dead-drop poller possible, of the kind written for POLYDROP
([`scripts/polydrop_deaddrop_poll.py`](../scripts/polydrop_deaddrop_poll.py)).
No equivalent script is shipped here, because writing one without knowing the
record format would be guesswork.

### 8.7 Not attempted

- The decryption routine for the string table was not located or reversed.
- The `62.238.107.2` C2 protocol is unknown.
- Persistence was never observed — the loader exited before establishing any.
- The 473-attempt loop's sleep interval was not measured.

---

## 9. Assessment

BLOATDROP is a **loader**, not a complete implant. It carries no payload (§3.3),
holds no capability beyond gating and resolution, and its entire purpose is to
determine whether it is being watched and, if not, to ask a social-media profile
where to go next.

Three design decisions are worth separating out.

**The scored gate.** A threshold of 8 out of 13 means no single environmental
tell defeats it, and equally that no single hardening measure defeats *it*. An
analysis environment must be broadly convincing rather than selectively patched.
That the SANS default username `REM` passed suggests the blocklist is narrow —
tuned against commercial sandbox defaults rather than against analyst VMs.

**The dead-drop resolver.** This is POLYDROP's architecture on cheaper, more
robust infrastructure. POLYDROP needed a deployed smart contract and three RPC
providers; BLOATDROP needs three free accounts and a five-character marker. Both
are immune to takedown of the primary C2, but the social-media version is immune
to takedown *entirely* — Telegram, Pinterest and Steam will not remove a profile
for containing five characters of unremarkable text, and no enterprise can block
all three. The barrier to building it is close to zero.

**The padding.** 84 MiB to defeat size-capped scanners is a crude technique that
works because the caps are real. It costs the operator only bandwidth. The
mitigation is a policy question about scan limits rather than a detection
question, and the exactness of the padding is a build-script artefact that will
not survive the actor noticing it.

The combination points at a competent but unremarkable commodity operation: Go
for cross-compilation convenience, standard library only, randomised module
path, `-trimpath`, encrypted strings, and resolution infrastructure that costs
nothing to replace. **The verbose logging is the outlier.** Everything else in
the sample is built to deny information to an analyst; the log hands it over in
full, in two languages. That is a build mistake — a debug configuration shipped
to production — and it is the reason this report has content.

---

## 10. Methodology notes

**The subsystem patch belongs in the standard workflow.** For any GUI-subsystem
binary that exits early and silently — Go binaries especially, since the runtime
writes panics to stderr — flipping `Subsystem` from 2 to 3 is a one-byte,
zero-instruction change that reveals anything the sample writes to stdout or
stderr. It cost minutes. The debugger had cost hours and produced a terminated
process. Try it *before* reaching for x64dbg, not after.

**Check for a prior infection before concluding evasion.** Not a lesson from
this sample but from the previous one, and it applies here: hours were spent on
POLYDROP chasing an anti-analysis chain that turned out to be our own earlier
infection holding a mutex. Clean state first.

**Isolation has a cost and it should be stated.** A lab with no internet cannot
resolve a dead drop. Everything downstream of §3.6 — the codeword format, the
real C2, the payload, the exfiltration — was structurally unreachable here. That
is the correct trade for a report that publishes indicators, but it means §11
exists because this analysis had a boundary, not because it was careless within
that boundary.

**Test before asserting.** §8.1, §8.2 and §8.3 are three separate instances in
one sample of a claim stated before it was checked. In each case the test that
settled it took under a minute.

---

## 11. Third-party reporting: VirusTotal

**Everything in this section is VirusTotal's public analysis of the same hash,
not a finding of this report.** It is recorded separately, and nothing from it
has been moved into §3–§6, so the boundary between what was determined here and
what was determined elsewhere stays visible.

Source: VirusTotal public report for
`c9082f765b9d6580d20d56814b1edca52502b754e3553fae7387584f3c32d37c`.
Detection ratio **16/68**, community score **-11**. Retrieved 2026-08-20.
Sandbox output from CAPE Sandbox, Dr.Web vxCube and VirusTotal Jujubox.

The material difference between the two analyses is **network access**.
VirusTotal's sandboxes had real internet, so `GET https://telegram.me/m1duus`
returned **200**, the codeword was found, and the loader proceeded to its actual
payload. The lab used here could not reach any dead drop (§3.6), so everything
below was structurally unreachable from this analysis rather than merely missed.

### 11.1 Confirmed independently

| Artefact | Status |
|---|---|
| Dead drop `telegram.me/m1duus` | contacted, `GET → 200` |
| Dead drop `www.pinterest.com` | contacted, TLS SNI |
| Dead drop `steamcommunity.com` | contacted, TLS SNI |
| Sandbox/VM evasion | MBC *Dynamic Analysis Evasion [B0003]*; ATT&CK T1497 |
| Binary padding / packing | MBC *Software Packing [F0001]* under Anti-Static Analysis |
| GUI subsystem, no console output | consistent with §3.4 |

### 11.2 Added — behaviour this analysis did not observe

**The resolved C2 endpoints.** Neither appears anywhere in this report's
first-hand findings; both were reached only after the codeword lookup succeeded:

| Host | Role | IPs observed | Hosting |
|---|---|---|---|
| `sii.11gokil.org` | **Exfiltration** — `POST /` → 200, `multipart/form-data` | `104.21.43.112` | Cloudflare |
| `ket.sm188daftar.mom` | Secondary, DNS + TLS SNI only | `188.114.96.0`, `188.114.97.0` | Cloudflare |

Both sit behind Cloudflare, so the origin addresses are not exposed. The
exfiltration `POST` used boundary `----67875b2020cb9c3ca234`.

The naming is worth a note. *gokil* is Indonesian slang, *daftar* is Indonesian
for "register", and `sm188` follows the numbering convention of Asian betting
brands. These read as compromised or repurposed Indonesian gambling
infrastructure, which sits oddly beside the Russian debug strings (§3.7). A
Russian-speaking developer operating on rented or stolen Asian hosting is the
ordinary explanation, and it is offered as the ordinary explanation rather than
as a conclusion.

**Browser credential and cookie theft.** Files opened:

```
C:\Program Files\Google\Chrome\Application\chrome.exe
%LOCALAPPDATA%\360Browser\Browser\User Data
%LOCALAPPDATA%\AVAST Software\Browser\User Data
%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data
%LOCALAPPDATA%\Chromium\User Data
    ...\History
    ...\Login Data
    ...\Login Data For Account
    ...\Network\Cookies
```

**Headless browsers spawned with throwaway profiles.** The technique, and the
most operationally interesting item in the VirusTotal report:

```
msedge.exe  --no-first-run --disable-extensions --headless --disable-logging
            --log-level=3 --user-data-dir="%LOCALAPPDATA%\tasSnc\f357c98f" about:blank
chrome.exe  --no-first-run --disable-extensions --headless --disable-logging
            --log-level=3 --user-data-dir="%LOCALAPPDATA%\tasSnc\640795e4" about:blank
firefox.exe --no-first-run --disable-extensions --headless --disable-logging
            --log-level=3 --user-data-dir="%LOCALAPPDATA%\tasSnc\42e22015" about:blank
```

Each is launched with an **empty, throwaway profile** pointed at `about:blank`.
Combined with the MBC tree reporting *Process Injection [E1055]* and
*Asynchronous Procedure Call [E1055.004]*, the reading is an **App-Bound
Encryption bypass**. Chrome 127 and later bind the cookie encryption key to the
browser's own identity, so code running outside `chrome.exe` cannot decrypt.
Spawning a clean headless instance supplies a legitimate, injectable browser
process; APC injection places the stealer's code inside it; the code then reads
the *real* profile's `Login Data` and `Cookies` with the browser's own
decryption authority.

The throwaway profile is an **injection host, not a data source** — which is why
it is empty and why it is deleted afterwards. This reading is an interpretation
of VirusTotal's observations, not something confirmed here.

`RstrtMgr.dll` (Restart Manager) is the companion technique, used to release
`Login Data` while a browser holds it locked. It triggered the Sigma rule *Load
Of RstrtMgr.DLL By An Uncommon Process*.

**Cleanup.** MBC *Self Deletion [F0007]*; VirusTotal tags the sample
`obfuscated self-delete`:

```
cmd.exe /c rmdir /s /q "%LOCALAPPDATA%\tasSnc\42e22015"
cmd.exe /c rmdir /s /q "%LOCALAPPDATA%\tasSnc\640795e4"
cmd.exe /c rmdir /s /q "%LOCALAPPDATA%\tasSnc\f357c98f"
```

**Mutex.** `Glasikprostik`, also as `\Sessions\1\BaseNamedObjects\Glasikprostik`.
Non-dictionary and transliteration-flavoured, consistent with §3.7. This is the
strongest single host indicator in either analysis — and it did not come from
this one.

**User-Agent — malformed.**

```
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Safari/537.36 Edg/144.0.0.0
```

A genuine Edge User-Agent reads
`...AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36 Edg/144.0.0.0`.
This one is missing **both** the `(KHTML, like Gecko)` token and the `Chrome/`
version token. It was assembled by hand from a half-remembered template, and it
is a clean network-layer signature that requires no TLS inspection.

**JA3:** `a0e9f5d64349fb13191bc781f81f42e1`.

**Recon and privilege escalation.** Child processes include `ping.exe`,
`ipconfig.exe`, `reg.exe`, `find.exe`, two `powershell.exe` instances,
`taskhostw.exe`, `svchost.exe` and — notably — **`consent.exe`**, the UAC
elevation prompt. The Sigma rule *Uncommon Svchost Command Line Parameter* fired
at `high`.

### 11.3 Third-party ATT&CK mapping

VirusTotal's own mapping, reproduced as theirs. It is **not** merged into §6:

Execution T1059, T1106, T1129 · Persistence T1112, T1543, T1547 ·
Privilege Escalation T1055, T1543, T1547 · Defense Evasion T1027, T1055, T1070,
T1202, T1218, T1497, T1562, T1564 · Credential Access T1003, T1539, T1552,
T1555 · Discovery T1012, T1057, T1082, T1083, T1497, T1518 · Collection T1005,
T1074, T1185 · Command and Control T1071, T1105, T1573.

### 11.4 Reported findings assessed as false positives

Two items in the VirusTotal report should not be carried forward.

**The root-certificate activity.** VirusTotal shows
`HKLM\...\SystemCertificates\AuthRoot\AutoUpdate\EncodedCtl`, `LastSyncTime`,
and a certificate blob under thumbprint
`CABD2A79A1076A31F21D253635CB039D4329A5E8` written and then deleted, triggering
the Sigma rule *New Root or CA or AuthRoot Certificate to Store*. This is
**standard Windows CryptoAPI certificate-trust-list synchronisation**, triggered
by the sample's own HTTPS connections. The evidence is the accompanying request:

```
GET http://x1.i.lencr.org/    User-Agent: Microsoft-CryptoAPI/10.0
```

That is Windows validating a Let's Encrypt chain, not the malware installing a
certificate. The Sigma hit is noise in this context.

**`C:\ksoelyx\hoofwhl.exe` and `C:\ylqf\ijiookzu.exe`.** Randomly-named
executables at the drive root are plausible second stages, but neither appears
in the report's dropped-files list, and CAPE virtual machines are frequently
dirty from prior detonations. These are recorded as **unconfirmed** and are not
listed as indicators.

### 11.5 What §11 changes about the assessment

The loader classification in §9 is unchanged and reinforced: BLOATDROP fetches
its capability, and the capability is **browser credential and session theft**
with an App-Bound Encryption bypass. It is an infostealer delivery chain.

One item genuinely revises this report's detection posture. §7.2 concluded that
memory scanning was the only route to string-based detection, because the
configuration is encrypted on disk. The mutex `Glasikprostik` is a **host**
artefact observable through handle enumeration without any file or memory
signature at all, and it was recovered by a sandbox rather than by static
analysis. Where a family encrypts everything on disk, sandbox-observed runtime
artefacts may be the *only* practical string indicators — and this one came from
a third party.
