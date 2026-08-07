# SALAT — A Go-Based Multi-Vector Infostealer with DoH and QUIC Command-and-Control

**Author:** Mustafa Emre
**Date:** 2026-08-07
**TLP:** CLEAR

**Sample analysed:**

| # | SHA-256 |
|---|---|
| 1 | `1fce06baa55f455053a1d5094513a1d509d14cc0270241d329d287feb9a66820` |

Name assigned from the module path embedded in the Go build metadata (`path salat`).
No public family name was matched at time of writing (§8).

---

## 1. Executive summary

A statically-linked **Go 1.24.0** Windows executable that harvests credentials,
session material and cryptocurrency wallets from a broad target list, captures
the screen, and exfiltrates over transports chosen specifically to defeat
network inspection.

The sample is **not packed**. Section entropy sits between 6.00 and 6.65 and
there is **no overlay** — the 12.5 MB size is entirely Go's static linking.
Because Go embeds its build metadata in cleartext, the **complete third-party
dependency tree was recovered without disassembly**, and that dependency list
alone establishes most of the capability set.

Two design choices are worth separating from the usual stealer feature list:

1. **C2 hostnames are resolved over DNS-over-HTTPS** against Cloudflare and
   Google resolvers. DNS-based blocklists and DNS telemetry never observe the
   lookup.
2. **Transport is QUIC/HTTP3 and WebSocket**, not plain HTTPS. QUIC is UDP/443
   and end-to-end encrypted; most inspection stacks do not decode it.

Together these mean that the two network controls that most reliably catch
commodity stealers — DNS sinkholing and TLS inspection of HTTP C2 — are both
addressed by design. Detection value therefore sits in host behaviour and in
the binary's structure, not in network indicators (§7).

The stealer targets **~30 Chromium-family browsers plus Firefox forks**,
**16 cryptocurrency wallets**, **Steam**, and **five messaging platforms**, and
includes a first-party multi-monitor screen capture module.

**No C2 domain or IP was recovered.** This is the analysis's principal gap and
is treated as an open question, not a negative result (§8).

---

## 2. Sample information

| Field | Value |
|---|---|
| SHA-256 | `1fce06baa55f455053a1d5094513a1d509d14cc0270241d329d287feb9a66820` |
| SHA-256 (MalwareBazaar zip) | `e3d6ed176e0dd41222e6c2917fd0744f0a330182f3ef762e0c2526b21fa22672` |
| Type | PE32 executable (GUI) Intel 80386, 6 sections |
| Size | 12,543,488 bytes |
| Compiler | Go 1.24.0 (gc) |
| Module path | `salat` (version `(devel)`) |
| Go build ID | `u7ZQnN-MtLJqJ81kowNe/gy79eCRypvFeAEuR8kdc/ZOJmiAkHNBnrk61JpF7D/8aAU95CcHUMEg3niAgk9` |
| TimeDateStamp | `0x00000000` |
| Entry point | `0x79370` |
| ImageBase | `0x400000` |
| Subsystem | 2 (GUI) |
| Resources | none |
| Version info | none |
| Source | MalwareBazaar |

### Section entropy

| Section | Entropy | VirtSize | RawSize |
|---|---|---|---|
| `.text` | 6.03 | 5,232,853 | 5,233,152 |
| `.rdata` | 6.07 | 6,622,168 | 6,622,208 |
| `.data` | 6.00 | 635,276 | 433,152 |
| `.idata` | 3.88 | 1,100 | 1,536 |
| `.reloc` | 6.65 | 251,584 | 251,904 |
| `.symtab` | 0.02 | 4 | 512 |

No section approaches the ~7.9 that would indicate compression or encryption.
The sample is unpacked and analysable directly.

**`.symtab` is the identifying tell.** That section name is emitted by the Go
`gc` linker and is not produced by MSVC, MinGW or Delphi. Combined with the
`.text`/`.rdata`/`.data`/`.idata`/`.reloc`/`.symtab` ordering, the toolchain was
identifiable before a single string was read.

### TimeDateStamp

`TimeDateStamp` is zero. This is **not** anti-forensics: the Go linker zeroes it
by default for reproducible builds. Recording it here because a zeroed timestamp
in a non-Go binary would carry a very different meaning, and the distinction
matters when triaging at speed.

### Imports

44 imports, `KERNEL32.DLL` only in the import directory. The set is the standard
Go runtime surface — `WerSetFlags`, `WerGetFlags`, `SwitchToThread`,
`GetQueuedCompletionStatusEx`, `CreateWaitableTimerExW`,
`SetProcessPriorityBoost`, `RaiseFailFastException`, `SetThreadContext`,
`DuplicateHandle`.

**The import table is not informative for this sample and should not be used to
triage it.** Go resolves almost everything else dynamically through
`LoadLibraryW`/`GetProcAddress`; the APIs that actually matter (WMI, GDI capture,
task scheduling, token manipulation) appear only as strings, not as imports.
An import-table-driven triage would conclude "does nothing interesting" and be
completely wrong. Additional Win32 API names present as strings but absent from
the import table include `WTSQueryUserToken`, `RtlAdjustPrivilege`,
`SetThreadToken`, `CreateProcessW`, `NetUserGetInfo`, `NetShareAdd`.

---

## 3. Analysis chain

### 3.1 Toolchain identification

`.symtab` plus the section layout indicated Go. Confirmed by:

```
Go build ID: "u7ZQnN-MtLJqJ81kowNe/gy79eCRypvFeAEuR8kdc/ZOJmiAkHNBnrk61JpF7D/8aAU95CcHUMEg3niAgk9"
go1.24.0
```

with 12 distinct `runtime.*` symbol matches (`runtime.main`, `runtime.goexit`,
`runtime.newproc`, `runtime.gopanic`).

### 3.2 Build metadata recovery

Go embeds a `buildinfo` blob containing the module path and the full dependency
list with versions and module hashes. Recovered in cleartext:

```
path  salat
mod   salat  (devel)
```

**This is the highest-value artefact in the sample.** It is the author's own
module name, it is not a library, and it appears in no public Go module index.

### 3.3 Dependency tree

Eighteen third-party modules, versions and `h1:` hashes intact:

| Module | Version | Purpose in this sample |
|---|---|---|
| `github.com/StackExchange/wmi` | v1.2.1 | WMI queries |
| `github.com/yusufpapurcu/wmi` | v1.2.3 | WMI queries (fork) |
| `github.com/go-ole/go-ole` | v1.2.6 | COM/OLE plumbing for WMI |
| `github.com/andygrunwald/vdf` | v1.1.0 | **Valve Data Format — Steam configs** |
| `github.com/capnspacehook/taskmaster` | 2021-05-19 | **Scheduled Task creation** |
| `github.com/gorilla/websocket` | v1.5.3 | **WebSocket C2** |
| `github.com/quic-go/quic-go` | v0.38.1 | **QUIC / HTTP3 C2** |
| `github.com/quic-go/qpack` | v0.4.0 | HTTP3 header compression |
| `github.com/ncruces/go-sqlite3` | v0.23.0 | **Browser database reads** |
| `github.com/tetratelabs/wazero` | v1.8.2 | WASM runtime (backs go-sqlite3) |
| `github.com/ncruces/julianday` | v1.0.0 | SQLite date handling |
| `github.com/xssnick/tonutils-go` | v1.16.0 | **TON blockchain operations** |
| `github.com/nfnt/resize` | 2018-02-21 | **Screenshot downscaling** |
| `github.com/lxn/win` | 2021-02-18 | Win32 API bindings |
| `github.com/rodolfoag/gow32` | 2023-05-12 | Win32 mutex / single-instance |
| `github.com/buger/jsonparser` | v1.1.1 | JSON parsing |
| `github.com/rickb777/date` | v1.21.1 | Date handling |
| `github.com/rickb777/plural` | v1.4.2 | String formatting |

A dependency list is not proof of behaviour — a module can be linked and never
called. But `vdf` (Steam), `taskmaster` (persistence), `tonutils-go` (TON
blockchain) and `resize` (screenshots) have no plausible benign purpose in a
single 12 MB binary with no version info and no resources. Each is corroborated
by strings below.

### 3.4 First-party source structure

The Go symbol table preserves the author's own file and function names:

```
salat/main.go
salat/init.go
salat/funcs.go
salat/sets.go
salat/task.go
salat/tsc.go
salat/screenshot/screenshot.go
```

The screenshot package is fully enumerated:

```
salat/screenshot.Capture          salat/screenshot.CaptureRect
salat/screenshot.CreateImage      salat/screenshot.GetDisplayBounds
salat/screenshot.enumDisplayMonitors
salat/screenshot.getMonitorBoundsCallback
salat/screenshot.getMonitorRealSize
salat/screenshot.getDesktopWindow
```

`enumDisplayMonitors` plus `getMonitorRealSize` means capture is
**multi-monitor aware** — it enumerates displays and captures each at true
resolution rather than grabbing a single primary screen.

---

## 4. Capabilities

### 4.1 Browser credential and session theft

SQL recovered directly from the string table:

```sql
SELECT origin_url, action_url, username_value, password_value, date_created FROM logins
SELECT name, encrypted_value, host_key, path, expires_utc FROM cookies
SELECT name, value FROM autofill
SELECT name, value, host, path, expiry FROM moz_cookies
SELECT service, encrypted_token FROM token_service
SELECT item1, item2 FROM metaData
```

`token_service` is the notable one. In Chromium that table holds **OAuth refresh
tokens for the signed-in Google account**. A stolen refresh token survives a
password reset and can defeat MFA, because it *is* the post-authentication
artefact. It is a materially more severe loss than a saved password.

`moz_cookies` and `metaData` are Firefox; `metaData` with `key4.db` is the
path to decrypting Firefox's `logins.json`.

Credential store filenames present: `Login Data`, `Web Data`, `Cookies`,
`Local State`, `key4.db`, `logins.json`, `masterkey_db`.

Approximately 30 Chromium-family user-data directories are targeted:

```
7Star                 360Browser            Amigo
BraveSoftware         CatalinaGroup         CentBrowser
Chedot                Chromium              CocCoc
Comodo\Dragon         Coowon                DCBrowser
Elements Browser      Epic Privacy Browser  Fenrir Inc
Google\Chrome         Google(x86)\Chrome    Google\Chrome SxS
Iridium               K-Melon               Kometa
MapleStudio\ChromePlus Maxthon3             Microsoft\Edge
Orbitum               QIP Surf              Slimjet
Sputnik               Thorium               Torch
UR Browser            Vivaldi               Yandex\YandexBrowser
```

Gecko-family:

```
Roaming\Mozilla\Firefox\Profiles
Roaming\Comodo\IceDragon\Profiles
```

The breadth of obscure Chromium forks is characteristic of commodity
stealer-as-a-service families rather than targeted tooling.

### 4.2 Cryptocurrency theft

Sixteen wallet brands referenced:

```
MetaMask     Exodus       Electrum     Atomic Wallet
Trust Wallet Phantom      Keplr        Guarda
Armory       Coinomi      Jaxx Liberty TerraStation
Binance      Bytecoin     Zcash        Monero
```

Separately, `tonutils-go` provides **first-class TON (Telegram Open Network)
blockchain support** — not merely file theft:

```
tonutils-go/address.NewAddress      tonutils-go/address.NewAddressExt
tonutils-go/address.NewAddressVar   tonutils-go/address.NewAddressNone
tonutils-go/tvm/cell.BeginCell      tonutils-go/tvm/cell.FromBOC
tonutils-go/tvm/cell.FromBOCMultiRoot
tonutils-go/crc16.ChecksumXMODEM
```

`BeginCell` and `FromBOC` are TON's Bag-of-Cells serialisation — the primitives
for **constructing and parsing TON transactions**, not for reading a wallet file
off disk. Whether this is used for exfiltration over TON, for on-chain C2, or
for direct asset transfer was not determined (§8).

### 4.3 Steam session theft

`github.com/andygrunwald/vdf` with:

```
APPDATA\steam\local.vdf
```

`local.vdf` holds Steam's saved login tokens. Parsing it enables session
takeover without the account password.

### 4.4 Messaging platform theft

References to `Telegram`, `Discord`, `Signal`, `Element` and `Riot` (Matrix).
Session-file theft from these clients yields authenticated access independent of
credentials.

### 4.5 Screen and video capture

First-party `salat/screenshot` package (§3.4), multi-monitor, with
`github.com/nfnt/resize` for downscaling before transmission.

`ffmpeg` and `-hide_banner` are present, indicating invocation of an external
ffmpeg binary. `-hide_banner` suppresses console output, consistent with
concealed execution. Whether ffmpeg is bundled, downloaded, or expected
pre-installed was not determined.

### 4.6 Host fingerprinting

```sql
SELECT LogonId, StartTime, LogonType FROM Win32_LogonSession
```

plus `SOFTWARE\Microsoft\Cryptography` (`MachineGuid` — a stable per-install
host identifier) and `IsWow64Process`.

`Win32_LogonSession` with `LogonType` distinguishes console from RDP sessions.
Also present: `Remote Connect`, `Session Lock`, `Session Unlock`.

### 4.7 Token and privilege manipulation

```
WTSQueryUserToken    RtlAdjustPrivilege    SetThreadToken
IsWellKnownSid       MakeAbsoluteSD        RevertToSelf
```

with the string `failed to enable privileges: %v`. `WTSQueryUserToken` plus
`create process as u...` (truncated by adjacent-string packing) indicates
**launching processes in another user's session** — the technique for moving
from a service/SYSTEM context into an interactive user session to reach
per-user credential stores.

### 4.8 Persistence

`capnspacehook/taskmaster` with `RegisterTaskDefinition`, `TaskService`,
`ITaskService`, `ITaskDefinition`, `IRegistrationInfo`, `IAction`, `ITrigger`,
and trigger types `DailyTrigger`, `WeeklyTrigger`, `DaysOfWeek`, `DaysInterval`,
`MonthsOfYear`, `RandomDelay`, `IdleSettings`, `Session Lock`, `Session Unlock`,
`Remote Connect`.

Persistence is via the **Scheduled Task COM interface directly**, not by
spawning `schtasks.exe`. Detections that watch for `schtasks.exe` command lines
will not fire.

`RandomDelay` is available, which if used would jitter execution and defeat
fixed-interval beacon detection.

### 4.9 Command and control

**Resolution — DNS over HTTPS:**

```
https://1.1.1.1/dns-query?name=
https://cloudflare-dns.com/dns-query?name=
https://dns.google/resolve?name=
```

(Trailing text in raw `strings` output — `failed`, `looking`, `SELECT` — belongs
to adjacent entries in Go's packed string table, which stores strings without
NUL terminators. The URLs end at `name=`.)

**Transport — QUIC/HTTP3 and WebSocket:**

```
quic-go HTTP/3       Sec-WebSocket-Key
websocket            H3_DATAGRAM
```

with full QUIC connection-ID, stream and version-negotiation handling.

Also present: `HTTPS_PROXY` / `https_proxy` awareness, randomised `User-Agent`
handling, and `NetShareAdd` / `NetShareDel`.

---

## 5. Indicators of compromise

### Files

```
SHA-256  1fce06baa55f455053a1d5094513a1d509d14cc0270241d329d287feb9a66820   (PE32, 12,543,488 bytes)
SHA-256  e3d6ed176e0dd41222e6c2917fd0744f0a330182f3ef762e0c2526b21fa22672   (MalwareBazaar zip container)
```

### Build fingerprint

```
Go build ID   u7ZQnN-MtLJqJ81kowNe/gy79eCRypvFeAEuR8kdc/ZOJmiAkHNBnrk61JpF7D/8aAU95CcHUMEg3niAgk9
Go version    go1.24.0
Module path   salat
```

The **module path `salat`** is the most durable static indicator recovered. It
survives recompilation, dependency bumps and code changes; only an explicit
module rename defeats it. The build ID is per-build and identifies this binary
only.

### Network

**No C2 domain or IP was recovered.** The DoH endpoints below are legitimate
public resolvers being abused as a resolution channel — they are **not
attacker infrastructure and must never be blocklisted**:

```
https://1.1.1.1/dns-query?name=
https://cloudflare-dns.com/dns-query?name=
https://dns.google/resolve?name=
```

Their value is behavioural: an unknown binary performing DoH to these endpoints
and then opening QUIC to an unrelated host is the signal.

### Host artefacts

```
%APPDATA%\steam\local.vdf                      (read)
SOFTWARE\Microsoft\Cryptography → MachineGuid   (read, host ID)
Scheduled Task via ITaskService COM             (created — name not determined)
ffmpeg invoked with -hide_banner
```

### Behavioural

- A non-browser process reading `Login Data`, `Cookies`, `Local State` or
  `key4.db` across **multiple** browser vendor directories in one burst
- A process reading `%APPDATA%\steam\local.vdf` that is not `steam.exe`
- DoH requests to `1.1.1.1` / `cloudflare-dns.com` / `dns.google` from a process
  that is not a browser or the OS resolver
- Outbound QUIC (UDP/443) from a freshly written, unsigned executable
- Scheduled Task registered via COM (`ITaskService`) rather than `schtasks.exe`
- `ffmpeg` spawned with `-hide_banner` by a non-media application
- A single process enumerating 20+ browser user-data directories

---

## 6. MITRE ATT&CK mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Credential Access | T1555.003 — Credentials from Web Browsers | `logins` / `Login Data` / `key4.db` across ~30 browsers |
| Credential Access | T1539 — Steal Web Session Cookie | `cookies`, `moz_cookies`, `token_service` |
| Credential Access | T1552.001 — Credentials In Files | `local.vdf`, wallet files, `logins.json` |
| Collection | T1005 — Data from Local System | Wallet and messaging session harvesting |
| Collection | T1113 — Screen Capture | `salat/screenshot` multi-monitor module |
| Collection | T1125 — Video Capture | `ffmpeg -hide_banner` |
| Discovery | T1082 — System Information Discovery | `MachineGuid`, `IsWow64Process` |
| Discovery | T1033 — System Owner/User Discovery | `Win32_LogonSession`, `NetUserGetInfo` |
| Discovery | T1057 — Process Discovery | `Thread32Next`, `Module32FirstW` |
| Execution | T1047 — Windows Management Instrumentation | WMI via `go-ole` |
| Persistence | T1053.005 — Scheduled Task | `taskmaster`, `RegisterTaskDefinition` |
| Privilege Escalation | T1134 — Access Token Manipulation | `WTSQueryUserToken`, `SetThreadToken`, `RtlAdjustPrivilege` |
| Defense Evasion | T1027 — Obfuscated Files or Information | — see §7.3; minimal, by design |
| Command and Control | T1071.004 — Application Layer Protocol: DNS | DoH resolution |
| Command and Control | T1572 — Protocol Tunneling | DNS queries tunnelled inside HTTPS |
| Command and Control | T1573 — Encrypted Channel | QUIC/HTTP3, WebSocket over TLS |
| Command and Control | T1090 — Proxy | `HTTPS_PROXY` awareness |
| Impact | T1657 — Financial Theft | 16 wallets, TON transaction primitives |

Not claimed: exfiltration technique (T1041 vs T1567) — the channel is
identified but the destination and protocol semantics were not (§8).

---

## 7. Detection opportunities

### 7.1 Static (see `salat.yar`)

| Rule | Target | Durability |
|---|---|---|
| `SALAT_Go_Module_Path` | Author's module + first-party package paths | **High** — survives rebuilds |
| `SALAT_Dependency_Fingerprint` | Improbable dependency combination | **High** — survives module rename |
| `SALAT_Build_1fce06ba` | Exact Go build ID | Low — this build only |

The three are deliberately independent so that no single change defeats all of
them. A module rename kills rule 1 but not rule 2; a dependency swap kills
rule 2 but not rule 1; a recompile kills only rule 3.

**Why the dependency fingerprint works.** Rule 2 does not detect "a Go binary" —
it requires the *co-occurrence* of `tonutils-go` (TON blockchain),
`andygrunwald/vdf` (Steam config parsing) and `capnspacehook/taskmaster`
(Scheduled Task creation) in one file. Each is individually legitimate and each
has real non-malicious users. There is no benign application that needs to parse
Steam configs, construct TON blockchain transactions, and register Scheduled
Tasks simultaneously. The improbability is in the intersection, not the parts.

### 7.2 Behavioural (higher value)

These survive recompilation, module renaming and dependency changes.

1. **A single process opening credential databases across multiple browser
   vendors.** A real browser touches only its own directory. Twenty-plus vendor
   directories from one process has effectively no legitimate baseline.
2. **DoH to a public resolver from a non-browser process**, followed by outbound
   QUIC to an unrelated host.
3. **Scheduled Task created via `ITaskService` COM by a recently written,
   unsigned binary.** Note that `schtasks.exe` command-line detections will not
   fire.
4. **`%APPDATA%\steam\local.vdf` read by a process other than `steam.exe`.**
5. **`ffmpeg` spawned with `-hide_banner`** by an application with no media
   function.
6. **Outbound UDP/443 from a process with no browser lineage** — QUIC has a low
   baseline outside browsers on most enterprise workstations.

Ranked by expected precision, 1 and 4 are the strongest; both have near-zero
legitimate occurrence and neither depends on any artefact the author can
trivially change.

### 7.3 Known limitations

- **All three YARA rules operate on cleartext Go metadata.** The author can
  strip the symbol table (`-ldflags="-s -w"`) or the build info
  (`-buildvcs=false`), or apply a packer. Any of these defeats all three rules
  simultaneously. This is the single most likely evasion and it is cheap — one
  compiler flag. The behavioural detections in §7.2 exist because of this.
- **`SALAT_Go_Module_Path` depends on the module being named `salat`.** A
  one-line `go.mod` change defeats it. It is included because it is exact while
  it holds, not because it is durable.
- **`SALAT_Dependency_Fingerprint` will degrade** if the author drops TON
  support or switches Steam parsing libraries. It is the most durable of the
  three but is not permanent.
- **No network signature is possible from this analysis.** No C2 was recovered,
  and even with one, DoH resolution plus QUIC transport means an IDS would see
  an encrypted UDP flow to an IP it cannot pre-resolve. Network detection here
  requires either endpoint telemetry or TLS/QUIC interception.
- **Rules are architecture-agnostic within PE.** They guard on `MZ` and
  `pe.is_pe` but deliberately impose no machine-type check, so a 64-bit rebuild
  of the same codebase would still match. This was verified against 64-bit Go
  binaries during FP testing (§7.4). They do **not** cover a Linux or macOS
  build of the same source; the `MZ` guard excludes ELF and Mach-O entirely.
- **These rules detect the family, not the campaign.** They will match any
  build of this codebase, including ones with different C2 and different
  operators.

### 7.4 False positive testing

| Corpus | Files | Result |
|---|---|---|
| Sample (positive control) | 1 | **3/3 rules match** |
| Benign Go **Windows PE** binaries | 2 | **no match** |
| `/usr/bin` (ELF) | ~2,000 | no match |
| `/opt` (REMnux tool tree, mixed) | 230,767 | **no match** |

The meaningful test is row 2. The others largely confirm the `MZ` guard works.

**Controls used:** `git-lfs.exe` (12,738,008 bytes) and an ASUS `packager.exe`
(6,024,096 bytes), both confirmed Go-built Windows PE with intact
`Go build ID:` metadata. `git-lfs.exe` is a deliberately harsh control — the
same toolchain, the same broad size class as the sample (12.7 MB vs 12.5 MB),
and the same cleartext build metadata. If a rule keys on Go-ness rather than
on this family, `git-lfs.exe` will expose it.

Both controls are 64-bit (PE32+) while the sample is 32-bit (PE32). The rules
impose no machine-type check, so this also confirms the negative result is
driven by content requirements rather than by an architecture accident.

**The failure mode this caught.** The obvious first draft of
`SALAT_Dependency_Fingerprint` keys on `Go build ID:` plus `github.com/` plus
browser-path strings. **That is a Go detector, not a malware detector** — Go
embeds build metadata in every binary by default, and any rule keyed on its
mere presence fires on the entire ecosystem. The rule was written instead to
require the *intersection* of three specific modules — TON blockchain, Steam
VDF parsing, Scheduled Task creation — none of which is suspicious alone.

The generalisable lesson: **a rule must be tested against a clean corpus of the
same file type and toolchain, not merely against a large corpus.** Scanning
230,767 mostly-ELF files proves far less here than scanning two Go Windows PEs.
Corpus relevance beats corpus size.

---

## 8. Gaps and unresolved questions

Recorded because the next analyst needs to know where the ground is soft.

**No C2 endpoint recovered.** No domain, IP or URL path attributable to the
operator was found in the string table. Three explanations, unresolved:

1. The C2 hostname is assembled at runtime from fragments (the XORTOR pattern),
   and was missed because Go's packed string table makes fragment-joining
   ambiguous without disassembly.
2. It is encrypted or encoded in `.rdata` and only materialises in memory.
3. It is resolved dynamically — a DGA, or a hostname fetched from a dead-drop.

The presence of DoH resolution machinery proves a hostname exists somewhere.
Resolving this requires disassembly of `salat/main.go` and `salat/sets.go`
around the DoH call sites, or memory analysis from a live run. **This is the
recommended next step.**

**TON usage not characterised.** `tonutils-go` provides transaction
construction, not just wallet file theft. Whether TON is used for asset
transfer, on-chain C2, or dead-drop resolution is undetermined. On-chain C2
would be a materially more significant finding than wallet theft and should not
be assumed absent.

**Scheduled Task name unknown.** Persistence via `ITaskService` is confirmed by
the library and COM interface strings, but the task name, path and trigger
actually used are constructed at runtime. A precise host IOC requires dynamic
analysis.

**ffmpeg provenance unknown.** Whether bundled, downloaded at runtime, or
assumed present is undetermined. If downloaded, that is an additional network
IOC and an additional detection opportunity.

**`capa` did not complete.** Run against the sample on REMnux, it was still
executing after ~20 minutes and was not waited out. Go binaries produce very
large function counts and are known to be slow under capa. The MITRE mapping in
§6 is derived from manual analysis and is **not** capa-corroborated.

**No family attribution.** The module name `salat` matched no public Go module
index and no known family name at time of writing. The feature set (broad
Chromium fork list, wallet breadth, Steam and Telegram theft) is characteristic
of commodity stealer-as-a-service, but no specific family is claimed. The string
`dQw4w9WgXcQ` — the YouTube video ID for Rick Astley's "Never Gonna Give You
Up" — is embedded, presumably an author joke. It is noted as a weak potential
overlap marker for future samples, **not** as attribution.

**Single sample.** No campaign evolution analysis is possible. The XORTOR work
showed that hash rotation and per-build key rotation are only visible across
builds; nothing equivalent can be said here from one binary.

---

## 9. Assessment

The engineering here is asymmetric in the opposite direction to XORTOR.

XORTOR stacked four layers of obfuscation over a weak cryptographic core, and
the obfuscation fell to frequency analysis. SALAT applies **almost no
obfuscation at all** — no packing, no string encryption, full symbol table, full
build metadata in cleartext — while making genuinely sophisticated choices at
the network layer.

That combination is coherent rather than careless. Static detection is
substantially a solved problem for the defender here: the binary tells you what
it is in plain text, and I recovered the entire capability set in roughly forty
minutes without disassembling a single function. What the author has optimised
against is the **network** layer, where DoH resolution and QUIC transport defeat
DNS sinkholing, domain blocklisting and most TLS inspection at once.

The implicit bet is that on-disk detection is survivable — a fresh build with a
new hash costs nothing — while burned C2 infrastructure is expensive. That is a
rational trade, and it is the same conclusion XORTOR's operator reached by a
different route.

For the defender it means detection value is concentrated in **endpoint
behaviour**, not in network indicators or file hashes. The two highest-precision
signals are host-level and cheap: a process reading credential databases across
multiple browser vendors, and a non-Steam process reading `local.vdf`. Neither
requires knowing the C2, and neither can be defeated by a compiler flag.

---

## 10. Methodology notes

Static-only. The sample was never executed. Analysis was performed inside an
isolated VirtualBox VM (host-only network, no NAT, no route to the host LAN or
internet), reverted from a clean snapshot before use.

| Tool | Use |
|---|---|
| `pefile` | PE parsing, section entropy, imports, overlay calculation |
| `strings` | String table extraction (37,784 strings) |
| `yara` | Rule development and testing (v4.5.0) |
| `sha256sum` | Hashing and chain of custody |
| `capa` | Attempted; did not complete (§8) |

Environment: REMnux (Ubuntu 24.04.3, distro release v2026.30.6) under
VirtualBox 7.2.14 on a Windows 11 host.

Sample transfer into the VM used a read-only ISO rather than a shared folder.
A shared folder is a writable bidirectional path from a machine running live
malware into the host filesystem; an ISO is not writable from the guest.

**Operational note — Go string tables.** Go stores strings in a packed blob
without NUL terminators, with lengths held separately in the code. `strings`
therefore emits runs of concatenated, unrelated strings. Reading
`https://1.1.1.1/dns-query?name=failed` as a single indicator would be wrong;
the URL ends at `name=` and `failed` begins the next entry. **Every string
extracted from a Go binary must be treated as potentially truncated at both
ends until confirmed against the code that references it.** This is the main
reason no C2 fragment could be confidently assembled (§8).
