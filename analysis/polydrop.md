# POLYDROP — A Packed Windows Implant with WebSocket C2 and a Polygon Blockchain Dead Drop

**Author:** Mustafa Emre
**Date:** 2026-08-19
**TLP:** CLEAR

**Sample analysed:**

| # | SHA-256 |
|---|---|
| 1 | `14bb4c85a5412e44fff51890c095c15d285bcfe83e320ca202121ce66911a0d3` |

**POLYDROP is a local handle, not an attribution claim.** It is derived from
the sample's defining characteristic — a **Poly**gon smart contract used as a
C2 dead **drop** — and is used here only so the report has something to call
the thing. **No attribution search was performed** (§8.2), so this family may
already have a published name. Do not propagate the label until that is
checked.

---

## 1. Executive summary

A packed 64-bit Windows implant that installs itself under a deceptive path,
persists via a rarely-monitored logon-script registry value, and takes
command-and-control over a **WebSocket** channel. When the primary C2 is
unreachable, it falls back to reading an **encrypted configuration from a smart
contract on the Polygon blockchain**, queried through three independent public
RPC providers.

The packing defeated all static analysis. Section entropy 7.95, five of seven
sections empty on disk, six camouflage imports, no recoverable strings, and
`capa` reporting a single capability. Everything of value in this report was
obtained **dynamically** — by letting the sample run in an isolated lab against
a simulated internet and observing what it asked for.

The C2 architecture is the finding worth carrying forward. Seizing the C2 domain
does not disrupt this botnet: each implant, on failing to reach the primary,
reads the current endpoint from a public smart contract that cannot be seized,
served by RPC providers that cannot be blocked without collateral damage. The
operator updates one on-chain value and the entire estate migrates.

**Full C2 infrastructure was recovered**, including the contract address and the
function selector, which means the operator's live configuration is publicly
readable without possessing a sample (§9).

---

## 2. Sample information

| Field | Value |
|---|---|
| SHA-256 | `14bb4c85a5412e44fff51890c095c15d285bcfe83e320ca202121ce66911a0d3` |
| SHA-1 | `63e6fd398839f8dff5ad3e8b8d11b01ded72f1cc` |
| MD5 | `4433e11c3de61fbc76804c206f321c87` |
| Type | PE32+ executable, x86-64, GUI |
| Size | 2,900,480 bytes |
| Sections | 7 |
| TimeDateStamp | `0x5F2D8903` — 2020-08-07 17:01:55 UTC |
| Linker | 14.29 (MSVC) — **stub only** |
| Entry point | `0x1402033D4` (RVA `0x2033D4`) |
| ImageBase | `0x140000000` |
| SizeOfImage | `0x482000` |
| Characteristics | `RELOCS_STRIPPED`, `LARGE_ADDRESS_AWARE` |
| Resources / version info | none |
| Signature | none |
| Overlay | none |
| Source | MalwareBazaar |

### Section table

| Name | VirtSize | RawSize | Entropy |
|---|---|---|---|
| `.text` | 0x00C46C | **0** | 0.00 |
| `.rdata` | 0x000D20 | **0** | 0.00 |
| `.data` | 0x001068 | **0** | 0.00 |
| `.CRT` | 0x000100 | **0** | 0.00 |
| `.*B{` | 0x1AAE03 | **0** | 0.00 |
| `.i:6` | 0x000098 | 0x200 | 0.42 |
| `.hT:` | 0x2C3BC4 | 0x2C3C00 | **7.95** |

**Five of seven sections have `SizeOfRawData = 0`** — declared in the virtual
address space but containing no bytes on disk. They are empty containers the
unpacking stub fills at runtime. All real content lives in `.hT:` at entropy
7.95 (ceiling 8.0), which is the entire file.

Section names `.*B{`, `.i:6`, `.hT:` contain punctuation no compiler emits.
Whether they **rotate between builds is unknown** — only one sample was
examined. No detection in this repository keys on them, so the question is open
rather than load-bearing (§7.3).

### Imports

Six imports, exactly one function per DLL:

```
KERNEL32.dll  GetWindowsDirectoryW
USER32.dll    PostQuitMessage
SHELL32.dll   SHGetFolderPathW
GDI32.dll     GetObjectW
VERSION.dll   GetFileVersionInfoSizeW
SHLWAPI.dll   PathAppendW
```

Six benign-looking functions across six DLLs is camouflage — enough to avoid
looking like an empty import table, not enough to reveal intent. Note the
absences: no `LoadLibrary`, no `GetProcAddress`, no `VirtualAlloc`, no
`VirtualProtect`. A packer requires all four; they are resolved at runtime
(§3.3).

### Packer identification

`diec` signature scan returned `Unknown`. Heuristic mode reported
`Compressed or packed data` and flagged the structural anomaly:

```
EP address (5370819540) more than last section address (5370535936)
```

The entry point lies outside the last section boundary.

**No known packer.** Custom crypter or an unreleased commercial protector.

---

## 3. Analysis chain

### 3.1 Static analysis exhausted

`capa` returned **one** capability across the whole binary:

```
Capability: encode data using Base64
ATT&CK:     T1027 — Obfuscated Files or Information
```

A 2.9 MB implant with one capability means the analyser cannot see the code.

`strings` on the raw file produced only the DOS stub message, the six DLL names,
and the six imported function names. Nothing else — no paths, no URLs, no
registry keys, no error messages.

`FLOSS` (v3.1.1) confirmed it:

```
static strings :  32,244
stack strings  :       4     ("Ll9x" x4)
tight strings  :       0
decoded strings:       0
```

**Zero decoded strings.** FLOSS found one candidate decoding routine
(`0x140468869`), emulated it, and recovered nothing. The 32,244 "static
strings" are chance 4+ byte printable runs inside 2.9 MB of ciphertext — noise,
not strings, and a reminder that a large static-string count means nothing on
its own.

Negative results that eliminated branches: not PyInstaller
(`pyinstxtractor-ng`: missing cookie), not an OLE document (`oledump`,
`oledir`: not OLE2).

### 3.2 The state machine

Under a debugger, the unpacked code is a **flattened control-flow state
machine**. State lives in `[rbp+3280]` and is obfuscated before dispatch:

```asm
mov  eax, dword ptr ss:[rbp+3280]
not  eax
xor  eax, BA4935A7
sub  eax, 3A9D03BB
cmp  eax, 3D
ja   ...        je ...        cmp eax, r8d
je   ...        cmp eax, 9    je ...
```

A fan of comparisons dispatches into handler blocks with no linear flow. This
is the shape produced by control-flow-flattening obfuscators.

### 3.3 API resolution by hash

Every API call routes through a resolver at `0x14000C488`, with the API name
hash in `EDX`:

```asm
mov  edx, 9E7CB791          ; API hash
mov  rcx, rax               ; module base
call sample.14000C488       ; resolve
mov  qword ptr ds:[...], rax  ; cache
call rax                    ; invoke
```

Hashes confirmed by breaking on the resolved address:

| Hash | API |
|---|---|
| `0x9E7CB791` | `kernel32.CreateMutexW` |
| `0xBEF78556` | `kernel32.GetLastError` |
| `0xC87FFF4A` | process exit function |

This is why the import table holds six entries. A breakpoint on `0x14000C488`
logging `EDX` reconstructs the true import table without unpacking.

### 3.4 Single-instance check

```asm
call rax                  ; CreateMutexW(NULL, TRUE, L"Global\85B6839F7FF0A23D")
...
call rax                  ; GetLastError()
cmp  eax, B7              ; 0xB7 = 183 = ERROR_ALREADY_EXISTS
jne  ...
```

`CreateMutexW` in the `Global\` namespace — system-wide across all sessions and
users, not per-session.

### 3.5 Installation and persistence

The sample copies **itself** — verified identical SHA-256 — to:

```
C:\Users\<user>\AppData\Local\ProgramData\Cache\2C196A50\SoftManager72fb40.exe
```

Note `AppData\Local\ProgramData`. **There is no such Windows folder.** Genuine
ProgramData is `C:\ProgramData`. The path is fabricated to survive a casual
glance.

`2C196A50` and `72fb40` were assumed here to be randomised per infection.
**They are not.** Both appear identically in third-party sandbox output from a
different environment (§11.1), so they are hardcoded and the full path can be
matched literally rather than by pattern. The assumption came from one
observation of one infection; it was never tested.

Persistence, recovered from wide strings in unpacked memory and then confirmed
on the host:

```
HKCU\Environment
    UserInitMprLogonScript    REG_SZ
    C:\Users\REM\AppData\Local\ProgramData\Cache\2C196A50\SoftManager72fb40.exe
```

**`UserInitMprLogonScript` is a logon script**, executed by Windows at every
user logon. It requires no administrative rights and appears in none of the
four locations most responders check. In this analysis, `HKCU\...\Run`,
`HKLM\...\Run`, the Startup folder and `schtasks` all returned empty before
this value was found.

> **This is not the only persistence mechanism.** A second one — hijacking an
> existing Windows scheduled task — was **not** found by this analysis and is
> documented in §11. The `schtasks` query above returned empty because it
> filtered on the malware's name, and the hijacked task carries a legitimate
> Microsoft name. Searching persistence by *name* rather than by *modification
> time or content* is what caused the miss.

### 3.6 ntdll hook

The running process holds exactly one **RWX** region, 8 KB at
`0x7FFA9F770000` — immediately adjacent to `ntdll.dll` (`0x7FFA9F590000`).
Contents:

```
4C 8B D1              mov r10, rcx
B8 50 00 00 00        mov eax, 0x50          ; syscall number
E9 6B 08 EC FF        jmp <ntdll+offset>     ; trampoline back
4C 8B D1              mov r10, rcx
B8 50 00 00 00        mov eax, 0x50
FF 25 00 00 00 00     jmp qword ptr [rip+0]
80 7B 01 40 ...       -> 0x140017B80          ; into the implant
```

`mov r10,rcx; mov eax,<n>` is the x64 syscall prologue. **Syscall `0x50` on
Windows 10 1709 x64 is `NtProtectVirtualMemory`.** The implant has inline-hooked
it, preserved the original prologue as a trampoline, and redirects execution to
its own handler at `0x140017B80`.

### 3.7 Simulated internet

With static analysis exhausted, the sample was run in an isolated lab against a
fake internet: a Linux analysis VM providing DNS (answering every query with its
own address) and a TLS server on 443 with a self-signed certificate. The implant
did not validate the certificate.

This is where every network artefact in §5 came from.

---

## 4. Capabilities

### 4.1 Command and control — WebSocket

```
GET /feed HTTP/1.1
Host: metric.gardenpark.click
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Key: <base64, per attempt>
Sec-WebSocket-Version: 13
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36
```

C2 is **`wss://metric.gardenpark.click/feed`**. Consistent with `Websocket.dll`
and `webio.dll` in the module list.

Retry timing observed at 4s, 7s, 15s — **exponential backoff**, not a fixed
interval. Detections keyed on regular beacon cadence will not match.

The hardcoded User-Agent claims **WOW64** — a 32-bit process on 64-bit Windows —
while the binary is native x64. That inconsistency is itself a network
signature. Chrome 145 is also a specific, static version claim.

### 4.2 Command and control — Polygon blockchain dead drop

When the WebSocket handshake fails (observed: after two attempts), the implant
issues an identical JSON-RPC call to three independent Polygon providers in
sequence:

```json
{"jsonrpc":"2.0","method":"eth_call",
 "params":[{"to":"0x0E04c59f31E382D2B8A1637f4B9A5f04165EC48d",
            "data":"0x44574e9b"},"latest"],
 "id":1}
```

| Field | Value |
|---|---|
| Contract | `0x0E04c59f31E382D2B8A1637f4B9A5f04165EC48d` |
| Chain | Polygon mainnet |
| Selector | `0x44574e9b` (no arguments) |
| Method | `eth_call` — read-only, off-chain, no transaction |

Providers tried, in observed order:

```
api.zan.top                        POST /polygon-mainnet
polygon.lava.build                 POST /
polygon-mainnet.gateway.tatum.io   POST /
```

The contract was queried directly against a neutral public Polygon RPC (not one
of the three above) during analysis. Two independent providers returned
identical data:

```
ABI: offset 0x20, length 0x60 (96 bytes)
string: d98603087b9a90a796b91e88ba8d35cccf613f12dd4061685670b192a1ce34af
        97e6af4ae8e12f3ca7665549f3aa8ccb
```

Hex-decoding the returned string yields **48 bytes**. Entropy 5.46 bits/byte —
against a theoretical maximum of log₂(48) ≈ 5.58 for a sample this size, i.e.
effectively at ceiling. The payload is **encrypted**, not encoded. The 48-byte
length is consistent with a 16-byte IV plus 32 bytes of AES ciphertext, and
`bcrypt.dll` / `bcryptprimitives.dll` are loaded.

**Contents not decrypted (§8).**

### 4.3 Loaded capability surface

Modules loaded by the running implant, grouped by what they enable:

| Modules | Capability |
|---|---|
| `winhttp`, `wininet`, `urlmon`, `webio`, `iertutil`, `msIso` | HTTP/HTTPS |
| `Websocket.dll` | WebSocket transport |
| `ws2_32`, `mswsock`, `dnsapi`, `IPHLPAPI`, `nsi`, `winnsi`, `dhcpcsvc` | Network stack |
| `bcrypt`, `bcryptprimitives`, `cryptbase` | Cryptography |
| `sspicli` | SSPI / authentication |
| `imagehlp` | PE manipulation |
| `combase`, `oleaut32`, `rpcrt4` | COM |
| `mscoree.dll` (referenced) | .NET runtime hosting |

`mscoree.dll` appears in the wide-string set, indicating the implant can host
the CLR — i.e. load and execute managed payloads. **Not observed executing.**

### 4.4 Recovered wide strings

Only 18 unique wide strings exist in the entire 4.6 MB unpacked image. The
implant keeps nearly everything encrypted until the moment of use:

```
Global\85B6839F7FF0A23D
SoftManager72fb40.exe
\ProgramData\Cache\2C196A50
UserInitMprLogonScript
Environment
Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36
\REGISTRY\MACHINE\SOFTWARE\Classes
\REGISTRY\USER
\Registry\Machine\Software\Classes\
Wow6432Node
mscoree.dll
ntdll.dll
```

---

## 5. Indicators of compromise

### Files

```
SHA-256  14bb4c85a5412e44fff51890c095c15d285bcfe83e320ca202121ce66911a0d3
SHA-1    63e6fd398839f8dff5ad3e8b8d11b01ded72f1cc
MD5      4433e11c3de61fbc76804c206f321c87
Size     2,900,480 bytes
```

Dropped copy — **identical hash**, self-copy not second stage:

```
%LOCALAPPDATA%\ProgramData\Cache\2C196A50\SoftManager72fb40.exe
```

Full path — **hardcoded, not randomised** (§11.1). Match literally:

```
%LOCALAPPDATA%\ProgramData\Cache\2C196A50\SoftManager72fb40.exe
```

The looser pattern below is retained only as a fallback in case a future build
does rotate these values:

```
%LOCALAPPDATA%\ProgramData\Cache\<8-hex>\SoftManager<6-hex>.exe
```

### Network

```
wss://metric.gardenpark.click/feed          primary C2 (WebSocket)
metric.gardenpark.click                     C2 domain
```

Blockchain dead drop:

```
contract  0x0E04c59f31E382D2B8A1637f4B9A5f04165EC48d   (Polygon mainnet)
selector  0x44574e9b
```

RPC providers abused — **legitimate services, do not blocklist**:

```
api.zan.top
polygon.lava.build
polygon-mainnet.gateway.tatum.io
```

User-Agent:

```
Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36
```

### Host

```
Mutex     Global\85B6839F7FF0A23D
Registry  HKCU\Environment\UserInitMprLogonScript
          = %LOCALAPPDATA%\ProgramData\Cache\<8-hex>\SoftManager<6-hex>.exe
Memory    8 KB RWX region adjacent to ntdll containing a syscall trampoline
```

### Behavioural

- Write to `HKCU\Environment\UserInitMprLogonScript` — **very low legitimate
  baseline**; this value is rarely used by real software
- Creation of a `Global\` mutex whose name is 16 uppercase hex characters
- Executable written to a path containing `AppData\Local\ProgramData` — a
  folder that does not exist in Windows
- WebSocket upgrade request to a non-browser destination from a non-browser
  process
- `eth_call` JSON-RPC to Polygon providers from a process with no blockchain
  function
- Outbound requests with a Chrome User-Agent claiming WOW64 from a 64-bit
  process
- Retry pattern with exponential backoff to a single HTTPS endpoint

---

## 6. MITRE ATT&CK mapping

| Tactic | Technique | Evidence | Confidence |
|---|---|---|---|
| Defense Evasion | T1027 — Obfuscated Files or Information | Custom crypter, entropy 7.95, empty sections | High |
| Defense Evasion | T1027.007 — Dynamic API Resolution | Hash resolver at `0x14000C488` | High |
| Defense Evasion | T1140 — Deobfuscate/Decode Files | Runtime unpacking into empty sections | High |
| Defense Evasion | T1562.001 — Impair Defenses | Inline hook on `NtProtectVirtualMemory` | Medium |
| Persistence | T1037.001 — Logon Script (Windows) | `UserInitMprLogonScript` | **Confirmed** |
| Command and Control | T1071.001 — Web Protocols | `wss://metric.gardenpark.click/feed` | **Confirmed** |
| Command and Control | T1102 — Web Service | Polygon smart contract as dead drop | **Confirmed** |
| Command and Control | T1573 — Encrypted Channel | TLS + AES-encrypted contract payload | High |
| Command and Control | T1008 — Fallback Channels | Blockchain fallback on primary failure | **Confirmed** |
| Execution | T1129 — Shared Modules | `mscoree.dll` — CLR hosting | Low (not observed executing) |
| Discovery | T1057 — Process Discovery | Module enumeration before exit | Medium |

T1102 (Web Service) is the closest existing technique for blockchain dead-drop
resolution. It is an imperfect fit — ATT&CK's examples are social media and
cloud storage, which can be taken down by their operators. A public blockchain
cannot. Recorded as a gap in the taxonomy rather than forced into a better-fitting
ID that does not exist.

Not claimed: collection, credential access, or exfiltration. No such behaviour
was observed, and the C2 session was never established (§8).

---

## 7. Detection opportunities

### 7.1 Behavioural — highest value

These survive repacking, C2 rotation and contract updates.

1. **Write to `HKCU\Environment\UserInitMprLogonScript`.** Near-zero legitimate
   use. This is the single best detection for this family and probably for
   several others. Sigma: registry set, `TargetObject` ending
   `\Environment\UserInitMprLogonScript`.
2. **Process executing from a path containing `AppData\Local\ProgramData`.**
   That folder does not exist in Windows; its presence is by definition
   anomalous.
3. **`eth_call` JSON-RPC to blockchain providers from a non-browser, non-wallet
   process.** Extremely low baseline on a corporate workstation.
4. **WebSocket upgrade to a non-browser destination** from a process with no
   browser lineage.
5. **Global mutex matching `Global\[A-F0-9]{16}`** created by an unsigned binary
   in a user-writable path.

Ranked by expected precision, 1 and 2 are strongest — both are near-unique and
neither depends on anything the operator can trivially change.

### 7.2 Network

```
metric.gardenpark.click                             domain
0x0E04c59f31E382D2B8A1637f4B9A5f04165EC48d          contract address in request body
0x44574e9b                                          selector in request body
```

The **contract address is the more durable network indicator** than the domain.
The domain is designed to be disposable — that is the entire point of the
dead-drop architecture. The contract is the fixed point the operator must keep
using, and it appears in cleartext inside the JSON-RPC request body, so it is
visible to any inspection point that can see the request.

Do **not** blocklist `api.zan.top`, `polygon.lava.build` or
`polygon-mainnet.gateway.tatum.io`. They are legitimate infrastructure.

### 7.3 Static (see `polydrop.yar`)

| Rule | Keys on | Durability |
|---|---|---|
| `POLYDROP_Crypter_Structure` | PE section geometry and entropy | **High** — no strings, names or key material |
| `POLYDROP_Import_Fingerprint` | The six-import camouflage set | Medium — dies if the set rotates |

**Correction to an earlier assessment.** This section initially stated that no
static rule was possible, on the grounds that "the packed file contains nothing
stable to key on" and that section names are randomised per build. Both claims
were wrong. The randomisation claim was an **assumption from a single sample**,
never verified. And the conclusion did not follow: a rule does not have to key
on names or strings — it can key on *structure*.

`POLYDROP_Crypter_Structure` does exactly that. The crypter's defining property
is geometric: four or more sections declared with `VirtualSize > 0` and
`SizeOfRawData == 0` — empty containers the stub unpacks into at runtime —
alongside one section holding over 90% of the file at entropy above 7.8. No
linker emits that shape. The rule contains no strings, no section names and no
hashes, so the unresolved question about name randomisation cannot affect it.

`POLYDROP_Import_Fingerprint` is more literal but earns its place through its
**negative** clauses. Any binary that unpacks itself must call
`GetProcAddress`, `VirtualAlloc` and `VirtualProtect`. This sample imports none
of them while importing six unrelated, benign-looking functions. The absence is
as diagnostic as the presence.

A memory-scan rule for the unpacked implant is **not shipped**. The artefacts
exist and are listed in §7.1, but the analysis VM was reverted before such a
rule could be tested, and an untested rule is a hypothesis.

**Implementation note.** YARA's lexer treats `/` as the start of a regular
expression. Writing the size comparison as `filesize * 90 / 100` causes the
parser to swallow the remainder of the file and report `unterminated regular
expression` on a later, unrelated line. Written as
`raw_data_size * 100 > filesize * 90` instead.

### 7.4 False positive testing

| Corpus | Files | `Crypter_Structure` | `Import_Fingerprint` |
|---|---|---|---|
| Sample (positive control) | 1 | **match** | **match** |
| All `.exe`/`.dll` on REMnux | **6,977** | 1 hit (the sample) | 1 hit (the sample) |
| — of which Wine PE64 binaries | **1,464** | no hits | no hits |

The Wine subset is what makes this meaningful. `POLYDROP_Crypter_Structure`
keys on PE geometry, so the risk it carries is firing on unusual-but-legitimate
linker output. Wine ships 1,464 genuine, legitimately-linked Windows PE64
binaries — precisely the corpus that would expose such a rule. It stayed
silent.

Scanning ELF binaries would have proved almost nothing here: the `MZ` guard
rejects them before any structural logic executes. Corpus **relevance**
decides the value of an FP test, not corpus size.

**Not tested:** signed Microsoft system binaries from a real Windows
installation. Wine's implementations are the closest available substitute on
this platform but are not byte-identical to Microsoft's. Anyone deploying
`POLYDROP_Crypter_Structure` broadly should scan a genuine `System32` first.

---

## 8. Gaps, dead ends and corrections

Recorded in full, including three of my own errors, because the next analyst
needs to know where the ground is soft.

### 8.1 Corrections to my own analysis

**The "anti-analysis chain" did not exist.** Several hours were spent chasing
what appeared to be a sequence of anti-analysis gates: the sample exited
cleanly with code `0x0`, no unpacking occurred, and bypassing one gate merely
moved the failure downstream. The cause was the **mutex check working
correctly** — an earlier successful run had already installed the implant, which
held `Global\85B6839F7FF0A23D`. Every subsequent launch was correctly detecting
its own installed copy. There was no anti-VM, anti-debug or locale check
involved. **The analysis environment had been polluted by the analysis itself.**

Lesson: when a sample exits cleanly and reproducibly, check for an existing
infection *before* concluding the sample is evasive. `Process Hacker` →
find handles → mutex name would have answered this in one minute.

**The RWX region was misattributed.** The region at `0x7FFA9F770000` was first
assessed as a ScyllaHide trampoline, since ScyllaHide was loaded at the time.
It is the implant's own ntdll hook (§3.6). Confirmed by observing the same
region in a process running with no debugger attached.

**`/feed` was assumed to be JSON.** Because `Content-Type: application/json`
appears in the unpacked image, the C2 endpoint was assumed to serve JSON. It is
a **WebSocket** endpoint; the JSON content type belongs to the blockchain RPC
calls, not the C2 channel. Corrected by observing the actual `Upgrade:
websocket` request.

### 8.2 Not determined

**The contract payload was not decrypted.** 48 encrypted bytes were retrieved
from the dead drop, but the decryption key resides in the implant and was not
recovered. The value is most likely the current C2 endpoint — after receiving
the genuine contract data, the implant returned to `metric.gardenpark.click`
rather than resolving anything new, which is consistent with the contract
currently pointing at the same domain.

Recommended next step: attach to the running implant, breakpoint
`BCryptDecrypt`, and read the output buffer. Recovering the key as well as the
plaintext would permit **passive long-term monitoring of the operator's
infrastructure** by polling the contract, with no further samples required.
That is the highest-value unfinished work here.

**The C2 session was never established, and this was the analysis's central
limitation.** The simulated internet returned `200 OK` to the WebSocket upgrade
instead of `101 Switching Protocols`, so the handshake never completed, no
tasking arrived, and the implant looped on retry for the entire observation
period.

The consequence was larger than first recorded here. **Most of the malware's
behaviour lives behind that handshake** — process injection, certificate store
tampering, scheduled-task hijacking and privilege escalation all occur after
tasking and none of them were observed (§11). Everything in §4.3 is inferred
from loaded modules, which shows what the implant *can* reach for, not what it
does.

Completing the handshake with a valid `Sec-WebSocket-Accept` is the single most
valuable unfinished step, ahead of decrypting the contract payload.

**No collection, credential access or exfiltration observed.** Absence of
evidence only, and given the above, weak evidence of absence.

**`mscoree.dll` was not seen executing.** CLR hosting is indicated by the
string, not by observed behaviour.

**Contract ownership and deployment history not investigated.** The deploying
address, deployment date, and any transaction history for
`0x0E04c59f31E382D2B8A1637f4B9A5f04165EC48d` are publicly available and were not
examined. This is a cheap and likely productive lead — the deployer address may
link to other campaigns.

**Attribution was not investigated.** This is a gap in the work, not a
conclusion about the malware.

What was actually done: two automated retrievals failed (MalwareBazaar served a
CAPTCHA, VirusTotal's page is client-rendered), and one VirusTotal report was
read manually — 20/56, all generic labels, no family name (§11.4). MalwareBazaar
carries no signature tag.

What was **not** done: no vendor blog search, no Malpedia or ETDA lookup, no
search on the distinctive artefacts (`SoftManager`, the hardcoded `2C196A50`
path component, `gardenpark.click`, or the contract address), and no review of
existing reporting on blockchain dead-drop tooling — a technique known to be
documented for other families.

An earlier version of this section stated "no public reporting was matched",
which implies a search took place. It did not. **The family name POLYDROP was
therefore assigned before establishing that the family is unnamed**, which risks
adding a redundant label to the taxonomy. Treat the name as a local handle for
this report, not as a claim of novelty, until the search above is performed.

**Single sample.** No campaign evolution analysis is possible.

**`capa` value was near-zero** against the packed binary, and no post-unpacking
`capa` run was performed against the dumped image. That would likely be
productive and was not done.

---

## 9. Assessment

The engineering priority here is unusually clear: **everything is spent on
resilience, almost nothing on the payload's own sophistication.**

The packing is competent but conventional. The persistence mechanism is clever
in its choice of an unmonitored location rather than in any technical novelty.
The ntdll hook is standard practice. Individually, none of this is remarkable.

The C2 architecture is what makes this sample worth documenting. Conventional
takedown assumes a fixed point of failure — seize the domain, sinkhole the IP,
and the botnet is severed from its operator. That assumption does not hold
here. The domain is deliberately disposable. The authoritative C2 address lives
in a smart contract on a public blockchain that no authority can seize, edit or
take offline, reachable through three independent commercial RPC providers that
cannot be blocked without breaking legitimate services. The operator updates one
on-chain value; every implant migrates on its next failure cycle, unprompted.

This inverts the usual defender advantage. The cost of moving infrastructure has
gone to nearly zero, while the cost of disrupting it has gone up sharply.

There is one compensating weakness, and it is significant. **The dead drop is
public.** `eth_call` is read-only and off-chain, so anyone holding the contract
address — recovered here in cleartext from the request body — can poll the
operator's live configuration indefinitely, at no cost, without a sample, and
without the operator ever knowing. The same property that makes the channel
unseizable makes it permanently transparent.

For the defender, that means the highest-value artefact in this report is not
the domain or the hash. It is
`0x0E04c59f31E382D2B8A1637f4B9A5f04165EC48d`, which is stable by design and
observable forever.

The detection guidance follows from the same reasoning. File hashes are
worthless here — the packer randomises section names per build. Domain
blocklists are worthless — the domain is meant to be burned. What holds is host
behaviour: the logon-script registry write, the impossible directory path, and
blockchain RPC traffic from a process that has no business making it.

---

## 10. Methodology notes

Analysis was performed in an isolated lab: a Windows analysis VM and a Linux
analysis VM on a private virtual switch with no route to the host or the
internet. The Windows VM was reverted from a clean snapshot before use.

Static analysis was performed on the Linux VM, where the x86-64 payload cannot
execute — a safety property, not a convenience.

| Tool | Use |
|---|---|
| `pefile` / `pecheck.py` | PE parsing, section entropy, imports |
| `diec` | Packer identification (signature and heuristic) |
| `capa` | Capability identification — near-zero yield when packed |
| `FLOSS` v3.1.1 | Obfuscated string recovery — zero yield |
| `strings` (ASCII **and** `-el` wide) | String extraction |
| x64dbg + ScyllaHide | Debugging, API resolution, hook analysis |
| Process Hacker | Process inspection, handle enumeration, memory dumping |
| Process Monitor | Registry and file activity |
| INetSim + a fake DNS responder | Simulated internet |
| Custom Python TLS server | C2 emulation, request capture, controlled responses |

**Operational note — wide strings.** ASCII `strings` recovered nothing useful
from the unpacked image. `strings -el` recovered the mutex, the persistence
value name, the drop path and the User-Agent. Windows malware stores most of
its strings as UTF-16; **any string extraction on a Windows sample that omits
`-el` is incomplete**, and in this case would have missed every host-based IOC
in this report.

**Operational note — memory region selection.** An initial extraction of
strings from the whole process returned 189,405 lines and no usable indicator.
The output was dominated by mapped system DLLs: the Public Suffix List from
`wininet`/`urlmon` (producing thousands of plausible-looking domains such as
`adygeya.ru` and `7-eleven.com`) and the Brotli static dictionary (producing
plausible-looking URL fragments). **Both are trivially mistaken for malware
indicators.** Restricting extraction to the implant's own image reduced 189,405
lines of noise to 18 wide strings, every one of which was relevant.

**Operational note — a 32 MB private region yielded nothing** because it was
*reserved*, not committed: `Total WS` was 4 KB. Region size in a memory map is
address space, not resident data. Check the working-set column before dumping.

---

## 11. Third-party reporting: VirusTotal

**Everything in this section is VirusTotal's public analysis of the same hash,
not a finding of this report.** It is recorded separately, and nothing from it
has been moved into §3–§5, so the boundary between what was determined here and
what was determined elsewhere stays visible.

Source: VirusTotal public report for
`14bb4c85a5412e44fff51890c095c15d285bcfe83e320ca202121ce66911a0d3`.
Detection ratio **20/56**. Retrieved 2026-08-19. Sandbox output from CAPA, CAPE
Sandbox, Dr.Web vxCube, VirusTotal Jujubox and VirusTotal Observer.

The material difference between the two analyses is network access.
VirusTotal's sandboxes had real internet, so the WebSocket upgrade to
`/feed` returned **`101`** and the implant received tasking. The lab used here
returned `200` and it never did (§8.2). Their post-tasking observations are
therefore things this analysis structurally could not have seen.

### 11.1 Confirmed independently

Findings reached here and separately reproduced by VirusTotal:

| Artefact | Status |
|---|---|
| Mutex `Global\85B6839F7FF0A23D` | exact match |
| `HKCU\Environment\UserInitMprLogonScript` | registry set; Sigma *Potential Persistence Via Logon Scripts — Registry* fired |
| Drop path `…\ProgramData\Cache\2C196A50\SoftManager72fb40.exe` | exact match |
| WebSocket C2 at `metric.gardenpark.click/feed` | `GET … → 101` |
| `api.zan.top`, `polygon.lava.build`, `polygon-mainnet.gateway.tatum.io` | all three |
| ntdll hooking | MBC `Unhook APIs [F0004.003]` |
| Single capability, Base64 | CAPA agrees |

One detail worth extracting: the folder name **`2C196A50` is identical** in
VirusTotal's sandbox and in this analysis. It was assumed here to be randomised
per infection (§5). It is **hardcoded**, which makes it a stronger indicator
than recorded — the path can be matched literally, not by pattern.

### 11.2 Added — behaviour this analysis did not observe

All of the following occur after C2 tasking and were therefore unreachable
here.

**A second persistence mechanism.** The implant writes to:

```
C:\Windows\System32\Tasks\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser
```

It **hijacks an existing legitimate Windows scheduled task** rather than
creating its own. This corrects §3.5, which reported `UserInitMprLogonScript`
as the only persistence found. The `schtasks` query used here filtered on the
malware's name and the hijacked task carries a Microsoft name, so it could not
have matched.

**Trust store tampering.** Three root certificates deleted:

```
HKLM\...\SystemCertificates\AuthRoot\Certificates\A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436
                                                  B1BC968BD4F49D622AA89A81F2150152A41D829C
                                                  CABD2A79A1076A31F21D253635CB039D4329A5E8
```

**Process injection.** MITRE T1055 ×2; Sigma *Uncommon Svchost Command Line
Parameter* fired, indicating injection into `svchost.exe`.

**Privilege escalation attempt.** `consent.exe` appears in the process list —
the UAC elevation prompt.

**Additional dropped files.** `DPAPI.DLL` and `ncrypt.dll` written alongside the
implant in the drop folder — legitimate DLL names in an attacker-controlled
directory, consistent with search-order hijacking.

**Telemetry disabling:**

```
schtasks /delete /f /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader"
```

**Sinkhole check.** Reads `%WINDIR%\system32\drivers\etc\hosts`.

**Randomly-named secondary executables**, copied, executed and deleted:

```
c:\lvbasx\bszee.exe
c:\oqiaiyo\qtybgngw.exe
```

**Non-interactive PowerShell** spawned — Sigma *Non Interactive PowerShell
Process Spawned* fired.

### 11.3 Added — infrastructure

**Domain registration:**

```
gardenpark.click    created 2026-08-11    registrar Dynadot, LLC
```

Registered **eight days** before this analysis. Fresh infrastructure, consistent
with a design that treats the domain as disposable (§9).

**C2 resolution** — behind Cloudflare:

```
172.67.201.199 · 188.114.96.0 · 188.114.97.0     (AS13335)
```

**JA3 TLS fingerprints:**

```
a0e9f5d64349fb13191bc781f81f42e1
98eaec8c8ef8baab245d0b65f788be91
cbcd1d81f242de31fd683d5acbc70dca
```

JA3 survives domain and IP rotation, making these more durable network
indicators than anything in §5.

**Emerging Threats IDS rules already fire** on the blockchain RPC lookups
(`api.zan.top`, `polygon.lava.build`, `polygon-mainnet.gateway.tatum.io` in TLS
SNI) and on `.top` DNS queries. These are informational rules, not malware
detections — but they mean the RPC pattern is already visible to any sensor
running the ET Open ruleset.

### 11.4 Attribution — unchanged

**20/56 detections, no family name.** All labels are generic or heuristic. The
"no family attribution" position in §8 stands, now supported by a second
source rather than only by absence of local evidence.

### 11.5 What this comparison shows

Static analysis produced almost nothing on this sample. Dynamic analysis in an
isolated lab produced the C2, the dead drop, the persistence value, the mutex
and the hook — a complete IOC set. Dynamic analysis **with real network access**
produced a materially different picture again: injection, trust-store
tampering, a second persistence mechanism and privilege escalation.

The gap between the second and third of those is not a matter of tooling or
skill. It is the direct consequence of denying the sample its C2. Isolation is
non-negotiable for safety, and it has an analytical cost that should be stated
rather than discovered later: **against a sample whose behaviour is delivered by
tasking, an isolated lab observes the loader, not the malware.**

A controlled-egress setup — real network, full logging, prior approval — would
have closed that gap. Absent that, a public sandbox report is the cheapest way
to find out what the isolated run could not see, and checking one *before*
declaring an analysis complete is the practice this report failed to follow.
