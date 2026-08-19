/*
    XORTOR - Detection ruleset
    ---------------------------------------------------------------
    Target : Modular Tor-based crimeware platform
             (WordPress brute-force botnet + crypto clipper)

    Sample : 448776210b0c1802fd3e5da66813e90e7469bcd365d64e11b2a992547bc2fd4a
    Chain  : PyInstaller dropper (custom-compiled bootloader)
               -> PyArmor-protected installer.pyc
                 -> 12-byte repeating-XOR encrypted payload set (data_p002)
                   -> JScript modules + bundled Tor client (uusd.exe)

    Author : Mustafa Emre
    Date   : 2026-07-18
    Revised: 2026-08-19
    TLP    : CLEAR

    ---------------------------------------------------------------
    2026-08-19 REVISION - what changed and why

    An external review found this ruleset shipped with defects that the report
    claimed were already fixed. All were reproduced before being corrected:

      1. XORTOR_Screenshot_Exfil had none of the mitigations report section 7.4
         described. A four-line benign PowerShell screenshot snippet matched it.
         The mitigations are now actually present.

      2. Four rules matched this .yar file itself, and three matched the report.
         Any MISP export, TI feed or blog post quoting these IOCs would alert.
         All rules now carry file-type and size guards.

      3. $o3b "1988hhzEeH" and $o3c "12Qntcik" were labelled ".onion C2
         fragments". They cannot be: v3 onion addresses are RFC4648 base32
         (a-z, 2-7) and these contain 1, 8 and 9. Verified programmatically -
         every other fragment validates. Removed; see XORTOR_Unclassified_Strings.

      4. XORTOR_XORed_PE_KeyAgnostic is key-agnostic but NOT linker-agnostic.
         Its meta claimed more scope than it has. Corrected rather than
         rewritten - see that rule's note for why.

    NOT re-tested against the original samples: they were not available at
    revision time. Changes 1-3 are verifiable by inspection and by scanning this
    repository (which the rules must no longer match). Change 4 is documentation
    only. Anyone with the samples should re-run the positive controls.
    ---------------------------------------------------------------
*/

import "pe"


rule XORTOR_Encrypted_Payload
{
    meta:
        description   = "DEPRECATED - payload encrypted with build-1 12-byte XOR key"
        author        = "Mustafa Emre"
        date          = "2026-07-18"
        revised       = "2026-08-19"
        reference     = "448776210b0c1802fd3e5da66813e90e7469bcd365d64e11b2a992547bc2fd4a"
        status        = "deprecated"
        superseded_by = "XORTOR_XORed_PE_KeyAgnostic"
        confidence    = "low"
        note          = "Keys on the literal build-1 key. Confirmed dead against build 2, which used a different key, exactly as report section 7.3 predicted. Retained for retro-hunting build 1 only."
        limitation    = "One build. Any rebuild rotates the key and defeats it."

    strings:
        // All 12 rotations. A NUL run in the plaintext exposes the key at an
        // arbitrary phase, so every rotation must be covered.
        $k0  = "tgn5AIyxKkQi" ascii
        $k1  = "gn5AIyxKkQit" ascii
        $k2  = "n5AIyxKkQitg" ascii
        $k3  = "5AIyxKkQitgn" ascii
        $k4  = "AIyxKkQitgn5" ascii
        $k5  = "IyxKkQitgn5A" ascii
        $k6  = "yxKkQitgn5AI" ascii
        $k7  = "xKkQitgn5AIy" ascii
        $k8  = "KkQitgn5AIyx" ascii
        $k9  = "kQitgn5AIyxK" ascii
        $k10 = "Qitgn5AIyxKk" ascii
        $k11 = "itgn5AIyxKkQ" ascii

        // Encrypted MZ header: plaintext MZ + e_lfanew NUL block, XORed
        $mz_enc = { 39 3d 16 35 40 49 79 78 4f 6b 51 69 74 67 6e 35 }

    condition:
        // must not be a plaintext PE, and must not be a text document quoting
        // the key - the previous version matched this .yar file and the report
        uint16(0) != 0x5A4D and
        filesize > 100KB and
        (
            $mz_enc at 0
            or 3 of ($k*)
        )
}


rule XORTOR_Dropper_PyInstaller_PyArmor
{
    meta:
        description = "XORTOR dropper: PyInstaller container with PyArmor loader and campaign filenames"
        author      = "Mustafa Emre"
        date        = "2026-07-18"
        revised     = "2026-08-19"
        reference   = "448776210b0c1802fd3e5da66813e90e7469bcd365d64e11b2a992547bc2fd4a"
        confidence  = "medium"
        note        = "Bootloader recompiled from source (PyInstaller 6.20.0 build artefacts embedded), which invalidates stock bootloader signatures."
        limitation  = "Requires 2 campaign filenames. The shared '002' prefix across data_p002/002_n.js/002a.txt/002w.txt may be a build counter - if so this dies at build 004. Untested hypothesis: check filenames across more samples."

    strings:
        $pyi1 = "PYINSTALLER_STRICT_UNPACK_MODE" ascii
        $pyi2 = "_pyinstaller_pyz" ascii
        $pyi3 = "PYINSTALLER_SUPPRESS_SPLASH_SCREEN" ascii

        $arm1 = "pyarmor_runtime_000000" ascii
        $arm2 = "__pyarmor__" ascii

        // Campaign-specific bundled filenames
        $f1 = "campus.py" ascii
        $f2 = "data_p002" ascii
        $f3 = "uusd.exe" ascii
        $f4 = "installer.pyc" ascii

    condition:
        uint16(0) == 0x5A4D and
        pe.is_pe and
        filesize > 5MB and
        1 of ($pyi*) and
        1 of ($arm*) and
        2 of ($f*)
}


rule XORTOR_JS_Modules_Decrypted
{
    meta:
        description = "Decrypted XORTOR JScript modules: WordPress brute-forcer and crypto clipper"
        author      = "Mustafa Emre"
        date        = "2026-07-18"
        revised     = "2026-08-19"
        reference   = "448776210b0c1802fd3e5da66813e90e7469bcd365d64e11b2a992547bc2fd4a"
        confidence  = "medium"
        scan_hint   = "Fires on decrypted content only; these files never touch disk in cleartext. Use for memory scanning (yara -p) or EDR in-memory rules."
        note        = "obfuscator.io moves string literals into a rotating array but leaves function names and global constants intact."
        limitation  = "Revised 2026-08-19: the bare string '9050' was removed as an anchor. Four characters, it occurs in version numbers, hashes and minified bundles. Tor use now requires 'localhost:9050' or '--socks5'. NOT tested against a JavaScript corpus - npm top-1k and node_modules remain untested."

    strings:
        // Campaign-specific function names
        $fn1 = "_decryptContent" ascii
        $fn2 = "PingToOnion" ascii
        $fn3 = "CheckOnionCMD" ascii

        // Generic function names - never sufficient alone
        $g1 = "_base64Decode" ascii
        $g2 = "GetUserAgent" ascii
        $g3 = "createGUID" ascii

        // Module B - WordPress brute-force
        $b1 = "WPGetUsers" ascii
        $b2 = "BRUTE_MAX_THREADS" ascii
        $b3 = "BRUTE_DPWD_COUNT" ascii
        $b4 = "BRUTE_STOR_TSIZE" ascii
        $b5 = "BRUTE_MAX_ERRORS" ascii
        $b6 = "<name>mt_k" ascii            // XML-RPC system.multicall

        // Module N - crypto clipper
        $n1 = "btc_1_addrs" ascii
        $n2 = "btc_3_addrs" ascii
        $n3 = "btc_q_addrs" ascii
        $n4 = "trn_addrs" ascii
        $n5 = "mony_addrs" ascii
        $n6 = "LoadBip39" ascii
        $n7 = "LoadREPL" ascii

        // Bot artefacts
        $a1 = "GUID_PATH" ascii
        $a2 = "GOOD_PATH" ascii
        $a3 = "GEOIP_PATH" ascii
        $a4 = "BIP39_PATH" ascii
        $a5 = "STOR_FILE" ascii
        $a6 = "PUSH_FILE" ascii

        // Tor exfiltration - specific forms only
        $t1 = "--socks5" ascii
        $t2 = "localhost:9050" ascii
        $t3 = ".onion/" ascii

    condition:
        uint16(0) != 0x5A4D and          // not a PE
        filesize < 200KB and
        (
            1 of ($fn*)                  // campaign-specific name, or
            or 3 of ($b*)                // three module-B constants, or
            or 3 of ($n*)                // three clipper address families, or
            or 3 of ($a*)                // three bot path constants, or
            (2 of ($g*) and 1 of ($t*))  // generic names WITH Tor evidence
        )
}


rule XORTOR_C2_Onion_Fragments
{
    meta:
        description = "XORTOR .onion C2 address fragments"
        author      = "Mustafa Emre"
        date        = "2026-07-18"
        revised     = "2026-08-19"
        reference   = "448776210b0c1802fd3e5da66813e90e7469bcd365d64e11b2a992547bc2fd4a"
        confidence  = "medium"
        note        = "Addresses are split into 10-character chunks inside the obfuscator string array and concatenated at runtime. All fragments below validate against RFC4648 base32 (a-z, 2-7), which is what a v3 onion address must be."
        limitation  = "Revised 2026-08-19: two strings previously listed here could not be onion fragments and were moved to XORTOR_Unclassified_Strings. Guards added - the previous 'condition: 2 of them' matched this .yar file, the report, and any document quoting two IOCs. Expected to degrade: the clipper C2 already rotated once between builds 1 and 2."

    strings:
        // C2 #1 - WordPress module (stable across builds 1-3)
        $o1a = "sqwzutzq7b" ascii
        $o1b = "3ad.onion/" ascii

        // C2 #2 - crypto clipper
        $o2a = "ffeasxsfee" ascii
        $o2b = "xev2rvxfiv" ascii
        $o2c = "i2wvkxre5v" ascii
        $o2d = "axkjeepxzx" ascii
        $o2e = "va4u4ydm2q" ascii
        $o2f = "ead.onion/" ascii

        // additional module-B fragment
        $o3a = "yxoedle2gd" ascii

    condition:
        uint16(0) != 0x5A4D and          // not a PE
        filesize < 200KB and             // not a report, feed dump or bundle
        3 of them                        // raised from 2: two co-occur in prose
}


rule XORTOR_Unclassified_Strings
{
    meta:
        description = "XORTOR - recovered strings of undetermined purpose"
        author      = "Mustafa Emre"
        date        = "2026-08-19"
        reference   = "448776210b0c1802fd3e5da66813e90e7469bcd365d64e11b2a992547bc2fd4a"
        confidence  = "low"
        note        = "These were previously mislabelled as .onion C2 fragments. They cannot be: v3 onion addresses use RFC4648 base32 (a-z, 2-7) and '1988hhzEeH' contains 1, 8 and 9 while '12Qntcik' contains 1. Verified programmatically against all recovered fragments - only these two fail. Actual purpose unknown; candidates include a bot identifier, an auth token or a base64 fragment."
        limitation  = "Low confidence by construction. Included so the strings are not lost, NOT for production deployment."

    strings:
        $u1 = "1988hhzEeH" ascii
        $u2 = "12Qntcik" ascii

    condition:
        uint16(0) != 0x5A4D and
        filesize < 200KB and
        all of them
}


rule XORTOR_Screenshot_Capture
{
    meta:
        description = "XORTOR hidden PowerShell screen capture routine"
        author      = "Mustafa Emre"
        date        = "2026-07-18"
        revised     = "2026-08-19"
        reference   = "448776210b0c1802fd3e5da66813e90e7469bcd365d64e11b2a992547bc2fd4a"
        confidence  = "medium"
        note        = "Renamed from XORTOR_Screenshot_Exfil. Evidence shows capture to %TEMP% only; upload was never demonstrated, so the name no longer claims exfiltration."
        limitation  = "Revised 2026-08-19. The previous version carried NONE of the mitigations report section 7.4 claimed for it - no filesize bound, none of the campaign anchors - and a four-line benign PowerShell screenshot snippet matched it. Both are now actually present."

    strings:
        // Generic PowerShell capture fragments - never sufficient alone
        $ps1 = "Add-Type -" ascii
        $ps2 = "Windows.Fo" ascii
        $ps3 = "stemInform" ascii
        $ps4 = "awing.Bitm" ascii
        $ps5 = "$g.ScaleTr" ascii
        $ps6 = "$bmp.Save(" ascii
        $ps7 = "g.Imaging." ascii
        $ps8 = "dowStyle H" ascii          // -WindowStyle Hidden

        // Campaign anchors - at least one is mandatory
        $a1 = "--socks5" ascii
        $a2 = ".onion/" ascii
        $a3 = "PingToOnion" ascii
        $a4 = "createGUID" ascii
        $a5 = "&GUID=" ascii
        $a6 = "mony_addrs" ascii

    condition:
        uint16(0) != 0x5A4D and
        filesize < 200KB and
        4 of ($ps*) and
        1 of ($a*)
}


rule XORTOR_XORed_PE_KeyAgnostic
{
    meta:
        description = "PE encrypted with a 12-byte repeating XOR key - key independent, linker dependent"
        author      = "Mustafa Emre"
        date        = "2026-07-22"
        revised     = "2026-08-19"
        reference   = "149ab46739ca442762502a69f0960365a7c5e7761c76f2e6c2997bd43744a62a"
        confidence  = "medium"
        note        = "With a 12-byte repeating key, C[i] ^ C[i+12] == P[i] ^ P[i+12] regardless of key value. Applied to the DOS header, whose first bytes are known, this recovers plaintext without the key. Matched builds 1-3 under three different keys."
        limitation  = "KEY-agnostic, not LINKER-agnostic - the meta previously overstated this. The constants below assume plaintext e_cblp == 0x0078 and NUL at 0x0C-0x0F. A typical MSVC PE has e_cblp == 0x0090 and FF FF at 0x0C, and will NOT match. True scope: 'a PE from this toolchain, 12-byte XOR, encrypted from file offset 0 at phase 0'. A rule that dies silently is more dangerous than no rule."
        todo        = "Generalise onto the DOS stub string 'This program cannot be run in DOS mode', which is linker-independent and yields ~27 invariant byte relations. NOT done here: the samples were unavailable at revision time and an untested rewrite would be worse than an honestly-scoped rule."
        scan_hint   = "On-disk, but only where the encrypted PE is written to disk - i.e. after the PyInstaller container extracts to _MEIxxxx at runtime. The dropper itself does NOT match. The previous 'pre-decryption' label implied otherwise."

    condition:
        filesize > 100KB and
        uint16(0) != 0x5A4D and          // not already a plaintext PE
        uint8(0) ^ uint8(12) == 0x4D and // 'M'
        uint8(1) ^ uint8(13) == 0x5A and // 'Z'
        uint8(2) ^ uint8(14) == 0x78 and // e_cblp low byte  - toolchain specific
        uint8(3) ^ uint8(15) == 0x00     // e_cblp high byte - toolchain specific
}
