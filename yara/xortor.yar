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
    TLP    : CLEAR
*/


rule XORTOR_Encrypted_Payload
{
    meta:
        description = "Payload encrypted with 12-byte repeating XOR; key leaks through NUL regions"
        author      = "Mustafa Emre"
        date        = "2026-07-18"
        reference   = "448776210b0c1802fd3e5da66813e90e7469bcd365d64e11b2a992547bc2fd4a"
        confidence  = "high"
        note        = "PE headers are NUL-heavy. NUL XOR key == key, so the key appears in cleartext inside the ciphertext. Detects the payload without decryption."

    strings:
        // All rotations of the key. Any NUL run (PE padding, UTF-16 text,
        // section alignment) exposes the key starting at an arbitrary offset.
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

        // Encrypted "MZ" DOS header: plaintext MZ + e_lfanew NUL block XORed
        $mz_enc = { 39 3d 16 35 40 49 79 78 4f 6b 51 69 74 67 6e 35 }

    condition:
        $mz_enc at 0
        or (filesize > 2KB and 3 of ($k*))
}


rule XORTOR_Dropper_PyInstaller_PyArmor
{
    meta:
        description = "PyInstaller dropper carrying a PyArmor loader and an encrypted payload set"
        author      = "Mustafa Emre"
        date        = "2026-07-18"
        reference   = "448776210b0c1802fd3e5da66813e90e7469bcd365d64e11b2a992547bc2fd4a"
        confidence  = "medium"
        note        = "Bootloader was recompiled from source (PyInstaller 6.20.0 build artifacts embedded), defeating stock bootloader signatures."

    strings:
        $pyi1 = "PYINSTALLER_STRICT_UNPACK_MODE" ascii
        $pyi2 = "_pyinstaller_pyz" ascii
        $pyi3 = "PYINSTALLER_RESET_ENVIRONMENT" ascii

        $arm1 = "pyarmor_runtime_000000" ascii
        $arm2 = "__pyarmor__" ascii

        // Campaign-specific bundled filenames
        $f1 = "campus.py" ascii
        $f2 = "data_p002" ascii
        $f3 = "uusd.exe" ascii
        $f4 = "installer.pyc" ascii

    condition:
        uint16(0) == 0x5A4D
        and filesize > 5MB
        and 1 of ($pyi*)
        and 1 of ($arm*)
        and 2 of ($f*)
}


rule XORTOR_JS_Modules_Decrypted
{
    meta:
        description = "Decrypted JScript modules: WordPress brute-forcer and crypto clipper"
        author      = "Mustafa Emre"
        date        = "2026-07-18"
        reference   = "448776210b0c1802fd3e5da66813e90e7469bcd365d64e11b2a992547bc2fd4a"
        confidence  = "high"
        note        = "obfuscator.io moves string literals into a rotating array but leaves function names and global constants intact. This is the weakest link in the chain."
        scan_hint   = "Fires on decrypted content only; these files never touch disk in cleartext. Use for memory scanning (yara -p) or EDR in-memory rules."

    strings:
        // Shared infrastructure
        $fn1 = "_decryptContent" ascii
        $fn2 = "_base64Decode" ascii
        $fn3 = "PingToOnion" ascii
        $fn4 = "CheckOnionCMD" ascii
        $fn5 = "GetUserAgent" ascii
        $fn6 = "createGUID" ascii

        // Module B - WordPress brute-force
        $b1 = "WPGetUsers" ascii
        $b2 = "BRUTE_MAX_THREADS" ascii
        $b3 = "BRUTE_DPWD_COUNT" ascii
        $b4 = "BRUTE_STOR_TSIZE" ascii
        $b5 = "BRUTE_MAX_ERRORS" ascii
        $b6 = "/wp-json/w" ascii
        $b7 = "<name>mt_k" ascii            // XML-RPC system.multicall amplification

        // Module N - crypto clipper / seed brute-force
        $n1 = "btc_1_addrs" ascii           // BTC P2PKH
        $n2 = "btc_3_addrs" ascii           // BTC P2SH
        $n3 = "btc_q_addrs" ascii           // BTC Bech32
        $n4 = "trn_addrs" ascii             // TRON
        $n5 = "mony_addrs" ascii            // Monero
        $n6 = "LoadBip39" ascii
        $n7 = "LoadREPL" ascii

        // Bot artefacts
        $a1 = "GUID_PATH" ascii
        $a2 = "GOOD_PATH" ascii
        $a3 = "GEOIP_PATH" ascii
        $a4 = "BIP39_PATH" ascii
        $a5 = "STOR_FILE" ascii
        $a6 = "PUSH_FILE" ascii

        // Tor exfiltration
        $t1 = "--socks5" ascii
        $t2 = "9050" ascii
        $t3 = ".onion/" ascii

    condition:
        filesize < 200KB
        and (
            (2 of ($fn*) and 1 of ($t*))
            or 3 of ($b*)
            or 3 of ($n*)
            or 3 of ($a*)
        )
}


rule XORTOR_C2_Onion_Fragments
{
    meta:
        description = "Campaign-specific .onion C2 address fragments"
        author      = "Mustafa Emre"
        date        = "2026-07-18"
        reference   = "448776210b0c1802fd3e5da66813e90e7469bcd365d64e11b2a992547bc2fd4a"
        confidence  = "high"
        note        = "Addresses are split into 10-character chunks inside the obfuscator string array and concatenated at runtime."

    strings:
        // C2 #1 - WordPress brute-force module
        $o1a = "sqwzutzq7b" ascii
        $o1b = "3ad.onion/" ascii

        // C2 #2 - crypto clipper module
        // Reassembled: ffeasxsfeexev2rvxfivi2wvkxre5vaxkjeepxzxva4u4ydm2qead.onion
        $o2a = "ffeasxsfee" ascii
        $o2b = "xev2rvxfiv" ascii
        $o2c = "i2wvkxre5v" ascii
        $o2d = "axkjeepxzx" ascii
        $o2e = "va4u4ydm2q" ascii
        $o2f = "ead.onion/" ascii

        // C2 #3 - additional fragments observed in module B
        $o3a = "yxoedle2gd" ascii
        $o3b = "1988hhzEeH" ascii
        $o3c = "12Qntcik" ascii

    condition:
        2 of them
}


rule XORTOR_Screenshot_Exfil
{
    meta:
        description = "Hidden PowerShell screen capture routine used for exfiltration"
        author      = "Mustafa Emre"
        date        = "2026-07-18"
        reference   = "448776210b0c1802fd3e5da66813e90e7469bcd365d64e11b2a992547bc2fd4a"
        confidence  = "medium"
        note        = "Fragmented across the obfuscator array; matches on decrypted content or on the reconstructed command line."

    strings:
        $ps1 = "Add-Type -" ascii
        $ps2 = "Windows.Fo" ascii
        $ps3 = "stemInform" ascii
        $ps4 = "awing.Bitm" ascii
        $ps5 = "$g.ScaleTr" ascii
        $ps6 = "$bmp.Save(" ascii
        $ps7 = "g.Imaging." ascii
        $ps8 = "dowStyle H" ascii          // -WindowStyle Hidden

        $art = "screenshot" ascii

    condition:
        4 of ($ps*)
        or ($art and 2 of ($ps*))
}


rule XORTOR_XORed_PE_KeyAgnostic
{
    meta:
        description = "12-byte XOR encrypted PE payload - key independent"
        author      = "Mustafa Emre"
        date        = "2026-07-22"
        reference   = "149ab46739ca442762502a69f0960365a7c5e7761c76f2e6c2997bd43744a62a"
        confidence  = "high"
        note        = "Plaintext PE header is MZ followed by NUL padding. With a 12-byte key, ciphertext bytes 12-15 encrypt NULs and therefore equal the key itself. XORing them against bytes 0-3 recovers the plaintext header regardless of key value. Survives key rotation; verified against two builds with different keys."

    condition:
        filesize > 100KB
        and uint16(0) != 0x5A4D          // not already a plaintext PE
        and uint8(0) ^ uint8(12) == 0x4D
        and uint8(1) ^ uint8(13) == 0x5A
        and uint8(2) ^ uint8(14) == 0x78
        and uint8(3) ^ uint8(15) == 0x00
}
