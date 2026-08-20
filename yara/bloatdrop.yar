/*
    BLOATDROP - Detection ruleset
    Report: analysis/bloatdrop.md
    Author: Mustafa Emre
    Date:   2026-08-21

    THREE RULES, NONE FALSE-POSITIVE TESTED. See analysis/bloatdrop.md section
    7.6. The sample and the clean corpus live inside the analysis VMs and were
    not reachable from the host when these were written. Treat every rule here
    as a hypothesis until it has been run against a corpus.

      BLOATDROP_Padded_Go_Loader  - ON DISK. Structural: a Go PE64 whose overlay
                                    is an exact multiple of 1 MiB, occupies more
                                    than 90% of the file, and is uniform random.
                                    No campaign strings, so it should survive
                                    rebuilds - but see the limitation below.

      BLOATDROP_Runtime_Config    - MEMORY DUMPS ONLY. The C2 configuration is
                                    encrypted on disk (section 3.1) and exists in
                                    plaintext only after runtime decryption.

      BLOATDROP_Sandbox_Gate      - MEMORY DUMPS ONLY. The scored evasion suite's
                                    own log labels (section 3.5).

    WHY THE ON-DISK RULE IS FRAGILE: it keys on the padding being exactly
    88,080,384 bytes / a round mebibyte. That is a build-script artefact. One
    line changed by the actor - pad to a random length - defeats it completely.
    Shipped because it costs nothing and works today, not because it will last.

    WHY THE TWO MEMORY RULES MAY NOT WORK AT ALL: whether any of these strings
    also exist in plaintext in the file on disk was NOT tested. They are written
    against console output observed at runtime, not against a disassembly of the
    format strings that produced it, so the exact string boundaries are inferred.
    If the loader builds these messages with printf-style formatting, the
    literals in the binary will be shorter than the lines below and some atoms
    will never match.

    NOT SHIPPED, deliberately (report section 7.5): no rule on the Go module
    path yNjFRWkjrSgSHsEYcCU (randomised per build), none on 62.238.107.2 (one
    IP in a design built to survive losing it), and no dependency-intersection
    rule (the loader has no third-party dependencies).
*/

import "pe"
import "math"


rule BLOATDROP_Padded_Go_Loader
{
    meta:
        description  = "Go PE64 padded with an exact multiple of 1 MiB of uniform random overlay data - binary padding for size-based scanner evasion"
        author       = "Mustafa Emre"
        date         = "2026-08-21"
        reference    = "analysis/bloatdrop.md"
        hash         = "c9082f765b9d6580d20d56814b1edca52502b754e3553fae7387584f3c32d37c"
        scope        = "On-disk"
        confidence   = "medium"
        tested       = "NO - not compiled against a corpus, not FP-tested"
        attack       = "T1027.001"
        note         = "The discriminator is exactness. Legitimate Go self-extracting installers also carry large high-entropy overlays, but a compressed archive appended to a stub does not land on a round mebibyte. 88,080,384 = 84 * 1,048,576 exactly."
        limitation   = "Fragile by construction - a randomised pad length defeats it. Also matches the console-subsystem copy produced during analysis, since the subsystem patch does not touch the overlay."

    strings:
        // Go buildinfo magic: "\xff Go buildinf:" - survives -trimpath
        $go_buildinf = { FF 20 47 6F 20 62 75 69 6C 64 69 6E 66 3A }
        $go_symtab   = ".symtab"

    condition:
        uint16(0) == 0x5A4D and
        pe.is_pe and
        pe.machine == pe.MACHINE_AMD64 and

        // the padding puts every build of this loader well above 50 MB
        filesize > 50MB and

        // Go toolchain. The toolchain VERSION is deliberately not required:
        // the sample is go1.25.4, but pinning that would make the rule stale
        // at the actor's next toolchain bump, and the detection value here is
        // the overlay geometry, not the compiler build.
        $go_buildinf and $go_symtab and

        pe.overlay.size > 0 and

        // exactly a whole number of mebibytes - the build-script artefact
        pe.overlay.size % 1048576 == 0 and

        // and the overlay is the overwhelming majority of the file.
        // written as multiplication: '/' begins a regex in YARA's lexer and
        // silently swallows the rest of the file.
        pe.overlay.size * 100 > filesize * 90 and

        // uniform random, not a compressed container. Sampled over the first
        // mebibyte only - hashing 84 MB per candidate file is not worth it.
        math.entropy(pe.overlay.offset, 1048576) > 7.99
}


rule BLOATDROP_Runtime_Config
{
    meta:
        description  = "BLOATDROP decrypted C2 configuration: codeword-keyed social-media dead drops, primary IP, operator handle"
        author       = "Mustafa Emre"
        date         = "2026-08-21"
        reference    = "analysis/bloatdrop.md"
        hash         = "c9082f765b9d6580d20d56814b1edca52502b754e3553fae7387584f3c32d37c"
        scope        = "Memory dumps only - NOT files at rest"
        confidence   = "medium"
        tested       = "NO - not compiled against a corpus, not FP-tested"
        attack       = "T1102.001"
        note         = "Campaign-level, not family-level. Every atom here is operator-controlled: the profiles, the handle m1duus and the codeword x4tte can all be changed without rebuilding the loader. Expect this rule to go stale."
        limitation   = "The codeword x4tte is 5 characters and is never sufficient alone - it is scored, not required. The mutex string is taken from third-party sandbox reporting (report section 11.2), not from first-hand observation."

    strings:
        // dead-drop resolver targets - observed first-hand (report section 3.6)
        $u1 = "telegram.me/m1duus" ascii wide
        $u2 = "pinterest.com/m1duus" ascii wide
        $u3 = "steamcommunity.com/profiles/76561198657426610" ascii wide

        // hardcoded primary C2 and operator handle
        $c1 = "62.238.107.2" ascii wide
        $c2 = "m1duus" ascii wide

        // codeword marking the C2 record in dead-drop page text
        $c3 = "x4tte" ascii wide

        // mutex - VirusTotal-reported, see report section 11.2
        $m1 = "Glasikprostik" ascii wide

        // resolver log lines
        $l1 = "Dead drop" ascii
        $l2 = "C2 unavailable" ascii
        $l3 = "Connect failed" ascii

        // Russian developer string: "Кодовое слово" (UTF-8)
        $r1 = { D0 9A D0 BE D0 B4 D0 BE D0 B2 D0 BE D0 B5 20 D1 81 D0 BB D0 BE D0 B2 D0 BE }

    condition:
        // floor keeps the rule off this .yar file and off small text artefacts;
        // any process memory dump clears it comfortably
        filesize > 1MB and
        (
            // two distinct dead-drop URLs
            2 of ($u*) or

            // one dead-drop URL plus an independent artefact. $c2 is excluded
            // from this set on purpose: "m1duus" is a substring of $u1 and $u2,
            // so including it would collapse the clause to "1 of ($u*)".
            (1 of ($u*) and 1 of ($c1, $c3, $m1, $r1)) or

            // operator handle together with the codeword, without a full URL
            ($c2 and $c3) or

            // the mutex plus the Russian string - both non-dictionary
            ($m1 and $r1) or

            // the resolver's own log vocabulary in full, plus one hard artefact
            (all of ($l*) and 1 of ($c1, $c3, $m1))
        )
}


rule BLOATDROP_Sandbox_Gate
{
    meta:
        description  = "BLOATDROP scored sandbox-evasion suite: check labels emitted by the loader's own verbose logging"
        author       = "Mustafa Emre"
        date         = "2026-08-21"
        reference    = "analysis/bloatdrop.md"
        hash         = "c9082f765b9d6580d20d56814b1edca52502b754e3553fae7387584f3c32d37c"
        scope        = "Memory dumps only - NOT files at rest"
        confidence   = "low"
        tested       = "NO - not compiled against a corpus, not FP-tested"
        attack       = "T1497.001, T1497.003, T1622"
        note         = "The gate needs 8 of 13 checks to pass, so it is deliberately tolerant of a single tell (report section 3.5). These labels are the loader's own, not a public library's."
        limitation   = "Lowest-confidence rule in this file. Individual tokens such as peb_flags and av_sandbox appear in legitimate anti-analysis research tooling, sandbox-detection test harnesses and security blog corpora. Four are required precisely because no two are meaningful together. Verify a hit against the C2 artefacts in BLOATDROP_Runtime_Config before acting on it."

    strings:
        $g1 = "Sandbox Check" ascii
        $g2 = "peb_flags" ascii
        $g3 = "av_sandbox" ascii
        $g4 = "sb: score" ascii
        $g5 = "sb: uptime" ascii
        $g6 = "sb: rdtsc" ascii
        $g7 = "sb: debugger" ascii
        $g8 = "sb: modules" ascii

    condition:
        filesize > 1MB and
        4 of ($g*)
}
