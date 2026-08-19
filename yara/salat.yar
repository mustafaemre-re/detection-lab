/*
    SALAT — Go-based multi-vector infostealer
    Report: analysis/salat.md
    Author: Mustafa Emre
    Date:   2026-08-07

    Three independent rules. A change that defeats one should not defeat the
    others:
      - a module rename kills SALAT_Go_Module_Path but not the dependency rule
      - a dependency swap kills SALAT_Dependency_Fingerprint but not the module rule
      - a recompile kills only SALAT_Build_1fce06ba

    ALL THREE read cleartext Go metadata. Building with -ldflags="-s -w" or
    -buildvcs=false, or applying any packer, defeats all three at once. That is
    one compiler flag. The durable detections for this family are behavioural
    and are documented in analysis/salat.md section 7.2 — do not rely on these
    rules alone.
*/

// Validated by .github/workflows/validate-rules.yml on every push.
import "pe"


rule SALAT_Go_Module_Path
{
    meta:
        description  = "SALAT infostealer - author's Go module path and first-party package symbols"
        author       = "Mustafa Emre"
        date         = "2026-08-07"
        reference    = "analysis/salat.md"
        hash         = "1fce06baa55f455053a1d5094513a1d509d14cc0270241d329d287feb9a66820"
        scope        = "On-disk, unstripped Go builds"
        note         = "Keys on the author's own module name and package paths, preserved in the Go symbol table. Exact while it holds; a one-line go.mod rename defeats it."
        limitation   = "Defeated by module rename, or by -ldflags='-s -w' which strips the symbol table"

    strings:
        // Go buildinfo module declaration: "path\tsalat\n"
        $path     = "path\tsalat" ascii

        // First-party source file paths from the symbol table
        $src1     = "salat/main.go" ascii
        $src2     = "salat/init.go" ascii
        $src3     = "salat/funcs.go" ascii
        $src4     = "salat/sets.go" ascii
        $src5     = "salat/task.go" ascii
        $src6     = "salat/tsc.go" ascii
        $src7     = "salat/screenshot/screenshot.go" ascii

        // First-party screenshot package symbols
        $fn1      = "salat/screenshot.Capture" ascii
        $fn2      = "salat/screenshot.CaptureRect" ascii
        $fn3      = "salat/screenshot.GetDisplayBounds" ascii
        $fn4      = "salat/screenshot.enumDisplayMonitors" ascii
        $fn5      = "salat/screenshot.getMonitorRealSize" ascii

        // Go toolchain marker - required so this cannot match a text file or
        // a report that merely quotes these strings
        $go       = "Go build ID:" ascii

    condition:
        uint16(0) == 0x5A4D and
        pe.is_pe and
        filesize > 2MB and filesize < 60MB and
        $go and
        (
            // module declaration plus corroboration, or several first-party paths
            ($path and 2 of ($src*, $fn*)) or
            (4 of ($src*, $fn*))
        )
}


rule SALAT_Dependency_Fingerprint
{
    meta:
        description  = "SALAT infostealer - improbable Go dependency intersection (TON blockchain + Steam VDF + Scheduled Tasks)"
        author       = "Mustafa Emre"
        date         = "2026-08-07"
        reference    = "analysis/salat.md"
        hash         = "1fce06baa55f455053a1d5094513a1d509d14cc0270241d329d287feb9a66820"
        scope        = "On-disk, Go builds retaining buildinfo"
        note         = "Does NOT detect 'a Go binary'. Requires co-occurrence of TON blockchain transaction primitives, Steam config parsing, and Scheduled Task creation in one file. Each module is individually legitimate; the intersection has no benign use case."
        limitation   = "Degrades if the author drops TON support or swaps the Steam parser. Defeated by -buildvcs=false or -ldflags='-s -w'."

    strings:
        // --- the improbable trio: each individually benign ---
        $ton      = "github.com/xssnick/tonutils-go" ascii     // TON blockchain
        $vdf      = "github.com/andygrunwald/vdf" ascii        // Steam VDF configs
        $task     = "github.com/capnspacehook/taskmaster" ascii // Scheduled Tasks

        // --- supporting capability modules ---
        $sqlite   = "github.com/ncruces/go-sqlite3" ascii      // browser DB reads
        $ws       = "github.com/gorilla/websocket" ascii       // WebSocket C2
        $quic     = "github.com/quic-go/quic-go" ascii         // QUIC/HTTP3 C2
        $resize   = "github.com/nfnt/resize" ascii             // screenshot scaling
        $gow32    = "github.com/rodolfoag/gow32" ascii         // Win32 mutex

        // --- TON transaction primitives (construction, not just file theft) ---
        $tvm1     = "tonutils-go/tvm/cell.BeginCell" ascii
        $tvm2     = "tonutils-go/tvm/cell.FromBOC" ascii

        // --- stealer behaviour corroboration ---
        $sql1     = "SELECT origin_url, action_url, username_value, password_value" ascii
        $sql2     = "encrypted_value,host_key,path,expires_utc FROM cookies" ascii
        $sql3     = "SELECT service,encrypted_token FROM token_service" ascii
        $steam    = "APPDATA\\steam\\local.vdf" ascii

        // --- DoH C2 resolution ---
        $doh1     = "https://1.1.1.1/dns-query?name=" ascii
        $doh2     = "https://cloudflare-dns.com/dns-query?name=" ascii
        $doh3     = "https://dns.google/resolve?name=" ascii

    condition:
        uint16(0) == 0x5A4D and
        pe.is_pe and
        filesize > 2MB and filesize < 60MB and

        // the whole trio is mandatory - this is what makes the rule specific
        $ton and $vdf and $task and

        // plus independent corroboration from two different evidence classes,
        // so a single coincidental dependency list cannot fire this alone
        2 of ($sqlite, $ws, $quic, $resize, $gow32) and
        2 of ($tvm1, $tvm2, $sql1, $sql2, $sql3, $steam, $doh1, $doh2, $doh3)
}


rule SALAT_Build_1fce06ba
{
    meta:
        description  = "SALAT infostealer - exact Go build ID for the 2026-08-07 build"
        author       = "Mustafa Emre"
        date         = "2026-08-07"
        reference    = "analysis/salat.md"
        hash         = "1fce06baa55f455053a1d5094513a1d509d14cc0270241d329d287feb9a66820"
        scope        = "On-disk, this build only"
        note         = "Go build IDs are derived from source and toolchain inputs, so this identifies one specific build. Included for precise retro-hunting across a sample corpus, NOT for production coverage."
        limitation   = "Any recompilation produces a new build ID and defeats this rule. Expected and by design."

    strings:
        $buildid = "u7ZQnN-MtLJqJ81kowNe/gy79eCRypvFeAEuR8kdc/ZOJmiAkHNBnrk61JpF7D/8aAU95CcHUMEg3niAgk9" ascii
        $gover   = "go1.24.0" ascii

    condition:
        uint16(0) == 0x5A4D and
        pe.is_pe and
        all of them
}
