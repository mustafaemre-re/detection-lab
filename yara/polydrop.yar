/*
    POLYDROP - Detection ruleset
    Report: analysis/polydrop.md
    Author: Mustafa Emre
    Date:   2026-08-19

    Two rules, both tested (see analysis/polydrop.md section 7.4):

      POLYDROP_Crypter_Structure   - the packer's structural shape. No strings,
                                     no section names, no key material. Should
                                     survive rebuilds. May match other malware
                                     using the same crypter - intentional.
      POLYDROP_Import_Fingerprint  - the exact six-import camouflage set, plus
                                     the absence of the APIs a packer needs.

    DERIVED FROM ONE SAMPLE. The section names (.*B{, .i:6, .hT:) look
    randomised but this was NOT confirmed across builds. No rule keys on them,
    so that open question does not affect either rule.

    A memory-scan rule for the unpacked implant is deliberately NOT shipped -
    it could not be tested after the analysis VM was reverted. The artefacts it
    would use are documented in section 7.1 of the report.
*/

import "pe"
import "math"


rule POLYDROP_Crypter_Structure
{
    meta:
        description  = "Packer structure: four or more sections declared but empty on disk, one high-entropy section carrying the whole file"
        author       = "Mustafa Emre"
        date         = "2026-08-19"
        reference    = "analysis/polydrop.md"
        hash         = "14bb4c85a5412e44fff51890c095c15d285bcfe83e320ca202121ce66911a0d3"
        scope        = "On-disk, packed state"
        confidence   = "high"
        tested       = "1 hit in 6977 PE files (incl. 1464 Wine PE64 binaries); only hit was the sample"
        note         = "Keys on shape, not content. A section with VirtualSize > 0 and SizeOfRawData == 0 is an empty container the stub unpacks into at runtime. Four of them plus one section holding >90% of the file at entropy >7.8 is the crypter's signature."
        limitation   = "Family-level, not campaign-level: matches the crypter, so it will fire on unrelated malware packed with the same tool. That is intended, but means a hit identifies the packer, not this implant."

    condition:
        uint16(0) == 0x5A4D and
        pe.is_pe and
        pe.machine == pe.MACHINE_AMD64 and
        filesize > 500KB and filesize < 20MB and

        // four or more sections declared in memory but absent from disk
        for 4 i in (0 .. pe.number_of_sections - 1) : (
            pe.sections[i].virtual_size > 0 and
            pe.sections[i].raw_data_size == 0
        ) and

        // and one section holding >90% of the file at near-maximum entropy.
        // written as multiplication: '/' begins a regex in YARA's lexer and
        // silently swallows the rest of the file.
        for 1 j in (0 .. pe.number_of_sections - 1) : (
            pe.sections[j].raw_data_size * 100 > filesize * 90 and
            math.entropy(pe.sections[j].raw_data_offset,
                         pe.sections[j].raw_data_size) > 7.8
        )
}


rule POLYDROP_Import_Fingerprint
{
    meta:
        description  = "Exact camouflage import set - six functions across six DLLs, with none of the APIs a packer requires"
        author       = "Mustafa Emre"
        date         = "2026-08-19"
        reference    = "analysis/polydrop.md"
        hash         = "14bb4c85a5412e44fff51890c095c15d285bcfe83e320ca202121ce66911a0d3"
        scope        = "On-disk, packed state"
        confidence   = "high"
        tested       = "1 hit in 6977 PE files (incl. 1464 Wine PE64 binaries); only hit was the sample"
        note         = "Six benign-looking functions, one per DLL, sized to avoid an empty import table without revealing intent. The negative clauses carry as much weight as the positive ones: a binary that unpacks itself must call GetProcAddress, VirtualAlloc and VirtualProtect, so their absence from the import table means runtime resolution."
        limitation   = "Dies if the crypter rotates its camouflage set. Only one sample was observed, so whether it rotates is unknown."

    condition:
        uint16(0) == 0x5A4D and
        pe.is_pe and
        pe.number_of_imported_functions <= 12 and

        pe.imports("KERNEL32.dll", "GetWindowsDirectoryW") and
        pe.imports("USER32.dll",   "PostQuitMessage") and
        pe.imports("SHELL32.dll",  "SHGetFolderPathW") and
        pe.imports("GDI32.dll",    "GetObjectW") and
        pe.imports("VERSION.dll",  "GetFileVersionInfoSizeW") and
        pe.imports("SHLWAPI.dll",  "PathAppendW") and

        not pe.imports("KERNEL32.dll", "GetProcAddress") and
        not pe.imports("KERNEL32.dll", "VirtualAlloc") and
        not pe.imports("KERNEL32.dll", "VirtualProtect")
}
