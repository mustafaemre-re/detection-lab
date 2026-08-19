# YARA rules

One `.yar` file per family, named after the report it comes from.

## Naming

`FAMILY_Target_Scope` — e.g. `POLYDROP_Crypter_Structure`,
`XORTOR_JS_Modules_Decrypted`.

## Required meta

| Field | Purpose |
|---|---|
| `description` | What it detects |
| `author`, `date` | Provenance |
| `reference` | Path to the report in `analysis/` |
| `hash` | Sample the rule was built from |
| `scope` | On-disk, memory, or post-decryption |
| `limitation` | What defeats it |

`limitation` is mandatory. A rule without a stated blind spot cannot be
reasoned about.

Add `tested` when a false-positive run has been done, with the corpus size.
Add `status = "deprecated"` and `superseded_by` rather than deleting a rule.

## Before committing

CI (`.github/workflows/validate-rules.yml`) enforces:

- every rule compiles
- no rule matches this repository's own files
- no rule matches a clean Windows PE corpus
- every rule references a report

The second check exists because rules here once matched their own `.yar` file
and their own report, which would alert on any TI feed quoting the IOCs.
