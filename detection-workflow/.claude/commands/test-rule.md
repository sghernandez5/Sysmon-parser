---
description: Test a Sigma (.yml/.yaml) or YARA (.yar/.yara) detection rule. Sigma rules are scanned against a target EVTX via Hayabusa; YARA rules are scanned against the tests/yara/positive and tests/yara/negative fixtures.
argument-hint: <rule-file-path> [target-evtx-path]
allowed-tools: Bash, Read, Glob
---

## Inputs

- `$1` — path to a rule file. Required. Extension picks the engine:
  `.yml`/`.yaml` → Sigma (tested via Hayabusa), `.yar`/`.yara` → YARA
  (tested via `yara-x`/`yr` against `tests/yara/`).
- `$2` — **Sigma rules only**: path to the target `.evtx` file to scan.
  Optional, defaults to `../mcp-hayabusa/samples/discovery_bloodhound.evtx`.
  Ignored for YARA rules.

If `$1` is missing or does not exist, stop and tell the user how to invoke
the command.

## Steps — Sigma rules (`.yml` / `.yaml`)

1. Read the rule file. Sanity-check it looks like Sigma YAML (has `title`,
   `logsource`, `detection` keys) — if not, stop and say so.
2. Locate the Hayabusa binary under `../mcp-hayabusa/hayabusa/`
   (`hayabusa.exe` on Windows, `hayabusa` elsewhere; releases ship
   version-qualified names like `hayabusa-3.10.0-win-x64.exe`, so glob for
   it). If none is found, stop and tell the user to run
   `python download_hayabusa.py` inside `mcp-hayabusa/` first — do not
   attempt to download it yourself.
3. Determine the target EVTX: `$2` if given, else
   `../mcp-hayabusa/samples/discovery_bloodhound.evtx`. If it doesn't
   exist, stop and report.
4. Create a temp directory and copy just this one rule file into it, so the
   scan is scoped to the rule under test rather than all ~5000 bundled
   rules.
5. Run, with the Hayabusa binary's own directory as `cwd` (it resolves
   `config/` relative to itself, matching `mcp-hayabusa/server.py`'s
   convention):
   ```
   <hayabusa-binary> json-timeline -r <temp-rules-dir> -f <target-evtx> -o <temp-output>.jsonl -L -b -w -C -Q
   ```
6. Read the resulting JSONL. Each line is one finding. Report how many
   times the rule fired, and for each finding show timestamp, computer, and
   key fields. Zero findings is a valid, useful result (the rule didn't
   fire) — report it plainly, not as an error.
7. Pull the rule's own `tags:` (Sigma's `attack.txxxx` convention) from the
   YAML and report which ATT&CK technique(s) it represents.
8. Clean up the temp directory and temp output file.

## Steps — YARA rules (`.yar` / `.yara`)

1. Verify `yara-x` or `yr` is on PATH. If neither is found, stop and tell
   the user to install YARA-X (`cargo install yara-x`, or their platform
   package manager) — do not attempt to install it yourself.
2. Find the `detection-workflow/` project root by walking up from the rule
   file, then confirm `tests/yara/positive/` and `tests/yara/negative/`
   exist there. If both are empty, stop and tell the user there's nothing
   to test against.
3. Run the YARA-X CLI against each fixture file individually (e.g.
   `yr scan <rule-file> <fixture-file>`), recording match/no-match per
   file.
4. Score each fixture: a `tests/yara/positive/*` file **passes** if the
   rule matched it; a `tests/yara/negative/*` file **passes** if the rule
   did **not** match it.

## Reporting

Report back: which engine ran, what it was tested against, and the
outcome — for Sigma, finding count + ATT&CK techniques; for YARA, pass/fail
per fixture plus an overall count. This command produces a validation
report for the user, not a saved artifact — unlike `/query`, it does not
write to `siem-queries/investigations/` or anywhere else.
