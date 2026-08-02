# detection-workflow

A Sigma/YARA rule authoring + testing workflow — the detection-engineering
half of this repo's portfolio story, complementing `../siem-queries/`'s
hunt-and-investigate half.

## Layout

```
detection-workflow/
├── CLAUDE.md                    # this file
├── .claude/commands/test-rule.md   # the /test-rule command
├── rules/
│   ├── sigma/
│   │   └── log-cleared-t1070.yml
│   └── yara/
│       └── encoded_powershell_invocation.yar
└── tests/
    └── yara/
        ├── positive/             # fixtures the YARA rule should match
        └── negative/             # fixtures it should not match
```

## Running it

```
/test-rule rules/<file>
```

- Sigma rules (`.yml`/`.yaml`) are scanned against a target `.evtx` via the
  **Hayabusa** binary already used by `../mcp-hayabusa/` (reused rather than
  duplicated — see Prerequisites). Defaults to scanning
  `../mcp-hayabusa/samples/discovery_bloodhound.evtx`, the one safe, real,
  committed EVTX fixture in this repo; pass a second argument to target a
  different file.
- YARA rules (`.yar`/`.yara`) are scanned against every file in
  `tests/yara/positive/` (expected to match) and `tests/yara/negative/`
  (expected not to), reported as pass/fail per fixture.

The command reports a rule-validation result (fired/not fired, pass/fail).
It does not write investigation notes — that's `/query`'s job in
`siem-queries/`, kept deliberately separate: this project validates
detections, that one investigates findings.

## Prerequisites

Neither toolchain is installed by default:

1. **Hayabusa binary** (for Sigma rules) — run `python download_hayabusa.py`
   inside `../mcp-hayabusa/` once. This fetches the Hayabusa binary and its
   bundled Sigma rule set (~70MB, gitignored there) into
   `../mcp-hayabusa/hayabusa/`. `detection-workflow` reuses that binary via
   a relative path rather than downloading its own copy.
2. **YARA-X CLI** (for YARA rules) — `cargo install yara-x`, or your
   platform's package manager. Provides the `yr` (or `yara-x`) command.

## Rule conventions

- **Sigma**: standard Sigma YAML (`title`/`id`/`logsource`/`detection`/
  `tags`), tagged with `attack.txxxx` ATT&CK technique IDs so `/test-rule`
  can surface them. `logsource` should match what Hayabusa expects from a
  Windows EVTX (`product: windows`, plus `service:`/`category:` as
  appropriate).
- **YARA**: written per the `yara-authoring` skill's conventions — behavioral,
  multi-indicator conditions (e.g. requiring an encoded-command flag
  *combined with* a hidden-window/bypass flag) rather than single generic
  strings, to keep false positives low. Every rule needs matching fixtures
  under `tests/yara/positive/` and `tests/yara/negative/` — the negative
  fixtures specifically should include "almost matches" (e.g. only one of
  the required flag categories present) to prove the condition logic, not
  just obviously unrelated text.

## Next steps (pick up here)

Neither the Hayabusa binary nor a YARA-X CLI is installed locally yet, so
nothing here has been run end-to-end. To resume:

1. `cd ../mcp-hayabusa && python download_hayabusa.py`
2. Install YARA-X (`cargo install yara-x`, or platform package manager)
3. `/test-rule rules/sigma/log-cleared-t1070.yml` — should report exactly
   one finding (`Log Cleared`, EventID 1102) against
   `discovery_bloodhound.evtx`, tagged `T1070.001`.
4. `/test-rule rules/yara/encoded_powershell_invocation.yar` — should
   report both `tests/yara/positive/` fixtures matched and all three
   `tests/yara/negative/` fixtures not matched.
5. If either doesn't behave as expected, that's real signal to debug
   (wrong Sigma field name for Hayabusa's parser, YARA condition too
   loose/strict) — not just a checklist to complete.
