# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A single-file Python CLI (`parser.py`, stdlib only) that extracts Sysmon **Event ID 1 (Process Creation)** fields from an XML file and prints JSON. See `README.md` for usage examples and the full field list.

## Commands

```
python parser.py <path-to-sysmon-xml> [--image SUBSTRING] [--user USER] [--integrity-level {High,Medium,Low,System}] [--format {json,jsonl,csv}] [--stats]
```

There is no test suite or build step — verify changes by running `parser.py` against the files in `samples/` and checking the JSON output (see `README.md`'s Sample data section for what each file covers, including two files with intentionally missing fields and one multi-event file).

## Architecture

`parser.py` has five parts:

- `parse_event(event_elem)` — takes one `<Event>` XML element, returns a flat dict with exactly 10 keys (`EventID`, `UtcTime`, `Image`, `CommandLine`, `User`, `IntegrityLevel`, `ParentImage`, `ParentCommandLine`, `Computer`, `Hashes`), or `None` if the event isn't `EventID == 1`. Field values come from `<EventData><Data Name="...">` children; a name/value dict is built first so lookups are `.get()`-based and missing fields become `None` (JSON `null`) rather than raising or being omitted — every event dict always has the same 10 keys.
- `parse_file(path)` — handles two possible XML root shapes: a lone `<Event>` root, or a synthetic `<Events>` root wrapping multiple `<Event>` children (this repo's convention for multi-event sample files — real Windows Event Log exports don't use this wrapper, so if real multi-event exports are ever fed in, this is the place to add support for their actual format). Returns a list of parsed event dicts.
- `matches_filters(event, args)` — post-processing filter step applied *after* parsing/extraction, not during. `--image` is case-insensitive substring, `--user` is case-insensitive exact match, `--integrity-level` is exact match (validated against the 4 known Sysmon values via argparse `choices`). Multiple filters combine with AND.
- `build_stats(events)` — computes `total_events`, unique `Image`/`User` values (sorted, deduplicated, `None` excluded), and an `IntegrityLevel` → count breakdown, over the already-filtered event list.
  # This stats feature is for quick triage to understand what's in a file before deep analysis
- `print_events(events, fmt)` — the output stage for the three `--format` values. `json` keeps the collapse behavior below; `jsonl` prints one `json.dumps(e)` per line with no collapsing; `csv` uses the stdlib `csv` module with `lineterminator="\n"` (needed to avoid doubled CRLFs from stacking with Windows text-mode stdout translation) and `FIELD_ORDER` as the single source of truth for column order, rendering `None` as `""`.

Output shape: for `--format json` (the default), `print_events` prints a single JSON object if exactly one event survives parsing+filtering, otherwise a JSON array (including `[]` for zero matches) — this collapsing is specific to `json` and does not apply to `jsonl`/`csv`, which always emit one line/row per event. `--stats`, when passed, bypasses `print_events` entirely and prints its own JSON summary instead, taking priority over `--format` if both are given.

All Sysmon XML elements live under the namespace `http://schemas.microsoft.com/win/2004/08/events/event` (the `NS` constant) — `ElementTree` calls need the `{NS}Tag` prefix or lookups silently return nothing.

## Sample data

`samples/*.xml` are hand-written realistic fixtures (not real Sysmon output) used for manual verification — see `README.md` for what each one covers. When adding new sample files, keep GUIDs/timestamps/hashes distinct from existing ones and follow the existing `<Event xmlns="...">...</Event>` shape (or wrap several in `<Events>` for multi-event cases, matching `multi_events.xml`).
