# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

An MCP (Model Context Protocol) server (`server.py`, stdlib + `mcp` + `pyyaml`) that wraps the Hayabusa CLI for EVTX (Windows Event Log) analysis. It shells out to a locally installed Hayabusa binary rather than reimplementing its detection logic. See `README.md` for setup and usage.

## Commands

```
pip install -r requirements.txt
python download_hayabusa.py  # fetches the latest Hayabusa release for this platform into ./hayabusa/
python server.py             # run the MCP server directly (normally launched by an MCP client via .mcp.json)
python test_server.py        # manual smoke test — imports server.py and calls both tools directly against samples/
```

There is no automated test suite — verify changes with `test_server.py` against `samples/discovery_bloodhound.evtx`.

## Architecture

`server.py` exposes two MCP tools:

- `scan_evtx(path, min_severity=None, rule_filter=None, output_format="summary", max_results=50)` — runs `hayabusa json-timeline` against the given `.evtx` file and returns parsed findings. `min_severity` filters by the 5 known Hayabusa levels (`informational`/`low`/`medium`/`high`/`critical`, ordered least-to-most severe); `rule_filter` is a case-insensitive substring match against each finding's `RuleTitle`; `output_format` controls whether findings keep only `SUMMARY_FIELDS` (`summary`, the default) or every field Hayabusa produced including `Details`/`ExtraFieldInfo` (`full`); `max_results` caps the returned list while `total_findings` always reports the full post-filter count, with `truncated: true` added when the cap actually cuts results. **Both filters and the cap are applied after Hayabusa runs**, not passed to the CLI itself. The default cap of 50 exists because real-world EVTX exports routinely produce thousands of low-severity findings (a single Security log export produced 12k+) that would blow past MCP output limits if returned unbounded — don't remove the default without a different way to bound output size.
- `get_hayabusa_rules(keyword=None, max_results=50)` — parses the YAML rule files under `hayabusa/rules/**/*.yml` (both `hayabusa/rules/hayabusa/` and `hayabusa/rules/sigma/`; the `config/` subdirectory holds non-rule `.yaml`/`.txt` files and is skipped implicitly since it has no `.yml` files) and returns per-rule summaries (`id`, `title`, `level`, `status`, `description`, `tags`, `product`, `service`). `keyword` matches case-insensitively against title/description/tags/id. Same `max_results`/`truncated` pattern as `scan_evtx`, for the same reason — there are ~5000 rule files, and a broad or absent keyword can match hundreds of them.

Both tools share the truncation pattern deliberately: report the true total, cap what's returned, flag when truncation happened. Keep new tools consistent with this if they can return unbounded-length results.

`find_hayabusa_binary()` looks for `hayabusa.exe`/`hayabusa` in `./hayabusa/`, falling back to a glob for version-qualified names (release zips ship e.g. `hayabusa-3.10.0-win-aarch64.exe`, not a stable `hayabusa.exe`).

## Dependencies (not committed)

`./hayabusa/` (the binary + `config/` + `rules/`) is fetched by `download_hayabusa.py` from the latest GitHub release and is gitignored — it's ~70MB and `hayabusa/rules/` is itself a separate git checkout (nested `.git/`), so it can't be added to this repo cleanly anyway. Anyone working on this project needs to run `download_hayabusa.py` once before `server.py` will find a binary to invoke.

## Sample data

`samples/discovery_bloodhound.evtx` is a small hand-obtained fixture with one real Hayabusa finding (`Log Cleared`, EventID 1102) — used by `test_server.py` and safe to commit. Do **not** add real Windows Event Log exports from a live machine to `samples/` or commit them — they contain that machine's actual hostname/usernames/SIDs. `samples/security_live.evtx` is gitignored for this reason if you generate one locally for testing (e.g. via `wevtutil epl Security samples/security_live.evtx` from an elevated shell).

## Client configuration

- **Claude Code**: auto-discovers `.mcp.json` in this directory (`command: "python"`) — no manual setup needed when working in this folder. Keep `.mcp.json`'s command as a bare `python`/`py`, not an absolute interpreter path — an absolute path is specific to one contributor's machine and breaks for everyone else. Which bare command is reliable depends on how Python is installed on the machine, and that has flipped once already: with the classic installer, `python` could resolve to a dead Microsoft Store execution-alias stub while the `py` launcher reliably found the real interpreter via the registry; with the newer Python Installation Manager (`PythonSoftwareFoundation.PythonManager`), it's the reverse — `python` resolves correctly but `py.exe` only ships inside a versioned package folder that isn't exposed on PATH, so `py` fails outright (MCP client reports this as a generic reconnect error, e.g. `-32000`, since the server process can't even spawn). If the server won't launch, check `Get-Command py`/`Get-Command python` in a fresh shell to see which one actually resolves on that machine before assuming the config is stale.
- **Claude Desktop**: a separate app with no project-folder concept, so it needs its own server registration (its "Claude Code" mode auto-discovers `.mcp.json` like Claude Code does; its chat mode needs the server added to Desktop's own local config, using **absolute paths** for both the interpreter and `server.py`, since that config is machine-specific and never committed to this repo).
