# mcp-hayabusa

An MCP (Model Context Protocol) server that wraps [Hayabusa](https://github.com/Yamato-Security/hayabusa) for EVTX (Windows Event Log) analysis, so an MCP client (Claude Code, Claude Desktop, etc.) can scan event logs and browse detection rules directly.

## Setup

```
pip install -r requirements.txt
py download_hayabusa.py
```

`download_hayabusa.py` fetches the latest Hayabusa release for your platform (Windows/Linux/macOS, x64/ARM64) and extracts it into `./hayabusa/`. This step is required before either tool below will work — the binary and rule set aren't committed to this repo (see [Why `hayabusa/` isn't committed](#why-hayabusa-isnt-committed)).

## Tools

### `scan_evtx`

Scans an EVTX file with Hayabusa and returns structured findings.

| Parameter | Default | Description |
|---|---|---|
| `path` | required | Path to the `.evtx` file to scan |
| `min_severity` | `None` | Minimum level to include: `informational`, `low`, `medium`, `high`, `critical` |
| `rule_filter` | `None` | Case-insensitive substring match against each finding's rule title (e.g. `"lateral"`, `"mimikatz"`) |
| `output_format` | `"summary"` | `"summary"` returns a condensed set of fields; `"full"` returns everything Hayabusa produced, including `Details`/`ExtraFieldInfo` |
| `max_results` | `50` | Caps the number of findings returned. `total_findings` in the response always reports the full post-filter count; `truncated: true` is added when the cap cuts results. Pass `None` for no cap |

Real-world logs are dominated by routine low/informational noise (a single live Security log export produced 12,000+ findings), so narrowing with `min_severity` or `rule_filter` is usually more useful than an unfiltered scan.

### `get_hayabusa_rules`

Lists available Hayabusa/Sigma detection rules, optionally filtered by keyword — useful for seeing what a rule title actually means before passing it to `scan_evtx`'s `rule_filter`.

| Parameter | Default | Description |
|---|---|---|
| `keyword` | `None` | Case-insensitive substring match against each rule's title, description, tags, and id. Omit to list all ~5000 rules |
| `max_results` | `50` | Same capping behavior as `scan_evtx` |

## Using it from an MCP client

**Claude Code**: nothing to configure — launching `claude` from this directory auto-discovers `.mcp.json` and connects.

**Claude Desktop**: this is a separate application with no project-folder concept, so it needs the server registered in its own config, using **absolute paths** (Desktop launches the process without your shell's PATH or working directory):

```json
{
  "mcpServers": {
    "hayabusa": {
      "command": "C:\\path\\to\\python.exe",
      "args": ["C:\\path\\to\\mcp-hayabusa\\server.py"]
    }
  }
}
```

(Some Desktop builds also offer a "Claude Code" mode alongside the chat interface — that mode behaves like the CLI above and auto-discovers `.mcp.json` if you open this folder directly, no config editing needed.)

## Sample data

`samples/discovery_bloodhound.evtx` is a small fixture with one finding (`Log Cleared`, EventID 1102) used by `test_server.py`.

If you generate your own local sample from a real machine (e.g. `wevtutil epl Security samples/security_live.evtx` from an elevated shell), be aware it will contain that machine's real hostname, usernames, and SIDs — such files are gitignored by name and should never be committed or shared.

## Why `hayabusa/` isn't committed

`download_hayabusa.py` extracts the binary plus `config/` and `rules/` into `./hayabusa/` (~70MB). `hayabusa/rules/` is itself a separate git checkout with its own `.git/`, which can't be cleanly added as a regular subdirectory of this repo. Run `download_hayabusa.py` once per machine instead.
