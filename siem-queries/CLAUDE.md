# siem-queries

A SIEM investigation workflow demo: SPL query files go in, an ATT&CK-mapped,
Obsidian-linkable investigation note comes out.

## Layout

```
siem-queries/
├── CLAUDE.md               # this file
├── .claude/commands/query.md   # the /query command implementation
├── queries/                 # SPL query files (input)
│   ├── whoami.spl
│   ├── mimikatz-hunt.spl
│   └── lateral-movement.spl
└── investigations/          # generated investigation notes (output)
```

## Running it

```
/query queries/<file>.spl [timerange]
```

- `<file>.spl` is a plain SPL query body (no leading `search`).
- `timerange` is a Splunk `earliest_time` value (e.g. `-24h`, `-7d`). Defaults to `-24h`.

The command submits the query to Splunk's REST API, polls until the search
job finishes, analyzes the results for suspicious patterns (credential
access, lateral movement, persistence, defense evasion, etc.), maps any
findings to MITRE ATT&CK technique IDs, and writes a dated, Obsidian-formatted
note to `investigations/`. Each note backlinks its ATT&CK techniques
(`[[T1003.001]]`), so opening `investigations/` as an Obsidian vault builds a
growing graph of investigations linked by shared techniques over time.

## Splunk setup

Requires `SPLUNK_HOST` and `SPLUNK_TOKEN` in `.env` (already gitignored) —
`SPLUNK_HOST` is the Splunk management endpoint (REST API port `8089`),
`SPLUNK_TOKEN` is a bearer token created under Settings → Tokens.

No production Splunk instance? Recommended path for practice data:

1. **Splunk Enterprise trial** — 60 days full-featured (installer or
   `docker run -p 8000:8000 -p 8089:8089 splunk/splunk:latest`), then reverts
   to single-user Splunk Free, which is still fine for query practice.
2. **Boss of the SOC (BOTS) datasets** — free, pre-indexed, realistic attack
   data (credential dumping, lateral movement, etc.) matching the kind of
   hunts in `queries/`. Preferred over installing Sysmon on a live/personal
   machine, since Sysmon logs full process command lines and can capture
   real credentials typed on a daily-driver box.

## Query conventions

Queries in `queries/` target `index=sysmon` using standard Sysmon field
names (`EventCode`, `Image`, `ParentImage`, `TargetImage`, `GrantedAccess`,
`CommandLine`). Depending on the actual sourcetype/CIM mapping of whatever
data ends up indexed (e.g. BOTS uses its own sourcetypes), field names in
these queries may need small adjustments before they return results.

## Next steps (pick up here)

No Splunk instance is connected yet — `SPLUNK_HOST`/`SPLUNK_TOKEN` are unset
in both the shell and `.env`. To resume:

1. Start a trial Splunk instance, e.g. via Docker:
   ```
   docker run -p 8000:8000 -p 8089:8089 \
     -e SPLUNK_START_ARGS=--accept-license \
     -e SPLUNK_PASSWORD=<choose-a-password> \
     splunk/splunk:latest
   ```
2. In the Splunk UI: Settings → Tokens → enable token auth → create a token.
3. Fill in `.env`:
   ```
   SPLUNK_HOST=localhost
   SPLUNK_TOKEN=<token from step 2>
   ```
4. Download and index a **Boss of the SOC (BOTS)** dataset so there's
   actual `index=sysmon`-shaped data to search (see "Splunk setup" above).
5. Run `/query queries/mimikatz-hunt.spl` and
   `/query queries/lateral-movement.spl` to generate the first real,
   non-fabricated investigation notes in `investigations/`.
6. Adjust field names in the two hunt queries if BOTS's sourcetype doesn't
   match the Sysmon field names assumed above.
