# sysmon-parser

A small Python tool that extracts key fields from Sysmon **Event ID 1 (Process Creation)** XML events and prints them as JSON.

## Requirements

- Python 3 (stdlib only — no dependencies to install)

## Usage

```
python parser.py <path-to-sysmon-xml> [--image SUBSTRING] [--user USER] [--integrity-level {High,Medium,Low,System}]
```

If a single event matches, the output is a JSON object. If multiple events match, the output is a JSON array. If none match, the output is `[]`.

### Examples

Extract every Event ID 1 record from a file:

```
python parser.py samples/event1.xml
```

Only processes whose path contains "powershell" (case-insensitive substring match):

```
python parser.py samples/multi_events.xml --image powershell
```

Only events for a specific user (case-insensitive exact match):

```
python parser.py samples/multi_events.xml --user "CONDEF\pwhite"
```

Only High-integrity processes:

```
python parser.py samples/event1.xml --integrity-level High
```

Filters combine with AND — this returns only events matching *both* conditions:

```
python parser.py samples/multi_events.xml --user "CONDEF\pwhite" --image ping
```

## Output fields

Each event object always has these 10 keys. A field not present in the source XML (e.g. `Hashes` when Sysmon's `HashAlgorithms` config excludes it) is `null` rather than omitted, so every event has the same shape:

| Field | Description |
|---|---|
| `EventID` | Always `1` |
| `UtcTime` | Event timestamp |
| `Image` | Process path |
| `CommandLine` | Full command line |
| `User` | User the process ran as |
| `IntegrityLevel` | `High`, `Medium`, `Low`, or `System` |
| `ParentImage` | Parent process path |
| `ParentCommandLine` | Parent's command line |
| `Computer` | Hostname |
| `Hashes` | File hash string (e.g. `SHA1=...,MD5=...,SHA256=...,IMPHASH=...`) |

## How it works

`parser.py` parses the input with `xml.etree.ElementTree`. It accepts two XML shapes:

- A single `<Event>` root (a lone Sysmon event export).
- A synthetic `<Events>` root wrapping multiple `<Event>` children (used for multi-event files — see `samples/multi_events.xml`).

For each `<Event>`, it reads `EventID` and `Computer` from `<System>`, skips any event where `EventID != 1`, then builds the output fields from the `Name`/text pairs under `<EventData><Data Name="...">`. Filters (`--image`, `--user`, `--integrity-level`) are applied afterward as a post-processing step over the already-extracted events.

## Sample data

`samples/` contains 7 realistic example files for testing:

- `event1.xml` – `whoami.exe /groups` (System Owner Discovery)
- `event2.xml` – `powershell.exe` with a base64-encoded command
- `event3.xml` – `rundll32.exe` LOLBin usage
- `event4.xml` – benign `notepad.exe` launch
- `event5.xml` – missing `Hashes` field (edge case)
- `event6.xml` – SYSTEM process, missing `ParentCommandLine` (edge case)
- `multi_events.xml` – 3 events in one file, exercises the array-output path
