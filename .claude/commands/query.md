---
description: Run a SIEM query file against Splunk, analyze results for suspicious activity, map findings to ATT&CK, and save an Obsidian-formatted investigation note.
argument-hint: <query-file-path> [timerange]
allowed-tools: Bash, Read, Write, Glob
---

## Inputs

- `$1` — path to a text file containing the SPL query to run. Required.
- `$2` — Splunk time range for `earliest_time` (e.g. `-24h`, `-7d`, `-1h@h`). Optional, defaults to `-24h`. `latest_time` is always `now`.

If `$1` is missing or does not exist, stop and tell the user how to invoke the command.

## Steps

1. **Read the query.** Use the Read tool to load the file at `$1`. Strip a leading `search ` if the file already has one; you'll add it back when building the request. Note the file's basename — it's used later for the output filename.

2. **Sanity-check the query before running it.** SPL can have side effects beyond returning rows: `outputlookup`, `delete`, `sendemail`, `collect`, `outputcsv` (writes to the Splunk server), `script`/`runshellscript`, or `| map` calling risky subsearches. If any of these appear, stop and confirm with the user before proceeding — this command is meant for read-only investigation, not to silently mutate Splunk state.

3. **Verify credentials are available.** Check that `SPLUNK_HOST` and `SPLUNK_TOKEN` are set in the environment (e.g. `[ -n "$SPLUNK_HOST" ] && [ -n "$SPLUNK_TOKEN" ]`). Never print the token value in any command output, log, or generated file.

4. **Determine the time range.** Use `$2` if provided, otherwise default to `-24h`.

5. **Submit the search job** via Splunk's REST API (management port, default `8089`). Splunk internal instances commonly run self-signed certs, so `-k` is used by default:

   ```bash
   SID=$(curl -sk -H "Authorization: Bearer $SPLUNK_TOKEN" \
     "https://$SPLUNK_HOST:8089/services/search/jobs" \
     --data-urlencode "search=search <query text>" \
     --data-urlencode "earliest_time=<timerange>" \
     --data-urlencode "latest_time=now" \
     --data-urlencode "output_mode=json" \
     | python -c "import sys,json;print(json.load(sys.stdin)['sid'])")
   ```

   (Any available JSON tool works if `python` isn't present — the goal is just to pull `sid` out of the response.)

6. **Poll until the job finishes.** Repeatedly `GET` the job status and check `dispatchState`:

   ```bash
   curl -sk -H "Authorization: Bearer $SPLUNK_TOKEN" \
     "https://$SPLUNK_HOST:8089/services/search/jobs/$SID?output_mode=json"
   ```

   Loop with a short sleep until `dispatchState` is `DONE` (or `FAILED`, in which case stop and report the error to the user, including `messages` from the response).

7. **Fetch results** once done:

   ```bash
   curl -sk -H "Authorization: Bearer $SPLUNK_TOKEN" \
     "https://$SPLUNK_HOST:8089/services/search/jobs/$SID/results?output_mode=json&count=0"
   ```

   Record the total result count (from the `results` array length, or the job status's `resultCount`).

8. **Analyze the results for suspicious patterns.** Look for things like:
   - Encoded/obfuscated commands (`-enc`, base64 PowerShell, `IEX`, etc.)
   - Credential access indicators (LSASS access, `sekurlsa`, SAM/NTDS dumping, `mimikatz`-style strings)
   - Living-off-the-land binaries used unusually (`psexec`, `wmic`, `certutil`, `rundll32`, `regsvr32`, `mshta`)
   - Lateral movement (unusual auth patterns, admin share access, new service creation across hosts)
   - Persistence (new scheduled tasks, registry run keys, new services, startup items)
   - Anomalous authentication (impossible travel, high-volume failures, off-hours privileged logons)
   - Defense evasion (log clearing, AMSI bypass strings, disabled security tooling)

   Only report patterns actually present in the returned data — do not speculate about activity the results don't support.

9. **Map findings to MITRE ATT&CK techniques**, citing specific technique IDs (including sub-techniques, e.g. `T1003.001`) only where the evidence in the results justifies them.

10. **Ensure `investigations/` exists** (create it if not), then write the note to `investigations/<YYYY-MM-DD>-<query-file-basename>.md`, where the date is today's date.

11. **Write the note** in this structure:

    ```markdown
    ---
    date: <YYYY-MM-DD>
    tags: [siem, investigation]
    techniques: [T1003.001, T1059.001]
    query_file: <path given in $1>
    timerange: <timerange used>
    result_count: <n>
    ---

    # Investigation: <query file basename>

    ## Summary

    <2-5 sentences: what was searched, what stood out, overall assessment>

    ## Findings

    <one subsection per notable finding, each referencing the specific
    ATT&CK technique(s) as backlinks, e.g. "Indicates credential dumping
    via LSASS access ([[T1003.001]])">

    ## ATT&CK Techniques

    - [[T1003.001]] — <one-line justification tied to the actual results>
    - [[T1059.001]] — <one-line justification>

    ## Query

    ```spl
    <raw query as read from the file>
    ```

    - **Time range:** <timerange>
    - **Result count:** <n>

    ## Analyst Notes

    <!-- for human follow-up: leave this section empty/blank for the analyst to fill in -->
    ```

12. **Report back** to the user with the output file path, result count, and a one-line summary of the most significant finding (if any).
