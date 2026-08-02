#!/usr/bin/env python3
"""MCP server exposing Hayabusa EVTX scanning as a tool."""
import json
import platform
import re
import subprocess
import tempfile
from pathlib import Path

import yaml
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("hayabusa")

HAYABUSA_DIR = Path(__file__).parent / "hayabusa"
RULES_DIR = HAYABUSA_DIR / "rules"
SEVERITY_LEVELS = ["informational", "low", "medium", "high", "critical"]
OUTPUT_FORMATS = ["summary", "full"]
SUMMARY_FIELDS = ["Timestamp", "RuleTitle", "Level", "Computer", "EventID", "RecordID"]
DEFAULT_SCAN_RESULTS = 50
ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


def find_hayabusa_binary() -> Path | None:
    name = "hayabusa.exe" if platform.system() == "Windows" else "hayabusa"
    candidate = HAYABUSA_DIR / name
    if candidate.is_file():
        return candidate

    # Release archives ship a version-qualified binary name
    # (e.g. hayabusa-3.10.0-win-x64.exe) rather than a plain one.
    pattern = "hayabusa*.exe" if platform.system() == "Windows" else "hayabusa*"
    matches = [p for p in HAYABUSA_DIR.glob(pattern) if p.is_file()]
    return matches[0] if matches else None


def _load_rule_summary(rule_path: Path) -> dict | None:
    try:
        with open(rule_path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError:
        return None

    if not isinstance(data, dict) or "title" not in data:
        return None

    logsource = data.get("logsource") or {}
    return {
        "id": data.get("id"),
        "title": data.get("title"),
        "level": data.get("level"),
        "status": data.get("status"),
        "description": data.get("description"),
        "tags": data.get("tags") or [],
        "product": logsource.get("product"),
        "service": logsource.get("service"),
    }


def _matches_keyword(rule: dict, needle: str) -> bool:
    haystack = " ".join(
        [
            rule.get("title") or "",
            rule.get("description") or "",
            rule.get("id") or "",
            " ".join(rule.get("tags") or []),
        ]
    ).lower()
    return needle in haystack


@mcp.tool()
def scan_evtx(
    path: str,
    min_severity: str | None = None,
    rule_filter: str | None = None,
    output_format: str = "summary",
    max_results: int | None = DEFAULT_SCAN_RESULTS,
) -> dict:
    """Scan an EVTX file with Hayabusa and return structured results.

    Args:
        path: Path to the .evtx file to scan.
        min_severity: Optional minimum severity level to include
            (informational, low, medium, high, critical). Findings below
            this level are excluded. Real-world logs are dominated by
            routine low/informational events, so setting this to "medium"
            or "high" is usually more useful than reading everything.
        rule_filter: Optional case-insensitive substring to match against
            each finding's rule title (e.g. "lateral" or "mimikatz"). Only
            matching findings are returned.
        output_format: "summary" (default) returns a condensed set of
            fields per finding; "full" returns every field Hayabusa
            produced, including Details and ExtraFieldInfo.
        max_results: Cap on the number of findings returned (default 50, to
            keep results from exceeding output limits on noisy real-world
            logs). total_findings still reports the full count after
            filtering. Pass None for no cap.
    """
    evtx_path = Path(path)
    if not evtx_path.is_file():
        return {"error": f"EVTX file not found: {path}"}

    if min_severity is not None and min_severity not in SEVERITY_LEVELS:
        return {
            "error": f"Invalid min_severity '{min_severity}'. "
            f"Must be one of {SEVERITY_LEVELS}"
        }

    if output_format not in OUTPUT_FORMATS:
        return {
            "error": f"Invalid output_format '{output_format}'. "
            f"Must be one of {OUTPUT_FORMATS}"
        }

    if max_results is not None and max_results <= 0:
        return {"error": "max_results must be a positive integer"}

    binary = find_hayabusa_binary()
    if binary is None:
        return {"error": f"Hayabusa executable not found in {HAYABUSA_DIR}"}

    with tempfile.TemporaryDirectory() as tmp_dir:
        output_path = Path(tmp_dir) / "results.jsonl"
        command = [
            str(binary),
            "json-timeline",
            "-f", str(evtx_path.resolve()),
            "-o", str(output_path),
            "-L",  # JSONL output (one JSON object per line)
            "-b",  # disable abbreviations so Level is spelled out in full
            "-w",  # no wizard, scan for all events and alerts
            "-C",  # overwrite output file if it exists
            "-Q",  # quiet errors, don't write an error log file
        ]

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=binary.parent,
                timeout=300,
            )
        except FileNotFoundError:
            return {"error": f"Failed to execute Hayabusa binary: {binary}"}
        except subprocess.TimeoutExpired:
            return {"error": "Hayabusa scan timed out after 300 seconds"}
        except OSError as e:
            return {"error": f"Failed to run Hayabusa: {e}"}

        if not output_path.exists():
            stderr = ANSI_ESCAPE.sub("", result.stderr).strip()
            return {
                "error": "Hayabusa scan failed to produce output",
                "details": stderr or f"exit code {result.returncode}",
            }

        findings = []
        with open(output_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    findings.append(json.loads(line))

    if min_severity is not None:
        min_index = SEVERITY_LEVELS.index(min_severity)
        findings = [
            finding
            for finding in findings
            if finding.get("Level") in SEVERITY_LEVELS
            and SEVERITY_LEVELS.index(finding["Level"]) >= min_index
        ]

    if rule_filter is not None:
        needle = rule_filter.lower()
        findings = [
            finding
            for finding in findings
            if needle in (finding.get("RuleTitle") or "").lower()
        ]

    total_findings = len(findings)

    truncated = max_results is not None and max_results < total_findings
    if max_results is not None:
        findings = findings[:max_results]

    if output_format == "summary":
        findings = [
            {field: finding.get(field) for field in SUMMARY_FIELDS}
            for finding in findings
        ]

    result = {
        "file": str(evtx_path),
        "total_findings": total_findings,
        "findings": findings,
    }
    if truncated:
        result["truncated"] = True
    return result


DEFAULT_RULE_RESULTS = 50


@mcp.tool()
def get_hayabusa_rules(
    keyword: str | None = None, max_results: int | None = DEFAULT_RULE_RESULTS
) -> dict:
    """List available Hayabusa detection rules, optionally filtered by keyword.

    Useful for understanding what detections exist before scanning, or for
    picking a value to pass as scan_evtx's rule_filter.

    Args:
        keyword: Optional case-insensitive substring matched against each
            rule's title, description, tags, and id (e.g. "lateral" or
            "mimikatz"). Omit to list all rules. Broad keywords (or no
            keyword) can match thousands of rules, so narrow the keyword
            if total_rules comes back much larger than the returned list.
        max_results: Cap on the number of rules returned (default 50, to
            keep results from exceeding output limits on broad keywords).
            total_rules still reports the full count after filtering. Pass
            None for no cap.
    """
    if not RULES_DIR.is_dir():
        return {"error": f"Hayabusa rules directory not found: {RULES_DIR}"}

    if max_results is not None and max_results <= 0:
        return {"error": "max_results must be a positive integer"}

    rules = []
    for rule_path in RULES_DIR.rglob("*.yml"):
        summary = _load_rule_summary(rule_path)
        if summary is not None:
            rules.append(summary)

    if keyword is not None:
        needle = keyword.lower()
        rules = [rule for rule in rules if _matches_keyword(rule, needle)]

    rules.sort(key=lambda rule: rule.get("title") or "")

    total_rules = len(rules)

    truncated = max_results is not None and max_results < total_rules
    if max_results is not None:
        rules = rules[:max_results]

    result = {
        "total_rules": total_rules,
        "rules": rules,
    }
    if truncated:
        result["truncated"] = True
    return result


def main():
    mcp.run()


if __name__ == "__main__":
    main()
