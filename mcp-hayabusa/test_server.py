#!/usr/bin/env python3
"""Manual smoke test: imports server.py and calls scan_evtx directly against a sample EVTX file."""
from pathlib import Path

from server import get_hayabusa_rules, scan_evtx

SAMPLE = Path(__file__).parent / "samples" / "discovery_bloodhound.evtx"


def main():
    print(f"Scanning {SAMPLE.name}...")
    result = scan_evtx(str(SAMPLE))
    if "error" in result:
        print(f"FAILED: {result['error']}")
        return
    print(f"total_findings: {result['total_findings']}")
    print(f"levels seen: {sorted({f['Level'] for f in result['findings']})}")

    print("\nFiltered to high+ severity:")
    filtered = scan_evtx(str(SAMPLE), min_severity="high")
    print(f"total_findings: {filtered['total_findings']}")

    print("\nMissing file:")
    print(scan_evtx("does_not_exist.evtx"))

    print("\nInvalid min_severity:")
    print(scan_evtx(str(SAMPLE), min_severity="extreme"))

    print("\nInvalid output_format:")
    print(scan_evtx(str(SAMPLE), output_format="verbose"))

    print("\nSummary output (default):")
    summary = scan_evtx(str(SAMPLE))
    print(f"total_findings: {summary['total_findings']}")
    print(f"sample finding keys: {sorted(summary['findings'][0].keys()) if summary['findings'] else []}")

    print("\nFull output:")
    full = scan_evtx(str(SAMPLE), output_format="full")
    print(f"sample finding keys: {sorted(full['findings'][0].keys()) if full['findings'] else []}")

    print("\nrule_filter='log cleared':")
    rule_filtered = scan_evtx(str(SAMPLE), rule_filter="log cleared")
    print(f"total_findings: {rule_filtered['total_findings']}")

    print("\nrule_filter with no matches:")
    no_match = scan_evtx(str(SAMPLE), rule_filter="nonexistent-rule-xyz")
    print(f"total_findings: {no_match['total_findings']}")

    print("\nmax_results=0 (should error):")
    print(scan_evtx(str(SAMPLE), max_results=0))

    print("\nmax_results=1:")
    capped = scan_evtx(str(SAMPLE), max_results=1)
    print(f"total_findings: {capped['total_findings']}, returned: {len(capped['findings'])}, truncated: {capped.get('truncated', False)}")

    print("\nget_hayabusa_rules(keyword='mimikatz'):")
    rules = get_hayabusa_rules(keyword="mimikatz")
    print(f"total_rules: {rules['total_rules']}")
    if rules["rules"]:
        print(f"first rule: {rules['rules'][0]['title']}")

    print("\nget_hayabusa_rules(keyword='zzz_no_such_keyword'):")
    no_rules = get_hayabusa_rules(keyword="zzz_no_such_keyword")
    print(f"total_rules: {no_rules['total_rules']}")

    print("\nget_hayabusa_rules(keyword='credential') [broad keyword, default cap]:")
    broad = get_hayabusa_rules(keyword="credential")
    print(f"total_rules: {broad['total_rules']}, returned: {len(broad['rules'])}, truncated: {broad.get('truncated', False)}")

    print("\nget_hayabusa_rules(max_results=0) (should error):")
    print(get_hayabusa_rules(max_results=0))


if __name__ == "__main__":
    main()
