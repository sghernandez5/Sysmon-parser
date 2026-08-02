#!/usr/bin/env python3
import argparse
import csv
import json
import sys
import xml.etree.ElementTree as ET

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
INTEGRITY_LEVELS = ["High", "Medium", "Low", "System"]
FIELD_ORDER = [
    "EventID",
    "UtcTime",
    "Image",
    "CommandLine",
    "User",
    "IntegrityLevel",
    "ParentImage",
    "ParentCommandLine",
    "Computer",
    "Hashes",
]


def parse_event(event_elem):
    system = event_elem.find(f"{NS}System")
    event_id = system.findtext(f"{NS}EventID")
    if event_id != "1":
        return None

    data_map = {}
    event_data = event_elem.find(f"{NS}EventData")
    if event_data is not None:
        for data in event_data.findall(f"{NS}Data"):
            data_map[data.get("Name")] = data.text

    return {
        "EventID": int(event_id),
        "UtcTime": data_map.get("UtcTime"),
        "Image": data_map.get("Image"),
        "CommandLine": data_map.get("CommandLine"),
        "User": data_map.get("User"),
        "IntegrityLevel": data_map.get("IntegrityLevel"),
        "ParentImage": data_map.get("ParentImage"),
        "ParentCommandLine": data_map.get("ParentCommandLine"),
        "Computer": system.findtext(f"{NS}Computer"),
        "Hashes": data_map.get("Hashes"),
    }


def matches_filters(event, args):
    if args.image is not None:
        if args.image.lower() not in (event["Image"] or "").lower():
            return False
    if args.user is not None:
        if (event["User"] or "").lower() != args.user.lower():
            return False
    if args.integrity_level is not None:
        if event["IntegrityLevel"] != args.integrity_level:
            return False
    return True


def build_stats(events):
    images = sorted({e["Image"] for e in events if e["Image"] is not None})
    users = sorted({e["User"] for e in events if e["User"] is not None})

    integrity_counts = {}
    for e in events:
        level = e["IntegrityLevel"]
        if level is not None:
            integrity_counts[level] = integrity_counts.get(level, 0) + 1

    return {
        "total_events": len(events),
        "unique_images": {"count": len(images), "values": images},
        "unique_users": {"count": len(users), "values": users},
        "events_by_integrity_level": integrity_counts,
    }


def print_events(events, fmt):
    if fmt == "jsonl":
        for e in events:
            print(json.dumps(e))
    elif fmt == "csv":
        writer = csv.writer(sys.stdout, lineterminator="\n")
        writer.writerow(FIELD_ORDER)
        for e in events:
            writer.writerow([e[f] if e[f] is not None else "" for f in FIELD_ORDER])
    else:
        if len(events) == 1:
            print(json.dumps(events[0], indent=2))
        else:
            print(json.dumps(events, indent=2))


def parse_file(path):
    tree = ET.parse(path)
    root = tree.getroot()
    root_tag = root.tag.replace(NS, "")

    if root_tag == "Event":
        event_elems = [root]
    else:
        event_elems = root.findall(f"{NS}Event")

    events = []
    for event_elem in event_elems:
        parsed = parse_event(event_elem)
        if parsed is not None:
            events.append(parsed)
    return events


def main():
    arg_parser = argparse.ArgumentParser(
        description="Extract Sysmon Event ID 1 (Process Creation) fields as JSON."
    )
    arg_parser.add_argument("path", help="Path to a Sysmon XML file")
    arg_parser.add_argument(
        "--image", help="Filter: Image path contains this substring (case-insensitive)"
    )
    arg_parser.add_argument(
        "--user", help="Filter: User matches exactly (case-insensitive)"
    )
    arg_parser.add_argument(
        "--integrity-level",
        choices=INTEGRITY_LEVELS,
        help="Filter: IntegrityLevel matches exactly",
    )
    arg_parser.add_argument(
        "--format",
        choices=["json", "jsonl", "csv"],
        default="json",
        help="Output format (default: json)",
    )
    arg_parser.add_argument(
        "--stats",
        action="store_true",
        help="Output summary statistics instead of events",
    )
    args = arg_parser.parse_args()

    try:
        events = parse_file(args.path)
    except FileNotFoundError:
        print(f"Error: file not found: {args.path}", file=sys.stderr)
        sys.exit(1)
    except ET.ParseError as e:
        print(f"Error: failed to parse XML: {e}", file=sys.stderr)
        sys.exit(1)

    events = [e for e in events if matches_filters(e, args)]

    if args.stats:
        print(json.dumps(build_stats(events), indent=2))
    else:
        print_events(events, args.format)


if __name__ == "__main__":
    main()
