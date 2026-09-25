"""
Drift detection — compares two scans of the same account and reports
what changed: newly failing checks, resolved checks, new resources, and
resources that disappeared between scans.
"""

CHANGE_TYPES = ["NEW_FAIL", "RESOLVED", "NEW_RESOURCE", "REMOVED_RESOURCE"]


def _finding_key(finding: dict):
    """Findings are matched across scans by (rule_id, service, resource) —
    the same check on the same resource, regardless of scan id.
    """
    return (finding.get("rule_id"), finding.get("service"), finding.get("resource"))


def compare_scans(previous_findings: list, current_findings: list) -> list:
    """Diff two findings lists and return a list of change events.

    Each change is a dict:
        {
            "type": "NEW_FAIL" | "RESOLVED" | "NEW_RESOURCE" | "REMOVED_RESOURCE",
            "rule_id": ...,
            "service": ...,
            "resource": ...,
            "title": ...,
            "severity": ...,
            "detail": "human readable description of what changed",
        }
    """
    prev_map = {_finding_key(f): f for f in previous_findings}
    curr_map = {_finding_key(f): f for f in current_findings}

    changes = []

    for key, curr in curr_map.items():
        prev = prev_map.get(key)

        if prev is None:
            changes.append({
                "type": "NEW_RESOURCE",
                "rule_id": curr.get("rule_id"),
                "service": curr.get("service"),
                "resource": curr.get("resource"),
                "title": curr.get("title"),
                "severity": curr.get("severity"),
                "detail": f"New resource evaluated — currently {curr.get('status')}",
            })
            continue

        if prev.get("status") != curr.get("status"):
            change_type = "NEW_FAIL" if curr.get("status") == "FAIL" else "RESOLVED"
            changes.append({
                "type": change_type,
                "rule_id": curr.get("rule_id"),
                "service": curr.get("service"),
                "resource": curr.get("resource"),
                "title": curr.get("title"),
                "severity": curr.get("severity"),
                "detail": f"Status changed from {prev.get('status')} to {curr.get('status')}",
            })

    for key, prev in prev_map.items():
        if key not in curr_map:
            changes.append({
                "type": "REMOVED_RESOURCE",
                "rule_id": prev.get("rule_id"),
                "service": prev.get("service"),
                "resource": prev.get("resource"),
                "title": prev.get("title"),
                "severity": prev.get("severity"),
                "detail": "Resource no longer present in the latest scan",
            })

    return changes


def summarize_drift(changes: list) -> dict:
    """Count changes by type. Always returns all CHANGE_TYPES keys, even
    if their count is zero, so callers don't need defensive .get() calls.
    """
    counts = {change_type: 0 for change_type in CHANGE_TYPES}
    for change in changes:
        counts[change["type"]] = counts.get(change["type"], 0) + 1
    return counts
