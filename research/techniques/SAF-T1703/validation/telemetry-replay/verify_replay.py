from __future__ import annotations

import importlib.util
import json
from collections import Counter
from pathlib import Path


BASE = Path(__file__).resolve().parent
REPO = BASE.parents[4]

NORMALIZED = BASE / "normalized-telemetry.json"
SERVER_AUDIT = BASE / "server-audit.jsonl"
SINK = BASE / "sink-events.jsonl"
RESULTS = BASE / "replay-results.txt"

DETECTOR = REPO / "tests" / "SAF-T1703" / "test_detection_rule.py"


def load_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def load_detector():
    spec = importlib.util.spec_from_file_location("saf_t1703_detector", DETECTOR)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load SAF-T1703 detector")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> None:
    payload = json.loads(NORMALIZED.read_text(encoding="utf-8"))
    detector = load_detector()

    observed = detector.alerts(payload["events"])
    expected = payload["expected_alert_event_ids"]

    if observed != expected:
        raise AssertionError(
            f"detector mismatch: expected {expected}, observed {observed}"
        )

    all_calls = [
        event["event_id"]
        for event in payload["events"]
        if event.get("event_type") == "tool_call"
    ]

    observed_nonalerts = [
        event_id for event_id in all_calls if event_id not in observed
    ]

    expected_nonalerts = payload["expected_nonalert_event_ids"]

    if observed_nonalerts != expected_nonalerts:
        raise AssertionError(
            f"nonalert mismatch: expected {expected_nonalerts}, "
            f"observed {observed_nonalerts}"
        )

    audit = load_jsonl(SERVER_AUDIT)
    trace_counts = Counter(event["trace_id"] for event in audit)

    expected_traces = {"p1", "p2", "n1", "n2", "n3", "n4", "n5", "n6"}

    if set(trace_counts) != expected_traces:
        raise AssertionError(
            f"server audit trace mismatch: {sorted(trace_counts)}"
        )

    incomplete = {
        trace: count
        for trace, count in trace_counts.items()
        if count < 2
    }

    if incomplete:
        raise AssertionError(
            f"expected source and target execution for each trace: {incomplete}"
        )

    sink = load_jsonl(SINK)

    summary = [
        "SAF-T1703 telemetry replay validation",
        "status=PASS",
        f"mcp_sdk_version={payload['capture_metadata']['mcp_sdk_version']}",
        f"python_version={payload['capture_metadata']['python_version']}",
        f"transport={payload['capture_metadata']['transport']}",
        f"normalized_events={len(payload['events'])}",
        f"server_execution_events={len(audit)}",
        f"harmless_sink_writes={len(sink)}",
        f"alerts={','.join(observed)}",
        f"nonalerts={','.join(observed_nonalerts)}",
        (
            "scope=real MCP subprocess execution replay validating causality, "
            "cross-server boundary, trust, user-intent, approval and action-class "
            "dimensions; production effectiveness is not claimed"
        ),
    ]

    RESULTS.write_text("\n".join(summary) + "\n", encoding="utf-8")

    print("\n".join(summary))


if __name__ == "__main__":
    main()
