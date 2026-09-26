from __future__ import annotations

import json
from pathlib import Path


BASE = Path(__file__).resolve().parent
RAW = BASE / "raw-telemetry.jsonl"
METADATA = BASE / "capture-metadata.json"
OUTPUT = BASE / "normalized-telemetry.json"


def load_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def main() -> None:
    raw = load_jsonl(RAW)
    metadata = json.loads(METADATA.read_text(encoding="utf-8"))

    events = []
    expected_alerts = []
    expected_nonalerts = []

    for event in raw:
        if event["event_type"] == "mcp_tool_result" and event.get("role") == "source":
            events.append(
                {
                    "trace_id": event["trace_id"],
                    "event_id": event["event_id"],
                    "event_type": "tool_result",
                    "timestamp": event["timestamp"],
                    "trust_label": event["trust_label"],
                    "source_server_id": event["source_server_id"],
                }
            )

        if event["event_type"] == "mcp_tool_call" and event.get("role") == "target":
            normalized = {
                "trace_id": event["trace_id"],
                "event_id": event["event_id"],
                "event_type": "tool_call",
                "timestamp": event["timestamp"],
                "target_server_id": event["target_server_id"],
                "user_intent_supported": event["user_intent_supported"],
                "approval_state": event["approval_state"],
                "action_class": event["action_class"],
            }

            if "caused_by_event_id" in event:
                normalized["caused_by_event_id"] = event["caused_by_event_id"]

            events.append(normalized)

            if event["expected_alert"]:
                expected_alerts.append(event["event_id"])
            else:
                expected_nonalerts.append(event["event_id"])

    payload = {
        "version": 1,
        "technique_id": "SAF-T1703",
        "validation_type": "telemetry_replay",
        "capture_metadata": metadata,
        "events": events,
        "expected_alert_event_ids": expected_alerts,
        "expected_nonalert_event_ids": expected_nonalerts,
    }

    OUTPUT.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    print(f"PASS: normalized {len(events)} runtime events")
    print(f"expected alerts: {','.join(expected_alerts)}")
    print(f"expected nonalerts: {','.join(expected_nonalerts)}")


if __name__ == "__main__":
    main()
