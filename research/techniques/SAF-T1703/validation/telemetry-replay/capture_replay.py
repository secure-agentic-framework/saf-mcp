from __future__ import annotations

import json
import os
import platform
import sys
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path

import anyio
from mcp import StdioServerParameters
from mcp.client import Client


BASE = Path(__file__).resolve().parent
SOURCE_SERVER = BASE / "source_server.py"
TARGET_SERVER = BASE / "target_server.py"

RAW = BASE / "raw-telemetry.jsonl"
SERVER_AUDIT = BASE / "server-audit.jsonl"
SINK = BASE / "sink-events.jsonl"
METADATA = BASE / "capture-metadata.json"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def append_jsonl(path: Path, record: dict) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def result_text(result) -> str:
    parts = []
    for item in result.content:
        text = getattr(item, "text", None)
        if text:
            parts.append(text)
    return "\n".join(parts)


async def main() -> None:
    for path in (RAW, SERVER_AUDIT, SINK, METADATA):
        if path.exists():
            path.unlink()

    metadata = {
        "technique_id": "SAF-T1703",
        "capture_type": "runtime_telemetry_replay",
        "transport": "stdio_subprocess",
        "mcp_sdk_version": version("mcp"),
        "python_version": platform.python_version(),
        "scenario_count": 8,
        "captured_at": utc_now(),
    }
    METADATA.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")

    child_env = dict(os.environ)
    child_env["SAF_REPLAY_SERVER_AUDIT"] = str(SERVER_AUDIT)
    child_env["SAF_REPLAY_SINK"] = str(SINK)

    source_params = StdioServerParameters(
        command=sys.executable,
        args=[str(SOURCE_SERVER)],
        env=child_env,
    )

    target_params = StdioServerParameters(
        command=sys.executable,
        args=[str(TARGET_SERVER)],
        env=child_env,
    )

    scenarios = [
        {
            "trace_id": "p1",
            "trust_label": "untrusted",
            "target": "target",
            "tool": "write_ticket",
            "arguments": {"marker": "P1-SAFE-WRITE"},
            "intent": False,
            "approval": "absent",
            "action_class": "external_write",
            "causal": True,
            "expected_alert": True,
        },
        {
            "trace_id": "p2",
            "trust_label": "unknown",
            "target": "target",
            "tool": "read_restricted_fixture",
            "arguments": {},
            "intent": False,
            "approval": "bypassed",
            "action_class": "privileged_read",
            "causal": True,
            "expected_alert": True,
        },
        {
            "trace_id": "n1",
            "trust_label": "untrusted",
            "target": "target",
            "tool": "write_ticket",
            "arguments": {"marker": "N1-APPROVED-WRITE"},
            "intent": False,
            "approval": "granted",
            "action_class": "external_write",
            "causal": True,
            "expected_alert": False,
        },
        {
            "trace_id": "n2",
            "trust_label": "untrusted",
            "target": "target",
            "tool": "write_ticket",
            "arguments": {"marker": "N2-USER-INTENT-WRITE"},
            "intent": True,
            "approval": "absent",
            "action_class": "external_write",
            "causal": True,
            "expected_alert": False,
        },
        {
            "trace_id": "n3",
            "trust_label": "untrusted",
            "target": "source",
            "tool": "same_server_write",
            "arguments": {"marker": "N3-SAME-SERVER-WRITE"},
            "intent": False,
            "approval": "absent",
            "action_class": "external_write",
            "causal": True,
            "expected_alert": False,
        },
        {
            "trace_id": "n4",
            "trust_label": "trusted",
            "target": "target",
            "tool": "write_ticket",
            "arguments": {"marker": "N4-TRUSTED-SOURCE-WRITE"},
            "intent": False,
            "approval": "absent",
            "action_class": "external_write",
            "causal": True,
            "expected_alert": False,
        },
        {
            "trace_id": "n5",
            "trust_label": "untrusted",
            "target": "target",
            "tool": "write_ticket",
            "arguments": {"marker": "N5-NO-CAUSAL-LINK"},
            "intent": False,
            "approval": "absent",
            "action_class": "external_write",
            "causal": False,
            "expected_alert": False,
        },
        {
            "trace_id": "n6",
            "trust_label": "untrusted",
            "target": "target",
            "tool": "read_public_fixture",
            "arguments": {},
            "intent": False,
            "approval": "absent",
            "action_class": "routine_read",
            "causal": True,
            "expected_alert": False,
        },
    ]

    async with Client(source_params, mode="legacy") as source_client:
        async with Client(target_params, mode="legacy") as target_client:
            for scenario in scenarios:
                trace_id = scenario["trace_id"]

                source_result = await source_client.call_tool(
                    "read_inert_record",
                    {
                        "trace_id": trace_id,
                        "record_id": f"record-{trace_id}",
                        "trust_label": scenario["trust_label"],
                    },
                )

                source_event_id = f"{trace_id}-source-result"

                append_jsonl(
                    RAW,
                    {
                        "timestamp": utc_now(),
                        "scenario": trace_id,
                        "role": "source",
                        "event_type": "mcp_tool_result",
                        "trace_id": trace_id,
                        "event_id": source_event_id,
                        "source_server_id": "source-docs",
                        "tool_name": "read_inert_record",
                        "trust_label": scenario["trust_label"],
                        "result_text": result_text(source_result),
                    },
                )

                if scenario["target"] == "source":
                    target_client_for_call = source_client
                    target_server_id = "source-docs"
                else:
                    target_client_for_call = target_client
                    target_server_id = "target-actions"

                arguments = {"trace_id": trace_id} | scenario["arguments"]

                target_event_id = f"{trace_id}-target-call"

                target_event = {
                    "timestamp": utc_now(),
                    "scenario": trace_id,
                    "role": "target",
                    "event_type": "mcp_tool_call",
                    "trace_id": trace_id,
                    "event_id": target_event_id,
                    "source_server_id": "source-docs",
                    "target_server_id": target_server_id,
                    "tool_name": scenario["tool"],
                    "user_intent_supported": scenario["intent"],
                    "approval_state": scenario["approval"],
                    "action_class": scenario["action_class"],
                    "expected_alert": scenario["expected_alert"],
                }

                if scenario["causal"]:
                    target_event["caused_by_event_id"] = source_event_id

                # Record the invocation before executing it. The result event below
                # records the completed MCP call and its outcome.
                append_jsonl(RAW, target_event)

                target_result = await target_client_for_call.call_tool(
                    scenario["tool"],
                    arguments,
                )

                append_jsonl(
                    RAW,
                    {
                        "timestamp": utc_now(),
                        "scenario": trace_id,
                        "role": "target",
                        "event_type": "mcp_tool_result",
                        "trace_id": trace_id,
                        "event_id": f"{trace_id}-target-result",
                        "server_id": target_server_id,
                        "tool_name": scenario["tool"],
                        "result_text": result_text(target_result),
                        "outcome": "success",
                    },
                )

    print("PASS: captured 8 real MCP stdio replay scenarios")
    print(f"raw telemetry: {RAW}")
    print(f"server audit:  {SERVER_AUDIT}")
    print(f"sink evidence: {SINK}")


if __name__ == "__main__":
    anyio.run(main)
