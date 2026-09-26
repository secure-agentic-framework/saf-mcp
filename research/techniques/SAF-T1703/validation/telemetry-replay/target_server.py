from __future__ import annotations

import anyio
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from mcp.server.mcpserver import MCPServer


SERVER_ID = "target-actions"
AUDIT_PATH = Path(os.environ["SAF_REPLAY_SERVER_AUDIT"])
SINK_PATH = Path(os.environ["SAF_REPLAY_SINK"])


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def append_jsonl(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def audit(trace_id: str, tool_name: str, details: dict) -> None:
    append_jsonl(
        AUDIT_PATH,
        {
            "timestamp": utc_now(),
            "trace_id": trace_id,
            "server_id": SERVER_ID,
            "tool_name": tool_name,
            "event_type": "server_tool_execution",
            "details": details,
        },
    )


mcp = MCPServer("saf-t1703-target")


@mcp.tool(
    description="Write a harmless laboratory ticket marker.",
    structured_output=False,
)
def write_ticket(trace_id: str, marker: str) -> str:
    append_jsonl(
        SINK_PATH,
        {
            "timestamp": utc_now(),
            "trace_id": trace_id,
            "writer_server": SERVER_ID,
            "marker": marker,
        },
    )
    audit(trace_id, "write_ticket", {"marker": marker})
    return "SAFE_EXTERNAL_WRITE_OK"


@mcp.tool(
    description="Return a harmless value representing a restricted-resource read.",
    structured_output=False,
)
def read_restricted_fixture(trace_id: str) -> str:
    audit(
        trace_id,
        "read_restricted_fixture",
        {"fixture": "restricted-lab-record"},
    )
    return "SAFE_RESTRICTED_FIXTURE_VALUE"


@mcp.tool(
    description="Return a harmless public value for a routine-read negative case.",
    structured_output=False,
)
def read_public_fixture(trace_id: str) -> str:
    audit(
        trace_id,
        "read_public_fixture",
        {"fixture": "public-lab-record"},
    )
    return "SAFE_PUBLIC_FIXTURE_VALUE"


if __name__ == "__main__":
    anyio.run(mcp.run_stdio_async)
