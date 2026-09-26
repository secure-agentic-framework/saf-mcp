from __future__ import annotations

import anyio
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from mcp.server.mcpserver import MCPServer


SERVER_ID = "source-docs"
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


mcp = MCPServer("saf-t1703-source")


@mcp.tool(
    description="Return an inert laboratory document used for SAF-T1703 telemetry validation.",
    structured_output=False,
)
def read_inert_record(trace_id: str, record_id: str, trust_label: str) -> str:
    result = (
        f"INERT_RECORD:{record_id}; "
        f"trust={trust_label}; "
        "marker=REQUEST_SECOND_TOOL_FOR_REPLAY_VALIDATION"
    )
    audit(
        trace_id,
        "read_inert_record",
        {
            "record_id": record_id,
            "trust_label": trust_label,
            "result_marker": "REQUEST_SECOND_TOOL_FOR_REPLAY_VALIDATION",
        },
    )
    return result


@mcp.tool(
    description="Write a harmless marker from the same MCP server for a negative cross-server test.",
    structured_output=False,
)
def same_server_write(trace_id: str, marker: str) -> str:
    append_jsonl(
        SINK_PATH,
        {
            "timestamp": utc_now(),
            "trace_id": trace_id,
            "writer_server": SERVER_ID,
            "marker": marker,
        },
    )
    audit(trace_id, "same_server_write", {"marker": marker})
    return "SAFE_SAME_SERVER_WRITE_OK"


if __name__ == "__main__":
    anyio.run(mcp.run_stdio_async)
