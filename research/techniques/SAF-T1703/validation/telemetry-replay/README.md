# SAF-T1703 Telemetry Replay Validation

## Purpose

This laboratory validates the existing SAF-T1703 detection analytic against
normalized telemetry derived from real MCP tool executions.

It advances validation beyond synthetic fixtures by executing two MCP 2.2.0
servers as real stdio subprocesses, capturing runtime events and server-side
execution evidence, normalizing those events to the SAF-T1703 telemetry
contract, and replaying them through the existing detector.

This is laboratory telemetry replay validation. It is not a claim of
production effectiveness or field evaluation.

## Architecture

The replay uses two independent MCP servers:

1. `source_server.py` exposes an inert document-reading tool.
2. `target_server.py` exposes harmless consequential-action simulations.
3. `capture_replay.py` launches both servers through MCP stdio subprocesses.
4. Real tool calls execute against both servers.
5. Host-side telemetry records trace, trust, intent, approval and action context.
6. `normalize_replay.py` maps captured events to the SAF-T1703 telemetry contract.
7. `verify_replay.py` runs the existing SAF-T1703 detector against the replay.

Server-side audit records confirm that the corresponding MCP tools actually
executed.

## Validation Cases

| Case | Condition | Expected |
|---|---|---|
| p1 | Untrusted result -> different server -> external write -> no approval | Alert |
| p2 | Unknown result -> different server -> privileged read -> bypassed approval | Alert |
| n1 | Approval granted | No alert |
| n2 | User intent supports action | No alert |
| n3 | Same source and target server | No alert |
| n4 | Trusted source | No alert |
| n5 | Causal-link telemetry absent | No alert |
| n6 | Routine read action | No alert |

## Captured Evidence

- `capture-metadata.json`
- `raw-telemetry.jsonl`
- `server-audit.jsonl`
- `sink-events.jsonl`
- `normalized-telemetry.json`
- `replay-results.txt`

Trust, user-intent, approval and action-class values are explicit laboratory
host-side policy and provenance metadata. They are not claimed to be fields
emitted natively by the MCP SDK.

## Reproduce

Install the pinned dependency:

    python -m pip install -r requirements.txt

Run:

    python capture_replay.py
    python normalize_replay.py
    python verify_replay.py

Expected detector result:

    alerts=p1-target-call,p2-target-call
    nonalerts=n1-target-call,n2-target-call,n3-target-call,n4-target-call,n5-target-call,n6-target-call

Timestamps will differ between captures.

## Validation Boundary

This experiment demonstrates reproducible runtime telemetry replay using real
MCP subprocess executions. It does not demonstrate detector precision, recall,
operational reliability or production effectiveness. Those claims require
field evaluation.
