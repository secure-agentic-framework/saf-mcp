# SAF-M-44: Tool Definition Integrity Monitoring

## Overview
**Mitigation ID**: SAF-M-44  
**Category**: Detective Control  
**Effectiveness**: Medium-High (bounded — see Limitations)  
**Implementation Complexity**: Medium  
**First Published**: 2026-09-08

## Description
Tool Definition Integrity Monitoring detects when the tool metadata a host approved is no longer the tool metadata the host is being served. At approval time the host canonicalizes the security-relevant fields of each tool definition, computes a digest, and stores it against the identity of the tool. On every subsequent `tools/list` — and, where the transport allows it, before every `tools/call` — it recomputes the digest and compares. A mismatch means the approved definition has been replaced, and is treated as an unapproved tool rather than as a new version of an approved one.

This addresses a specific gap that cryptographic authenticity controls do not close. A signature proves **origin**: that the descriptor was published by the party holding the key. A pin proves **stability**: that the descriptor being served today is the one that was reviewed. A server in possession of its own signing key can sign a changed descriptor perfectly well, and the signature will verify. The two controls answer different questions, and a host that verifies only origin will accept a validly-signed replacement of a tool a human approved on the strength of its earlier description. SAF-M-44 is the stability half; [SAF-M-45](../SAF-M-45/README.md) is the origin half, and neither substitutes for the other.

## Mitigates
- [SAF-T1201](../../techniques/SAF-T1201/README.md): Post-Approval Tool Mutation
- [SAF-T1205](../../techniques/SAF-T1205/README.md): Persistent Tool Redefinition
- [SAF-T1001](../../techniques/SAF-T1001/README.md): Tool Poisoning Attack
- [SAF-T1501](../../techniques/SAF-T1501/README.md): Full-Schema Poisoning (FSP)
- [SAF-T1405](../../techniques/SAF-T1405/README.md): Tool Obfuscation/Renaming
- [SAF-T1008](../../techniques/SAF-T1008/README.md): Cross-Server Tool Shadowing

## Technical Implementation

### Core Principles

1. **Pin identity is the (server, tool) pair, not the tool name.** A digest stored under a bare tool name is defeated two ways: a second server can register a tool with the same name and inherit the first server's approval ([SAF-T1008](../../techniques/SAF-T1008/README.md)), and a rename escapes the pin entirely ([SAF-T1405](../../techniques/SAF-T1405/README.md)). Key on a stable server identity — a configured server ID or the verified identity from [SAF-M-45](../SAF-M-45/README.md) — combined with the tool name, so that a rename presents as an unpinned tool requiring approval rather than as a silent change.

2. **Define the covered field set by exclusion, not enumeration.** An allowlist of fields to hash fails open on whatever the protocol adds next: a field introduced after the implementation was written is silently outside the digest, and behaviour-bearing content moved into it produces no mismatch. Canonicalize the whole tool object and exclude only fields known to be volatile and non-security-relevant, documenting each exclusion. The MCP `Tool` object in the 2025-06-18 schema carries `name`, `title`, `description`, `inputSchema`, `outputSchema`, `annotations`, and `_meta`; an implementation that hashes only `name`, `description`, and `inputSchema` leaves four fields unpinned, two of which carry approval-relevant content.

3. **`annotations` is security-relevant and must be inside the digest.** `ToolAnnotations` carries `readOnlyHint`, `destructiveHint`, `idempotentHint`, and `openWorldHint`. The MCP schema notes that clients should not make tool-use decisions on annotations received from untrusted servers — which is precisely the reason to pin them: pinning is the mechanism by which a host treats a server as trusted-since-approval. A server that is approved while advertising `destructiveHint: true` and later serves `destructiveHint: false`, with every other field unchanged, has altered the input to the host's approval logic without altering anything the digest covers, if annotations are excluded.

4. **Canonicalize before hashing.** JSON object key order is not semantically meaningful but changes the bytes. Use a deterministic serialization — [RFC 8785 JCS](https://www.rfc-editor.org/rfc/rfc8785) is the natural choice — so that a re-serialized but unchanged definition does not present as a mismatch. Without this, the control generates false mismatches, and the operational response to false mismatches is to disable the control.

5. **An unresolvable pin is not an approval.** The failure mode this control most often degrades into is a lookup that cannot find a pin — because the server identity did not resolve, the store was unreachable, or the tool is genuinely new — and returns "no mismatch". Absence of a pin and equality of digests must be distinct outcomes with distinct handling. Treating them alike produces a control that reads as enforcing while enforcing nothing.

### Architecture Components

```
                    approval time                         steady state
                    ─────────────                         ────────────
  tools/list  ──►  canonicalize                    tools/list  ──►  canonicalize
                        │                                                │
                        ▼                                                ▼
                   digest(fields)                                  digest(fields)
                        │                                                │
                        ▼                                                ▼
                 ┌─────────────┐                              ┌──────────────────┐
                 │  pin store  │◄─────────────────────────────┤  compare by      │
                 │ (srv,tool)  │        pinned digest          │  (server, tool)  │
                 │  → digest   │──────────────────────────────►                  │
                 └─────────────┘                              └────────┬─────────┘
                        ▲                                              │
                        │                                    ┌─────────┴─────────┐
                   human approval                            │                   │
                   (explicit, bound                       match               mismatch
                    to the digest)                            │                   │
                                                              ▼                   ▼
                                                          proceed         withhold tool,
                                                                          require re-approval
                                                                          bound to the new digest
```

### Prerequisites
- A stable server identity that survives reconnection, so pins can be keyed on something an attacker does not control.
- A pin store that persists across sessions; an in-memory pin detects mutation only within one session, which is not the threat model of [SAF-T1201](../../techniques/SAF-T1201/README.md).
- A defined approval flow that can be re-entered — the control's output is "this needs approval again", which requires somewhere for that to go.

### Implementation Steps

1. **Design Phase**:
   - Decide the excluded field set and write down why each field is excluded. Prefer excluding nothing.
   - Choose the canonicalization (RFC 8785 JCS unless there is a reason not to) and pin the hash algorithm in the stored record, so the scheme can be migrated later.
   - Decide the response to a mismatch: withholding the tool from the model is the minimum; failing the session closed is stronger and appropriate where the host cannot re-prompt.

2. **Development Phase**:
   - Compute pins at the point the definition enters the host, before any transformation that could normalize away a difference.
   - Store `(server_id, tool_name) → {digest, algorithm, approved_at, approved_by}`. Binding the approval record to the digest is what makes re-approval meaningful.
   - Make "no pin found" a distinct branch from "digest matches", and cover both with tests.

3. **Deployment Phase**:
   - Emit a telemetry event on every mismatch containing the server identity, tool name, both digests, and the approval ID — the fields [SAF-T1201](../../techniques/SAF-T1201/README.md) lists as required telemetry.
   - Alert on mismatch rate rather than only on individual mismatches; a server mutating many tools at once is a different event from one tool changing.
   - Treat `notifications/tools/list_changed` as a signal to re-verify, not as authorization to re-pin silently.

## Benefits
- **Detects the change a signature cannot.** A validly-signed replacement of an approved descriptor verifies under [SAF-M-45](../SAF-M-45/README.md) and fails here, which is the case [SAF-T1201](../../techniques/SAF-T1201/README.md) describes.
- **Cheap relative to the alternatives.** One canonicalization and one hash per tool per listing, with no additional network round trip and no dependency on external infrastructure being reachable — unlike signature verification, it does not fail when a transparency log or trust root is unavailable.
- **Produces an actionable artifact.** A mismatch names the tool, the server, and both digests, so a reviewer can diff two concrete definitions rather than investigate a generic verification failure.
- **Independent of key management.** It requires no publisher enrolment, so it applies to servers that do not sign at all — which, at time of writing, is most of them.

## Limitations
- **Definition-only detection cannot see backend changes.** A server that keeps its tool metadata byte-identical and changes what the tool actually does produces no mismatch. [SAF-T1201](../../techniques/SAF-T1201/README.md)'s telemetry guidance states this directly. Pair with distribution-level controls (package digest, repository commit) where the implementation is fetched rather than remote.
- **Trust on first use.** The first observation is trusted by construction: a server that is malicious at approval time is pinned as legitimate, and every subsequent check confirms the malicious definition is unchanged. This is the limitation [SAF-M-45](../SAF-M-45/README.md) exists to close, and is the reason the two controls are complementary rather than alternatives.
- **Unpinned protocol extensions.** Any field the implementation excludes — and any field added to the protocol after the implementation was written, if the covered set is an allowlist — is a channel for behaviour-bearing content that produces no mismatch. This is the failure mode Core Principle 2 is written against, and it recurs in practice.
- **Re-approval fatigue.** Servers that legitimately revise descriptions produce mismatches that are not attacks. If re-approval is frequent and low-information, operators will approve without reading, and the control degrades to a logging mechanism. Showing a field-level diff rather than "this tool changed" is the difference between a control and a prompt.

## Implementation Examples

### Example 1: Field coverage — the difference the digest sees

```python
import hashlib, json

TOOL_BEFORE = {
    "name": "read_file",
    "description": "Read a file from the workspace.",
    "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
    "annotations": {"readOnlyHint": True, "destructiveHint": False},
}

# The same tool after the server flips one annotation. Nothing else changes.
TOOL_AFTER = {
    **TOOL_BEFORE,
    "annotations": {"readOnlyHint": False, "destructiveHint": True},
}


def digest_allowlist(tool):
    """Vulnerable: enumerates the fields to cover, so anything else is invisible."""
    covered = {k: tool[k] for k in ("name", "description", "inputSchema") if k in tool}
    return hashlib.sha256(
        json.dumps(covered, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def digest_exclusion(tool, volatile=frozenset()):
    """Protected: covers the whole object, excluding only documented volatile fields."""
    covered = {k: v for k, v in tool.items() if k not in volatile}
    return hashlib.sha256(
        json.dumps(covered, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


assert digest_allowlist(TOOL_BEFORE) == digest_allowlist(TOOL_AFTER)   # no mismatch: bypass
assert digest_exclusion(TOOL_BEFORE) != digest_exclusion(TOOL_AFTER)   # mismatch: detected
```

The assertion on the left is the finding, not the test: a host using the allowlist digest sees no change when a tool is re-declared as destructive.

### Example 2: Pin identity, and the three distinct outcomes

```python
from dataclasses import dataclass

@dataclass(frozen=True)
class PinKey:
    server_id: str          # stable server identity, not the display name
    tool_name: str


class PinStore:
    def __init__(self):
        self._pins: dict[PinKey, str] = {}

    def approve(self, key: PinKey, digest: str) -> None:
        self._pins[key] = digest

    def check(self, key: PinKey, digest: str) -> str:
        """Returns one of: 'match', 'mismatch', 'unpinned'.

        'unpinned' is deliberately NOT folded into 'match'. A lookup that fails
        — unknown server, unresolved identity, empty store — must not read as
        approval; that is the degenerate case this control most often collapses
        into.
        """
        pinned = self._pins.get(key)
        if pinned is None:
            return "unpinned"
        return "match" if pinned == digest else "mismatch"


def gate(outcome: str) -> bool:
    if outcome == "match":
        return True
    if outcome == "mismatch":
        return False        # withhold; require re-approval bound to the new digest
    return False            # 'unpinned' — needs approval, not a pass
```

### Example 3: Configuration

```json
{
  "toolIntegrity": {
    "enabled": true,
    "canonicalization": "RFC8785",
    "hashAlgorithm": "sha256",
    "excludedFields": [],
    "pinKey": ["serverId", "toolName"],
    "onMismatch": "withhold-and-reapprove",
    "onUnpinned": "require-approval",
    "persistPinsAcrossSessions": true,
    "reverifyOn": ["tools/list", "notifications/tools/list_changed"]
  }
}
```

`excludedFields` is empty by default and every entry added to it should be justified in review; that default is the difference between Core Principle 2 being implemented and being documented.

## Testing and Validation

1. **Security Testing**:
   - Mutate exactly one field per run across the full `Tool` object — including `annotations` sub-fields and `outputSchema` — and assert a mismatch for each. A field that can be mutated without producing a mismatch is outside the digest, whether or not that was intended.
   - Register a second server offering a tool with the same name as an approved one and assert it is treated as unpinned.
   - Rename an approved tool and assert it is treated as unpinned rather than silently accepted.
   - Re-serialize an unchanged definition with different key order and assert **no** mismatch; this is the control test for canonicalization.

2. **Functional Testing**:
   - Assert the three outcomes (`match`, `mismatch`, `unpinned`) are distinguishable at the call site, not collapsed to a boolean.
   - Assert an empty or unreachable pin store yields `unpinned` and withholds, rather than passing.
   - Measure the added latency per `tools/list` against a realistic catalogue size.

3. **Integration Testing**:
   - Confirm pins survive a host restart and a server reconnection.
   - Confirm `notifications/tools/list_changed` triggers re-verification and does not silently re-pin.
   - Confirm the mismatch telemetry event carries the fields [SAF-T1201](../../techniques/SAF-T1201/README.md) lists as required.

## Deployment Considerations

### Resource Requirements
- **CPU**: One canonicalization and one SHA-256 per tool per listing; negligible relative to the transport round trip for catalogues of typical size.
- **Memory**: One digest and approval record per `(server, tool)` pair.
- **Storage**: Persistent, and small — a digest, an algorithm identifier, and approval metadata per pinned tool. Retain superseded digests long enough to diff across sessions, as [SAF-T1201](../../techniques/SAF-T1201/README.md) advises.
- **Network**: None. The control adds no round trip and does not depend on external services being reachable.

### Performance Impact
- **Latency**: Bounded by catalogue size at listing time; no per-call cost unless the deployment re-verifies before `tools/call`.
- **Throughput**: Unaffected on the invocation path in the listing-only configuration.
- **Resource Usage**: Dominated by the pin store, which grows with distinct `(server, tool)` pairs rather than with traffic.

### Monitoring and Alerting
- Mismatch count by server identity and by tool.
- `unpinned` outcome rate — a sustained rise can indicate identity resolution failing rather than genuinely new tools, which is a control-degradation signal rather than a security signal.
- Time between a `list_changed` notification and completed re-verification.
- Alert on any mismatch on a tool whose `annotations` changed, separately from other mismatches; that is the case where the host's approval logic was the target.

## Current Status (2026)
Content pinning is named as a preventive control in [SAF-T1201](../../techniques/SAF-T1201/README.md) and in the [OWASP third-party MCP guidance](https://genai.owasp.org/download/51928/?tmstv=1762283701). Host-side lifecycle handling that disables prior permissions on a tool-list change is documented for Visual Studio's MCP implementation ([Visual Studio MCP lifecycle](https://learn.microsoft.com/en-us/visualstudio/ide/mcp-servers?view=visualstudio)). Published demonstrations of the underlying technique are controlled rather than in-the-wild ([Song et al.](https://arxiv.org/html/2506.02040), [Rashidi](https://arxiv.org/html/2607.05744)).

## References
- [Model Context Protocol specification — Tools (2025-06-18)](https://modelcontextprotocol.io/specification/2025-06-18/server/tools)
- [RFC 8785: JSON Canonicalization Scheme (JCS)](https://www.rfc-editor.org/rfc/rfc8785)
- [OWASP Third-Party MCP Guidance](https://genai.owasp.org/download/51928/?tmstv=1762283701)
- [Visual Studio MCP servers — lifecycle](https://learn.microsoft.com/en-us/visualstudio/ide/mcp-servers?view=visualstudio)
- [Protecting against indirect injection attacks in MCP — Microsoft](https://developer.microsoft.com/blog/protecting-against-indirect-injection-attacks-mcp/)
- [Song et al., 2025](https://arxiv.org/html/2506.02040)
- [Rashidi, 2026](https://arxiv.org/html/2607.05744)

## Related Mitigations
- [SAF-M-45](../SAF-M-45/README.md): Tool Manifest Signing & Server Attestation — establishes origin, where this establishes stability. Signing closes the trust-on-first-use limitation above; pinning closes the validly-signed-replacement gap. Deploy both where key management is available.
- [SAF-M-51](../SAF-M-51/README.md): Embedding Anomaly Detection — detects semantic change in descriptions that a digest reports only as "different".
- [SAF-M-53](../SAF-M-53/README.md): Multimodal Behavioral Monitoring — observes what a tool does, where this observes what a tool declares.

## Version History
| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-09-08 | Initial documentation |
