# SAF-M-76: Protected Owner Approval Path

## Overview

**Mitigation ID**: SAF-M-76  
**Category**: UI Security  
**Effectiveness**: Not measured; depends on the stated enforcement boundary and deployment evaluation.  
**Implementation Complexity**: High  
**First Published**: 2026-09-16  
**Specification Status**: Pre-Draft proposal

## Description

Accept owner approval only from a protected interaction that the agent cannot render, observe, automate, or alter. Bind the displayed decision to the action ultimately dispatched.

SAF-M-69 establishes out-of-band privileged authorization. This control specifies the independent input/display boundary and exclusive owner attribution needed against an agent that can control its ordinary workspace.

This original control is part of the [Agent Containment and Owner Authorization profile](../../profiles/agent-containment/README.md). Its requirements are proposed profile obligations, not a claim of existing MCP behavior or independently measured protection.

## Mitigates

- [SAF-T1206: Credential Implant in Config](../../techniques/SAF-T1206/README.md) — reduces the opportunities described by the linked profile scenarios when the corresponding requirements are actually enforced.
- [SAF-T1302: Agentic Confused Deputy](../../techniques/SAF-T1302/README.md) — reduces the opportunities described by the linked profile scenarios when the corresponding requirements are actually enforced.
- [SAF-T1307: Confused Deputy Attack](../../techniques/SAF-T1307/README.md) — reduces the opportunities described by the linked profile scenarios when the corresponding requirements are actually enforced.
- [SAF-T1403: Consent-Fatigue Exploit](../../techniques/SAF-T1403/README.md) — reduces the opportunities described by the linked profile scenarios when the corresponding requirements are actually enforced.
- [SAF-T1404: Response Tampering](../../techniques/SAF-T1404/README.md) — reduces the opportunities described by the linked profile scenarios when the corresponding requirements are actually enforced.
- [SAF-T1505: In-Memory Secret Extraction](../../techniques/SAF-T1505/README.md) — reduces the opportunities described by the linked profile scenarios when the corresponding requirements are actually enforced.

**Related assessment contexts (not direct mitigation mappings):** [SAF-T1407: Server Proxy Masquerade](../../techniques/SAF-T1407/README.md). Their scenario-specific distinctions are recorded in the profile catalog.

## Technical Implementation

### Core Principles

- **ACP-R010: Binding enrollment.** Enrollment MUST bind an established owner identity to the agent, protected approval mechanism, verifier identity, credential reference, and current policy version.
- **ACP-R011: Protected display and input.** The owner interaction MUST use a path the agent cannot render over, read, keylog, screen-capture, or control through accessibility or automation interfaces.
- **ACP-R012: Exact-action approval.** The protected display MUST show the relying service, operation, resource, material parameters, recipient, session, expiry, and policy change, and approval MUST bind those immutable values.
- **ACP-R013: Exclusive approval attribution.** Only the designated protected mechanism MAY produce owner-attributable approval. Agent-authored flags, simulated clicks, model text, and ordinary tool responses MUST NOT substitute for it.

### Architecture Components

The agent runtime proposes actions. A separately protected controller owns external connections and administrative state. A protected owner-approval component supplies action-bound evidence. The downstream service returns an execution receipt. An independent audit path records the decision without exposing approval secrets.

### Prerequisites

- Document the actual trusted components, administrative owners, deployment identities, and excluded physical access.
- Supply independent controller and destination observations; agent-generated reports alone are not enforcement evidence.
- Define how a permitted task completes when this control denies an unauthorized variation.

### Implementation Steps

1. Select the applicable requirements above and bind them to concrete runtime, broker, verifier, and service components.
2. Configure the enforcement path and remove alternate routes that would bypass the decision.
3. Run the linked negative cases and authorized control cases before enabling production operations.
4. Retain configuration and evidence versions; repeat relevant tests after a material boundary change.

## Benefits

The design supplies explicit failure conditions and reviewable responsibility for each boundary. Its intended benefit is narrower unauthorized authority and clearer incident attribution; this contribution provides no measured reduction percentage.

## Limitations

A compromised approval device or a person knowingly approving a harmful action remains outside the guarantee. Recognition of enrolled authority does not independently establish civil identity.

The controller, enrollment, protected UI, and recovery path remain trusted components. This specification does not implement them or establish their correctness. Transcript privacy and action authorization must be evaluated separately.

## Implementation Examples

The [contextual attack items](../../profiles/agent-containment/groups/owner-approval.md) provide bounded procedures and discriminators. Use only inert local sinks and synthetic secrets when exercising them. No deployable attack payload or invented production configuration is supplied.

## Testing and Validation

| Requirement | Planned deployment test |
| --- | --- |
| ACP-R010 | [ACP-V010](../../profiles/agent-containment/VALIDATION.md#acp-v010) |
| ACP-R011 | [ACP-V011](../../profiles/agent-containment/VALIDATION.md#acp-v011) |
| ACP-R012 | [ACP-V012](../../profiles/agent-containment/VALIDATION.md#acp-v012) |
| ACP-R013 | [ACP-V013](../../profiles/agent-containment/VALIDATION.md#acp-v013) |

No deployment tests have been executed for this proposal. Repository checks validate references and completeness only. Claims about isolation, privacy, and detection accuracy require the corresponding deployment evidence.

## Deployment Considerations

### Resource Requirements

Budget protected processing, durable state, private material where applicable, independent audit storage, and operator availability. Capacity depends on the actual implementation; no throughput or hardware minimum is asserted.

### Performance Impact

Measure approval latency, broker overhead, recovery behavior, and denial rates with representative authorized tasks. A performance shortcut must not introduce a bypass.

### Monitoring and Alerting

Correlate owner and agent identity, request context, policy version, event state, denial reason, and downstream execution receipt. Protect the emitter and collector from agent modification. Minimize retained sensitive content.

## References

- [Profile source notes and reviewed external baselines](../../profiles/agent-containment/SOURCES.md)
- [Machine-readable requirements and attack items](../../profiles/agent-containment/catalog.yml)
- [Framework Model v2](../../research/FRAMEWORK-MODEL.md)

## Related Mitigations

- [SAF-M-29](../SAF-M-29/README.md): Explicit Privilege Boundaries.
- [SAF-M-69](../SAF-M-69/README.md): Out-of-Band Authorization for Privileged Tool Invocations.
- [SAF-M-74](../SAF-M-74/README.md): Per-Invocation Capability Brokering.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 0.1 | 2026-09-16 | Initial containment-profile proposal; acceptance tests planned | Franciscus Dylan Rosario; Codex drafting assistance |
