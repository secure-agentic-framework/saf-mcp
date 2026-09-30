# SAF-M-77: Durable Single-Use Action Authorization

## Overview

**Mitigation ID**: SAF-M-77  
**Category**: Cryptographic Control  
**Effectiveness**: Not measured; depends on the stated enforcement boundary and deployment evaluation.  
**Implementation Complexity**: High  
**First Published**: 2026-09-16  
**Specification Status**: Pre-Draft proposal

## Description

Bind every protected approval to one immutable request context, consume its attempt atomically, authenticate any remote verdict, and prevent duplicate external effects across retries and crashes.

SAF-M-31 provides proof-of-possession token guidance and SAF-M-69 binds privileged approvals. This control adds durable attempt consumption and a separate execution receipt across multiple enforcement instances.

This original control is part of the [Agent Containment and Owner Authorization profile](../../profiles/agent-containment/README.md). Its requirements are proposed profile obligations, not a claim of existing MCP behavior or independently measured protection.

## Mitigates

- [SAF-T1302: Agentic Confused Deputy](../../techniques/SAF-T1302/README.md) — reduces the opportunities described by the linked profile scenarios when the corresponding requirements are actually enforced.
- [SAF-T1404: Response Tampering](../../techniques/SAF-T1404/README.md) — reduces the opportunities described by the linked profile scenarios when the corresponding requirements are actually enforced.
- [SAF-T2102: Service Disruption](../../techniques/SAF-T2102/README.md) — reduces the opportunities described by the linked profile scenarios when the corresponding requirements are actually enforced.

**Related assessment contexts (not direct mitigation mappings):** [SAF-T1207: Hijack Update Mechanism](../../techniques/SAF-T1207/README.md), [SAF-T1407: Server Proxy Masquerade](../../techniques/SAF-T1407/README.md), [SAF-T1706: OAuth Token Pivot Replay](../../techniques/SAF-T1706/README.md). Their scenario-specific distinctions are recorded in the profile catalog.

## Technical Implementation

### Core Principles

- **ACP-R014: Event allocation.** Each approval attempt MUST have a unique full event identifier bound to its tenant, enrollment, agent, verifier, request, session, policy, expiry, and private resource allocation.
- **ACP-R015: Atomic attempt consumption.** After transport authentication and event-routing checks, the verifier MUST atomically claim one eligible attempt before substantive witness validation; accept, reject, or abort MUST NOT reopen that attempt.
- **ACP-R016: Conservative crash recovery.** Expiry, abort, and uncertain recovery MUST retire the event and any allocated private masks. Replica restoration MUST NOT make a consumed allocation available again.
- **ACP-R017: Authenticated verifier result.** The controller MUST authenticate the verifier result and its complete context, including issuer, audience, agent, enrollment, policy, event, request, result, and expiry. A public success bit MUST NOT authorize an action.
- **ACP-R018: Single execution.** The controller MUST maintain durable execution state distinct from verification state and use downstream idempotency or reconciliation before retrying an uncertain external action.

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

Single-use verification does not automatically imply single execution. An external service without idempotency or reconciliation may leave an uncertain outcome after a crash; do not blindly retry.

The controller, enrollment, protected UI, and recovery path remain trusted components. This specification does not implement them or establish their correctness. Transcript privacy and action authorization must be evaluated separately.

## Implementation Examples

The [contextual attack items](../../profiles/agent-containment/groups/one-use.md) provide bounded procedures and discriminators. Use only inert local sinks and synthetic secrets when exercising them. No deployable attack payload or invented production configuration is supplied.

## Testing and Validation

| Requirement | Planned deployment test |
| --- | --- |
| ACP-R014 | [ACP-V014](../../profiles/agent-containment/VALIDATION.md#acp-v014) |
| ACP-R015 | [ACP-V015](../../profiles/agent-containment/VALIDATION.md#acp-v015) |
| ACP-R016 | [ACP-V016](../../profiles/agent-containment/VALIDATION.md#acp-v016) |
| ACP-R017 | [ACP-V017](../../profiles/agent-containment/VALIDATION.md#acp-v017) |
| ACP-R018 | [ACP-V018](../../profiles/agent-containment/VALIDATION.md#acp-v018) |

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
