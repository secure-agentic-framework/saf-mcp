# SAF-M-80: Owner-Separated Agent Delegation

## Overview

**Mitigation ID**: SAF-M-80  
**Category**: Architectural Control  
**Effectiveness**: Not measured; depends on the stated enforcement boundary and deployment evaluation.  
**Implementation Complexity**: High  
**First Published**: 2026-09-16  
**Specification Status**: Pre-Draft proposal

## Description

Give the agent a distinct identity and a revocable, audience-bound delegation. Downstream services retain the initiating principal and task boundary; delegation never includes the ability to approve expansion of its own authority.

SAF-M-16 limits token scopes. This control also preserves the difference between an owner and a delegated agent throughout subdelegation, logging, and policy changes.

This original control is part of the [Agent Containment and Owner Authorization profile](../../profiles/agent-containment/README.md). Its requirements are proposed profile obligations, not a claim of existing MCP behavior or independently measured protection.

## Mitigates

- [SAF-T1302: Agentic Confused Deputy](../../techniques/SAF-T1302/README.md) — reduces the opportunities described by the linked profile scenarios when the corresponding requirements are actually enforced.
- [SAF-T1308: Token Scope Substitution](../../techniques/SAF-T1308/README.md) — reduces the opportunities described by the linked profile scenarios when the corresponding requirements are actually enforced.
- [SAF-T1404: Response Tampering](../../techniques/SAF-T1404/README.md) — reduces the opportunities described by the linked profile scenarios when the corresponding requirements are actually enforced.

**Related assessment contexts (not direct mitigation mappings):** [SAF-T1407: Server Proxy Masquerade](../../techniques/SAF-T1407/README.md). Their scenario-specific distinctions are recorded in the profile catalog.

## Technical Implementation

### Core Principles

- **ACP-R023: Distinct machine identity.** Agent actions MUST identify the agent and its delegating owner separately; routine machine requests MUST NOT be recorded as fresh personal owner approvals.
- **ACP-R024: Scoped and expiring delegation.** Delegations MUST bind the owner, agent, audience, permitted operation and resources, policy version, expiry, and revocation state; they MUST exclude owner-policy-change authority.
- **ACP-R025: Receiver-enforced binding.** Every downstream hop MUST validate the initiating principal, resource, and delegated scope; forwarding an accepted proof or credential MUST NOT transfer owner authority to another session or audience.
- **ACP-R026: Subdelegation ceiling.** An agent-created worker MUST receive an equal or smaller authority set, never the owner approval capability; its lineage and revocation dependency MUST be recorded.

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

A correctly authorized delegation may still permit harmful conduct within its scope. A copied bearer credential remains usable unless the recipient enforces its binding and revocation conditions.

The controller, enrollment, protected UI, and recovery path remain trusted components. This specification does not implement them or establish their correctness. Transcript privacy and action authorization must be evaluated separately.

## Implementation Examples

The [contextual attack items](../../profiles/agent-containment/groups/delegation.md) provide bounded procedures and discriminators. Use only inert local sinks and synthetic secrets when exercising them. No deployable attack payload or invented production configuration is supplied.

## Testing and Validation

| Requirement | Planned deployment test |
| --- | --- |
| ACP-R023 | [ACP-V023](../../profiles/agent-containment/VALIDATION.md#acp-v023) |
| ACP-R024 | [ACP-V024](../../profiles/agent-containment/VALIDATION.md#acp-v024) |
| ACP-R025 | [ACP-V025](../../profiles/agent-containment/VALIDATION.md#acp-v025) |
| ACP-R026 | [ACP-V026](../../profiles/agent-containment/VALIDATION.md#acp-v026) |

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
