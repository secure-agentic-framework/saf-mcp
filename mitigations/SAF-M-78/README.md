# SAF-M-78: Enrollment and Policy Lifecycle Integrity

## Overview

**Mitigation ID**: SAF-M-78  
**Category**: Preventive Control  
**Effectiveness**: Not measured; depends on the stated enforcement boundary and deployment evaluation.  
**Implementation Complexity**: High  
**First Published**: 2026-09-16  
**Specification Status**: Pre-Draft proposal

## Description

Bind the owner, agent, verifier, enrollment, policy, and running enforcement version. Permit version replacement, recovery, and ownership changes only through the authorized administrative path.

SAF-M-45 covers tool manifests and attestation. This control governs the owner-to-enrollment relationship and every route capable of changing the policy or verifier, including recovery and rollback.

This original control is part of the [Agent Containment and Owner Authorization profile](../../profiles/agent-containment/README.md). Its requirements are proposed profile obligations, not a claim of existing MCP behavior or independently measured protection.

## Mitigates

- [SAF-T1206: Credential Implant in Config](../../techniques/SAF-T1206/README.md) — reduces the opportunities described by the linked profile scenarios when the corresponding requirements are actually enforced.
- [SAF-T1207: Hijack Update Mechanism](../../techniques/SAF-T1207/README.md) — reduces the opportunities described by the linked profile scenarios when the corresponding requirements are actually enforced.
- [SAF-T1302: Agentic Confused Deputy](../../techniques/SAF-T1302/README.md) — reduces the opportunities described by the linked profile scenarios when the corresponding requirements are actually enforced.
- [SAF-T2103: Code Sabotage](../../techniques/SAF-T2103/README.md) — reduces the opportunities described by the linked profile scenarios when the corresponding requirements are actually enforced.

**Related assessment contexts (not direct mitigation mappings):** [SAF-T1706: OAuth Token Pivot Replay](../../techniques/SAF-T1706/README.md). Their scenario-specific distinctions are recorded in the profile catalog.

## Technical Implementation

### Core Principles

- **ACP-R019: Protected policy changes.** A policy version MUST be immutable once approved. Replacing it MUST require a new owner-authorized event bound to the old and proposed versions; the agent may propose but not install changes.
- **ACP-R020: Revocation and rollback resistance.** The controller MUST reject revoked owners, agents, delegations, enrollments, and superseded policy versions, including after restart and replica recovery.
- **ACP-R021: Updates and recovery.** Updates, administrative recovery, emergency access, and verifier replacement MUST preserve owner approval and containment; a software digest alone MUST NOT count as execution attestation.
- **ACP-R030: Governed ownership and recovery.** Ownership transfer and recovery MUST require designated organizational authority, revoke replaced bindings, and support a documented human fallback without general agent bypass.

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

A published hash identifies bytes, not the behavior of a running machine. An append-only ledger does not establish honest execution, safe policy, or immediate consensus.

The controller, enrollment, protected UI, and recovery path remain trusted components. This specification does not implement them or establish their correctness. Transcript privacy and action authorization must be evaluated separately.

## Implementation Examples

The [contextual attack items](../../profiles/agent-containment/groups/lifecycle.md) provide bounded procedures and discriminators. Use only inert local sinks and synthetic secrets when exercising them. No deployable attack payload or invented production configuration is supplied.

## Testing and Validation

| Requirement | Planned deployment test |
| --- | --- |
| ACP-R019 | [ACP-V019](../../profiles/agent-containment/VALIDATION.md#acp-v019) |
| ACP-R020 | [ACP-V020](../../profiles/agent-containment/VALIDATION.md#acp-v020) |
| ACP-R021 | [ACP-V021](../../profiles/agent-containment/VALIDATION.md#acp-v021) |
| ACP-R030 | [ACP-V030](../../profiles/agent-containment/VALIDATION.md#acp-v030) |

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
