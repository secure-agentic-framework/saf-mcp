# SAF-M-81: Fail-Closed Containment Operations

## Overview

**Mitigation ID**: SAF-M-81  
**Category**: Architectural Control  
**Effectiveness**: Not measured; depends on the stated enforcement boundary and deployment evaluation.  
**Implementation Complexity**: High  
**First Published**: 2026-09-16  
**Specification Status**: Pre-Draft proposal

## Description

Maintain an independent shutdown path, protected audit records, resource budgets, and conservative recovery. Security service interruption must not grant new external access.

SAF-M-12 supplies audit logging and SAF-M-73 caps sampling. This control ties audit, availability, attempt exhaustion, and operator recovery to the containment boundary.

This original control is part of the [Agent Containment and Owner Authorization profile](../../profiles/agent-containment/README.md). Its requirements are proposed profile obligations, not a claim of existing MCP behavior or independently measured protection.

## Mitigates

- [SAF-T1302: Agentic Confused Deputy](../../techniques/SAF-T1302/README.md) — reduces the opportunities described by the linked profile scenarios when the corresponding requirements are actually enforced.
- [SAF-T1403: Consent-Fatigue Exploit](../../techniques/SAF-T1403/README.md) — reduces the opportunities described by the linked profile scenarios when the corresponding requirements are actually enforced.
- [SAF-T1505: In-Memory Secret Extraction](../../techniques/SAF-T1505/README.md) — reduces the opportunities described by the linked profile scenarios when the corresponding requirements are actually enforced.
- [SAF-T1902: Response-Borne Covert Channel](../../techniques/SAF-T1902/README.md) — reduces the opportunities described by the linked profile scenarios when the corresponding requirements are actually enforced.
- [SAF-T1910: Covert Channel Exfiltration](../../techniques/SAF-T1910/README.md) — reduces the opportunities described by the linked profile scenarios when the corresponding requirements are actually enforced.
- [SAF-T2102: Service Disruption](../../techniques/SAF-T2102/README.md) — reduces the opportunities described by the linked profile scenarios when the corresponding requirements are actually enforced.
- [SAF-T2103: Code Sabotage](../../techniques/SAF-T2103/README.md) — reduces the opportunities described by the linked profile scenarios when the corresponding requirements are actually enforced.

## Technical Implementation

### Core Principles

- **ACP-R022: Independent stop.** Authorized operators MUST be able to pause execution and revoke external authority through a path unavailable to the agent.
- **ACP-R027: Independent audit.** The audit service MUST record allocation, claim, validation, authorization, execution, denial, revocation, and policy changes outside agent control while excluding secrets and unnecessary personal data.
- **ACP-R028: Budgets and fail-closed behavior.** Attempts, concurrency, compute, sampling, output, and retries MUST have enforceable budgets. Failure of approval, ledger, clock policy, or audit dependencies MUST NOT create new external permission.
- **ACP-R029: Side-channel scope.** The threat model MUST inventory relevant timing, length, error, feedback, shared-resource, sensor, and physical channels; it MUST distinguish evaluated channels from unmeasured ones.

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

Availability can be reduced by conservative denial. Essential workflows need a human fallback that preserves authorization rather than a general bypass.

The controller, enrollment, protected UI, and recovery path remain trusted components. This specification does not implement them or establish their correctness. Transcript privacy and action authorization must be evaluated separately.

## Implementation Examples

The [contextual attack items](../../profiles/agent-containment/groups/operations.md) provide bounded procedures and discriminators. Use only inert local sinks and synthetic secrets when exercising them. No deployable attack payload or invented production configuration is supplied.

## Testing and Validation

| Requirement | Planned deployment test |
| --- | --- |
| ACP-R022 | [ACP-V022](../../profiles/agent-containment/VALIDATION.md#acp-v022) |
| ACP-R027 | [ACP-V027](../../profiles/agent-containment/VALIDATION.md#acp-v027) |
| ACP-R028 | [ACP-V028](../../profiles/agent-containment/VALIDATION.md#acp-v028) |
| ACP-R029 | [ACP-V029](../../profiles/agent-containment/VALIDATION.md#acp-v029) |

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
