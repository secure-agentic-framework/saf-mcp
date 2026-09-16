# SAF-M-82: Protected Approval Secret Handling

## Overview

**Mitigation ID**: SAF-M-82  
**Category**: Cryptographic Control  
**Effectiveness**: Not measured; depends on the stated enforcement boundary and deployment evaluation.  
**Implementation Complexity**: High  
**First Published**: 2026-09-16  
**Specification Status**: Pre-Draft proposal

## Description

Keep private approval inputs, decoding references, and any secret randomization outside the agent observation boundary. State the exact privacy property and the resources on which it depends.

SAF-M-69 addresses authorization. This control separately addresses what observing the approval exchange reveals, without equating transcript privacy with authorization or machine isolation.

This original control is part of the [Agent Containment and Owner Authorization profile](../../profiles/agent-containment/README.md). Its requirements are proposed profile obligations, not a claim of existing MCP behavior or independently measured protection.

## Mitigates

- [SAF-T1206: Credential Implant in Config](../../techniques/SAF-T1206/README.md) — reduces the opportunities described by the linked profile scenarios when the corresponding requirements are actually enforced.
- [SAF-T1505: In-Memory Secret Extraction](../../techniques/SAF-T1505/README.md) — reduces the opportunities described by the linked profile scenarios when the corresponding requirements are actually enforced.

**Related assessment contexts (not direct mitigation mappings):** [SAF-T1207: Hijack Update Mechanism](../../techniques/SAF-T1207/README.md), [SAF-T1407: Server Proxy Masquerade](../../techniques/SAF-T1407/README.md), [SAF-T1706: OAuth Token Pivot Replay](../../techniques/SAF-T1706/README.md). Their scenario-specific distinctions are recorded in the profile catalog.

## Technical Implementation

### Core Principles

- **ACP-R031: Fresh private masking resources.** An implementation claiming the supplied ENI6MA ideal transcript property MUST use the specified fresh independent secret masks without reusing allocations; a public nonce is not a secret mask.
- **ACP-R032: Complete observation declaration.** The privacy claim MUST name all information visible to the agent, including challenges, responses, timing, errors, acceptance feedback, recovery, and correlated sensors.
- **ACP-R033: Protected verification state.** Private naming maps, legends, raw inputs, masks, enrolled references, and reconstructed credentials MUST remain outside agent-controlled memory, tools, logs, and interfaces.
- **ACP-R034: Separate security properties.** Deployment claims MUST distinguish transcript privacy, knowledge verification, enrolled identity attribution, action authorization, result authenticity, replay resistance, and runtime confinement.

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

No privacy theorem repairs a secret captured before protection. Fresh secret randomness, where required, must actually be provisioned; public nonces and deterministic seed expansion do not supply unlimited independent secret entropy.

The controller, enrollment, protected UI, and recovery path remain trusted components. This specification does not implement them or establish their correctness. Transcript privacy and action authorization must be evaluated separately.

## Implementation Examples

The [contextual attack items](../../profiles/agent-containment/groups/proof-privacy.md) provide bounded procedures and discriminators. Use only inert local sinks and synthetic secrets when exercising them. No deployable attack payload or invented production configuration is supplied.

## Testing and Validation

| Requirement | Planned deployment test |
| --- | --- |
| ACP-R031 | [ACP-V031](../../profiles/agent-containment/VALIDATION.md#acp-v031) |
| ACP-R032 | [ACP-V032](../../profiles/agent-containment/VALIDATION.md#acp-v032) |
| ACP-R033 | [ACP-V033](../../profiles/agent-containment/VALIDATION.md#acp-v033) |
| ACP-R034 | [ACP-V034](../../profiles/agent-containment/VALIDATION.md#acp-v034) |

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
