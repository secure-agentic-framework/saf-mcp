# SAF-M-79: Disclosure-Bounded Tool Brokering

## Overview

**Mitigation ID**: SAF-M-79  
**Category**: Data Security  
**Effectiveness**: Not measured; depends on the stated enforcement boundary and deployment evaluation.  
**Implementation Complexity**: High  
**First Published**: 2026-09-16  
**Specification Status**: Pre-Draft proposal

## Description

Represent requests as constrained operations on registered resources. The broker resolves destinations, retains service credentials, and separately authorizes every information release.

SAF-M-72 inspects outputs for data loss. This control constrains input selection, request destinations, arguments, response recipients, and permitted disclosure before relying on content inspection.

This original control is part of the [Agent Containment and Owner Authorization profile](../../profiles/agent-containment/README.md). Its requirements are proposed profile obligations, not a claim of existing MCP behavior or independently measured protection.

## Mitigates

- [SAF-T1307: Confused Deputy Attack](../../techniques/SAF-T1307/README.md) — reduces the opportunities described by the linked profile scenarios when the corresponding requirements are actually enforced.
- [SAF-T1505: In-Memory Secret Extraction](../../techniques/SAF-T1505/README.md) — reduces the opportunities described by the linked profile scenarios when the corresponding requirements are actually enforced.
- [SAF-T1902: Response-Borne Covert Channel](../../techniques/SAF-T1902/README.md) — reduces the opportunities described by the linked profile scenarios when the corresponding requirements are actually enforced.
- [SAF-T1910: Covert Channel Exfiltration](../../techniques/SAF-T1910/README.md) — reduces the opportunities described by the linked profile scenarios when the corresponding requirements are actually enforced.
- [SAF-T1911: Parameter Exfiltration](../../techniques/SAF-T1911/README.md) — reduces the opportunities described by the linked profile scenarios when the corresponding requirements are actually enforced.
- [SAF-T1914: Tool-to-Tool Exfil](../../techniques/SAF-T1914/README.md) — reduces the opportunities described by the linked profile scenarios when the corresponding requirements are actually enforced.

## Technical Implementation

### Core Principles

- **ACP-R005: Typed requests.** The broker MUST accept schema-validated operations on registered resources; agent text MUST NOT become arbitrary broker code, shell commands, or open-ended forwarding instructions.
- **ACP-R006: Broker-owned service credentials.** External service credentials MUST remain outside the runtime, prompts, tool results, environment variables, shared files, and diagnostic output.
- **ACP-R007: Destination and operation binding.** The broker MUST bind service, resource, method, recipient, and resolved destination; redirects, address changes, and metadata or loopback access require explicit authorization.
- **ACP-R008: Explicit disclosure boundary.** Every outgoing argument, generated file, report, browser render, and message MUST have an authorized recipient, permitted content scope, and release decision. Arbitrary output MUST NOT be described as zero leakage.
- **ACP-R009: Minimum input access.** The broker MUST minimize records, fields, and task context supplied to the agent and MUST treat remote inference as a disclosure to the model provider.

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

Arbitrary agent-controlled output to an outside recipient remains a communication channel. Content classification alone cannot establish zero leakage.

The controller, enrollment, protected UI, and recovery path remain trusted components. This specification does not implement them or establish their correctness. Transcript privacy and action authorization must be evaluated separately.

## Implementation Examples

The [contextual attack items](../../profiles/agent-containment/groups/broker.md) provide bounded procedures and discriminators. Use only inert local sinks and synthetic secrets when exercising them. No deployable attack payload or invented production configuration is supplied.

## Testing and Validation

| Requirement | Planned deployment test |
| --- | --- |
| ACP-R005 | [ACP-V005](../../profiles/agent-containment/VALIDATION.md#acp-v005) |
| ACP-R006 | [ACP-V006](../../profiles/agent-containment/VALIDATION.md#acp-v006) |
| ACP-R007 | [ACP-V007](../../profiles/agent-containment/VALIDATION.md#acp-v007) |
| ACP-R008 | [ACP-V008](../../profiles/agent-containment/VALIDATION.md#acp-v008) |
| ACP-R009 | [ACP-V009](../../profiles/agent-containment/VALIDATION.md#acp-v009) |

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
