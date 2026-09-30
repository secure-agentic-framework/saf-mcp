# SAF-M-75: Broker-Only Egress and Descendant Containment

## Overview

**Mitigation ID**: SAF-M-75  
**Category**: Isolation and Containment  
**Effectiveness**: Not measured; depends on the stated enforcement boundary and deployment evaluation.  
**Implementation Complexity**: High  
**First Published**: 2026-09-16  
**Specification Status**: Pre-Draft proposal

## Description

Place the model runtime, tools, interpreters, browser processes, and descendants inside an enforcement boundary they cannot administer. Only the external broker may initiate approved external effects.

SAF-M-74 constrains individual invocations. This control additionally removes ambient communication from the whole agent execution tree and separates the broker from that tree.

This original control is part of the [Agent Containment and Owner Authorization profile](../../profiles/agent-containment/README.md). Its requirements are proposed profile obligations, not a claim of existing MCP behavior or independently measured protection.

## Mitigates

- [SAF-T1302: Agentic Confused Deputy](../../techniques/SAF-T1302/README.md) — reduces the opportunities described by the linked profile scenarios when the corresponding requirements are actually enforced.
- [SAF-T1303: Sandbox Escape via Server Exec](../../techniques/SAF-T1303/README.md) — reduces the opportunities described by the linked profile scenarios when the corresponding requirements are actually enforced.
- [SAF-T1903: Malicious Server Control Channel](../../techniques/SAF-T1903/README.md) — reduces the opportunities described by the linked profile scenarios when the corresponding requirements are actually enforced.
- [SAF-T1910: Covert Channel Exfiltration](../../techniques/SAF-T1910/README.md) — reduces the opportunities described by the linked profile scenarios when the corresponding requirements are actually enforced.
- [SAF-T1914: Tool-to-Tool Exfil](../../techniques/SAF-T1914/README.md) — reduces the opportunities described by the linked profile scenarios when the corresponding requirements are actually enforced.
- [SAF-T2103: Code Sabotage](../../techniques/SAF-T2103/README.md) — reduces the opportunities described by the linked profile scenarios when the corresponding requirements are actually enforced.

## Technical Implementation

### Core Principles

- **ACP-R001: Independent enforcement.** The deployment MUST enforce isolation outside the agent-controlled runtime; the agent MUST NOT administer the host, broker, hypervisor, or their credentials.
- **ACP-R002: Broker-only external effects.** All agent-caused network, file-sharing, messaging, and service effects MUST pass through the broker. Direct outbound connections MUST be denied.
- **ACP-R003: Descendant inheritance.** Child processes, nested runtimes, delegated workers, and subsidiary agents MUST inherit an equal or narrower ceiling and MUST NOT acquire ambient host capabilities.
- **ACP-R004: Complete channel inventory.** The boundary inventory MUST include DNS, inherited sockets, IPC, mounts, clipboard, display, devices, telemetry, updates, crash reports, and remote model inference.

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

Host or hypervisor compromise can defeat the boundary. A disconnected virtual network does not account for inherited sockets, shared folders, peripherals, or a remote inference provider.

The controller, enrollment, protected UI, and recovery path remain trusted components. This specification does not implement them or establish their correctness. Transcript privacy and action authorization must be evaluated separately.

## Implementation Examples

The [contextual attack items](../../profiles/agent-containment/groups/isolation.md) provide bounded procedures and discriminators. Use only inert local sinks and synthetic secrets when exercising them. No deployable attack payload or invented production configuration is supplied.

## Testing and Validation

| Requirement | Planned deployment test |
| --- | --- |
| ACP-R001 | [ACP-V001](../../profiles/agent-containment/VALIDATION.md#acp-v001) |
| ACP-R002 | [ACP-V002](../../profiles/agent-containment/VALIDATION.md#acp-v002) |
| ACP-R003 | [ACP-V003](../../profiles/agent-containment/VALIDATION.md#acp-v003) |
| ACP-R004 | [ACP-V004](../../profiles/agent-containment/VALIDATION.md#acp-v004) |

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
