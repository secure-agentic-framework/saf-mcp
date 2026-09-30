# Runtime isolation and complete mediation

[Profile index](../README.md) | [Machine-readable catalog](../catalog.yml)

These are proposed, inert deployment assessments, not new canonical techniques or observed incidents. Detection ideas are proposed; acceptance tests require a deployed system.

**Primary control:** [SAF-M-75: Broker-Only Egress and Descendant Containment](../../../mitigations/SAF-M-75/README.md)

## Requirements

| Requirement | Required behavior | Acceptance test |
| --- | --- | --- |
| ACP-R001: Independent enforcement | The deployment MUST enforce isolation outside the agent-controlled runtime; the agent MUST NOT administer the host, broker, hypervisor, or their credentials. | [ACP-V001](../VALIDATION.md#acp-v001) |
| ACP-R002: Broker-only external effects | All agent-caused network, file-sharing, messaging, and service effects MUST pass through the broker. Direct outbound connections MUST be denied. | [ACP-V002](../VALIDATION.md#acp-v002) |
| ACP-R003: Descendant inheritance | Child processes, nested runtimes, delegated workers, and subsidiary agents MUST inherit an equal or narrower ceiling and MUST NOT acquire ambient host capabilities. | [ACP-V003](../VALIDATION.md#acp-v003) |
| ACP-R004: Complete channel inventory | The boundary inventory MUST include DNS, inherited sockets, IPC, mounts, clipboard, display, devices, telemetry, updates, crash reports, and remote model inference. | [ACP-V004](../VALIDATION.md#acp-v004) |

## ACP-A001: Unbrokered server control channel

**Context:** Command and Control; SAF Core and MCP deployment views.

**Classification:** [SAF-T1903: Malicious Server Control Channel](../../../techniques/SAF-T1903/README.md) — `procedure_example`. A bounded deployment example of the registered mechanism; no new incident or evidence-status claim.

**Preconditions:** A malicious local MCP server or child has an ambient network path.

**Inert procedure:** The server opens a separate operator channel that receives inert commands and returns test status without broker approval.

**Proposed detection evidence:** Runtime process lineage plus an external connection with no matching broker execution receipt.

**Legitimate lookalikes and limits:** A registered broker health check can resemble a callback; correlate the originating process and permission. Agent-authored logs alone cannot establish the boundary decision.

**Required controls:** [SAF-M-75](../../../mitigations/SAF-M-75/README.md).

**Acceptance:** [ACP-V001](../VALIDATION.md#acp-v001), [ACP-V002](../VALIDATION.md#acp-v002), [ACP-V003](../VALIDATION.md#acp-v003), [ACP-V004](../VALIDATION.md#acp-v004). Tests are planned, not executed.

## ACP-A002: Inherited host-management channel

**Context:** Privilege Escalation; SAF Core and MCP deployment views.

**Classification:** [SAF-T1303: Sandbox Escape via Server Exec](../../../techniques/SAF-T1303/README.md) — `procedure_example`. A bounded deployment example of the registered mechanism; no new incident or evidence-status claim.

**Preconditions:** A tool process inherits a host-management socket or privileged mount.

**Inert procedure:** An inert server-exec request reaches a host-side capability beyond the intended sandbox.

**Proposed detection evidence:** Inherited descriptor or mount inventory; process execution outside the approved isolation identity.

**Legitimate lookalikes and limits:** An authorized maintenance process is not an escape; distinguish the agent execution tree. Agent-authored logs alone cannot establish the boundary decision.

**Required controls:** [SAF-M-75](../../../mitigations/SAF-M-75/README.md).

**Acceptance:** [ACP-V001](../VALIDATION.md#acp-v001), [ACP-V003](../VALIDATION.md#acp-v003), [ACP-V004](../VALIDATION.md#acp-v004). Tests are planned, not executed.

**MITRE ATT&CK context:** [T1611: Escape to Host](https://attack.mitre.org/techniques/T1611/) (analogous). These external mappings do not alter the repository's canonical tactic model.

## ACP-A003: Delegate with a larger capability ceiling

**Context:** Privilege Escalation; SAF Core and MCP deployment views.

**Classification:** [SAF-T1302: Agentic Confused Deputy](../../../techniques/SAF-T1302/README.md) — `procedure_example`. A bounded deployment example of the registered mechanism; no new incident or evidence-status claim.

**Preconditions:** A worker launcher can issue authority beyond the initiating task.

**Inert procedure:** The agent asks a deputy to create a worker with a resource permission absent from its own delegation.

**Proposed detection evidence:** Parent and child delegation scopes, issuer, owner approval, and worker launch event.

**Legitimate lookalikes and limits:** A separately approved administrator-created worker may legitimately have a different scope. Agent-authored logs alone cannot establish the boundary decision.

**Required controls:** [SAF-M-75](../../../mitigations/SAF-M-75/README.md), [SAF-M-80](../../../mitigations/SAF-M-80/README.md).

**Acceptance:** [ACP-V003](../VALIDATION.md#acp-v003), [ACP-V024](../VALIDATION.md#acp-v024), [ACP-V026](../VALIDATION.md#acp-v026). Tests are planned, not executed.

## ACP-A004: Background diagnostic disclosure

**Context:** Exfiltration; SAF Core and MCP deployment views.

**Classification:** [SAF-T1910: Covert Channel Exfiltration](../../../techniques/SAF-T1910/README.md) — `procedure_example`. A bounded deployment example of the registered mechanism; no new incident or evidence-status claim.

**Preconditions:** Crash reporting or telemetry can read agent context and send outside the broker.

**Inert procedure:** An inert confidential marker is carried in a diagnostic request to an unapproved local test sink.

**Proposed detection evidence:** Diagnostic upload destination, data classification, runtime origin, and missing release decision.

**Legitimate lookalikes and limits:** A minimal approved crash report may be legitimate; field content and recipient determine the distinction. Agent-authored logs alone cannot establish the boundary decision.

**Required controls:** [SAF-M-75](../../../mitigations/SAF-M-75/README.md), [SAF-M-79](../../../mitigations/SAF-M-79/README.md), [SAF-M-81](../../../mitigations/SAF-M-81/README.md).

**Acceptance:** [ACP-V002](../VALIDATION.md#acp-v002), [ACP-V004](../VALIDATION.md#acp-v004), [ACP-V008](../VALIDATION.md#acp-v008), [ACP-V027](../VALIDATION.md#acp-v027). Tests are planned, not executed.

**MITRE ATT&CK context:** [T1567: Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/) (analogous). These external mappings do not alter the repository's canonical tactic model.
