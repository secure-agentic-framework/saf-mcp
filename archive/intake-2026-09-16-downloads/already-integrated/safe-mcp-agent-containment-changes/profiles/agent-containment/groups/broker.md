# Broker requests and information release

[Profile index](../README.md) | [Machine-readable catalog](../catalog.yml)

These are proposed, inert deployment assessments, not new canonical techniques or observed incidents. Detection ideas are proposed; acceptance tests require a deployed system.

**Primary control:** [SAF-M-79: Disclosure-Bounded Tool Brokering](../../../mitigations/SAF-M-79/README.md)

## Requirements

| Requirement | Required behavior | Acceptance test |
| --- | --- | --- |
| ACP-R005: Typed requests | The broker MUST accept schema-validated operations on registered resources; agent text MUST NOT become arbitrary broker code, shell commands, or open-ended forwarding instructions. | [ACP-V005](../VALIDATION.md#acp-v005) |
| ACP-R006: Broker-owned service credentials | External service credentials MUST remain outside the runtime, prompts, tool results, environment variables, shared files, and diagnostic output. | [ACP-V006](../VALIDATION.md#acp-v006) |
| ACP-R007: Destination and operation binding | The broker MUST bind service, resource, method, recipient, and resolved destination; redirects, address changes, and metadata or loopback access require explicit authorization. | [ACP-V007](../VALIDATION.md#acp-v007) |
| ACP-R008: Explicit disclosure boundary | Every outgoing argument, generated file, report, browser render, and message MUST have an authorized recipient, permitted content scope, and release decision. Arbitrary output MUST NOT be described as zero leakage. | [ACP-V008](../VALIDATION.md#acp-v008) |
| ACP-R009: Minimum input access | The broker MUST minimize records, fields, and task context supplied to the agent and MUST treat remote inference as a disclosure to the model provider. | [ACP-V009](../VALIDATION.md#acp-v009) |

## ACP-A005: Broker destination substitution

**Context:** Privilege Escalation; SAF Core and MCP deployment views.

**Classification:** [SAF-T1307: Confused Deputy Attack](../../../techniques/SAF-T1307/README.md) — `procedure_example`. A bounded deployment example of the registered mechanism; no new incident or evidence-status claim.

**Preconditions:** The broker accepts agent-selected URLs, redirect destinations, or resource aliases.

**Inert procedure:** A permitted resource request is redirected to a different local test service that the initiating agent cannot access.

**Proposed detection evidence:** Requested resource, resolved addresses, redirect chain, effective service identity, and authorization decision.

**Legitimate lookalikes and limits:** Routine address changes are not automatically malicious; approval must cover the actual resolved service. Agent-authored logs alone cannot establish the boundary decision.

**Required controls:** [SAF-M-76](../../../mitigations/SAF-M-76/README.md), [SAF-M-79](../../../mitigations/SAF-M-79/README.md).

**Acceptance:** [ACP-V005](../VALIDATION.md#acp-v005), [ACP-V007](../VALIDATION.md#acp-v007), [ACP-V012](../VALIDATION.md#acp-v012). Tests are planned, not executed.

## ACP-A006: Secret carried in a permitted tool argument

**Context:** Exfiltration; SAF Core and MCP deployment views.

**Classification:** [SAF-T1911: Parameter Exfiltration](../../../techniques/SAF-T1911/README.md) — `procedure_example`. A bounded deployment example of the registered mechanism; no new incident or evidence-status claim.

**Preconditions:** The agent knows protected data and can choose outbound argument values.

**Inert procedure:** A synthetic secret marker is placed in an otherwise valid tool argument sent to an unauthorized test recipient.

**Proposed detection evidence:** Argument classification, intended recipient, actual recipient, request approval, and sink receipt.

**Legitimate lookalikes and limits:** The same field may legitimately contain public text; test data classification and authorized purpose. Agent-authored logs alone cannot establish the boundary decision.

**Required controls:** [SAF-M-79](../../../mitigations/SAF-M-79/README.md).

**Acceptance:** [ACP-V005](../VALIDATION.md#acp-v005), [ACP-V007](../VALIDATION.md#acp-v007), [ACP-V008](../VALIDATION.md#acp-v008), [ACP-V009](../VALIDATION.md#acp-v009). Tests are planned, not executed.

**MITRE ATT&CK context:** [T1567: Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/) (analogous). These external mappings do not alter the repository's canonical tactic model.

## ACP-A007: Context forwarded to an outside model

**Context:** Exfiltration; SAF Core and MCP deployment views.

**Classification:** [SAF-T1914: Tool-to-Tool Exfil](../../../techniques/SAF-T1914/README.md) — `procedure_example`. A bounded deployment example of the registered mechanism; no new incident or evidence-status claim.

**Preconditions:** A source tool returns confidential records and a distinct remote inference tool can transmit them.

**Inert procedure:** The agent forwards source-tool context to the outside model without an authorized disclosure for that recipient.

**Proposed detection evidence:** Source record IDs, downstream model destination, request lineage, and disclosure authorization.

**Legitimate lookalikes and limits:** An explicitly approved remote inference workload is a permitted disclosure, not evidence of theft. Agent-authored logs alone cannot establish the boundary decision.

**Required controls:** [SAF-M-75](../../../mitigations/SAF-M-75/README.md), [SAF-M-79](../../../mitigations/SAF-M-79/README.md).

**Acceptance:** [ACP-V004](../VALIDATION.md#acp-v004), [ACP-V008](../VALIDATION.md#acp-v008), [ACP-V009](../VALIDATION.md#acp-v009). Tests are planned, not executed.

**MITRE ATT&CK context:** [T1567: Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/) (analogous). These external mappings do not alter the repository's canonical tactic model.

## ACP-A008: Covert content in an approved report

**Context:** Exfiltration; SAF Core and MCP deployment views.

**Classification:** [SAF-T1902: Response-Borne Covert Channel](../../../techniques/SAF-T1902/README.md) — `procedure_example`. A bounded deployment example of the registered mechanism; no new incident or evidence-status claim.

**Preconditions:** An agent may return arbitrary text or rendered content to a recipient who should not receive its private context.

**Inert procedure:** An inert marker is encoded in a report or rendering callback that reaches an unapproved local receiver.

**Proposed detection evidence:** Output recipient, render-initiated requests, content scope, output size, and release receipt.

**Legitimate lookalikes and limits:** Legitimate formatting and encoded public data are lookalikes; semantic filters alone cannot establish absence. Agent-authored logs alone cannot establish the boundary decision.

**Required controls:** [SAF-M-79](../../../mitigations/SAF-M-79/README.md), [SAF-M-81](../../../mitigations/SAF-M-81/README.md).

**Acceptance:** [ACP-V008](../VALIDATION.md#acp-v008), [ACP-V009](../VALIDATION.md#acp-v009), [ACP-V029](../VALIDATION.md#acp-v029). Tests are planned, not executed.

**MITRE ATT&CK context:** [T1567: Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/) (analogous). These external mappings do not alter the repository's canonical tactic model.
