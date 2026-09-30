# Owner identity and protected approval

[Profile index](../README.md) | [Machine-readable catalog](../catalog.yml)

These are proposed, inert deployment assessments, not new canonical techniques or observed incidents. Detection ideas are proposed; acceptance tests require a deployed system.

**Primary control:** [SAF-M-76: Protected Owner Approval Path](../../../mitigations/SAF-M-76/README.md)

## Requirements

| Requirement | Required behavior | Acceptance test |
| --- | --- | --- |
| ACP-R010: Binding enrollment | Enrollment MUST bind an established owner identity to the agent, protected approval mechanism, verifier identity, credential reference, and current policy version. | [ACP-V010](../VALIDATION.md#acp-v010) |
| ACP-R011: Protected display and input | The owner interaction MUST use a path the agent cannot render over, read, keylog, screen-capture, or control through accessibility or automation interfaces. | [ACP-V011](../VALIDATION.md#acp-v011) |
| ACP-R012: Exact-action approval | The protected display MUST show the relying service, operation, resource, material parameters, recipient, session, expiry, and policy change, and approval MUST bind those immutable values. | [ACP-V012](../VALIDATION.md#acp-v012) |
| ACP-R013: Exclusive approval attribution | Only the designated protected mechanism MAY produce owner-attributable approval. Agent-authored flags, simulated clicks, model text, and ordinary tool responses MUST NOT substitute for it. | [ACP-V013](../VALIDATION.md#acp-v013) |

## ACP-A009: Counterfeit owner approval interface

**Context:** Credential Access; SAF Core and MCP deployment views.

**Classification:** [SAF-T1302: Agentic Confused Deputy](../../../techniques/SAF-T1302/README.md) — `related_context`. Counterfeit GUI capture is a conventional input-capture behavior; SAF-T1302 covers the adjacent misuse of the resulting owner authority.

**Preconditions:** The agent can display a form resembling the protected approval interface.

**Inert procedure:** A mock form collects synthetic owner input or claims that its local button is authoritative.

**Proposed detection evidence:** UI origin and protected-path provenance; owner-authenticator events; absence of a genuine approval receipt.

**Legitimate lookalikes and limits:** A non-authoritative preview is legitimate only if it cannot collect secrets or produce authority. Agent-authored logs alone cannot establish the boundary decision.

**Required controls:** [SAF-M-76](../../../mitigations/SAF-M-76/README.md).

**Acceptance:** [ACP-V010](../VALIDATION.md#acp-v010), [ACP-V011](../VALIDATION.md#acp-v011), [ACP-V013](../VALIDATION.md#acp-v013). Tests are planned, not executed.

**MITRE ATT&CK context:** [T1056.002: Input Capture: GUI Input Capture](https://attack.mitre.org/techniques/T1056/002/) (analogous). These external mappings do not alter the repository's canonical tactic model.

## ACP-A010: Owner input captured before protection

**Context:** Credential Access; SAF Core and MCP deployment views.

**Classification:** [SAF-T1505: In-Memory Secret Extraction](../../../techniques/SAF-T1505/README.md) — `related_context`. Keylogging is distinct from the live-state extraction contract of SAF-T1505; this join supplies credential-boundary context only.

**Preconditions:** The approval keyboard, screen, accessibility path, or input buffer is visible to the runtime.

**Inert procedure:** An inert capture probe obtains synthetic private input before it is transformed into a released response.

**Proposed detection evidence:** Input-device permissions, screen-capture access, process memory access, and synthetic canary exposure.

**Legitimate lookalikes and limits:** Approved accessibility support belongs inside the protected boundary; ordinary agent automation does not. Agent-authored logs alone cannot establish the boundary decision.

**Required controls:** [SAF-M-76](../../../mitigations/SAF-M-76/README.md), [SAF-M-79](../../../mitigations/SAF-M-79/README.md), [SAF-M-82](../../../mitigations/SAF-M-82/README.md).

**Acceptance:** [ACP-V006](../VALIDATION.md#acp-v006), [ACP-V011](../VALIDATION.md#acp-v011), [ACP-V033](../VALIDATION.md#acp-v033). Tests are planned, not executed.

**MITRE ATT&CK context:** [T1056.001: Input Capture: Keylogging](https://attack.mitre.org/techniques/T1056/001/) (analogous). These external mappings do not alter the repository's canonical tactic model.

## ACP-A011: Agent-authored approval assertion

**Context:** Privilege Escalation; SAF Core and MCP deployment views.

**Classification:** [SAF-T1302: Agentic Confused Deputy](../../../techniques/SAF-T1302/README.md) — `procedure_example`. A bounded deployment example of the registered mechanism; no new incident or evidence-status claim.

**Preconditions:** A privileged deputy accepts model text or caller-supplied approval fields.

**Inert procedure:** An inert request asserts that the owner approved a policy change although no protected approval occurred.

**Proposed detection evidence:** Approval issuer, protected ceremony receipt, request context, and attempted privileged dispatch.

**Legitimate lookalikes and limits:** An agent may relay an authentic receipt; authenticity must be independently established. Agent-authored logs alone cannot establish the boundary decision.

**Required controls:** [SAF-M-76](../../../mitigations/SAF-M-76/README.md).

**Acceptance:** [ACP-V010](../VALIDATION.md#acp-v010), [ACP-V012](../VALIDATION.md#acp-v012), [ACP-V013](../VALIDATION.md#acp-v013). Tests are planned, not executed.

## ACP-A012: Approved action replaced before dispatch

**Context:** Privilege Escalation; SAF Core and MCP deployment views.

**Classification:** [SAF-T1302: Agentic Confused Deputy](../../../techniques/SAF-T1302/README.md) — `procedure_example`. A bounded deployment example of the registered mechanism; no new incident or evidence-status claim.

**Preconditions:** The approved display and executed request are not bound to the same immutable values.

**Inert procedure:** After a benign local approval, the recipient or operation is changed before broker dispatch.

**Proposed detection evidence:** Approved context digest, dispatched context digest, approver identity, and external action receipt.

**Legitimate lookalikes and limits:** A change requested by the owner is legitimate only with a fresh matching approval. Agent-authored logs alone cannot establish the boundary decision.

**Required controls:** [SAF-M-76](../../../mitigations/SAF-M-76/README.md), [SAF-M-77](../../../mitigations/SAF-M-77/README.md).

**Acceptance:** [ACP-V012](../VALIDATION.md#acp-v012), [ACP-V014](../VALIDATION.md#acp-v014), [ACP-V017](../VALIDATION.md#acp-v017), [ACP-V018](../VALIDATION.md#acp-v018). Tests are planned, not executed.
