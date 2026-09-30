# Agent identity and bounded delegation

[Profile index](../README.md) | [Machine-readable catalog](../catalog.yml)

These are proposed, inert deployment assessments, not new canonical techniques or observed incidents. Detection ideas are proposed; acceptance tests require a deployed system.

**Primary control:** [SAF-M-80: Owner-Separated Agent Delegation](../../../mitigations/SAF-M-80/README.md)

## Requirements

| Requirement | Required behavior | Acceptance test |
| --- | --- | --- |
| ACP-R023: Distinct machine identity | Agent actions MUST identify the agent and its delegating owner separately; routine machine requests MUST NOT be recorded as fresh personal owner approvals. | [ACP-V023](../VALIDATION.md#acp-v023) |
| ACP-R024: Scoped and expiring delegation | Delegations MUST bind the owner, agent, audience, permitted operation and resources, policy version, expiry, and revocation state; they MUST exclude owner-policy-change authority. | [ACP-V024](../VALIDATION.md#acp-v024) |
| ACP-R025: Receiver-enforced binding | Every downstream hop MUST validate the initiating principal, resource, and delegated scope; forwarding an accepted proof or credential MUST NOT transfer owner authority to another session or audience. | [ACP-V025](../VALIDATION.md#acp-v025) |
| ACP-R026: Subdelegation ceiling | An agent-created worker MUST receive an equal or smaller authority set, never the owner approval capability; its lineage and revocation dependency MUST be recorded. | [ACP-V026](../VALIDATION.md#acp-v026) |

## ACP-A021: Agent authority presented as personal owner approval

**Context:** Privilege Escalation; SAF Core and MCP deployment views.

**Classification:** [SAF-T1302: Agentic Confused Deputy](../../../techniques/SAF-T1302/README.md) — `procedure_example`. A bounded deployment example of the registered mechanism; no new incident or evidence-status claim.

**Preconditions:** A downstream service equates routine agent credentials with unrestricted owner authority.

**Inert procedure:** A task-scoped machine request is accepted as the owner personally approving a policy or payment change.

**Proposed detection evidence:** Owner and agent principals, delegation ID, operation, approval origin, and receiving service decision.

**Legitimate lookalikes and limits:** An agent may legitimately perform a delegated task; personal approval must remain separately recorded. Agent-authored logs alone cannot establish the boundary decision.

**Required controls:** [SAF-M-76](../../../mitigations/SAF-M-76/README.md), [SAF-M-80](../../../mitigations/SAF-M-80/README.md), [SAF-M-81](../../../mitigations/SAF-M-81/README.md).

**Acceptance:** [ACP-V013](../VALIDATION.md#acp-v013), [ACP-V023](../VALIDATION.md#acp-v023), [ACP-V024](../VALIDATION.md#acp-v024), [ACP-V027](../VALIDATION.md#acp-v027). Tests are planned, not executed.

## ACP-A022: Delegation widened at the next service

**Context:** Privilege Escalation; SAF Core and MCP deployment views.

**Classification:** [SAF-T1308: Token Scope Substitution](../../../techniques/SAF-T1308/README.md) — `procedure_example`. A bounded deployment example of the registered mechanism; no new incident or evidence-status claim.

**Preconditions:** A grant is not bound to its intended resource or operation at the next authorization hop.

**Inert procedure:** A benign task token is accepted for a different service or a broader permission set.

**Proposed detection evidence:** Original grant audience and scope, exchanged claims, receiver validation, and requested operation.

**Legitimate lookalikes and limits:** Intentional reauthorization is legitimate only when issued by an authorized principal for the new context. Agent-authored logs alone cannot establish the boundary decision.

**Required controls:** [SAF-M-80](../../../mitigations/SAF-M-80/README.md).

**Acceptance:** [ACP-V024](../VALIDATION.md#acp-v024), [ACP-V025](../VALIDATION.md#acp-v025), [ACP-V026](../VALIDATION.md#acp-v026). Tests are planned, not executed.

**MITRE ATT&CK context:** [T1550.001: Use Alternate Authentication Material: Application Access Token](https://attack.mitre.org/techniques/T1550/001/) (analogous). These external mappings do not alter the repository's canonical tactic model.

## ACP-A023: Live approval relayed through the wrong endpoint

**Context:** Defense Evasion; SAF Core and MCP deployment views.

**Classification:** [SAF-T1407: Server Proxy Masquerade](../../../techniques/SAF-T1407/README.md) — `related_context`. A live owner-proof relay is not necessarily an MCP proxy masquerade. Endpoint and authority confusion are the related boundary.

**Preconditions:** A proxy can forward current owner responses without the protected UI binding the real recipient and action.

**Inert procedure:** The local relay forwards a fresh inert approval to an unintended relying service without recovering the secret.

**Proposed detection evidence:** Displayed relying service, authenticated verifier, session origin, relay endpoint, and result audience.

**Legitimate lookalikes and limits:** Authorized proxies require explicit hop binding; secret non-disclosure alone does not distinguish them. Agent-authored logs alone cannot establish the boundary decision.

**Required controls:** [SAF-M-76](../../../mitigations/SAF-M-76/README.md), [SAF-M-77](../../../mitigations/SAF-M-77/README.md), [SAF-M-80](../../../mitigations/SAF-M-80/README.md), [SAF-M-82](../../../mitigations/SAF-M-82/README.md).

**Acceptance:** [ACP-V011](../VALIDATION.md#acp-v011), [ACP-V012](../VALIDATION.md#acp-v012), [ACP-V017](../VALIDATION.md#acp-v017), [ACP-V025](../VALIDATION.md#acp-v025), [ACP-V034](../VALIDATION.md#acp-v034). Tests are planned, not executed.
