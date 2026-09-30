# Independent audit, shutdown, and recovery

[Profile index](../README.md) | [Machine-readable catalog](../catalog.yml)

These are proposed, inert deployment assessments, not new canonical techniques or observed incidents. Detection ideas are proposed; acceptance tests require a deployed system.

**Primary control:** [SAF-M-81: Fail-Closed Containment Operations](../../../mitigations/SAF-M-81/README.md)

## Requirements

| Requirement | Required behavior | Acceptance test |
| --- | --- | --- |
| ACP-R022: Independent stop | Authorized operators MUST be able to pause execution and revoke external authority through a path unavailable to the agent. | [ACP-V022](../VALIDATION.md#acp-v022) |
| ACP-R027: Independent audit | The audit service MUST record allocation, claim, validation, authorization, execution, denial, revocation, and policy changes outside agent control while excluding secrets and unnecessary personal data. | [ACP-V027](../VALIDATION.md#acp-v027) |
| ACP-R028: Budgets and fail-closed behavior | Attempts, concurrency, compute, sampling, output, and retries MUST have enforceable budgets. Failure of approval, ledger, clock policy, or audit dependencies MUST NOT create new external permission. | [ACP-V028](../VALIDATION.md#acp-v028) |
| ACP-R029: Side-channel scope | The threat model MUST inventory relevant timing, length, error, feedback, shared-resource, sensor, and physical channels; it MUST distinguish evaluated channels from unmeasured ones. | [ACP-V029](../VALIDATION.md#acp-v029) |

## ACP-A024: Approval pressure through repeated requests

**Context:** Defense Evasion; SAF Core and MCP deployment views.

**Classification:** [SAF-T1403: Consent-Fatigue Exploit](../../../techniques/SAF-T1403/README.md) — `procedure_example`. A bounded deployment example of the registered mechanism; no new incident or evidence-status claim.

**Preconditions:** The agent can repeatedly request substantially equivalent owner approvals.

**Inert procedure:** A synthetic request sequence pressures an operator to accept a broadened permission to stop the interruptions.

**Proposed detection evidence:** Equivalent-context request counts, deny history, cooldowns, actual approvals, and independent stop availability.

**Legitimate lookalikes and limits:** Legitimate retries must be distinguished from escalation or consent pressure using context and budget. Agent-authored logs alone cannot establish the boundary decision.

**Required controls:** [SAF-M-76](../../../mitigations/SAF-M-76/README.md), [SAF-M-81](../../../mitigations/SAF-M-81/README.md).

**Acceptance:** [ACP-V012](../VALIDATION.md#acp-v012), [ACP-V013](../VALIDATION.md#acp-v013), [ACP-V022](../VALIDATION.md#acp-v022), [ACP-V028](../VALIDATION.md#acp-v028). Tests are planned, not executed.

## ACP-A025: One-use attempts exhausted to force fail-open recovery

**Context:** Impact; SAF Core and MCP deployment views.

**Classification:** [SAF-T2102: Service Disruption](../../../techniques/SAF-T2102/README.md) — `procedure_example`. A bounded deployment example of the registered mechanism; no new incident or evidence-status claim.

**Preconditions:** An attacker can flood allocation or consume another party's event attempts.

**Inert procedure:** A bounded local test exhausts attempt capacity and then requests a fallback that bypasses owner verification.

**Proposed detection evidence:** Authenticated allocator, tenant quotas, claim denial reasons, recovery policy, and any effects during outage.

**Legitimate lookalikes and limits:** Ordinary load and network retransmissions can exhaust capacity; containment must hold regardless of intent. Agent-authored logs alone cannot establish the boundary decision.

**Required controls:** [SAF-M-77](../../../mitigations/SAF-M-77/README.md), [SAF-M-81](../../../mitigations/SAF-M-81/README.md).

**Acceptance:** [ACP-V014](../VALIDATION.md#acp-v014), [ACP-V015](../VALIDATION.md#acp-v015), [ACP-V016](../VALIDATION.md#acp-v016), [ACP-V022](../VALIDATION.md#acp-v022), [ACP-V028](../VALIDATION.md#acp-v028). Tests are planned, not executed.

## ACP-A026: Agent removes containment audit configuration

**Context:** Impact; SAF Core and MCP deployment views.

**Classification:** [SAF-T2103: Code Sabotage](../../../techniques/SAF-T2103/README.md) — `procedure_example`. A bounded deployment example of the registered mechanism; no new incident or evidence-status claim.

**Preconditions:** Agent-visible configuration controls the only audit or enforcement record.

**Inert procedure:** An inert code change disables the audit sink before a protected-operation request.

**Proposed detection evidence:** Audit configuration mutation, independent heartbeat, policy activation record, and unexplained event gaps.

**Legitimate lookalikes and limits:** A planned maintenance window requires independent approval and a protected alternate audit path. Agent-authored logs alone cannot establish the boundary decision.

**Required controls:** [SAF-M-75](../../../mitigations/SAF-M-75/README.md), [SAF-M-78](../../../mitigations/SAF-M-78/README.md), [SAF-M-81](../../../mitigations/SAF-M-81/README.md).

**Acceptance:** [ACP-V001](../VALIDATION.md#acp-v001), [ACP-V019](../VALIDATION.md#acp-v019), [ACP-V027](../VALIDATION.md#acp-v027), [ACP-V028](../VALIDATION.md#acp-v028). Tests are planned, not executed.
