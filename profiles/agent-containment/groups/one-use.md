# One-use approval and authenticated results

[Profile index](../README.md) | [Machine-readable catalog](../catalog.yml)

These are proposed, inert deployment assessments, not new canonical techniques or observed incidents. Detection ideas are proposed; acceptance tests require a deployed system.

**Primary control:** [SAF-M-77: Durable Single-Use Action Authorization](../../../mitigations/SAF-M-77/README.md)

## Requirements

| Requirement | Required behavior | Acceptance test |
| --- | --- | --- |
| ACP-R014: Event allocation | Each approval attempt MUST have a unique full event identifier bound to its tenant, enrollment, agent, verifier, request, session, policy, expiry, and private resource allocation. | [ACP-V014](../VALIDATION.md#acp-v014) |
| ACP-R015: Atomic attempt consumption | After transport authentication and event-routing checks, the verifier MUST atomically claim one eligible attempt before substantive witness validation; accept, reject, or abort MUST NOT reopen that attempt. | [ACP-V015](../VALIDATION.md#acp-v015) |
| ACP-R016: Conservative crash recovery | Expiry, abort, and uncertain recovery MUST retire the event and any allocated private masks. Replica restoration MUST NOT make a consumed allocation available again. | [ACP-V016](../VALIDATION.md#acp-v016) |
| ACP-R017: Authenticated verifier result | The controller MUST authenticate the verifier result and its complete context, including issuer, audience, agent, enrollment, policy, event, request, result, and expiry. A public success bit MUST NOT authorize an action. | [ACP-V017](../VALIDATION.md#acp-v017) |
| ACP-R018: Single execution | The controller MUST maintain durable execution state distinct from verification state and use downstream idempotency or reconciliation before retrying an uncertain external action. | [ACP-V018](../VALIDATION.md#acp-v018) |

## ACP-A013: Recorded success reused for another request

**Context:** Defense Evasion; SAF Core and MCP deployment views.

**Classification:** [SAF-T1404: Response Tampering](../../../techniques/SAF-T1404/README.md) — `procedure_example`. A bounded deployment example of the registered mechanism; no new incident or evidence-status claim.

**Preconditions:** A prior verifier result can be substituted into a new request context.

**Inert procedure:** The agent replays an inert success result under a different event, session, resource, or relying service.

**Proposed detection evidence:** Verdict provenance, event-to-context binding, consumer identity, expiry, and execution history.

**Legitimate lookalikes and limits:** Read-only retrieval of a prior result is not new authorization and must not execute an action. Agent-authored logs alone cannot establish the boundary decision.

**Required controls:** [SAF-M-77](../../../mitigations/SAF-M-77/README.md), [SAF-M-80](../../../mitigations/SAF-M-80/README.md).

**Acceptance:** [ACP-V014](../VALIDATION.md#acp-v014), [ACP-V017](../VALIDATION.md#acp-v017), [ACP-V018](../VALIDATION.md#acp-v018), [ACP-V025](../VALIDATION.md#acp-v025). Tests are planned, not executed.

## ACP-A014: Concurrent verification of one approval

**Context:** Privilege Escalation; SAF Core and MCP deployment views.

**Classification:** [SAF-T1706: OAuth Token Pivot Replay](../../../techniques/SAF-T1706/README.md) — `related_context`. SAF-T1706 is OAuth bearer replay. Concurrent one-use proof consumption is a different mechanism; this is related context, not an OAuth claim.

**Preconditions:** Multiple verifier or controller instances do not share atomic consumption state.

**Inert procedure:** Two simultaneous inert submissions use the same event and attempt to produce two authorized effects.

**Proposed detection evidence:** One event identifier with multiple successful claim transitions or separate execution receipts.

**Legitimate lookalikes and limits:** Duplicate delivery is common; it becomes a control failure only if eligibility or effects are duplicated. Agent-authored logs alone cannot establish the boundary decision.

**Required controls:** [SAF-M-77](../../../mitigations/SAF-M-77/README.md).

**Acceptance:** [ACP-V014](../VALIDATION.md#acp-v014), [ACP-V015](../VALIDATION.md#acp-v015), [ACP-V018](../VALIDATION.md#acp-v018). Tests are planned, not executed.

**MITRE ATT&CK context:** [T1550.001: Use Alternate Authentication Material: Application Access Token](https://attack.mitre.org/techniques/T1550/001/) (analogous). These external mappings do not alter the repository's canonical tactic model.

## ACP-A015: Consumed approval restored after a crash

**Context:** Privilege Escalation; SAF Core and MCP deployment views.

**Classification:** [SAF-T1706: OAuth Token Pivot Replay](../../../techniques/SAF-T1706/README.md) — `related_context`. SAF-T1706 is OAuth-specific. Restored approval state is an assessment scenario, not a newly observed instance of that technique.

**Preconditions:** Recovery can restore event eligibility or private allocations from a stale snapshot.

**Inert procedure:** An already consumed inert approval is accepted after restoring a verifier or execution store.

**Proposed detection evidence:** Recovery epoch, durable claim record, allocation identifier, and repeated execution receipt.

**Legitimate lookalikes and limits:** Legitimate disaster recovery must preserve consumed state or deny uncertain events. Agent-authored logs alone cannot establish the boundary decision.

**Required controls:** [SAF-M-77](../../../mitigations/SAF-M-77/README.md), [SAF-M-78](../../../mitigations/SAF-M-78/README.md), [SAF-M-82](../../../mitigations/SAF-M-82/README.md).

**Acceptance:** [ACP-V016](../VALIDATION.md#acp-v016), [ACP-V018](../VALIDATION.md#acp-v018), [ACP-V020](../VALIDATION.md#acp-v020), [ACP-V031](../VALIDATION.md#acp-v031). Tests are planned, not executed.

## ACP-A016: Forged remote verifier acceptance

**Context:** Defense Evasion; SAF Core and MCP deployment views.

**Classification:** [SAF-T1404: Response Tampering](../../../techniques/SAF-T1404/README.md) — `procedure_example`. A bounded deployment example of the registered mechanism; no new incident or evidence-status claim.

**Preconditions:** The controller accepts an unsigned or misbound remote success message.

**Inert procedure:** An inert substituted response claims acceptance from the wrong verifier or for the wrong audience.

**Proposed detection evidence:** Authenticated issuer and audience, complete bound context, result integrity check, and dispatch decision.

**Legitimate lookalikes and limits:** A transport retry from the same authenticated verifier still requires the original binding and consumption checks. Agent-authored logs alone cannot establish the boundary decision.

**Required controls:** [SAF-M-76](../../../mitigations/SAF-M-76/README.md), [SAF-M-77](../../../mitigations/SAF-M-77/README.md).

**Acceptance:** [ACP-V010](../VALIDATION.md#acp-v010), [ACP-V013](../VALIDATION.md#acp-v013), [ACP-V017](../VALIDATION.md#acp-v017). Tests are planned, not executed.
