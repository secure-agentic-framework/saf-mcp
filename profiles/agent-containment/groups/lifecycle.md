# Policy, enrollment, and recovery lifecycle

[Profile index](../README.md) | [Machine-readable catalog](../catalog.yml)

These are proposed, inert deployment assessments, not new canonical techniques or observed incidents. Detection ideas are proposed; acceptance tests require a deployed system.

**Primary control:** [SAF-M-78: Enrollment and Policy Lifecycle Integrity](../../../mitigations/SAF-M-78/README.md)

## Requirements

| Requirement | Required behavior | Acceptance test |
| --- | --- | --- |
| ACP-R019: Protected policy changes | A policy version MUST be immutable once approved. Replacing it MUST require a new owner-authorized event bound to the old and proposed versions; the agent may propose but not install changes. | [ACP-V019](../VALIDATION.md#acp-v019) |
| ACP-R020: Revocation and rollback resistance | The controller MUST reject revoked owners, agents, delegations, enrollments, and superseded policy versions, including after restart and replica recovery. | [ACP-V020](../VALIDATION.md#acp-v020) |
| ACP-R021: Updates and recovery | Updates, administrative recovery, emergency access, and verifier replacement MUST preserve owner approval and containment; a software digest alone MUST NOT count as execution attestation. | [ACP-V021](../VALIDATION.md#acp-v021) |
| ACP-R030: Governed ownership and recovery | Ownership transfer and recovery MUST require designated organizational authority, revoke replaced bindings, and support a documented human fallback without general agent bypass. | [ACP-V030](../VALIDATION.md#acp-v030) |

## ACP-A017: Self-modified containment policy

**Context:** Impact; SAF Core and MCP deployment views.

**Classification:** [SAF-T2103: Code Sabotage](../../../techniques/SAF-T2103/README.md) — `procedure_example`. A bounded deployment example of the registered mechanism; no new incident or evidence-status claim.

**Preconditions:** The coding or file agent can write configuration used by its enforcement boundary.

**Inert procedure:** A harmless local policy fixture is edited to broaden its own egress or administrative permissions.

**Proposed detection evidence:** Policy file change, parent version, approver event, executing policy fingerprint, and authoring process.

**Legitimate lookalikes and limits:** Authorized policy development may edit a proposal; activation is the privileged boundary. Agent-authored logs alone cannot establish the boundary decision.

**Required controls:** [SAF-M-75](../../../mitigations/SAF-M-75/README.md), [SAF-M-78](../../../mitigations/SAF-M-78/README.md), [SAF-M-81](../../../mitigations/SAF-M-81/README.md).

**Acceptance:** [ACP-V001](../VALIDATION.md#acp-v001), [ACP-V019](../VALIDATION.md#acp-v019), [ACP-V021](../VALIDATION.md#acp-v021), [ACP-V027](../VALIDATION.md#acp-v027). Tests are planned, not executed.

**MITRE ATT&CK context:** [T1686: Disable or Modify System Firewall](https://attack.mitre.org/techniques/T1686/) (analogous). These external mappings do not alter the repository's canonical tactic model.

## ACP-A018: Owner reference substituted in configuration

**Context:** Persistence; SAF Core and MCP deployment views.

**Classification:** [SAF-T1206: Credential Implant in Config](../../../techniques/SAF-T1206/README.md) — `procedure_example`. A bounded deployment example of the registered mechanism; no new incident or evidence-status claim.

**Preconditions:** The agent can replace a persistent enrollment or credential reference consumed by the controller.

**Inert procedure:** An inert configuration substitutes an attacker-owned reference while preserving the visible owner label.

**Proposed detection evidence:** Enrollment identity, credential-reference change, owner transfer receipt, and current revocation epoch.

**Legitimate lookalikes and limits:** A legitimate ownership transfer requires independent approval and retirement of the old binding. Agent-authored logs alone cannot establish the boundary decision.

**Required controls:** [SAF-M-76](../../../mitigations/SAF-M-76/README.md), [SAF-M-78](../../../mitigations/SAF-M-78/README.md), [SAF-M-82](../../../mitigations/SAF-M-82/README.md).

**Acceptance:** [ACP-V010](../VALIDATION.md#acp-v010), [ACP-V020](../VALIDATION.md#acp-v020), [ACP-V030](../VALIDATION.md#acp-v030), [ACP-V033](../VALIDATION.md#acp-v033). Tests are planned, not executed.

## ACP-A019: Update activates an older permissive controller

**Context:** Persistence; SAF Core and MCP deployment views.

**Classification:** [SAF-T1207: Hijack Update Mechanism](../../../techniques/SAF-T1207/README.md) — `procedure_example`. A bounded deployment example of the registered mechanism; no new incident or evidence-status claim.

**Preconditions:** The normal updater accepts an unapproved or obsolete enforcement version.

**Inert procedure:** An inert update fixture retains an approved name while replacing the active controller with an older policy interpretation.

**Proposed detection evidence:** Update provenance, version floor, binary identity, running attestation, and policy migration approval.

**Legitimate lookalikes and limits:** An authorized rollback may be safe only if current security policy and revocation requirements still hold. Agent-authored logs alone cannot establish the boundary decision.

**Required controls:** [SAF-M-78](../../../mitigations/SAF-M-78/README.md).

**Acceptance:** [ACP-V019](../VALIDATION.md#acp-v019), [ACP-V020](../VALIDATION.md#acp-v020), [ACP-V021](../VALIDATION.md#acp-v021). Tests are planned, not executed.

## ACP-A020: Recovery used as an owner-approval bypass

**Context:** Privilege Escalation; SAF Core and MCP deployment views.

**Classification:** [SAF-T1302: Agentic Confused Deputy](../../../techniques/SAF-T1302/README.md) — `procedure_example`. A bounded deployment example of the registered mechanism; no new incident or evidence-status claim.

**Preconditions:** A recovery deputy trusts agent-reachable credentials or caller-declared emergencies.

**Inert procedure:** An inert emergency request attempts to reset the owner binding and widen firewall access without designated approvers.

**Proposed detection evidence:** Recovery actor, designated approver set, scope change, revocation updates, and external effects.

**Legitimate lookalikes and limits:** An approved human fallback remains legitimate when it preserves the same authority boundary. Agent-authored logs alone cannot establish the boundary decision.

**Required controls:** [SAF-M-76](../../../mitigations/SAF-M-76/README.md), [SAF-M-78](../../../mitigations/SAF-M-78/README.md), [SAF-M-81](../../../mitigations/SAF-M-81/README.md).

**Acceptance:** [ACP-V013](../VALIDATION.md#acp-v013), [ACP-V021](../VALIDATION.md#acp-v021), [ACP-V022](../VALIDATION.md#acp-v022), [ACP-V030](../VALIDATION.md#acp-v030). Tests are planned, not executed.

**MITRE ATT&CK context:** [T1686: Disable or Modify System Firewall](https://attack.mitre.org/techniques/T1686/) (analogous). These external mappings do not alter the repository's canonical tactic model.
