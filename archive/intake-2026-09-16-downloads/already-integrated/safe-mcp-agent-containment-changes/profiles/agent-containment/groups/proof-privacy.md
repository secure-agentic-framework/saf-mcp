# Approval secrets and observation boundaries

[Profile index](../README.md) | [Machine-readable catalog](../catalog.yml)

These are proposed, inert deployment assessments, not new canonical techniques or observed incidents. Detection ideas are proposed; acceptance tests require a deployed system.

**Primary control:** [SAF-M-82: Protected Approval Secret Handling](../../../mitigations/SAF-M-82/README.md)

## Requirements

| Requirement | Required behavior | Acceptance test |
| --- | --- | --- |
| ACP-R031: Fresh private masking resources | An implementation claiming the supplied ENI6MA ideal transcript property MUST use the specified fresh independent secret masks without reusing allocations; a public nonce is not a secret mask. | [ACP-V031](../VALIDATION.md#acp-v031) |
| ACP-R032: Complete observation declaration | The privacy claim MUST name all information visible to the agent, including challenges, responses, timing, errors, acceptance feedback, recovery, and correlated sensors. | [ACP-V032](../VALIDATION.md#acp-v032) |
| ACP-R033: Protected verification state | Private naming maps, legends, raw inputs, masks, enrolled references, and reconstructed credentials MUST remain outside agent-controlled memory, tools, logs, and interfaces. | [ACP-V033](../VALIDATION.md#acp-v033) |
| ACP-R034: Separate security properties | Deployment claims MUST distinguish transcript privacy, knowledge verification, enrolled identity attribution, action authorization, result authenticity, replay resistance, and runtime confinement. | [ACP-V034](../VALIDATION.md#acp-v034) |

## ACP-A027: Retired mask allocation returned to service

**Context:** Credential Access; SAF Core and MCP deployment views.

**Classification:** [SAF-T1207: Hijack Update Mechanism](../../../techniques/SAF-T1207/README.md) — `related_context`. SAF-T1207 concerns a hijacked normal update path; private-mask allocation rollback is a separate design scenario with a related lifecycle boundary.

**Preconditions:** A protected approval implementation uses one-use secret masks but provisioning or recovery can replay their allocation state.

**Inert procedure:** A local provisioning rollback fixture makes a retired allocation eligible for another credential-dependent exchange.

**Proposed detection evidence:** Allocation identifiers, claim history, restored epoch, and duplicate resource assignment across events.

**Legitimate lookalikes and limits:** Repeated numeric mask values from independent samples are not reuse; allocation identity and joint distribution matter. Agent-authored logs alone cannot establish the boundary decision.

**Required controls:** [SAF-M-77](../../../mitigations/SAF-M-77/README.md), [SAF-M-78](../../../mitigations/SAF-M-78/README.md), [SAF-M-82](../../../mitigations/SAF-M-82/README.md).

**Acceptance:** [ACP-V016](../VALIDATION.md#acp-v016), [ACP-V020](../VALIDATION.md#acp-v020), [ACP-V031](../VALIDATION.md#acp-v031), [ACP-V032](../VALIDATION.md#acp-v032). Tests are planned, not executed.

## ACP-A028: Private approval legend or decoding state exposed

**Context:** Credential Access; SAF Core and MCP deployment views.

**Classification:** [SAF-T1505: In-Memory Secret Extraction](../../../techniques/SAF-T1505/README.md) — `procedure_example`. A bounded deployment example of the registered mechanism; no new incident or evidence-status claim.

**Preconditions:** The runtime can inspect verifier memory, private legends, debugging output, or correlated observation channels.

**Inert procedure:** An inert probe reads synthetic private decoding material even though released authentication responses remain masked.

**Proposed detection evidence:** Secret-state access, logger configuration, protected display provenance, and canary exposure.

**Legitimate lookalikes and limits:** The authorized verifier intentionally processes private state; the discriminator is access by an unauthorized observer. Agent-authored logs alone cannot establish the boundary decision.

**Required controls:** [SAF-M-76](../../../mitigations/SAF-M-76/README.md), [SAF-M-79](../../../mitigations/SAF-M-79/README.md), [SAF-M-81](../../../mitigations/SAF-M-81/README.md), [SAF-M-82](../../../mitigations/SAF-M-82/README.md).

**Acceptance:** [ACP-V006](../VALIDATION.md#acp-v006), [ACP-V011](../VALIDATION.md#acp-v011), [ACP-V029](../VALIDATION.md#acp-v029), [ACP-V032](../VALIDATION.md#acp-v032), [ACP-V033](../VALIDATION.md#acp-v033), [ACP-V034](../VALIDATION.md#acp-v034). Tests are planned, not executed.
