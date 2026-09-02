# SAF-T1705: Cross-Agent Instruction Injection

## Overview

- **Tactic**: Lateral Movement (ATK-TA0008)
- **Technique ID**: SAF-T1705
- **Research Packet**: [research/techniques/SAF-T1705](../../research/techniques/SAF-T1705/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1705/traceability-ledger.yml)
- **Documentation Status**: draft
- **Evidence Status**: demonstrated
- **Severity**: high
- **Severity Rationale**: Severity is high when a receiving agent can operationalize the relayed instruction with privileged tools or sensitive data access; it is lower when the receiver is read-only, independently authorized, or strongly sandboxed. <!-- SAF-TRACE: claims=SAF-T1705-C009; sources=SRC-triedman-jha-shmatikov-mas-hijacking,SRC-naik-et-al-omni-leak -->
- **First Observed**: Not observed in production in the reviewed authority corpora; controlled demonstrations were published from 2024 through 2026. <!-- SAF-TRACE: claims=SAF-T1705-C006,SAF-T1705-C015; sources=SRC-aiid-snapshot-20260831,SRC-nvd-token-scope-corpus,SRC-lee-tiwari-prompt-infection -->
- **Last Updated**: 2026-09-02

## Scope

Cross-Agent Instruction Injection is the transfer of attacker-authored instructions from an attacker-influenced agent context into a distinct receiving agent, where the receiver treats the peer's output as task content, evidence, or authority and changes behavior or invokes a capability. <!-- SAF-TRACE: claims=SAF-T1705-C003,SAF-T1705-C004,SAF-T1705-C008; sources=SRC-lee-tiwari-prompt-infection,SRC-triedman-jha-shmatikov-mas-hijacking -->

### In Scope

- An originating agent incorporates attacker-controlled instructions into its message, metadata, artifact, or task result for another agent. <!-- SAF-TRACE: claims=SAF-T1705-C003,SAF-T1705-C004; sources=SRC-lee-tiwari-prompt-infection,SRC-triedman-jha-shmatikov-mas-hijacking -->
- A distinct receiving agent follows, reframes, delegates, or operationalizes those instructions under its own context, privileges, tools, or service connections. <!-- SAF-TRACE: claims=SAF-T1705-C004,SAF-T1705-C005,SAF-T1705-C008; sources=SRC-triedman-jha-shmatikov-mas-hijacking,SRC-naik-et-al-omni-leak -->
- The immediate security outcome is movement of adversary influence across an agent boundary; code execution, collection, disclosure, or disruption are conditional follow-on effects. <!-- SAF-TRACE: claims=SAF-T1705-C008,SAF-T1705-C009; sources=SRC-triedman-jha-shmatikov-mas-hijacking,SRC-naik-et-al-omni-leak -->

### Out of Scope

- Direct prompt injection that affects only the agent consuming an external document, tool result, or user message. <!-- SAF-TRACE: claims=SAF-T1705-C003,SAF-T1705-C008; sources=SRC-lee-tiwari-prompt-infection,SRC-triedman-jha-shmatikov-mas-hijacking -->
- Benign delegation in which the receiver preserves provenance, independently evaluates authority, and performs only an authorized task. <!-- SAF-TRACE: claims=SAF-T1705-C008,SAF-T1705-C012; sources=SRC-a2a-spec,SRC-mcp-architecture -->
- Spawn-time inherited memory, planner-only tool-output injection, protocol command injection, and downstream impact considered without the defining peer-agent instruction hop. See the [scope contract](../../research/techniques/SAF-T1705/technique-contract.yml).

### Distinguishing Characteristics

The decisive evidence is a causal sequence with two agent contexts: attacker influence reaches the originator, the originator emits content for a peer, and the peer changes behavior or invokes a capability because of that content. A shared run alone, or two agents independently exposed to the same input, is insufficient. <!-- SAF-TRACE: claims=SAF-T1705-C008,SAF-T1705-C010; sources=SRC-a2a-spec,SRC-triedman-jha-shmatikov-mas-hijacking -->

## Description

Agent-to-agent systems exchange message parts, artifacts, metadata, and task references. A2A gives messages identifiers, roles, content parts, context and task joins, and optional referenced task IDs; MCP hosts coordinate multiple isolated client connections and make policy, consent, authorization, and context-aggregation decisions. <!-- SAF-TRACE: claims=SAF-T1705-C001,SAF-T1705-C002; sources=SRC-a2a-spec,SRC-mcp-architecture -->

The technique begins when attacker-controlled material influences one agent and that agent emits an instruction-bearing response or metadata to a different agent. The receiver may see a trusted peer or structured task result rather than the original untrusted source, which can change presentation and obscure provenance. <!-- SAF-TRACE: claims=SAF-T1705-C003,SAF-T1705-C004; sources=SRC-lee-tiwari-prompt-infection,SRC-triedman-jha-shmatikov-mas-hijacking -->

Controlled studies demonstrate self-replicating prompt infection, subagent-to-orchestrator request laundering that reaches an executor, and an SQL-agent-to-orchestrator-to-notification chain that discloses protected data. These studies establish feasibility, not production prevalence or universal success. <!-- SAF-TRACE: claims=SAF-T1705-C003,SAF-T1705-C004,SAF-T1705-C005,SAF-T1705-C015; sources=SRC-lee-tiwari-prompt-infection,SRC-triedman-jha-shmatikov-mas-hijacking,SRC-naik-et-al-omni-leak -->

## Attack Vectors

- **Primary Vector**: Attacker-controlled external content influences a content-facing agent, whose response, error metadata, task result, or delegated instruction is consumed by another agent. <!-- SAF-TRACE: claims=SAF-T1705-C003,SAF-T1705-C004,SAF-T1705-C005; sources=SRC-lee-tiwari-prompt-infection,SRC-triedman-jha-shmatikov-mas-hijacking,SRC-naik-et-al-omni-leak -->
- **Secondary Vectors**:
  - A compromised or already-influenced agent intentionally or unintentionally repeats the instruction to peers. <!-- SAF-TRACE: claims=SAF-T1705-C003; sources=SRC-lee-tiwari-prompt-infection -->
  - An orchestrator accepts attacker-influenced subagent metadata and converts it into a task for a more capable worker. <!-- SAF-TRACE: claims=SAF-T1705-C004; sources=SRC-triedman-jha-shmatikov-mas-hijacking -->
  - A data-processing agent passes an injected action request through the orchestrator to an external-communications agent. <!-- SAF-TRACE: claims=SAF-T1705-C005; sources=SRC-naik-et-al-omni-leak -->
- **Affected Components**: Originating agents, orchestrators, peer-agent messages, task metadata, shared workspaces, receiving agents, receiver-side tools, and connected services. <!-- SAF-TRACE: claims=SAF-T1705-C001,SAF-T1705-C002,SAF-T1705-C008; sources=SRC-a2a-spec,SRC-mcp-architecture,SRC-triedman-jha-shmatikov-mas-hijacking -->

## Technical Details

### Prerequisites

- An attacker can place instruction-bearing content where an originating agent will process it, or can otherwise influence that originator. <!-- SAF-TRACE: claims=SAF-T1705-C003,SAF-T1705-C004,SAF-T1705-C008; sources=SRC-lee-tiwari-prompt-infection,SRC-triedman-jha-shmatikov-mas-hijacking -->
- The originator can communicate a message, artifact, task result, metadata, or shared-workspace entry to a distinct agent context. <!-- SAF-TRACE: claims=SAF-T1705-C001,SAF-T1705-C008; sources=SRC-a2a-spec,SRC-triedman-jha-shmatikov-mas-hijacking -->
- The receiver evaluates that content as actionable and can change state, delegate work, or invoke a tool under receiver-side authority. <!-- SAF-TRACE: claims=SAF-T1705-C005,SAF-T1705-C008; sources=SRC-naik-et-al-omni-leak,SRC-a2a-spec -->
- Provenance, authorization, approval, or content controls fail to stop the specific cross-agent transition. <!-- SAF-TRACE: claims=SAF-T1705-C008,SAF-T1705-C012; sources=SRC-a2a-spec,SRC-mcp-architecture,SRC-mcp-security-2025-11-25 -->

### Attack Flow

1. The adversary places a labeled, inert instruction placeholder in data processed by Agent A. <!-- SAF-TRACE: claims=SAF-T1705-C003,SAF-T1705-C004; sources=SRC-lee-tiwari-prompt-infection,SRC-triedman-jha-shmatikov-mas-hijacking -->
2. Agent A incorporates the placeholder's requested action into a peer message or task result and omits or weakens its untrusted provenance. <!-- SAF-TRACE: claims=SAF-T1705-C003,SAF-T1705-C004; sources=SRC-lee-tiwari-prompt-infection,SRC-triedman-jha-shmatikov-mas-hijacking -->
3. Agent B receives the peer content in a distinct context and interprets it as a task instruction, constraint, or error-recovery step. <!-- SAF-TRACE: claims=SAF-T1705-C004,SAF-T1705-C005; sources=SRC-triedman-jha-shmatikov-mas-hijacking,SRC-naik-et-al-omni-leak -->
4. Agent B changes behavior or invokes an inert test capability without an independent authorization decision tied to the original source. <!-- SAF-TRACE: claims=SAF-T1705-C008,SAF-T1705-C010; sources=SRC-a2a-spec,SRC-nist-ai-600-1 -->
5. Additional agents may receive the rephrased instruction, expanding the influenced workflow, but further propagation is not required for this technique. <!-- SAF-TRACE: claims=SAF-T1705-C003,SAF-T1705-C005; sources=SRC-lee-tiwari-prompt-infection,SRC-naik-et-al-omni-leak -->

### Example Scenario

A document-review agent reads an inert test record containing `[UNTRUSTED INSTRUCTION PLACEHOLDER]`. It reports to a ticketing agent that the placeholder's requested marker must be added before the review can complete. The ticketing agent adds only the benign marker in a sandbox. The security-relevant fact is that the second agent acted on attacker-influenced peer output, not the marker itself. <!-- SAF-TRACE: claims=SAF-T1705-C004,SAF-T1705-C008,SAF-T1705-C010; sources=SRC-triedman-jha-shmatikov-mas-hijacking,SRC-a2a-spec -->

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1705-C001 | A2A carries content and correlation identifiers across client and remote-agent roles. | Research-Derived | SRC-a2a-spec | Protocol semantics do not prove model obedience. |
| SAF-T1705-C002 | MCP hosts coordinate isolated clients, policy, consent, authorization, and context. | Research-Derived | SRC-mcp-architecture | MCP does not define this attack. |
| SAF-T1705-C003 | Prompt Infection reproduced instruction propagation across agents. | Demonstrated | SRC-lee-tiwari-prompt-infection | Basic architectures and mainly GPT-family models were tested. |
| SAF-T1705-C004 | MAS Hijacking reproduced subagent metadata influencing an orchestrator and executor. | Demonstrated | SRC-triedman-jha-shmatikov-mas-hijacking | Controlled selected-framework study. |
| SAF-T1705-C005 | OMNI-LEAK reproduced a multi-hop agent chain that disclosed protected data. | Demonstrated | SRC-naik-et-al-omni-leak | Benchmark environment, not a production breach. |
| SAF-T1705-C006 | The reviewed AIID and NVD corpora yielded no qualifying production event or direct CVE. | Research-Derived | SRC-aiid-snapshot-20260831; SRC-nvd-token-scope-corpus | Corpus-, term-, and date-bounded absence. |
| SAF-T1705-C007 | Reviewed adjacent advisories lacked the defining second-agent instruction hop. | Research-Derived | See research packet. | They may still enable a later agent compromise. |
| SAF-T1705-C008 | The technique requires attacker influence, an inter-agent channel, and receiver-side action authority. | Research-Derived | SRC-a2a-spec; SRC-triedman-jha-shmatikov-mas-hijacking | Exact prerequisites are deployment-specific. |
| SAF-T1705-C009 | Impact depends on receiver permissions, tools, data, and selected action. | Research-Derived | SRC-triedman-jha-shmatikov-mas-hijacking; SRC-naik-et-al-omni-leak | Demonstrated outcomes are not inevitable. |
| SAF-T1705-C010 | Provenance and causal identifiers can support an experimental message-to-action correlation. | Research-Derived | SRC-a2a-spec; SRC-nist-ai-600-1 | Required instrumentation is implementation-defined. |
| SAF-T1705-C011 | Content-only labels and wrappers are inadequate as sole controls. | Research-Derived | SRC-lee-tiwari-prompt-infection | Cross-study defenses and threat models differ. |
| SAF-T1705-C012 | Layered provenance, authorization, validation, least privilege, and action gates address the boundary. | Research-Derived | SRC-a2a-spec; SRC-mcp-architecture; SRC-mcp-security-2025-11-25 | No single control is shown to eliminate the technique. |
| SAF-T1705-C013 | Response requires provenance preservation, containment, scope review, and correlated-run analysis. | Research-Derived | SRC-nist-ai-600-1; SRC-mcp-security-2025-11-25 | Exact actions depend on deployment and authority. |
| SAF-T1705-C014 | ATT&CK T1072 is only an analogous centralized-coordination mapping. | Research-Derived | SRC-mitre-t1072 | T1072 concerns deployment suites, not agent messages. |
| SAF-T1705-C015 | The overall label is Demonstrated, not Observed. | Demonstrated | SRC-lee-tiwari-prompt-infection; SRC-triedman-jha-shmatikov-mas-hijacking; SRC-naik-et-al-omni-leak | Production evidence remains a bounded gap. |

### Current State

- **Affected Environments**: Multi-agent systems in which content-facing agents report to orchestrators or peers that possess different tools, data access, identities, or execution authority. <!-- SAF-TRACE: claims=SAF-T1705-C004,SAF-T1705-C005,SAF-T1705-C008; sources=SRC-triedman-jha-shmatikov-mas-hijacking,SRC-naik-et-al-omni-leak -->
- **Known Exploitation**: Public controlled demonstrations exist; no qualifying production exploitation was identified in the reviewed authority corpora. <!-- SAF-TRACE: claims=SAF-T1705-C006,SAF-T1705-C015; sources=SRC-aiid-snapshot-20260831,SRC-nvd-token-scope-corpus,SRC-lee-tiwari-prompt-infection -->
- **Available Protections**: Protocol validation, explicit provenance, receiver-side authorization, least privilege, sandboxing, step-level monitoring, and human approval can reduce exposure when combined. <!-- SAF-TRACE: claims=SAF-T1705-C012; sources=SRC-a2a-spec,SRC-mcp-architecture,SRC-mcp-security-2025-11-25,SRC-naik-et-al-omni-leak -->
- **Residual Risk**: Rephrasing, missing provenance, incomplete causal telemetry, legitimate-looking delegation, and content-classifier evasion can obscure the transition. <!-- SAF-TRACE: claims=SAF-T1705-C010,SAF-T1705-C011; sources=SRC-lee-tiwari-prompt-infection,SRC-triedman-jha-shmatikov-mas-hijacking -->

### Known Breaches and Vulnerabilities

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| Prompt Infection | 2024; simulated multi-agent applications and agent societies | Instruction propagation and bounded data-theft and memory effects; layered defenses were evaluated. | Direct demonstration | Mainly GPT-family models and basic architectures; no production event. <!-- SAF-TRACE: claims=SAF-T1705-C003; sources=SRC-lee-tiwari-prompt-infection --> |
| MAS Hijacking | 2025; controlled AutoGen, CrewAI, and MetaGPT configurations | Code execution and data exfiltration in controlled sinks; authors disclosed findings and used lab isolation. | Direct demonstration | Selected systems, models, configurations, and controlled payloads. <!-- SAF-TRACE: claims=SAF-T1705-C004; sources=SRC-triedman-jha-shmatikov-mas-hijacking --> |
| OMNI-LEAK | 2026; controlled orchestrator, SQL, and notification agents | Protected-data disclosure across agent roles; step-level monitoring and data-entry controls were recommended. | Direct demonstration | Benchmark environment; adaptation to other architectures remains future work. <!-- SAF-TRACE: claims=SAF-T1705-C005; sources=SRC-naik-et-al-omni-leak --> |
| Production incidents and direct CVEs | Reviewed through 2026-09-02 in named authority corpora | None qualified; continue current catalog and incident monitoring. | Evidence gap | Absence does not establish that no unpublished or differently indexed event exists. <!-- SAF-TRACE: claims=SAF-T1705-C006; sources=SRC-aiid-snapshot-20260831,SRC-nvd-token-scope-corpus --> |

### Real-World Incidents or Demonstrations

#### Prompt Infection (2024)

Lee and Tiwari showed that instruction-bearing prompts can propagate from one agent response into subsequent agents and that origin tagging alone reduced attack success only slightly in their experiments. The study's model and architecture limits make it a direct feasibility demonstration, not a prevalence estimate. <!-- SAF-TRACE: claims=SAF-T1705-C003,SAF-T1705-C011; sources=SRC-lee-tiwari-prompt-infection -->

#### MAS Hijacking (2025)

Triedman, Jha, and Shmatikov showed that a content-reading agent could return attacker-influenced error metadata to an orchestrator, which could then direct another agent to execute code. They ran the experiments in a controlled lab, contacted affected project teams, and did not attack live production agents. <!-- SAF-TRACE: claims=SAF-T1705-C004,SAF-T1705-C015; sources=SRC-triedman-jha-shmatikov-mas-hijacking -->

#### OMNI-LEAK (2026)

Naik, Culligan, Gal, Torr, Aljundi, Paren, and Bibi demonstrated a public-data injection reaching an SQL agent, then an orchestrator, then a notification agent that sent protected data. Their results varied by model and configuration, and the work explicitly frames the risk as preemptive red teaming rather than a reported breach. <!-- SAF-TRACE: claims=SAF-T1705-C005,SAF-T1705-C015; sources=SRC-naik-et-al-omni-leak -->

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | High | A receiver with private-data or external-communication capability can disclose sensitive records; without those capabilities the confidentiality effect is bounded. <!-- SAF-TRACE: claims=SAF-T1705-C005,SAF-T1705-C009; sources=SRC-naik-et-al-omni-leak --> |
| Integrity | High | A receiver may alter task plans, messages, files, or external state when its tools permit; read-only receivers reduce this effect. <!-- SAF-TRACE: claims=SAF-T1705-C003,SAF-T1705-C004,SAF-T1705-C009; sources=SRC-lee-tiwari-prompt-infection,SRC-triedman-jha-shmatikov-mas-hijacking --> |
| Availability | Medium | Disruption is possible through repeated or unsafe receiver actions, but direct availability effects were not the primary result of the selected demonstrations. <!-- SAF-TRACE: claims=SAF-T1705-C009; sources=SRC-triedman-jha-shmatikov-mas-hijacking,SRC-lee-tiwari-prompt-infection --> |
| Scope | Multi-System | Orchestrators can route influence to multiple specialized agents and connected services, while segmentation, approval, and least privilege constrain the blast radius. <!-- SAF-TRACE: claims=SAF-T1705-C003,SAF-T1705-C005,SAF-T1705-C012; sources=SRC-lee-tiwari-prompt-infection,SRC-naik-et-al-omni-leak,SRC-mcp-architecture --> |

### Severity Conditions

- Raise severity when the receiver has code execution, private-data access, external messaging, broad scopes, or authority to delegate further. <!-- SAF-TRACE: claims=SAF-T1705-C009,SAF-T1705-C012; sources=SRC-triedman-jha-shmatikov-mas-hijacking,SRC-naik-et-al-omni-leak,SRC-mcp-security-2025-11-25 -->
- Lower severity when the channel preserves untrusted provenance, the receiver is read-only or sandboxed, every sensitive action requires independent authorization, and peer outputs cannot expand effective authority. <!-- SAF-TRACE: claims=SAF-T1705-C012; sources=SRC-a2a-spec,SRC-mcp-architecture,SRC-mcp-security-2025-11-25 -->

## Detection Methods

### Required Telemetry

- Inter-agent message events: timestamp, run, context, task, message, sender, receiver, content hash, provenance trust, instruction signal, and referenced or parent message. <!-- SAF-TRACE: claims=SAF-T1705-C001,SAF-T1705-C010; sources=SRC-a2a-spec,SRC-nist-ai-600-1 -->
- Receiver action events: timestamp, agent, tool, argument hash, effective authority, inherited-authority flag, approval state, policy version, and causal message. <!-- SAF-TRACE: claims=SAF-T1705-C010; sources=SRC-a2a-spec,SRC-nist-ai-600-1 -->
- Policy events: evaluated source trust, requested and granted scope, allow or deny outcome, approver, and correlation identifier. <!-- SAF-TRACE: claims=SAF-T1705-C010,SAF-T1705-C012; sources=SRC-mcp-security-2025-11-25,SRC-nist-ai-600-1 -->

### Indicators of Compromise (IoCs)

No stable universal content IoC is established. Investigators should treat provenance discontinuity, unexplained peer-authored constraints, and receiver actions causally tied to mixed-trust messages as behavioral leads, then validate them against the original user intent and policy record. <!-- SAF-TRACE: claims=SAF-T1705-C010,SAF-T1705-C011; sources=SRC-lee-tiwari-prompt-infection,SRC-triedman-jha-shmatikov-mas-hijacking,SRC-nist-ai-600-1 -->

### Behavioral Indicators

- A receiver invokes a tool shortly after an untrusted or mixed-provenance peer message and the action's causal identifier points to that message. <!-- SAF-TRACE: claims=SAF-T1705-C010; sources=SRC-a2a-spec,SRC-nist-ai-600-1 -->
- An originator's message reframes an external error or data record as a mandatory next step for a more privileged peer. <!-- SAF-TRACE: claims=SAF-T1705-C004; sources=SRC-triedman-jha-shmatikov-mas-hijacking -->
- Several agents repeat or operationalize the same instruction lineage even though it was absent from the user's authorized request. <!-- SAF-TRACE: claims=SAF-T1705-C003,SAF-T1705-C005; sources=SRC-lee-tiwari-prompt-infection,SRC-naik-et-al-omni-leak -->

### Detection Analytic

The [experimental correlation rule](detection-rule.yml) requires an ordered message-to-action join within 120 seconds, matching run, receiver, and causal message identifiers. It selects only untrusted or mixed-provenance messages with an upstream instruction signal and actions that inherit authority without independent approval. The rule is an auditable starting point, not a natural-language ground-truth classifier. <!-- SAF-TRACE: claims=SAF-T1705-C010,SAF-T1705-C011; sources=SRC-a2a-spec,SRC-nist-ai-600-1,SRC-lee-tiwari-prompt-infection -->

Tune for higher-risk tools and sensitive resources, keep a narrow allowlist for reviewed automation, and monitor missing provenance and causal fields. Expect blind spots for delayed actions, shared-memory paths, multimodal or encoded instructions, and compromised telemetry. <!-- SAF-TRACE: claims=SAF-T1705-C010,SAF-T1705-C011,SAF-T1705-C012; sources=SRC-nist-ai-600-1,SRC-lee-tiwari-prompt-infection,SRC-mcp-security-2025-11-25 -->

### Validation

The [detector test suite](../../tests/SAF-T1705/test_detection_rule.py) and [inert fixtures](../../tests/SAF-T1705/fixtures.yml) cover a positive event, trusted-message negative, exact 120-second boundary, over-boundary negative, malformed event, human-approved legitimate lookalike, and missing-causality negative. The checked-in [detector transcript](../../research/techniques/SAF-T1705/validation/detection-tests.txt), [strict-validator transcript](../../research/techniques/SAF-T1705/validation/strict-validator.txt), and [quality review](../../research/techniques/SAF-T1705/quality-review.yml) record both isolated and canonical proof.

## Mitigation Strategies

### Preventive Controls

- Apply [SAF-M-1](../../mitigations/SAF-M-1/README.md) and [SAF-M-21](../../mitigations/SAF-M-21/README.md): preserve the original trust label and content lineage through every agent message, artifact, summary, and delegation; do not upgrade peer output to trusted merely because an agent authored it. <!-- SAF-TRACE: claims=SAF-T1705-C010,SAF-T1705-C012; sources=SRC-a2a-spec,SRC-mcp-architecture,SRC-nist-ai-600-1 -->
- Apply [SAF-M-69](../../mitigations/SAF-M-69/README.md) and [SAF-M-74](../../mitigations/SAF-M-74/README.md): evaluate authorization at the receiving agent for the exact requested action, identity, data, and scope; require separate approval for destructive, external, or privilege-expanding actions. <!-- SAF-TRACE: claims=SAF-T1705-C008,SAF-T1705-C012; sources=SRC-a2a-spec,SRC-mcp-security-2025-11-25 -->
- Apply [SAF-M-29](../../mitigations/SAF-M-29/README.md): minimize receiver privileges, isolate tool execution, restrict filesystem and network access, and prevent one agent's content from silently expanding another agent's effective authority. <!-- SAF-TRACE: claims=SAF-T1705-C009,SAF-T1705-C012; sources=SRC-mcp-architecture,SRC-mcp-security-2025-11-25 -->
- Apply [SAF-M-5](../../mitigations/SAF-M-5/README.md) and [SAF-M-22](../../mitigations/SAF-M-22/README.md): validate and sanitize untrusted data, but combine content controls with provenance, policy, and action gates because isolated prompt wrappers and labels are bypassable. <!-- SAF-TRACE: claims=SAF-T1705-C011,SAF-T1705-C012; sources=SRC-a2a-spec,SRC-lee-tiwari-prompt-infection,SRC-mcp-security-2025-11-25 -->

### Detective Controls

- Apply [SAF-M-12](../../mitigations/SAF-M-12/README.md): retain complete message, task, policy, authorization, approval, and action correlations with protected timestamps and identifiers. <!-- SAF-TRACE: claims=SAF-T1705-C010,SAF-T1705-C013; sources=SRC-a2a-spec,SRC-nist-ai-600-1 -->
- Apply [SAF-M-70](../../mitigations/SAF-M-70/README.md): alert on receiver actions sourced from mixed-trust peer content, unexpected scope elevation, and missing or rewritten provenance at an agent boundary. <!-- SAF-TRACE: claims=SAF-T1705-C010,SAF-T1705-C012; sources=SRC-mcp-security-2025-11-25,SRC-nist-ai-600-1 -->
- Apply [SAF-M-9](../../mitigations/SAF-M-9/README.md): red-team complete multi-agent workflows, including benign lookalikes and adaptive paraphrase, rather than testing each model or agent in isolation. <!-- SAF-TRACE: claims=SAF-T1705-C011,SAF-T1705-C012; sources=SRC-lee-tiwari-prompt-infection,SRC-naik-et-al-omni-leak -->

### Response Procedures

1. Preserve the original external input, inter-agent messages, task graph, policy decisions, authorization state, and receiver actions for the complete correlated run. <!-- SAF-TRACE: claims=SAF-T1705-C013; sources=SRC-nist-ai-600-1,SRC-mcp-security-2025-11-25 -->
2. Contain affected agents and suspend high-risk tools, external messaging, delegated credentials, and broad scopes until the instruction lineage is understood. <!-- SAF-TRACE: claims=SAF-T1705-C012,SAF-T1705-C013; sources=SRC-nist-ai-600-1,SRC-mcp-security-2025-11-25 -->
3. Determine the first attacker-influenced context, every agent and shared store that received derivative content, and each action performed under receiver authority. <!-- SAF-TRACE: claims=SAF-T1705-C003,SAF-T1705-C010,SAF-T1705-C013; sources=SRC-lee-tiwari-prompt-infection,SRC-a2a-spec,SRC-nist-ai-600-1 -->
4. Revoke or narrow exposed credentials and scopes, correct affected external state, and restore agents only after provenance and policy enforcement are verified. <!-- SAF-TRACE: claims=SAF-T1705-C012,SAF-T1705-C013; sources=SRC-mcp-security-2025-11-25,SRC-nist-ai-600-1 -->
5. Add the event to regression tests and update channel, tool, and approval policies without treating a model swap as sufficient remediation. <!-- SAF-TRACE: claims=SAF-T1705-C011,SAF-T1705-C013; sources=SRC-lee-tiwari-prompt-infection,SRC-nist-ai-600-1 -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1102: Prompt Injection (Multiple Vectors)](../SAF-T1102/README.md) | Prerequisite or alternative | Direct injection lacks the defining peer-agent hop. See the [scope contract](../../research/techniques/SAF-T1705/technique-contract.yml). |
| [SAF-T1701: Cross-Tool Contamination](../SAF-T1701/README.md) | Prerequisite or overlapping | Tool-result consumption remains in one agent context unless that agent relays the instruction to a distinct receiver. See the [scope contract](../../research/techniques/SAF-T1705/technique-contract.yml). |
| [SAF-T1204: Context Memory Implant](../SAF-T1204/README.md) | Adjacent persistence path | Context memory implantation requires storage and later retrieval across sessions or consumers; SAF-T1705 requires an inter-agent instruction hop but not persistence. See the [Framework Model v2 taxonomy review](../../research/taxonomy-review.yml). |

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1072](https://attack.mitre.org/techniques/T1072/) | Software Deployment Tools | Analogous | Both behaviors use a trusted coordination mechanism to cause action in another managed context, but T1072 specifically covers deployment and configuration-management suites rather than agent message interpretation. <!-- SAF-TRACE: claims=SAF-T1705-C014; sources=SRC-mitre-t1072 --> |

### Additional Framework Mappings

| Framework | ID | Name | Rationale |
| --- | --- | --- | --- |
| NIST AI RMF Generative AI Profile | NIST AI 600-1 | Prompt-injection and incident-lifecycle guidance | The profile supports provenance, red-team, logging, retention, containment, and recovery practices used here; it is control guidance, not a direct technique equivalence. <!-- SAF-TRACE: claims=SAF-T1705-C010,SAF-T1705-C012,SAF-T1705-C013; sources=SRC-nist-ai-600-1 --> |

## References

1. **SRC-a2a-spec**: [Agent2Agent Protocol Specification — A2A Protocol Working Group](https://a2a-protocol.org/latest/specification/) — message, task, context, authorization, and security semantics.
2. **SRC-mcp-architecture**: [Model Context Protocol Architecture — MCP project, 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/architecture) — host, client isolation, policy, and context responsibilities.
3. **SRC-mcp-security-2025-11-25**: [Model Context Protocol Security Best Practices — MCP project, 2025-11-25](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices) — validation, logging, sandboxing, authorization, and scope minimization.
4. **SRC-nist-ai-600-1**: [NIST AI 600-1 — Autio, Dunietz, Hall, Jain, Roberts, Schwartz, Stanley, Tabassi, and the NIST Generative AI Public Working Group, 2024](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf) — prompt injection, provenance, testing, incident monitoring, containment, and recovery.
5. **SRC-lee-tiwari-prompt-infection**: [Prompt Infection — Donghyun Lee and Mo Tiwari, 2024](https://arxiv.org/html/2410.07283) — direct controlled cross-agent propagation and defense evaluation.
6. **SRC-triedman-jha-shmatikov-mas-hijacking**: [Multi-Agent Systems Execute Arbitrary Malicious Code — Harold Triedman, Rishi Jha, and Vitaly Shmatikov, 2025](https://arxiv.org/html/2503.12188) — direct controlled metadata laundering, orchestrator influence, and downstream execution.
7. **SRC-naik-et-al-omni-leak**: [OMNI-LEAK — Akshat Naik, Jay J Culligan, Yarin Gal, Philip Torr, Rahaf Aljundi, Alasdair Paren, and Adel Bibi, 2026](https://arxiv.org/html/2602.13477v2) — direct controlled multi-hop data disclosure.
8. **SRC-aiid-snapshot-20260831**: [AI Incident Database weekly snapshots — Sean McGregor and AIID editors and contributors](https://incidentdatabase.ai/research/snapshots/) — current incident-corpus review and bounded evidence gap.
9. **SRC-nvd-token-scope-corpus**: [National Vulnerability Database CVE API 2.0 — NVD team](https://services.nvd.nist.gov/rest/json/cves/2.0) — current exact-query vulnerability review and bounded evidence gap.
10. **SRC-mitre-t1072**: [MITRE ATT&CK T1072 Software Deployment Tools, version 3.2](https://attack.mitre.org/techniques/T1072/) — analogous lateral-movement mapping; contributors Joe Gumke, Shane Tully, and Tamir Yehuda.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 0.1 | 2026-09-02 | Initial independent clean-room draft with evidence packet and tested detection. | SAF-MCP clean-room research |
| 0.2 | 2026-09-02 | Repointed the adjacent memory relationship to canonical SAF-T1204 under SAF-TAX-014. | The SAF-MCP Authors |
