# SAF-T1702: Shared-Memory Poisoning

- **Technique ID**: SAF-T1702
- **Lifecycle Status**: Deprecated. [Framework Model v2 taxonomy review](../../research/taxonomy-review.yml)
- **Tactic**: ATK-TA0008 (Lateral Movement)
- **Documentation Status**: Deprecated
- **Evidence Status**: Demonstrated
- **Severity**: High
- **Severity Rationale**: A poisoned record can persist across sessions or principals and influence a later high-risk action, but the consequence depends on a shared retrieval path, write opportunity, retrieval, and downstream authority. <!-- SAF-TRACE: claims=SAF-T1702-C007, SAF-T1702-C011; sources=SRC-owasp-agentic-top10-2026, SRC-minja-2026 -->
- **First Observed**: Controlled research published in 2024 demonstrated long-term-memory and retrieval poisoning; the reviewed corpus did not establish an earlier qualifying production incident. <!-- SAF-TRACE: claims=SAF-T1702-C003, SAF-T1702-C004, SAF-T1702-C006; sources=SRC-agentpoison-2024, SRC-minja-2026, SRC-cisco-memorytrap-2026 -->
- **Research Packet**: [research/techniques/SAF-T1702/](../../research/techniques/SAF-T1702/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1702/traceability-ledger.yml)
- **Last Updated**: 2026-09-02

> **Deprecated compatibility ID:** SAF-T1702 is consolidated into [SAF-T1204: Context Memory Implant](../SAF-T1204/README.md). Both frozen contracts define the same persistent-memory write, later cross-session retrieval, and behavior-influence mechanism. This page and its evidence packet remain available for provenance; use SAF-T1204 for new mappings. [Framework Model v2 taxonomy review](../../research/taxonomy-review.yml)

## Overview

Shared-Memory Poisoning is the insertion or alteration of a persistent memory record that a different session, principal, or agent later retrieves, causing the later consumer's reasoning, planning, or action selection to be influenced across that sharing boundary. <!-- SAF-TRACE: claims=SAF-T1702-C001, SAF-T1702-C007; sources=SRC-owasp-agentic-top10-2026, SRC-minja-2026 -->

The defining pivot is not merely hostile text: it is the transition from an attacker-reachable ingestion or write path into memory that is subsequently trusted by another consumer. <!-- SAF-TRACE: claims=SAF-T1702-C001, SAF-T1702-C007; sources=SRC-owasp-agentic-top10-2026, SRC-minja-2026 -->

## Scope

This technique covers poisoning of stored or retrievable agent memory, summaries, embeddings, or retrieval records when the affected record crosses a session, principal, tenant, or agent boundary and changes a later consumer's behavior. <!-- SAF-TRACE: claims=SAF-T1702-C001, SAF-T1702-C007; sources=SRC-owasp-agentic-top10-2026, SRC-minja-2026 -->

It excludes transient instructions confined to the current interaction, model-training data poisoning, and inter-agent messages that are never persisted and retrieved as memory. <!-- SAF-TRACE: claims=SAF-T1702-C015; sources=SRC-owasp-agentic-top10-2026 -->

Goal hijacking, unauthorized tool use, data disclosure, and service disruption are potential downstream outcomes; they are not required to classify the memory-poisoning mechanism itself. <!-- SAF-TRACE: claims=SAF-T1702-C011, SAF-T1702-C015; sources=SRC-owasp-agentic-top10-2026 -->

## Description

Agentic systems may retain summaries, preferences, observations, embeddings, and retrieved records for later use. MCP itself defines resources and other context-bearing capabilities while requiring implementations to treat tool descriptions and data access as trust decisions; persistent-memory policy is therefore an implementation boundary rather than a protocol guarantee. <!-- SAF-TRACE: claims=SAF-T1702-C002; sources=SRC-mcp-spec-2025-06 -->

An adversary uses an accepted interaction, document, repository, tool result, or other ingestion path to seed a record. The record becomes dangerous when a later retrieval gives it authority disproportionate to its origin and the consumer acts without sufficient provenance, isolation, or approval. <!-- SAF-TRACE: claims=SAF-T1702-C001, SAF-T1702-C007; sources=SRC-owasp-agentic-top10-2026, SRC-cisco-memorytrap-2026, SRC-minja-2026 -->

## Attack Vectors

1. **Query-only injection**: crafted interactions cause an agent to write attacker-chosen content into shared long-term memory without direct database access. <!-- SAF-TRACE: claims=SAF-T1702-C003; sources=SRC-minja-2026 -->
2. **Untrusted project or artifact ingestion**: a user-authorized workflow processes attacker-controlled content that reaches a persistent global or shared memory location. <!-- SAF-TRACE: claims=SAF-T1702-C005, SAF-T1702-C007; sources=SRC-cisco-memorytrap-2026 -->
3. **Direct memory or retrieval-corpus access**: an attacker able to add a small number of crafted records biases later retrieval while preserving most benign behavior. <!-- SAF-TRACE: claims=SAF-T1702-C004; sources=SRC-agentpoison-2024 -->
4. **Cross-agent propagation**: one agent writes a poisoned record that another agent later consumes from common context. <!-- SAF-TRACE: claims=SAF-T1702-C001; sources=SRC-owasp-agentic-top10-2026 -->

## Technical Details

The minimal sequence is an accepted write, a durable or retrievable record, a later cross-boundary read, and a behaviorally relevant use of that record. The write and read may be separated by sessions or reboots, so content inspection at the final action cannot reconstruct the full causal chain by itself. <!-- SAF-TRACE: claims=SAF-T1702-C005, SAF-T1702-C007, SAF-T1702-C008; sources=SRC-cisco-memorytrap-2026, SRC-minja-2026, SRC-smsr-2026 -->

An inert event sequence suitable for detector testing is shown below; it contains no executable instruction. <!-- SAF-TRACE: claims=SAF-T1702-C008; sources=SRC-owasp-agentic-top10-2026, SRC-mind-2026 -->

```json
{"event_type":"memory_write","memory_id":"m-42","writer_principal_id":"external-user","writer_session_id":"s-1","tenant_id":"demo","namespace":"shared","source_trust":"untrusted","review_status":"unreviewed"}
{"event_type":"memory_read","memory_ids":["m-42"],"reader_principal_id":"service-agent","reader_session_id":"s-2","tenant_id":"demo","namespace":"shared"}
{"event_type":"agent_action","principal_id":"service-agent","session_id":"s-2","risk":"high","context_memory_ids":["m-42"],"action":"open example.invalid staging record"}
```

## Evidence and Current State

### Evidence Summary

| Claim | Evidence | Status |
|---|---|---|
| SAF-T1702-C001 | OWASP defines shared-memory poisoning as persistent manipulation of stored or retrievable agent information, including cross-session and cross-agent propagation. | Validated <!-- SAF-TRACE: claims=SAF-T1702-C001; sources=SRC-owasp-agentic-top10-2026 --> |
| SAF-T1702-C002 | MCP specifies context-bearing capabilities and explicit trust, consent, and access-control responsibilities, without standardizing a persistent-memory trust model. | Validated <!-- SAF-TRACE: claims=SAF-T1702-C002; sources=SRC-mcp-spec-2025-06 --> |
| SAF-T1702-C003 | MINJA demonstrates query-only injection into shared long-term memory across users in controlled agent systems. | Validated <!-- SAF-TRACE: claims=SAF-T1702-C003; sources=SRC-minja-2026 --> |
| SAF-T1702-C004 | AgentPoison demonstrates poisoning of long-term memory and retrieval-augmented agent stores under a partial-memory-access assumption. | Validated <!-- SAF-TRACE: claims=SAF-T1702-C004; sources=SRC-agentpoison-2024 --> |
| SAF-T1702-C005 | Cisco's MemoryTrap disclosure demonstrates persistence across Claude Code projects, sessions, and reboots after a user processes an untrusted repository. | Validated <!-- SAF-TRACE: claims=SAF-T1702-C005; sources=SRC-cisco-memorytrap-2026 --> |
| SAF-T1702-C006 | The reviewed direct-authority corpus establishes controlled demonstrations and a disclosed vulnerability, but no qualifying production breach or mechanism-specific CVE/KEV. | Validated, search-bounded <!-- SAF-TRACE: claims=SAF-T1702-C006; sources=SRC-cisco-memorytrap-2026, SRC-agentpoison-2024, SRC-minja-2026 --> |
| SAF-T1702-C007 | A shared store, an attacker-reachable write or ingestion route, later retrieval, and cross-boundary influence are required conditions. | Validated <!-- SAF-TRACE: claims=SAF-T1702-C007; sources=SRC-owasp-agentic-top10-2026, SRC-minja-2026 --> |
| SAF-T1702-C008 | Correlating memory-write provenance, cross-principal retrieval, and a later sensitive action is a behavior-focused detection design. | Validated inference <!-- SAF-TRACE: claims=SAF-T1702-C008; sources=SRC-owasp-agentic-top10-2026, SRC-mitre-t1565.001, SRC-mind-2026 --> |
| SAF-T1702-C009 | Content-only or prompt-level detectors can be bypassed or produce false positives, so they are insufficient as the sole control. | Validated <!-- SAF-TRACE: claims=SAF-T1702-C009; sources=SRC-minja-2026, SRC-agentpoison-2024, SRC-injecmem-2026, SRC-mind-2026 --> |
| SAF-T1702-C010 | Isolation, provenance, quarantine, rollback, and action gating reduce the opportunity or consequence, subject to implementation assumptions. | Validated <!-- SAF-TRACE: claims=SAF-T1702-C010; sources=SRC-owasp-agentic-top10-2026, SRC-smsr-2026, SRC-poem-2026 --> |
| SAF-T1702-C011 | Integrity impact is direct; confidentiality, availability, or external action impact is conditional on the consumer's downstream authority. | Validated inference <!-- SAF-TRACE: claims=SAF-T1702-C011; sources=SRC-owasp-agentic-top10-2026, SRC-cisco-memorytrap-2026 --> |
| SAF-T1702-C012 | Stored Data Manipulation is an analogous ATT&CK data-integrity mapping, while Lateral Movement reflects the cross-consumer pivot rather than a network logon. | Validated analogy <!-- SAF-TRACE: claims=SAF-T1702-C012; sources=SRC-mitre-ta0008-2025, SRC-mitre-t1565.001 --> |
| SAF-T1702-C013 | Response should preserve evidence, block further retrieval, revoke affected write paths, quarantine records, and restore trusted state. | Validated <!-- SAF-TRACE: claims=SAF-T1702-C013; sources=SRC-owasp-agentic-top10-2026 --> |
| SAF-T1702-C014 | Attack success varies with model, memory density, pre-existing correct memory, and defense configuration; laboratory rates do not establish field prevalence. | Validated challenge <!-- SAF-TRACE: claims=SAF-T1702-C014; sources=SRC-arxiv-memory-defense-2026, SRC-minja-2026 --> |
| SAF-T1702-C015 | The technique is distinguished from current-session prompt injection and unpersisted inter-agent communication by the durable retrieval boundary. | Validated inference <!-- SAF-TRACE: claims=SAF-T1702-C015; sources=SRC-owasp-agentic-top10-2026 --> |

### Highest-Impact Qualifying Examples

| Example | Relationship | What the evidence establishes | Limitation |
|---|---|---|---|
| MemoryTrap | Direct vulnerability and controlled demonstration | An untrusted repository plus user-approved setup reached global Claude Code memory and hooks, persisting across projects, sessions, and reboots; Cisco reports remediation in version 2.1.50. | No production exploitation was reported, and the patch status was not independently verified in a reviewed Anthropic advisory. <!-- SAF-TRACE: claims=SAF-T1702-C005, SAF-T1702-C006; sources=SRC-cisco-memorytrap-2026 --> |
| MINJA | Direct demonstration | Query-only interactions poisoned shared long-term memory without direct storage access; the paper reports aggregate injection and attack success across evaluated systems. | Controlled benchmarks do not establish production prevalence, and results depend on model and memory conditions. <!-- SAF-TRACE: claims=SAF-T1702-C003, SAF-T1702-C014; sources=SRC-minja-2026, SRC-arxiv-memory-defense-2026 --> |
| AgentPoison | Direct demonstration | Crafted records biased long-term-memory and retrieval-augmented agents while using a small poisoning budget. | The attacker model assumes partial access to the memory or retrieval corpus, and reported rates are laboratory results. <!-- SAF-TRACE: claims=SAF-T1702-C004, SAF-T1702-C014; sources=SRC-agentpoison-2024 --> |

No reviewed direct source established a production breach, a mechanism-specific CVE in NVD, or inclusion in CISA's Known Exploited Vulnerabilities catalog. This absence is a bounded research result, not proof that exploitation has never occurred. <!-- SAF-TRACE: claims=SAF-T1702-C006; sources=SRC-cisco-memorytrap-2026, SRC-agentpoison-2024, SRC-minja-2026 -->

## Impact Assessment

Memory integrity is the immediate loss: a later consumer reasons from attacker-influenced state. If that consumer can access tools or sensitive context, the poison can conditionally cause unauthorized changes, disclosure, unsafe guidance, or service disruption. <!-- SAF-TRACE: claims=SAF-T1702-C011; sources=SRC-owasp-agentic-top10-2026, SRC-cisco-memorytrap-2026 -->

The cross-consumer pivot supports a Lateral Movement classification, but it should not be read as evidence of a conventional remote-service or credential-based network movement step. <!-- SAF-TRACE: claims=SAF-T1702-C012; sources=SRC-mitre-ta0008-2025, SRC-mitre-t1565.001 -->

## Detection Methods

Capture append-only memory-write records with writer identity, session, tenant, namespace, origin, trust decision, review state, record identifier, and content hash; capture retrieval records with reader identity and retrieved memory identifiers; and capture later high-risk actions with the context identifiers that influenced them. <!-- SAF-TRACE: claims=SAF-T1702-C008; sources=SRC-owasp-agentic-top10-2026, SRC-mind-2026, SRC-smsr-2026 -->

Alert when an untrusted or unknown write is retrieved by a different principal or session and the reader performs a high-risk action soon afterward using that memory identifier. Treat the timing windows as deployment-specific because dormant poisons may persist longer than the tested analytic window. <!-- SAF-TRACE: claims=SAF-T1702-C008, SAF-T1702-C009; sources=SRC-mind-2026, SRC-smsr-2026 -->

The repository analytic and deterministic tests are recorded in [detection-rule.yml](detection-rule.yml), [tests/SAF-T1702/](../../tests/SAF-T1702/), and the [validation proof](../../research/techniques/SAF-T1702/validation/detection-test.txt).

Expected false positives include approved shared-memory curation, multi-session workflows owned by the same trust domain, migrations, and legitimate automation that performs a sensitive action after consuming newly curated shared context. <!-- SAF-TRACE: claims=SAF-T1702-C008, SAF-T1702-C009; sources=SRC-mind-2026, SRC-injecmem-2026 -->

## Mitigation Strategies

- **[SAF-M-29: Explicit Privilege Boundaries](../../mitigations/SAF-M-29/README.md)** and **[SAF-M-21: Output Context Isolation](../../mitigations/SAF-M-21/README.md)**: Partition memory by tenant, principal, agent, purpose, and trust level; make cross-boundary sharing explicit and least-privileged. <!-- SAF-TRACE: claims=SAF-T1702-C010; sources=SRC-owasp-agentic-top10-2026 -->
- **[SAF-M-30: Vector Store Integrity Verification](../../mitigations/SAF-M-30/README.md)** and **[SAF-M-12: Audit Logging](../../mitigations/SAF-M-12/README.md)**: Preserve write-time provenance and authenticate origins, while recognizing that provenance alone does not prove content safety. <!-- SAF-TRACE: claims=SAF-T1702-C009, SAF-T1702-C010; sources=SRC-smsr-2026, SRC-injecmem-2026 -->
- Require review or bounded trust promotion before untrusted records enter durable shared memory; expire unverified records and prevent automatic re-ingestion of model output. <!-- SAF-TRACE: claims=SAF-T1702-C010; sources=SRC-owasp-agentic-top10-2026 -->
- Maintain quarantine and rollback paths for contaminated memory, and preserve lineage for incident reconstruction. <!-- SAF-TRACE: claims=SAF-T1702-C010, SAF-T1702-C013; sources=SRC-owasp-agentic-top10-2026, SRC-smsr-2026 -->
- **[SAF-M-32: Continuous Vector Store Monitoring](../../mitigations/SAF-M-32/README.md)**: Monitor memory writes, cross-principal retrieval, trust promotion, and later high-risk action for suspicious correlations. <!-- SAF-TRACE: claims=SAF-T1702-C008, SAF-T1702-C009; sources=SRC-owasp-agentic-top10-2026, SRC-mind-2026, SRC-smsr-2026 -->
- **[SAF-M-69: Out-of-Band Authorization for Privileged Tool Invocations](../../mitigations/SAF-M-69/README.md)** and **[SAF-M-74: Per-Invocation Capability Brokering](../../mitigations/SAF-M-74/README.md)**: Gate sensitive actions independently of memory content so a poisoned recommendation cannot directly authorize execution. <!-- SAF-TRACE: claims=SAF-T1702-C010; sources=SRC-poem-2026 -->

## Related Techniques

- [SAF-T1102: Prompt Injection (Multiple Vectors)](../SAF-T1102/README.md) differs because its defining hostile instruction can affect the current context without requiring a persistent cross-consumer memory retrieval. <!-- SAF-TRACE: claims=SAF-T1702-C015; sources=SRC-owasp-agentic-top10-2026 -->
- [SAF-T1705: Cross-Agent Instruction Injection](../SAF-T1705/README.md) differs because its defining boundary is an exchanged inter-agent instruction that need not become durable retrievable memory. <!-- SAF-TRACE: claims=SAF-T1702-C015; sources=SRC-owasp-agentic-top10-2026 -->

## MITRE ATT&CK Mapping

| Mapping | Relationship | Rationale |
|---|---|---|
| ATK-TA0008 Lateral Movement | Primary tactic | The attacker-controlled record crosses into a different session, principal, or agent's trusted working context; this is an agentic-system pivot, not necessarily a network logon. <!-- SAF-TRACE: claims=SAF-T1702-C012; sources=SRC-mitre-ta0008-2025 --> |
| T1565.001 Stored Data Manipulation | Analogous enterprise technique | Both mechanisms target the integrity of stored information so a later consumer acts on modified data, but ATT&CK's enterprise entry is not an agent-memory specification. <!-- SAF-TRACE: claims=SAF-T1702-C012; sources=SRC-mitre-t1565.001 --> |

## References

- **SRC-mcp-spec-2025-06** — Model Context Protocol Specification, 2025-06-18. Model Context Protocol contributors. https://modelcontextprotocol.io/specification/2025-06-18/index
- **SRC-owasp-agentic-top10-2026** — OWASP Top 10 for Agentic Applications 2026. OWASP GenAI Security Project Agentic Security Initiative; project and ASI06 leads credited in the source acknowledgements. https://genai.owasp.org/download/52117/?tmstv=1765059207
- **SRC-cisco-memorytrap-2026** — “Identifying and Remediating a Persistent Memory Compromise in Claude Code.” Idan Habler and Amy Chang; Cisco AI Defense. https://blogs.cisco.com/ai/identifying-and-remediating-a-persistent-memory-compromise-in-claude-code
- **SRC-agentpoison-2024** — “AgentPoison: Red-teaming LLM Agents via Poisoning Memory or Knowledge Bases.” Zhaorun Chen, Zhen Xiang, Chaowei Xiao, Dawn Song, and Bo Li. https://arxiv.org/pdf/2407.12784
- **SRC-minja-2026** — “Memory Injection Attacks on LLM Agents via Query-Only Interaction.” Shen Dong, Shaochen Xu, Pengfei He, Yige Li, Jiliang Tang, Tianming Liu, Hui Liu, and Zhen Xiang. https://arxiv.org/pdf/2503.03704
- **SRC-arxiv-memory-defense-2026** — “Defending Long-Term Memory in LLM Agents Against Memory Injection Attacks.” Balachandra Devarangadi Sunil, Isheeta Sinha, Piyush Maheshwari, Shantanu Todmal, Shreyan Mallik, and Shuchi Mishra. https://arxiv.org/pdf/2601.05504
- **SRC-mitre-ta0008-2025** — “Lateral Movement, Tactic TA0008.” MITRE ATT&CK Team. https://attack.mitre.org/tactics/TA0008/
- **SRC-mitre-t1565.001** — “Stored Data Manipulation, T1565.001.” MITRE ATT&CK Team. https://attack.mitre.org/techniques/T1565/001/
- **SRC-smsr-2026** — “SMSR: Certified Defence for Multi-Session LLM Agents Against Memory Poisoning.” Tarun Sharma. https://arxiv.org/pdf/2606.12703
- **SRC-poem-2026** — “PoEM: A Verifiable Execution Layer for LLM Agents Under Memory Poisoning.” Md Habibur Rahman and Jaeho Kim. https://arxiv.org/pdf/2608.16032
- **SRC-injecmem-2026** — “InjecMEM: Benchmarking Memory Injection Attacks and Defenses in LLM Agents.” Hanling Tian, Gengyu Zhang, Zeyang Sha, Jingying Wang, Yuhang Liu, Zhehao Huang, Kun Yang, and Xiaolin Huang. https://arxiv.org/pdf/2608.23471
- **SRC-mind-2026** — “MIND: Lightweight and Effective Memory Injection Defense for LLM Agents.” Dongyi Liu, Haixing He, Xiaobao Wu, and Jia Li. https://arxiv.org/pdf/2607.28103

## Version History

| Version | Date | Author/Team | Changes |
|---|---|---|---|
| 1.0 | 2026-09-02 | OpenAI Codex clean-room generator `/root/cleanroom_saf_t1702` | Independent source-or-omit authoring, behavioral detector, isolated strict validation, and publication-rights review. |
| 1.1 | 2026-09-02 | The SAF-MCP Authors | Deprecated as a compatibility ID after consolidation into SAF-T1204 under SAF-TAX-014; retained the evidence and attribution record. |
