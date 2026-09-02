# SAF-T2106: Context Memory Poisoning via Vector Store Contamination

## Overview

- **Technique ID**: SAF-T2106
- **Tactic**: ATK-TA0040
- **Evidence Status**: Demonstrated
- **Documentation Status**: Under Review
- **Severity**: High
- **Research Packet**: [research/techniques/SAF-T2106](../../research/techniques/SAF-T2106/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T2106/traceability-ledger.yml)
- **Last Updated**: 2026-09-02

Persistent attacker-controlled records can affect later retrievals and, in demonstrated agent settings, induce unsafe actions while benign performance remains nearly unchanged. <!-- SAF-TRACE: claims=SAF-T2106-C002,SAF-T2106-C003; sources=SRC-neurips-agentpoison-2024 -->

No qualifying production breach was established in the reviewed sources; the end-to-end behavior is demonstrated experimentally and direct product vulnerabilities were disclosed in 2026. <!-- SAF-TRACE: claims=SAF-T2106-C005,SAF-T2106-C006,SAF-T2106-C007; sources=SRC-openwebui-ghsa,SRC-ibm-langflow,SRC-ms-recommendation-poisoning-2026,SRC-microsoft-ai-gateway-incident -->

## Scope

Context memory poisoning via vector store contamination occurs when an adversary crosses a write or collection-ownership boundary to place attacker-controlled records in persistent retrieval memory, and a later semantically matched retrieval incorporates those records into an agent's context. <!-- SAF-TRACE: claims=SAF-T2106-C001,SAF-T2106-C002,SAF-T2106-C004; sources=SRC-mcp-resources-2025-11-25,SRC-neurips-agentpoison-2024,SRC-usenix-poisonedrag-2025 -->

The defining outcome is persistent influence through retrieved external state; one-turn prompt injection and poisoning learned model weights are outside this technique. <!-- SAF-TRACE: claims=SAF-T2106-C008; sources=SRC-nist-aml,SRC-neurips-agentpoison-2024 -->

## Description

MCP resources can expose text or binary context, while the application decides how resources are incorporated and may automatically include them; MCP resource semantics do not themselves define a vector-memory implementation. <!-- SAF-TRACE: claims=SAF-T2106-C001; sources=SRC-mcp-resources-2025-11-25 -->

In common RAG and memory architectures, a query is embedded, similar stored records are retrieved, and their content is supplied to the model or agent. <!-- SAF-TRACE: claims=SAF-T2106-C002,SAF-T2106-C004; sources=SRC-neurips-agentpoison-2024,SRC-usenix-poisonedrag-2025 -->

## Attack Vectors

- The target uses persistent vector-backed memory or a RAG knowledge base in a later model or agent decision. <!-- SAF-TRACE: claims=SAF-T2106-C002,SAF-T2106-C004; sources=SRC-neurips-agentpoison-2024,SRC-usenix-poisonedrag-2025 -->
- The adversary can insert, replace, or cause ingestion of records across an intended write, tenancy, provenance, or collection-ownership boundary. <!-- SAF-TRACE: claims=SAF-T2106-C005,SAF-T2106-C006; sources=SRC-openwebui-ghsa,SRC-ibm-langflow -->
- A later query is sufficiently similar to retrieve the poisoned record, and the consuming agent assigns that record enough influence to affect its response or action. <!-- SAF-TRACE: claims=SAF-T2106-C002,SAF-T2106-C004; sources=SRC-neurips-agentpoison-2024,SRC-usenix-poisonedrag-2025 -->

## Technical Details

1. The adversary identifies a persistent retrieval collection whose write or ownership boundary is missing, weak, or otherwise reachable. <!-- SAF-TRACE: claims=SAF-T2106-C005,SAF-T2106-C006; sources=SRC-openwebui-ghsa,SRC-ibm-langflow -->
2. The adversary places or substitutes attacker-controlled content in that collection. <!-- SAF-TRACE: claims=SAF-T2106-C002,SAF-T2106-C004,SAF-T2106-C005; sources=SRC-neurips-agentpoison-2024,SRC-usenix-poisonedrag-2025,SRC-openwebui-ghsa -->
3. A later request causes semantic retrieval of the contaminated record. <!-- SAF-TRACE: claims=SAF-T2106-C002,SAF-T2106-C004; sources=SRC-neurips-agentpoison-2024,SRC-usenix-poisonedrag-2025 -->
4. The host supplies the retrieved content to the model or agent, which may produce an attacker-favored answer or action. <!-- SAF-TRACE: claims=SAF-T2106-C002,SAF-T2106-C003,SAF-T2106-C004; sources=SRC-neurips-agentpoison-2024,SRC-usenix-poisonedrag-2025 -->

## Evidence and Current State

### Evidence Summary

| Claim ID | Validated proposition |
|---|---|
| SAF-T2106-C001 | MCP resources can carry context, but the application controls incorporation; this supports the protocol boundary without asserting that MCP itself specifies vector memory. |
| SAF-T2106-C002 | AgentPoison demonstrated that a small number of poisoned memory or knowledge-base records can be preferentially retrieved and influence three evaluated agent types. |
| SAF-T2106-C003 | AgentPoison reported high retrieval attack success with low average benign-performance impact, while its primary method assumed white-box embedder access and evaluated bounded environments rather than production incidents. |
| SAF-T2106-C004 | PoisonedRAG demonstrated targeted answer manipulation by injecting a small number of texts into RAG knowledge databases, including an LLM-agent evaluation, but documented failure cases and non-target effects. |
| SAF-T2106-C005 | GHSA-7r82-qhg4-6wvj / CVE-2026-44554 disclosed that an authorization failure could overwrite another Open WebUI vector collection with attacker-controlled content; version 0.9.0 fixed it, and CISA's reviewed record reported no known exploitation. |
| SAF-T2106-C006 | IBM disclosed CVE-2026-13444, in which shared Langflow Chroma and FAISS namespaces permitted cross-tenant collection pollution and reads; version 1.10.2 fixed it. |
| SAF-T2106-C007 | The reviewed incident and vulnerability corpus did not establish a qualifying production breach with verified vector-store contamination and downstream model effect. |
| SAF-T2106-C008 | This technique changes persistent external retrieval state without retraining model weights and is distinct from content that affects only the current prompt. |
| SAF-T2106-C009 | A practical analytic can correlate an unauthorized or untrusted memory-write event with a later retrieval of the same record identifier in a different session. |
| SAF-T2106-C010 | Missing identifiers and provenance limit correlation; approved bulk ingestion, migrations, and evaluation fixtures can resemble contamination and require tuning. |
| SAF-T2106-C011 | Write authorization, provenance, versioning, source approval, and retrieval monitoring directly reduce or expose this technique's defining mechanism. |
| SAF-T2106-C012 | Evaluated query-paraphrasing and perplexity defenses did not reliably eliminate retrieval poisoning, so they should not replace write-boundary controls. |
| SAF-T2106-C013 | ReliabilityRAG shows that filtering can provide bounded robustness under explicit corruption, reliability, and inference assumptions, which limits any claim that retrieval poisoning is intrinsically indefensible. |
| SAF-T2106-C014 | MITRE ATT&CK Stored Data Manipulation is a historical enterprise analogue for unauthorized stored-data changes that influence later outcomes, not proof of this AI-specific technique. |

### Demonstrations and Disclosures

| Evidence | Relationship | Result and boundary |
|---|---|---|
| AgentPoison (NeurIPS 2024) | Direct demonstration | Poisoned long-term memory or RAG knowledge bases altered agent outcomes across driving, question-answering, and healthcare evaluations; the method's main setup assumed white-box embedding access. <!-- SAF-TRACE: claims=SAF-T2106-C002,SAF-T2106-C003; sources=SRC-neurips-agentpoison-2024 --> |
| PoisonedRAG (USENIX Security 2025) | Direct demonstration | Five injected texts achieved high target-question attack success in evaluated datasets and produced substantial LLM-agent attack success, with documented failures and utility tradeoffs. <!-- SAF-TRACE: claims=SAF-T2106-C004,SAF-T2106-C012; sources=SRC-usenix-poisonedrag-2025 --> |
| CVE-2026-44554 | Direct vulnerability | An Open WebUI authorization failure permitted vector-collection replacement; the vendor advisory credits Classic298 as reporter and doge-woof as publisher, and 0.9.0 is the patched release. <!-- SAF-TRACE: claims=SAF-T2106-C005; sources=SRC-openwebui-ghsa,SRC-nvd-openwebui --> |
| CVE-2026-13444 | Direct vulnerability | IBM reported shared vector namespaces enabling cross-tenant pollution and reads in Langflow 1.0.0 through 1.10.1; 1.10.2 is the fix. <!-- SAF-TRACE: claims=SAF-T2106-C006; sources=SRC-ibm-langflow --> |

No selected item is presented as a confirmed production breach. Microsoft's observed AI-recommendation manipulation attempts did not establish the vector-store write and downstream effect required by this contract, while its RAGFlow compromise concerned infrastructure execution and credential theft rather than memory poisoning. <!-- SAF-TRACE: claims=SAF-T2106-C007; sources=SRC-ms-recommendation-poisoning-2026,SRC-microsoft-ai-gateway-incident -->

## Impact Assessment

Successful contamination can persist across sessions and affect answer integrity or agent actions; the demonstrated consequences ranged from wrong answers to unsafe driving behavior and a generated database-deletion action in bounded evaluations. <!-- SAF-TRACE: claims=SAF-T2106-C002,SAF-T2106-C003,SAF-T2106-C004; sources=SRC-neurips-agentpoison-2024,SRC-usenix-poisonedrag-2025 -->

The practical impact depends on retrieval, model reliance on retrieved content, agent permissions, and whether downstream actions are separately authorized. <!-- SAF-TRACE: claims=SAF-T2106-C002,SAF-T2106-C004; sources=SRC-neurips-agentpoison-2024,SRC-usenix-poisonedrag-2025 -->

## Detection Methods

Correlate a write carrying collection, record, actor, source, approval, tenant, and timestamp fields with a later retrieval carrying the same record identifier, retrieval score, requesting session, and consumer. Prioritize unapproved or untrusted writes followed by retrieval in another session. <!-- SAF-TRACE: claims=SAF-T2106-C009; sources=SRC-ms-zero-trust-memory-2026,SRC-otel-genai-2026,SRC-attack-det0193 -->

OpenTelemetry defines retrieval-document identifiers and scores that can support the retrieval half of this correlation, but deployments must instrument memory writes and preserve provenance themselves. <!-- SAF-TRACE: claims=SAF-T2106-C009,SAF-T2106-C010; sources=SRC-otel-genai-2026,SRC-ms-zero-trust-memory-2026 -->

Tune for approved bulk ingestion, migrations, administrative rebuilds, and test fixtures; without stable record identifiers or immutable write provenance, the analytic cannot reliably join write and retrieval events. <!-- SAF-TRACE: claims=SAF-T2106-C010; sources=SRC-ms-zero-trust-memory-2026,SRC-attack-det0193 -->

See the repository [detection rule](detection-rule.yml), [test cases](../../tests/SAF-T2106/test-cases.json), and [test implementation](../../tests/SAF-T2106/test_detection_rule.py).

## Mitigation Strategies

- Enforce collection-level authorization and tenant isolation on every ingestion, update, overwrite, and delete operation. <!-- SAF-TRACE: claims=SAF-T2106-C005,SAF-T2106-C006,SAF-T2106-C011; sources=SRC-openwebui-ghsa,SRC-ibm-langflow,SRC-azure-search-acl -->
- Record source identity, actor, time, change reason, approval state, and version for each memory record; monitor both writes and later retrieval influence. <!-- SAF-TRACE: claims=SAF-T2106-C011; sources=SRC-ms-zero-trust-memory-2026,SRC-nist-aml -->
- Require source approval before persistent ingestion and retain recoverable versions so contaminated collections can be compared and restored. <!-- SAF-TRACE: claims=SAF-T2106-C011; sources=SRC-ms-zero-trust-memory-2026,SRC-nist-aml -->
- Treat content-only filters as defense in depth: empirical evaluations found that paraphrasing, perplexity filtering, duplicate checks, and knowledge expansion can leave substantial attack success. <!-- SAF-TRACE: claims=SAF-T2106-C012; sources=SRC-neurips-agentpoison-2024,SRC-usenix-poisonedrag-2025 -->
- Where assumptions can be justified, reliability-aware filtering can bound attack success, but its guarantees depend on bounded corruption and classifier or inference reliability. <!-- SAF-TRACE: claims=SAF-T2106-C013; sources=SRC-reliabilityrag -->

## Related Techniques

- **[SAF-T1102: Prompt Injection (Multiple Vectors)](../SAF-T1102/README.md):** changes the current model context without requiring a persistent vector-store write and later retrieval. <!-- SAF-TRACE: claims=SAF-T2106-C008; sources=SRC-neurips-agentpoison-2024 -->
- **[SAF-T2107: AI Model Poisoning via MCP Tool Training Data Contamination](../SAF-T2107/README.md):** changes learned model behavior through training; this technique changes external persistent retrieval state without retraining. <!-- SAF-TRACE: claims=SAF-T2106-C008; sources=SRC-nist-aml,SRC-neurips-agentpoison-2024 -->
- **[SAF-T2105: Disinformation Output](../SAF-T2105/README.md):** requires a false or materially misleading informational result; this technique requires persistent vector-memory contamination and later retrieval regardless of the downstream response or action type. <!-- SAF-TRACE: claims=SAF-T2106-C008; sources=SRC-nist-aml,SRC-neurips-agentpoison-2024 -->
- **[SAF-T3001: RAG Backdoor Attack](../SAF-T3001/README.md):** is the trigger-conditioned specialization that requires an attacker-selected generated response while ordinary queries remain substantially unaffected. [Framework Model v2 taxonomy review](../../research/taxonomy-review.yml)
- **MITRE ATT&CK T1565.001 — Stored Data Manipulation:** provides an enterprise integrity analogue for stored-data changes, but does not establish the AI retrieval mechanism. <!-- SAF-TRACE: claims=SAF-T2106-C014; sources=SRC-mitre-t1565.001 -->

## MITRE ATT&CK Mapping

T1565.001 Stored Data Manipulation is the closest reviewed enterprise analogue because it covers unauthorized stored-data changes made to influence later outcomes; it is an analogy, not direct evidence of vector retrieval or model influence. <!-- SAF-TRACE: claims=SAF-T2106-C014; sources=SRC-mitre-t1565.001 -->

## Validation

The detection analytic was exercised against positive, temporal-boundary, negative, legitimate-administration, and malformed-telemetry cases; all cases passed. See the [destination validation proof](../../research/techniques/SAF-T2106/validation/canonical-validation.txt).

The complete claim inventory, source locators, exclusion ledger, rights review, and quality gates begin with the declared [claim inventory](../../research/techniques/SAF-T2106/claim-inventory.yml).

## References

- SRC-mcp-resources-2025-11-25
- SRC-neurips-agentpoison-2024
- SRC-usenix-poisonedrag-2025
- SRC-nist-aml
- SRC-otel-genai-2026
- SRC-azure-search-acl
- SRC-reliabilityrag
- SRC-ms-zero-trust-memory-2026
- SRC-mitre-t1565.001
- SRC-attack-det0193
- SRC-openwebui-ghsa
- SRC-nvd-openwebui
- SRC-ibm-langflow
- SRC-ms-recommendation-poisoning-2026
- SRC-microsoft-ai-gateway-incident

## Version History

| Version | Date | Changes |
|---|---|---|
| 1.0 | 2026-09-02 | Clean-room research draft frozen for canonical integration. |
| 1.1 | 2026-09-02 | Classified SAF-T3001 as a trigger-conditioned specialization under SAF-TAX-014. |
