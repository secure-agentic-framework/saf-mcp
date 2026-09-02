# SAF-T3001: RAG Backdoor Attack

- **Technique ID**: SAF-T3001
- **Tactic**: ATK-TA0040 (Impact)
- **Evidence Status**: Demonstrated
- **Documentation Status**: Stable
- **Last Updated**: 2026-09-02

## Overview

A RAG backdoor attack plants attacker-controlled passages in a retrieval corpus so that trigger-matching queries retrieve those passages and the generator produces an attacker-selected response while ordinary queries remain substantially unaffected. <!-- SAF-TRACE: claims=SAF-T3001-C001, SAF-T3001-C002; sources=SRC-badrag -->

The defining boundary is the transition from material admitted to a trusted knowledge source into retrieved model context; the attack does not require changing the base model or retriever. <!-- SAF-TRACE: claims=SAF-T3001-C001, SAF-T3001-C006; sources=SRC-badrag, SRC-nist-aml -->

## Scope

This technique covers durable corpus insertion, trigger-conditioned retrieval, and downstream generation of the selected response with an unchanged retriever and generator. <!-- SAF-TRACE: claims=SAF-T3001-C001; sources=SRC-badrag -->

It excludes transient prompt injection with no corpus state, poisoning model weights or retriever training, ordinary authorization failures, and any later tool execution caused by the generated response. <!-- SAF-TRACE: claims=SAF-T3001-C006; sources=SRC-nist-aml -->

## Description

An adversary first obtains a path by which documents or passages can enter a corpus used for retrieval. The adversary then crafts content that ranks highly for a chosen semantic trigger and carries the desired answer or behavioral instruction. <!-- SAF-TRACE: claims=SAF-T3001-C001, SAF-T3001-C002; sources=SRC-badrag -->

When a matching query arrives, the retriever supplies the planted passage as trusted grounding context and the generator can emit the adversary's target. Clean-query behavior can remain close to baseline, making result-only monitoring insufficient. <!-- SAF-TRACE: claims=SAF-T3001-C002; sources=SRC-badrag -->

## Attack Vectors

- Upload or publish a crafted passage through a source that an ingestion pipeline accepts. <!-- SAF-TRACE: claims=SAF-T3001-C001, SAF-T3001-C009; sources=SRC-badrag, SRC-owasp-rag-security -->
- Modify a document in an already trusted source before synchronization or re-indexing. <!-- SAF-TRACE: claims=SAF-T3001-C009; sources=SRC-owasp-rag-security -->
- Optimize several passages for a target question or semantic trigger so at least one survives retrieval and affects generation. <!-- SAF-TRACE: claims=SAF-T3001-C003, SAF-T3001-C004; sources=SRC-usenix-poisonedrag-2025, SRC-riprag -->

## Technical Details

The attack has two coupled requirements: a planted passage must satisfy the retriever's ranking condition and its content must satisfy the generator condition for the selected output. <!-- SAF-TRACE: claims=SAF-T3001-C003; sources=SRC-usenix-poisonedrag-2025 -->

BadRAG demonstrated group-level semantic triggers using ten corpus passages without modifying the retriever or generator; in its reported Contriever tests, triggered top-1 retrieval was 98.2–99.8% while clean-query retrieval of the poison was 0.05–0.21%. <!-- SAF-TRACE: claims=SAF-T3001-C002; sources=SRC-badrag -->

PoisonedRAG demonstrated targeted answer corruption across three datasets, eight language models, three application tests, and both retriever-knowledge settings; five malicious texts per target produced at least 90% attack success in the headline evaluation. <!-- SAF-TRACE: claims=SAF-T3001-C003; sources=SRC-usenix-poisonedrag-2025 -->

RIPRAG demonstrated a black-box variant that learns from interactions with the target system; reported attack-success rates ranged from 0.35 to 1.00 with one injected document across evaluated configurations. <!-- SAF-TRACE: claims=SAF-T3001-C004; sources=SRC-riprag -->

Confundo reports that preprocessing and query variation can sharply reduce earlier attacks in practical pipelines, and demonstrates a poison generator designed to improve robustness across those transformations. <!-- SAF-TRACE: claims=SAF-T3001-C005; sources=SRC-usenix-confundo-2026 -->

## Evidence and Current State

The status is **Demonstrated** because independent controlled studies show the complete corpus-insertion, retrieval, and generation path; the reviewed record does not establish a confirmed production compromise using this exact mechanism. <!-- SAF-TRACE: claims=SAF-T3001-C001, SAF-T3001-C012; sources=SRC-badrag, SRC-usenix-poisonedrag-2025, SRC-ms-recommendation-poisoning-2026 -->

The [research packet](../../research/techniques/SAF-T3001/source-coverage.yml) records domain-restricted incident, vulnerability, demonstration, defense, and contrary-evidence searches and the explicit production-evidence gap.

### Evidence Summary

| Claim | Status | Summary |
|---|---|---|
| SAF-T3001-C001 | Demonstrated | Corpus insertion can condition retrieval and generated output without changing model components. |
| SAF-T3001-C002 | Demonstrated | BadRAG reports high triggered retrieval and low clean-query retrieval of poison. |
| SAF-T3001-C003 | Demonstrated | PoisonedRAG reports targeted answer corruption across models, datasets, and applications. |
| SAF-T3001-C004 | Demonstrated | RIPRAG reports black-box optimization with one injected document. |
| SAF-T3001-C005 | Demonstrated | Confundo tests preprocessing- and query-robust poison generation. |
| SAF-T3001-C006 | Research-Derived | The technique boundary is runtime retrieval state, not training-time weights. |
| SAF-T3001-C007 | Demonstrated | Consequences are bounded by what the generated response influences. |
| SAF-T3001-C008 | Research-Derived | ATT&CK Impact and Stored Data Manipulation are the closest enterprise mappings. |
| SAF-T3001-C009 | Research-Derived | Provenance, integrity, write controls, and retrieval tracing reduce exposure and aid response. |
| SAF-T3001-C010 | Research-Derived | The supplied analytic is a provenance/integrity signal, not proof of poisoning. |
| SAF-T3001-C011 | Demonstrated | Evaluated defenses reduce some attacks but leave meaningful residual success. |
| SAF-T3001-C012 | Research-Derived | In-the-wild AI memory poisoning attempts are adjacent, not exact corpus-backdoor evidence. |

## Impact Assessment

The immediate impact is integrity loss: selected queries can receive attacker-chosen facts, recommendations, sentiment, or refusal behavior while other queries appear normal. <!-- SAF-TRACE: claims=SAF-T3001-C002, SAF-T3001-C007; sources=SRC-badrag, SRC-usenix-poisonedrag-2025 -->

Severity is **High** when answers guide consequential human or automated decisions; higher downstream harm requires a separate action path and is not inherent to the retrieval backdoor itself. <!-- SAF-TRACE: claims=SAF-T3001-C007; sources=SRC-nist-aml, SRC-ms-recommendation-poisoning-2026 -->

## Detection Methods

Collect ingestion and retrieval events containing document identity, source approval, stored and observed hashes, index-write identity, query or trigger grouping, returned rank, and downstream response identifiers. <!-- SAF-TRACE: claims=SAF-T3001-C009, SAF-T3001-C010; sources=SRC-owasp-rag-security -->

The accompanying [candidate analytic](detection-rule.yml) alerts when a returned passage is from an unapproved source or fails integrity verification, excluding declared test traffic. <!-- SAF-TRACE: claims=SAF-T3001-C010; sources=SRC-owasp-rag-security -->

This signal cannot detect a malicious but intact passage admitted through an approved source, and anomalous embeddings or retrieval distributions alone do not prove poisoning. <!-- SAF-TRACE: claims=SAF-T3001-C010, SAF-T3001-C011; sources=SRC-owasp-rag-security, SRC-badrag -->

## Mitigation Strategies

- Restrict corpus and index writes to authenticated ingestion services and require approval for new sources. <!-- SAF-TRACE: claims=SAF-T3001-C009; sources=SRC-owasp-rag-security -->
- Hash documents at ingestion, verify integrity before retrieval, preserve source attribution, and keep replayable query-to-chunk-to-output traces. <!-- SAF-TRACE: claims=SAF-T3001-C009; sources=SRC-owasp-rag-security -->
- Quarantine identified passages, invalidate affected caches, restore a known-good index snapshot, and identify users who received tainted responses. <!-- SAF-TRACE: claims=SAF-T3001-C009; sources=SRC-owasp-rag-security -->
- Treat paraphrasing, perplexity filtering, duplicate filtering, and retrieval guardrails as defense in depth because published evaluations report residual attack success or substantial false positives. <!-- SAF-TRACE: claims=SAF-T3001-C011; sources=SRC-usenix-poisonedrag-2025, SRC-riprag -->

## Related Techniques

- A transient indirect-instruction injection differs because it influences one assembled context without first establishing trigger-conditioned retrieval from durable corpus state. <!-- SAF-TRACE: claims=SAF-T3001-C006; sources=SRC-nist-aml -->
- Memory poisoning differs when an instruction is written to assistant memory directly rather than selected through a document retriever. <!-- SAF-TRACE: claims=SAF-T3001-C012; sources=SRC-ms-recommendation-poisoning-2026 -->
- [SAF-T2106: Context Memory Poisoning via Vector Store Contamination](../SAF-T2106/README.md) is the parent vector-store write-and-retrieval behavior; SAF-T3001 adds trigger-conditioned retrieval and an attacker-selected generated response. [Framework Model v2 taxonomy review](../../research/taxonomy-review.yml)

## MITRE ATT&CK Mapping

This technique maps to **Impact (ATK-TA0040)** because the immediate objective is to manipulate the integrity of answers or decisions, and it is analogous to **T1565.001 Stored Data Manipulation** because attacker-inserted stored data changes later outcomes. This is a framework inference, not an assertion that ATT&CK defines RAG backdoors. <!-- SAF-TRACE: claims=SAF-T3001-C008; sources=SRC-mitre-ta0040, SRC-mitre-attack-t1565 -->

## References

1. **SRC-badrag** — Jiaqi Xue, Mengxin Zheng, Yebowen Hu, Fei Liu, Xun Chen, and Qian Lou, “BadRAG: Identifying Vulnerabilities in Retrieval Augmented Generation of Large Language Models,” 2024.
2. **SRC-usenix-poisonedrag-2025** — Wei Zou, Runpeng Geng, Binghui Wang, and Jinyuan Jia, “PoisonedRAG: Knowledge Corruption Attacks to Retrieval-Augmented Generation of Large Language Models,” USENIX Security 2025.
3. **SRC-riprag** — Meng Xi, Sihan Lv, Yechen Jin, Guanjie Cheng, Naibo Wang, Ying Li, and Jianwei Yin, “RIPRAG,” Findings of ACL 2026.
4. **SRC-usenix-confundo-2026** — Haoyang Hu, Zhejun Jiang, Yueming Lyu, Junyuan Zhang, Yi Liu, and Ka-Ho Chow, “Confundo,” USENIX Security 2026.
5. **SRC-owasp-rag-security** — OWASP Cheat Sheet Series contributors, “RAG Security Cheat Sheet.”
6. **SRC-nist-aml** — Apostol Vassilev, Alina Oprea, Alie Fordyce, and Hyrum Anderson, NIST AI 100-2e2023.
7. **SRC-mitre-ta0040** — MITRE ATT&CK team, “Impact, Tactic TA0040.”
8. **SRC-mitre-attack-t1565** — MITRE ATT&CK team, “Data Manipulation, T1565.”
9. **SRC-ms-recommendation-poisoning-2026** — Microsoft Defender Security Research Team, “Manipulating AI memory for profit,” 2026.

## Version History

| Version | Date | Changes |
|---|---|---|
| 1.0 | 2026-09-02 | Clean-room authored technique with research packet and tested candidate analytic. |
| 1.1 | 2026-09-02 | Classified as the trigger-conditioned specialization of SAF-T2106 under SAF-TAX-014. |
