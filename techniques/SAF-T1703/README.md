# SAF-T1703: Tool-Chaining Pivot

## Overview

- **Technique ID**: SAF-T1703
- **Tactic**: Lateral Movement (ATK-TA0008)
- **Documentation Status**: Stable
- **Evidence Status**: Demonstrated
- **Severity**: High
- **Last Updated**: 2026-09-26
- **Research Packet**: [research/techniques/SAF-T1703](../../research/techniques/SAF-T1703/technique-contract.yml)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1703/traceability-ledger.yml)

Tool-Chaining Pivot is the adversarial use of content or metadata from one tool boundary to induce an agent or host to invoke a different, already-authorized tool or service outside the user's supported intent. <!-- SAF-TRACE: claims=SAF-T1703-C018; sources=SRC-ms-redteam-update-2026 -->

The technique starts at the cross-tool decision: delivery of the malicious instruction is a prerequisite, while the defining outcome is a second-boundary call that exposes different data or action authority. <!-- SAF-TRACE: claims=SAF-T1703-C002,SAF-T1703-C018; sources=SRC-mcp-architecture-2026-07-28,SRC-ms-redteam-update-2026 -->

## Scope

In scope, an upstream tool description, result, retrieved object, or server-supplied instruction influences a later call to a distinct tool, server, connector, application, or security domain; the later call is unsupported by user intent and uses authority already available to the agent. <!-- SAF-TRACE: claims=SAF-T1703-C005,SAF-T1703-C018; sources=SRC-ms-agt,SRC-ms-redteam-update-2026 -->

Out of scope are injection delivery without a second tool boundary, misuse confined to one tool, direct compromise of a tool server, ordinary user-authorized multi-tool workflows, and conventional infrastructure exploit chains whose sequencing is chosen by an attacker rather than induced through agent context. <!-- SAF-TRACE: claims=SAF-T1703-C017,SAF-T1703-C018; sources=SRC-mitre-t1072,SRC-ms-redteam-update-2026 -->

## Description

MCP hosts can compose multiple isolated client-server sessions, and tool outputs return to the host's model context; that composition makes the host's cross-server decision point the relevant security boundary. <!-- SAF-TRACE: claims=SAF-T1703-C001,SAF-T1703-C002; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-architecture-2026-07-28 -->

An adversary who controls tool metadata or content returned by an upstream tool may steer the model toward a second tool call. The pivot succeeds when the later tool grants access or effect that the upstream source did not possess directly and the user did not authorize for that task. <!-- SAF-TRACE: claims=SAF-T1703-C006,SAF-T1703-C018; sources=SRC-ms-indirect-injection-2025,SRC-ms-redteam-update-2026 -->

## Attack Vectors

- A compromised or malicious integration inserts hidden instructions into a tool description that causes a trusted connector to read or write another system. <!-- SAF-TRACE: claims=SAF-T1703-C006,SAF-T1703-C012; sources=SRC-ms-indirect-injection-2025,SRC-microsoft-tool-poisoning-2026-06-30 -->
- An attacker-controlled record, message, page, document, or repository artifact enters through a read tool and directs a subsequent mail, file, code, browser, or administrative tool. <!-- SAF-TRACE: claims=SAF-T1703-C003,SAF-T1703-C004; sources=SRC-openai-atlas,SRC-usenix-attriguard -->
- A writable configuration surface causes an agent to register or trust a new tool and then execute through that added boundary. <!-- SAF-TRACE: claims=SAF-T1703-C007; sources=SRC-ghsa-cursor-4cxx-2025 -->
- A source-system message causes an agent to retrieve local secrets with one capability and disclose them through a different connected service. <!-- SAF-TRACE: claims=SAF-T1703-C008; sources=SRC-cve-34072 -->

## Technical Details

The minimum behavioral sequence is an untrusted or unknown upstream result, a causally linked later call to a distinct server or service, no supported user intent for that later call, and absent or bypassed approval for a consequential action. <!-- SAF-TRACE: claims=SAF-T1703-C011,SAF-T1703-C015; sources=SRC-microsoft-tool-poisoning-2026-06-30,SRC-usenix-attriguard -->

```text
source_tool_result(event_id=A, trust=untrusted)
  -> agent_context(A)
  -> target_tool_call(caused_by=A, server!=source, intent=false)
  -> privileged_read | external_write | code_execution
```

Authorization alone does not distinguish abuse: each individual call may be permitted even when the compound sequence was not approved as a workflow. <!-- SAF-TRACE: claims=SAF-T1703-C005,SAF-T1703-C010; sources=SRC-ms-agt,SRC-microsoft-tool-poisoning-2026-06-30 -->

### Prerequisites

- The agent can consume attacker-influenced tool metadata, results, or retrieved content. <!-- SAF-TRACE: claims=SAF-T1703-C006; sources=SRC-ms-indirect-injection-2025 -->
- The same host or workflow can invoke at least one additional tool or service with materially different authority. <!-- SAF-TRACE: claims=SAF-T1703-C002; sources=SRC-mcp-architecture-2026-07-28 -->
- Cross-tool policy, provenance controls, or consequential-action approval do not block the induced call. <!-- SAF-TRACE: claims=SAF-T1703-C013; sources=SRC-mcp-tools-2026-07-28 -->

## Evidence and Current State

The overall label is **Demonstrated**. Public evidence includes controlled end-to-end demonstrations, disclosed vulnerabilities, empirical experiments, and red-team engagements against deployed agentic systems; no public report reviewed here establishes a production intrusion by an external adversary that exactly matches the contract. <!-- SAF-TRACE: claims=SAF-T1703-C003,SAF-T1703-C004,SAF-T1703-C009; sources=SRC-openai-atlas,SRC-usenix-attriguard,SRC-ms-redteam-update-2026,SRC-openai-monitor -->

### Evidence Summary

| Claim | Status | Finding |
|---|---|---|
| SAF-T1703-C001 | Research-derived | MCP tools are model-controlled interfaces to external systems, with client-side confirmation and validation duties. |
| SAF-T1703-C002 | Research-derived | MCP hosts compose isolated server sessions and control cross-server interactions. |
| SAF-T1703-C003 | Demonstrated | OpenAI automated red teaming showed hostile email content causing a later unintended email action. |
| SAF-T1703-C004 | Demonstrated | AttriGuard evaluated indirect instructions in tool outputs that induce subsequent calls. |
| SAF-T1703-C005 | Research-derived | Per-call governance can miss risk that emerges only across a call sequence. |
| SAF-T1703-C006 | Research-derived | Tool descriptions and results are injection surfaces that can steer later calls. |
| SAF-T1703-C007 | Demonstrated | CVE-2025-54135 showed prompt injection creating MCP configuration that led to code execution. |
| SAF-T1703-C008 | Demonstrated | CVE-2025-34072 showed a Slack-originated instruction causing local-secret retrieval and Slack-mediated disclosure. |
| SAF-T1703-C009 | Research-derived | The reviewed corpus did not establish a contract-exact external-adversary production incident. |
| SAF-T1703-C010 | Research-derived | Impact depends on the second tool's authority and the compound workflow. |
| SAF-T1703-C011 | Research-derived | Cross-tool detection requires correlated tool-result and tool-call telemetry. |
| SAF-T1703-C012 | Research-derived | New destinations and expanded parameters are useful sequence-level signals. |
| SAF-T1703-C013 | Research-derived | Input validation, result validation, confirmation, and logging are protocol-level controls. |
| SAF-T1703-C014 | Research-derived | Legitimate multi-tool work and accidental injections are important false-positive sources. |
| SAF-T1703-C015 | Research-derived | Causal linkage plus a bounded window is a conservative analytic design. |
| SAF-T1703-C016 | Research-derived | Least privilege, provenance, output inspection, and action policy reduce pivot opportunity. |
| SAF-T1703-C017 | Research-derived | MITRE ATT&CK T1072 is an analogy, not an exact mapping. |
| SAF-T1703-C018 | Demonstrated | The complete cross-tool mechanism is supported by demonstrations and deployed-system red-team evidence. |

### Highest-Impact Qualifying Examples

- **Microsoft deployed-system red-team engagements (2025–2026):** several zero-click chains beginning with external input achieved exfiltration or lateral movement; the public account does not identify affected customers or provide a contract-exact event trace. <!-- SAF-TRACE: claims=SAF-T1703-C009,SAF-T1703-C018; sources=SRC-ms-redteam-update-2026 -->
- **CVE-2025-54135 (Cursor MCPoison):** prompt injection could write MCP configuration and produce code execution after a restart; the vendor added approval for MCP-related changes in version 1.3.9. <!-- SAF-TRACE: claims=SAF-T1703-C007; sources=SRC-ghsa-cursor-4cxx-2025 -->
- **CVE-2025-34072 (Anthropic Slack MCP server):** a controlled scenario chained Slack content, local-file access, Slack posting, and link unfurling to disclose data; the unmaintained server was archived rather than patched. <!-- SAF-TRACE: claims=SAF-T1703-C008; sources=SRC-cve-34072 -->
- **OpenAI Atlas red-team scenario:** content in an email encountered during a routine workflow caused the agent to send an unintended resignation email; OpenAI reports the demonstrated attack was patched. <!-- SAF-TRACE: claims=SAF-T1703-C003; sources=SRC-openai-atlas -->

### Evidence Gaps

The public evidence does not provide a named external threat actor, customer incident, and auditable cross-tool event sequence for the same production compromise; current confidence therefore stops at Demonstrated rather than Observed. <!-- SAF-TRACE: claims=SAF-T1703-C009; sources=SRC-ms-redteam-update-2026,SRC-openai-monitor -->

## Impact Assessment

Potential impact is high but conditional: a pivot can expose confidential data, create unauthorized external writes, or reach code execution when the target tool carries those permissions. <!-- SAF-TRACE: claims=SAF-T1703-C010; sources=SRC-microsoft-tool-poisoning-2026-06-30,SRC-ghsa-cursor-4cxx-2025 -->

The technique is lateral movement because the adversary-controlled influence crosses from its source integration into a distinct connected system using authority delegated to the agent. <!-- SAF-TRACE: claims=SAF-T1703-C017,SAF-T1703-C018; sources=SRC-mitre-t1072,SRC-ms-redteam-update-2026 -->

## Detection Methods

Correlate normalized agent telemetry by trace and causal event ID: flag an untrusted or unknown tool result followed within five minutes by a different-server tool call that is unsupported by user intent, lacks valid approval, and requests a privileged read, external write, or code execution. <!-- SAF-TRACE: claims=SAF-T1703-C011,SAF-T1703-C015; sources=SRC-microsoft-tool-poisoning-2026-06-30,SRC-usenix-attriguard -->

Tune on service identity, action class, target novelty, parameter expansion, approval outcome, user-intent binding, and whether the later call names the earlier result as its cause. <!-- SAF-TRACE: claims=SAF-T1703-C011,SAF-T1703-C012; sources=SRC-microsoft-tool-poisoning-2026-06-30,SRC-usenix-attriguard -->

No durable technique-specific indicator is expected across implementations; sequence provenance is more stable than a tool name, hostname, or payload string. <!-- SAF-TRACE: claims=SAF-T1703-C014,SAF-T1703-C015; sources=SRC-openai-monitor,SRC-usenix-attriguard -->

### Detection Validation

- The behavioral rule is in [detection-rule.yml](detection-rule.yml).
- The detector implementation is in [test_detection_rule.py](../../tests/SAF-T1703/test_detection_rule.py).
- The inert fixture set is in [test-logs.json](../../tests/SAF-T1703/test-logs.json).
- The captured passing result is in [detection-test.txt](../../research/techniques/SAF-T1703/validation/detection-test.txt).
- A reproducible MCP runtime replay is documented in [telemetry-replay/README.md](../../research/techniques/SAF-T1703/validation/telemetry-replay/README.md).
- The replay executes real MCP 2.2.0 stdio subprocesses and records server-side execution evidence in [server-audit.jsonl](../../research/techniques/SAF-T1703/validation/telemetry-replay/server-audit.jsonl).
- The normalized replay events are in [normalized-telemetry.json](../../research/techniques/SAF-T1703/validation/telemetry-replay/normalized-telemetry.json), with the deterministic detector result in [replay-results.txt](../../research/techniques/SAF-T1703/validation/telemetry-replay/replay-results.txt).
- Detection validation maturity is `telemetry_replay_tested` based on the [captured replay result](../../research/techniques/SAF-T1703/validation/telemetry-replay/replay-results.txt); this laboratory validation does not claim production effectiveness or field evaluation.

### False Positives and Limits

Legitimate cross-tool automation, user-approved compound tasks, and accidental prompt-like content can resemble the sequence; require unsupported intent plus absent or bypassed approval and preserve the full trace for review. <!-- SAF-TRACE: claims=SAF-T1703-C014; sources=SRC-openai-monitor -->

The analytic cannot establish semantic causation when telemetry omits result trust, causal linkage, user-intent support, approvals, or stable tool/server identities; in those environments it should be used for hunting rather than automatic blocking. <!-- SAF-TRACE: claims=SAF-T1703-C005,SAF-T1703-C011,SAF-T1703-C015; sources=SRC-ms-agt,SRC-usenix-attriguard -->

## Mitigation Strategies

- **[SAF-M-29: Explicit Privilege Boundaries](../../mitigations/SAF-M-29/README.md)** and **[SAF-M-74: Per-Invocation Capability Brokering](../../mitigations/SAF-M-74/README.md)**: Minimize each agent's tool inventory and bind authorization to the task, tool, resource, and user rather than granting broad reusable scopes. <!-- SAF-TRACE: claims=SAF-T1703-C016; sources=SRC-mcp-tools-2026-07-28,SRC-microsoft-tool-poisoning-2026-06-30 -->
- **[SAF-M-21: Output Context Isolation](../../mitigations/SAF-M-21/README.md)** and **[SAF-M-22: Semantic Output Validation](../../mitigations/SAF-M-22/README.md)**: Treat tool descriptions and returned content as untrusted, validate structured results, sanitize outputs, and track provenance into later calls. <!-- SAF-TRACE: claims=SAF-T1703-C006,SAF-T1703-C013; sources=SRC-mcp-tools-2026-07-28,SRC-ms-indirect-injection-2025 -->
- **[SAF-M-69: Out-of-Band Authorization for Privileged Tool Invocations](../../mitigations/SAF-M-69/README.md)**: Require deterministic confirmation for sensitive actions and show the actual target tool and arguments, not an agent-generated summary alone. <!-- SAF-TRACE: claims=SAF-T1703-C013,SAF-T1703-C016; sources=SRC-mcp-tools-2026-07-28,SRC-ms-redteam-update-2026 -->
- **[SAF-M-70: Tool-Invocation Anomaly Detection & Baselining](../../mitigations/SAF-M-70/README.md)** and **[SAF-M-12: Audit Logging](../../mitigations/SAF-M-12/README.md)**: Enforce policy at the action boundary and correlate decisions across the full sequence, including destination novelty and data-flow constraints. <!-- SAF-TRACE: claims=SAF-T1703-C005,SAF-T1703-C016; sources=SRC-ms-agt,SRC-microsoft-tool-poisoning-2026-06-30 -->
- **[SAF-M-2: Cryptographic Integrity for Tool Descriptions](../../mitigations/SAF-M-2/README.md)** and **[SAF-M-14: Server Allowlisting](../../mitigations/SAF-M-14/README.md)**: Pin and review tool definitions, monitor metadata changes, and revoke or contain compromised integrations and delegated credentials. <!-- SAF-TRACE: claims=SAF-T1703-C012,SAF-T1703-C016; sources=SRC-microsoft-tool-poisoning-2026-06-30,SRC-ms-redteam-update-2026 -->

## Related Techniques

- **[SAF-T1102: Prompt Injection (Multiple Vectors)](../SAF-T1102/README.md):** that neighbor covers how hostile instructions enter model context; this technique requires the later transition into a distinct tool boundary. <!-- SAF-TRACE: claims=SAF-T1703-C018; sources=SRC-ms-redteam-update-2026 -->
- **[SAF-T1104: Over-Privileged Tool Abuse](../SAF-T1104/README.md):** that neighbor covers an unauthorized action confined to one tool; this technique requires a causally linked second tool, server, service, or application boundary. <!-- SAF-TRACE: claims=SAF-T1703-C018; sources=SRC-ms-redteam-update-2026 -->

## MITRE ATT&CK Mapping

- **T1072 — Software Deployment Tools (analogous):** both patterns use a centralized, already-authorized control interface to act elsewhere, but T1072 concerns deployment software and does not require adversarial influence flowing from one agent tool into another. <!-- SAF-TRACE: claims=SAF-T1703-C017; sources=SRC-mitre-t1072 -->
- **ATK-TA0008 — Lateral Movement:** assigned because the immediate objective is to pivot from the attacker-influenced source boundary into a different connected system through the agent's delegated authority. <!-- SAF-TRACE: claims=SAF-T1703-C017,SAF-T1703-C018; sources=SRC-mitre-t1072,SRC-ms-redteam-update-2026 -->

## References

- **SRC-mcp-tools-2026-07-28** — Model Context Protocol contributors, “Tools,” specification revision 2026-07-28: https://modelcontextprotocol.io/specification/2026-07-28/server/tools
- **SRC-mcp-architecture-2026-07-28** — Model Context Protocol contributors, “Architecture,” specification revision 2026-07-28: https://modelcontextprotocol.io/specification/2026-07-28/architecture
- **SRC-ms-indirect-injection-2025** — Sarah Young and Den Delimarsky, Microsoft, “Protecting against indirect prompt injection attacks in MCP,” 2025-04-28: https://developer.microsoft.com/blog/protecting-against-indirect-injection-attacks-mcp/
- **SRC-ms-agt** — Jack Batzner, Microsoft, “Securing MCP: A Control Plane for Agent Tool Execution,” 2026-04-22: https://developer.microsoft.com/blog/securing-mcp-a-control-plane-for-agent-tool-execution/
- **SRC-microsoft-tool-poisoning-2026-06-30** — Microsoft Defender Experts Cybersecurity Incident Response, “Securing AI agents: When AI tools move from reading to acting,” 2026-06-30: https://www.microsoft.com/en-us/security/blog/2026/06/30/securing-ai-agents-ai-tools-move-from-reading-acting/
- **SRC-ms-redteam-update-2026** — Microsoft AI Red Team, “Updating the taxonomy of failure modes in agentic AI systems,” 2026-06-04: https://www.microsoft.com/en-us/security/blog/2026/06/04/updating-taxonomy-failure-modes-agentic-ai-systems-year-red-teaming-taught-us/
- **SRC-openai-atlas** — OpenAI, “Continuously hardening ChatGPT Atlas against prompt injection attacks,” 2025-12-22: https://openai.com/index/hardening-atlas-against-prompt-injection/
- **SRC-openai-monitor** — Marcus Williams, Hao Sun, Swetha Sekhar, Micah Carroll, David G. Robinson, and Ian Kivlichan, OpenAI, “How we monitor internal coding agents for misalignment,” 2026-03-19: https://openai.com/index/how-we-monitor-internal-coding-agents-misalignment/
- **SRC-anthropic-rfi** — Anthropic, response to the NIST Request for Information on agentic artificial intelligence security, 2026: https://www-cdn.anthropic.com/43ec7e770925deabc3f0bc1dbf0133769fd03812.pdf
- **SRC-usenix-attriguard** — Yu He, Haozhe Zhu, Yiming Li, Shuo Shao, Hongwei Yao, Zhihao Liu, and Zhan Qin, USENIX Security 26, “AttriGuard,” 2026-08: https://www.usenix.org/conference/usenixsecurity26/presentation/he-yu
- **SRC-cve-cursor** — CVE Program and Cursor, “CVE-2025-54135,” 2025: https://www.cve.org/CVERecord?id=CVE-2025-54135
- **SRC-ghsa-cursor-4cxx-2025** — Cursor and security advisory contributors, “MCPoison: Persistent Code Execution via Prompt Injection,” GHSA-4cxx-hrm3-49rm, 2025-08-02: https://github.com/cursor/cursor/security/advisories/GHSA-4cxx-hrm3-49rm
- **SRC-cve-34072** — wunderwuzzi / Embrace The Red, “Anthropic MCP Server for Slack: Data Leakage via Indirect Prompt Injection,” 2025-06-24: https://embracethered.com/blog/posts/2025/security-advisory-anthropic-slack-mcp-server-data-leakage/
- **SRC-mitre-t1072** — MITRE ATT&CK, “Software Deployment Tools: T1072,” version 3.2, 2026-05-12: https://attack.mitre.org/techniques/T1072/

## Version History

| Version | Date | Author / Team | Changes |
|---|---|---|---|
| 1.0 | 2026-09-02 | OpenAI Codex fresh-agent clean-room research | Initial clean-room technique, evidence packet, tested detector, and integration fragments. |
| 1.1 | 2026-09-26 | Michael Adedeji | Added reproducible MCP 2.2.0 subprocess telemetry replay validation and advanced detection maturity to `telemetry_replay_tested`; production effectiveness is not claimed. |
