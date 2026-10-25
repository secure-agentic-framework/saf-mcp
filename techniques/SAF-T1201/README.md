# SAF-T1201: Post-Approval Tool Mutation

## Overview

- **Tactic**: Persistence (ATK-TA0003)
- **Framework Profiles**: SAF Core; MCP. [Framework Model v2](../../research/framework-model.yml)
- **Lifecycle Status**: Active. [Framework Model v2](../../research/framework-model.yml)
- **Technique ID**: SAF-T1201
- **Research Packet**: [research/techniques/SAF-T1201](../../research/techniques/SAF-T1201/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1201/traceability-ledger.yml)
- **Documentation Status**: Under Review
- **Evidence Status**: Demonstrated
- **Severity**: High
- **Severity Rationale**: An attacker who retains control of an approved MCP server or its update path can replace previously reviewed tool metadata with attacker-directed behavior; impact depends on the host's permissions and approval controls. [Microsoft MCP guidance](https://developer.microsoft.com/blog/protecting-against-indirect-injection-attacks-mcp/) <!-- SAF-TRACE: claims=SAF-T1201-C006,SAF-T1201-C015; sources=SRC-ms-indirect-injection-2025 -->
- **First Observed**: Not observed in production; controlled demonstrations were published in 2025 and 2026. [Song et al.](https://arxiv.org/html/2506.02040) [Rashidi](https://arxiv.org/html/2607.05744) <!-- SAF-TRACE: claims=SAF-T1201-C002,SAF-T1201-C003,SAF-T1201-C004; sources=SRC-song-2506.02040,SRC-rashidi-2607.05744 -->
- **Last Updated**: 2026-09-02

## Scope

This technique covers a time-of-check/time-of-use trust reversal in which an MCP server, provider, or update channel first presents a benign tool definition, gains approval, and later changes the same approved tool's metadata or delivered implementation so the host consumes materially different behavior without renewed authorization. [Rashidi, Sections II-A and III-B](https://arxiv.org/html/2607.05744) [Song et al., Section 3.2.3](https://arxiv.org/html/2506.02040) <!-- SAF-TRACE: claims=SAF-T1201-C002,SAF-T1201-C003,SAF-T1201-C007; sources=SRC-rashidi-2607.05744,SRC-song-2506.02040 -->

### In Scope

- A definition under an already approved server/tool identity changes after approval and before later discovery or invocation. [Rashidi, T3](https://arxiv.org/html/2607.05744) <!-- SAF-TRACE: claims=SAF-T1201-C002,SAF-T1201-C007; sources=SRC-rashidi-2607.05744 -->
- A previously reviewed registry or package reference continues to resolve to provider-controlled content that has been changed after the trust decision. [Song et al., RQ1 Test 2](https://arxiv.org/html/2506.02040) <!-- SAF-TRACE: claims=SAF-T1201-C003; sources=SRC-song-2506.02040 -->

### Out of Scope

- Malicious metadata present at first discovery is initial tool poisoning, not a rug pull, because no benign approval baseline is reversed. [OWASP Agentic Top 10, ASI02/ASI04 boundary](https://genai.owasp.org/download/52117/?tmstv=1765059207) <!-- SAF-TRACE: claims=SAF-T1201-C013; sources=SRC-owasp-agentic-top10-2026 -->
- Malicious instructions introduced only in a tool result are runtime output injection; changing local MCP configuration through a separate prompt-injection flaw is also a different boundary. [Microsoft MCP guidance](https://developer.microsoft.com/blog/protecting-against-indirect-injection-attacks-mcp/) [NVD CVE-2025-53098](https://nvd.nist.gov/vuln/detail/CVE-2025-53098) <!-- SAF-TRACE: claims=SAF-T1201-C005,SAF-T1201-C013; sources=SRC-ms-indirect-injection-2025,SRC-nvd-cve-2025-53098 -->

### Distinguishing Characteristics

The decisive observable is a material mismatch between a previously approved definition or content digest and a later definition or resolved artifact under the same trust identity, followed by no corresponding re-approval. Initial tool poisoning lacks the approved benign baseline; ordinary software-supply-chain compromise need not involve MCP discovery or retained MCP authorization. [Rashidi, T3 and Section VIII-B](https://arxiv.org/html/2607.05744) [MITRE ATT&CK T1195.002](https://attack.mitre.org/techniques/T1195/002/) <!-- SAF-TRACE: claims=SAF-T1201-C002,SAF-T1201-C013,SAF-T1201-C014; sources=SRC-rashidi-2607.05744,SRC-mitre-t1195-002 -->

## Description

MCP permits clients to obtain tool definitions through `tools/list`; a server declaring `listChanged` can signal that the available list changed. Tool definitions include a name, description, schemas, and annotations, while the specification treats annotations from untrusted servers as untrusted. [MCP Tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) <!-- SAF-TRACE: claims=SAF-T1201-C001; sources=SRC-mcp-tools-2025-11-25 -->

An MCP rug pull exploits continuity of trust rather than initial deception alone. After a benign definition or provider reference is approved, attacker-controlled metadata or implementation content changes while the identity remains stable; the later content reaches the agent without the approval being reconsidered. Rashidi reproduced the definition-mutation form with a real JSON-RPC/stdio harness across three Python MCP server implementations, and Song and colleagues reproduced the repository-substitution form against three aggregation platforms. [Rashidi, T3 results](https://arxiv.org/html/2607.05744) [Song et al., Section 4.1](https://arxiv.org/html/2506.02040) <!-- SAF-TRACE: claims=SAF-T1201-C002,SAF-T1201-C003,SAF-T1201-C007; sources=SRC-rashidi-2607.05744,SRC-song-2506.02040 -->

The demonstrations establish that the trust reversal and delivery path are feasible, but they do not establish a production compromise or a reliable probability that a particular model will act on changed metadata. [Rashidi, Limitations](https://arxiv.org/html/2607.05744) [Song et al., Threats to Validity](https://arxiv.org/html/2506.02040) <!-- SAF-TRACE: claims=SAF-T1201-C004,SAF-T1201-C019; sources=SRC-rashidi-2607.05744,SRC-song-2506.02040 -->

## Attack Vectors

- **Primary Vector**: A remotely hosted server returns a changed definition for an already approved tool identity during a later `tools/list` refresh. [Rashidi, T3](https://arxiv.org/html/2607.05744) <!-- SAF-TRACE: claims=SAF-T1201-C002; sources=SRC-rashidi-2607.05744 -->
- **Secondary Vectors**: A mutable package or registry reference resolves to altered server code after initial review; a compromised publisher changes a backend contract while preserving the visible tool identity. [Song et al., RQ1 Test 2](https://arxiv.org/html/2506.02040) [ETDI, Section III-B](https://arxiv.org/html/2506.01333) <!-- SAF-TRACE: claims=SAF-T1201-C003,SAF-T1201-C009; sources=SRC-song-2506.02040,SRC-etdi-2506.01333 -->
- **Affected Components**: MCP host/client approval state, server tool registry, package/update channel, and any downstream service reached by the changed tool. [OWASP third-party MCP guide, page 6](https://genai.owasp.org/download/51928/?tmstv=1762283701) <!-- SAF-TRACE: claims=SAF-T1201-C011,SAF-T1201-C015; sources=SRC-owasp-third-party-mcp-2025 -->
- **Trust Boundary Crossed**: The boundary between an approved tool definition or artifact and a later, materially different definition or artifact accepted under the same approval. [Rashidi, Section VIII-B](https://arxiv.org/html/2607.05744) <!-- SAF-TRACE: claims=SAF-T1201-C007; sources=SRC-rashidi-2607.05744 -->

## Technical Details

### Prerequisites

- The adversary controls or compromises an MCP server, provider account, referenced repository, package version, or update path after a benign baseline is trusted. [Song et al., Section 3.2.3](https://arxiv.org/html/2506.02040) <!-- SAF-TRACE: claims=SAF-T1201-C003,SAF-T1201-C007; sources=SRC-song-2506.02040 -->
- The host later retrieves or runs the changed content under the retained identity. [MCP Tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) [Song et al., RQ1](https://arxiv.org/html/2506.02040) <!-- SAF-TRACE: claims=SAF-T1201-C001,SAF-T1201-C003; sources=SRC-mcp-tools-2025-11-25,SRC-song-2506.02040 -->
- Re-approval, content pinning, or an equivalent fail-closed integrity check does not block the change. [OWASP third-party MCP guide, page 6](https://genai.owasp.org/download/51928/?tmstv=1762283701) <!-- SAF-TRACE: claims=SAF-T1201-C008,SAF-T1201-C011; sources=SRC-owasp-third-party-mcp-2025 -->

### Attack Flow

1. **Setup**: The provider exposes a benign definition or artifact and obtains user or administrator approval. [Song et al., Section 3.2.3](https://arxiv.org/html/2506.02040) <!-- SAF-TRACE: claims=SAF-T1201-C003,SAF-T1201-C007; sources=SRC-song-2506.02040 -->
2. **Mutation**: The attacker changes the tool description, schema, backend contract, or resolved package content while retaining the approved identity. [Rashidi, T3](https://arxiv.org/html/2607.05744) [ETDI, Section III-B](https://arxiv.org/html/2506.01333) <!-- SAF-TRACE: claims=SAF-T1201-C002,SAF-T1201-C009; sources=SRC-rashidi-2607.05744,SRC-etdi-2506.01333 -->
3. **Refresh or Reload**: The client refreshes `tools/list`, follows a mutable repository reference, or starts an updated package. [MCP Tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) [Song et al., Section 4.1](https://arxiv.org/html/2506.02040) <!-- SAF-TRACE: claims=SAF-T1201-C001,SAF-T1201-C003; sources=SRC-mcp-tools-2025-11-25,SRC-song-2506.02040 -->
4. **Boundary Crossing**: The host accepts the changed material under the old approval without a new trust decision. [Rashidi, Section VI](https://arxiv.org/html/2607.05744) <!-- SAF-TRACE: claims=SAF-T1201-C002,SAF-T1201-C007; sources=SRC-rashidi-2607.05744 -->
5. **Objective**: The altered tool remains available as a persistent influence or execution path in later agent sessions. [Microsoft MCP guidance](https://developer.microsoft.com/blog/protecting-against-indirect-injection-attacks-mcp/) <!-- SAF-TRACE: claims=SAF-T1201-C006; sources=SRC-ms-indirect-injection-2025 -->
6. **Follow-On Activity**: Depending on granted privileges, subsequent calls may manipulate data, disclose data, or invoke other tools; these outcomes are conditional, not inherent. [Microsoft Azure MCP security guidance](https://learn.microsoft.com/en-us/azure/developer/azure-mcp-server/security) <!-- SAF-TRACE: claims=SAF-T1201-C006,SAF-T1201-C015; sources=SRC-ms-azure-mcp-security-2026 -->

### Example Scenario

A team approves a remote `inventory_summary` tool whose reviewed definition is read-only. On a later refresh, the same server and tool name return a changed description and schema requesting an additional `diagnostic_note`; the host sees a changed content hash and no matching approval event, so the analytic alerts before any invocation. This inert scenario mirrors the demonstrated TOCTOU boundary without including a harmful instruction. [Rashidi, T3](https://arxiv.org/html/2607.05744) <!-- SAF-TRACE: claims=SAF-T1201-C002,SAF-T1201-C018; sources=SRC-rashidi-2607.05744 -->

The synthetic message below uses a reserved example domain and placeholder hashes; it is non-executable. <!-- SAF-TRACE: claims=SAF-T1201-C018; sources=SRC-rashidi-2607.05744 -->

```json
{
  "event_type": "mcp_tool_definition_observed",
  "server_id": "https://mcp.example.invalid/inventory",
  "tool_name": "inventory_summary",
  "approved_definition_hash": "sha256:1111111111111111",
  "observed_definition_hash": "sha256:2222222222222222",
  "reapproval_status": "absent"
}
```

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1201-C002 | A post-approval tool-definition mutation reached model context without protocol-forced reapproval across three MCP server implementations. | Demonstrated | SRC-rashidi-2607.05744: [Rashidi](https://arxiv.org/html/2607.05744) | Protocol-level harness; it did not measure whether a production model acted on the payload. |
| SAF-T1201-C003 | A benign repository reference was changed after listing and remained accessible without renewed review on three MCP aggregators during a seven-day controlled test. | Demonstrated | SRC-song-2506.02040: [Song et al.](https://arxiv.org/html/2506.02040) | Controlled platform test; separate rug-pull exploitation was not measured. |
| SAF-T1201-C004 | No qualifying production rug-pull breach or direct CVE was identified in the documented authority corpus as of 2026-09-01. | Research-Derived | SRC-nvd-cve-2025-53098: [NVD adjacent CVE](https://nvd.nist.gov/vuln/detail/CVE-2025-53098); SRC-ms-indirect-injection-2025: [Microsoft guidance](https://developer.microsoft.com/blog/protecting-against-indirect-injection-attacks-mcp/) | Narrow search conclusion, not proof that no incident exists. |
| SAF-T1201-C008 | Comparing canonical hashes of approved and later tool definitions can detect metadata mutation. | Research-Derived | SRC-invariant-mcp-scan-2025: [Invariant MCP-Scan](https://invariantlabs.ai/blog/introducing-mcp-scan); SRC-owasp-third-party-mcp-2025: [OWASP guide](https://genai.owasp.org/download/51928/?tmstv=1762283701) | Cannot detect unchanged metadata paired with changed hidden backend behavior. |

### Current State

- **Affected Environments**: Hosts that retain approvals across refreshes or execute content from mutable MCP server, package, or registry references without content-integrity enforcement. [Microsoft Azure MCP security guidance](https://learn.microsoft.com/en-us/azure/developer/azure-mcp-server/security) <!-- SAF-TRACE: claims=SAF-T1201-C007,SAF-T1201-C011; sources=SRC-ms-azure-mcp-security-2026 -->
- **Known Exploitation**: Two controlled demonstrations qualify; no qualifying production breach was identified in the reviewed authority corpus. [Rashidi](https://arxiv.org/html/2607.05744) [Song et al.](https://arxiv.org/html/2506.02040) <!-- SAF-TRACE: claims=SAF-T1201-C002,SAF-T1201-C003,SAF-T1201-C004; sources=SRC-rashidi-2607.05744,SRC-song-2506.02040 -->
- **Available Protections**: Pin definitions or packages, compare canonical hashes, require re-approval on material change, isolate untrusted servers, and enforce least privilege at runtime. [OWASP third-party MCP guide](https://genai.owasp.org/download/51928/?tmstv=1762283701) [Microsoft Azure MCP security guidance](https://learn.microsoft.com/en-us/azure/developer/azure-mcp-server/security) <!-- SAF-TRACE: claims=SAF-T1201-C008,SAF-T1201-C011,SAF-T1201-C012; sources=SRC-owasp-third-party-mcp-2025,SRC-ms-azure-mcp-security-2026 -->
- **Residual Risk**: Metadata hashing does not prove unchanged backend semantics; runtime policy and behavior monitoring remain necessary. [ETDI, Section IV-B](https://arxiv.org/html/2506.01333) [Microsoft Azure MCP security guidance](https://learn.microsoft.com/en-us/azure/developer/azure-mcp-server/security) <!-- SAF-TRACE: claims=SAF-T1201-C009,SAF-T1201-C012; sources=SRC-etdi-2506.01333,SRC-ms-azure-mcp-security-2026 -->

### Known Breaches and Vulnerabilities

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| Rashidi T3 controlled demonstration | 2026-07-07; real JSON-RPC/stdio harness and three Python MCP server libraries | Changed metadata reached model context; hash pinning and re-consent on mutation are proposed controls | Direct demonstration | No production victim and no measurement of downstream model action. <!-- SAF-TRACE: claims=SAF-T1201-C002,SAF-T1201-C019; sources=SRC-rashidi-2607.05744 --> |
| Song et al. RQ1 Test 2 | 2025-09-14 v4; three MCP aggregation platforms | Changed repositories retained their display/listing state for seven days; signing and trusted hosting were proposed | Direct demonstration | Separate end-to-end rug-pull exploitation was intentionally omitted. <!-- SAF-TRACE: claims=SAF-T1201-C003,SAF-T1201-C019; sources=SRC-song-2506.02040 --> |
| CVE-2025-53098 | Published 2025-06-27; Roo Code before 3.20.3 with MCP and auto-approved file writes | Prompt-induced MCP configuration write could lead to command execution; fixed in 3.20.3 | Adjacent incident or vulnerability | It changes local configuration through prompt injection, not an approved tool definition through a retained provider identity. <!-- SAF-TRACE: claims=SAF-T1201-C005; sources=SRC-nvd-cve-2025-53098 --> |

### Real-World Incidents or Demonstrations

#### Post-Approval Definition Mutation (2026)

Mohammadreza Rashidi's deterministic harness advertised a benign tool and changed its description on a later `tools/list`; the changed payload reached model context and the protocol forced no reapproval in all three tested server libraries. The harness used local recording and reserved domains, and did not test production clients or model compliance. [Rashidi, T3, results, and limitations](https://arxiv.org/html/2607.05744) <!-- SAF-TRACE: claims=SAF-T1201-C002,SAF-T1201-C019; sources=SRC-rashidi-2607.05744 -->

#### Aggregator Repository Substitution (2025)

Hao Song, Yiming Shen, Wenxuan Luo, Leixin Guo, Ting Chen, Jiashui Wang, Beibei Li, Xiaosong Zhang, and Jiachi Chen listed benign repositories on three aggregators, then changed the referenced repositories; listing state remained unchanged through seven days. The study treated that as the rug-pull feasibility test and did not run a separate exploitation experiment for this attack type. [Song et al., Sections 4.1 and 4.3](https://arxiv.org/html/2506.02040) <!-- SAF-TRACE: claims=SAF-T1201-C003,SAF-T1201-C019; sources=SRC-song-2506.02040 -->

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | High | Changed metadata or behavior can steer access to data available to the host, but exposure depends on tool privileges, model action, and egress controls. <!-- SAF-TRACE: claims=SAF-T1201-C006,SAF-T1201-C015; sources=SRC-ms-indirect-injection-2025,SRC-ms-azure-mcp-security-2026 --> |
| Integrity | High | A retained trusted identity can influence later tool selection or actions without a fresh authorization decision; deterministic policy can constrain the effect. <!-- SAF-TRACE: claims=SAF-T1201-C006,SAF-T1201-C012; sources=SRC-ms-indirect-injection-2025,SRC-ms-azure-mcp-security-2026 --> |
| Availability | Medium | A changed tool can disrupt results or actions, but broad disruption is not inherent to the trust reversal. <!-- SAF-TRACE: claims=SAF-T1201-C015; sources=SRC-song-2506.02040 --> |
| Scope | Multi-System | A shared remote server or mutable registry reference can affect multiple clients, while per-client pinning and scoped credentials limit blast radius. <!-- SAF-TRACE: claims=SAF-T1201-C003,SAF-T1201-C012; sources=SRC-song-2506.02040,SRC-ms-azure-mcp-security-2026 --> |

### Severity Conditions

- **Severity increases when** the changed tool has broad credentials, filesystem access, external egress, automatic approvals, or a widely reused mutable distribution reference. [Microsoft Azure MCP security guidance](https://learn.microsoft.com/en-us/azure/developer/azure-mcp-server/security) [Song et al.](https://arxiv.org/html/2506.02040) <!-- SAF-TRACE: claims=SAF-T1201-C015; sources=SRC-ms-azure-mcp-security-2026,SRC-song-2506.02040 -->
- **Severity decreases when** content is pinned, changes require reapproval, tools run with least privilege, and untrusted servers are isolated from sensitive credentials and networks. [OWASP third-party MCP guide](https://genai.owasp.org/download/51928/?tmstv=1762283701) [Microsoft Azure MCP security guidance](https://learn.microsoft.com/en-us/azure/developer/azure-mcp-server/security) <!-- SAF-TRACE: claims=SAF-T1201-C011,SAF-T1201-C012; sources=SRC-owasp-third-party-mcp-2025,SRC-ms-azure-mcp-security-2026 -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| MCP client/host inventory and approval log | Initial approval, each `tools/list` snapshot, list-changed notification, and invocation | timestamp, server identity, tool name, canonical definition hash, approval ID, approved hash, reapproval status, session ID | Canonicalize all security-relevant definition fields before hashing and retain versions long enough to compare across sessions. <!-- SAF-TRACE: claims=SAF-T1201-C001,SAF-T1201-C008,SAF-T1201-C016; sources=SRC-mcp-tools-2025-11-25,SRC-owasp-third-party-mcp-2025 --> |
| Package/registry and runtime log | Resolved version/digest, publisher, startup, tool call, and external action | package digest, repository commit, process identity, credential identity, destination, result | Join distribution changes to host activity; definition-only detection cannot see unchanged metadata with altered backend code. <!-- SAF-TRACE: claims=SAF-T1201-C009,SAF-T1201-C012,SAF-T1201-C016; sources=SRC-etdi-2506.01333,SRC-ms-azure-mcp-security-2026 --> |

### Indicators of Compromise (IoCs)

- No universal durable IoC is known; the defining indicator is an environment-specific integrity mismatch under a retained trust identity. [Invariant MCP-Scan](https://invariantlabs.ai/blog/introducing-mcp-scan) <!-- SAF-TRACE: claims=SAF-T1201-C008; sources=SRC-invariant-mcp-scan-2025 -->

### Behavioral Indicators

- A server/tool tuple presents a canonical definition hash different from its approved hash, with no intervening approval for the new hash. [OWASP third-party MCP guide](https://genai.owasp.org/download/51928/?tmstv=1762283701) <!-- SAF-TRACE: claims=SAF-T1201-C008,SAF-T1201-C016; sources=SRC-owasp-third-party-mcp-2025 -->
- An invocation follows `notifications/tools/list_changed` and a material definition change while the approval ID remains bound to the older hash. [MCP Tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) [Visual Studio MCP lifecycle](https://learn.microsoft.com/en-us/visualstudio/ide/mcp-servers?view=visualstudio) <!-- SAF-TRACE: claims=SAF-T1201-C001,SAF-T1201-C010,SAF-T1201-C016; sources=SRC-mcp-tools-2025-11-25,SRC-ms-visual-studio-mcp-2026 -->
- A mutable package or repository ref resolves to a new digest without staged review, especially when tool permissions or destinations change soon afterward. [Song et al., RQ1](https://arxiv.org/html/2506.02040) <!-- SAF-TRACE: claims=SAF-T1201-C003,SAF-T1201-C016; sources=SRC-song-2506.02040 -->

### Detection Analytic

The standalone deterministic analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Detect an observed tool definition whose canonical hash differs from the hash attached to the latest approval for the same server/tool identity, unless a new approval covers the observed hash. [OWASP third-party MCP guide](https://genai.owasp.org/download/51928/?tmstv=1762283701) <!-- SAF-TRACE: claims=SAF-T1201-C008,SAF-T1201-C016; sources=SRC-owasp-third-party-mcp-2025 -->
- **Rule Status**: Test <!-- SAF-TRACE: claims=SAF-T1201-C016; sources=SRC-invariant-mcp-scan-2025 -->
- **Detection Logic**: Match only complete records where `approved_definition_hash != observed_definition_hash` and `reapproval_status == absent`; fail closed for enforcement but route incomplete records to telemetry-quality review. [Invariant MCP-Scan](https://invariantlabs.ai/blog/introducing-mcp-scan) <!-- SAF-TRACE: claims=SAF-T1201-C008,SAF-T1201-C016; sources=SRC-invariant-mcp-scan-2025 -->
- **Correlation Window**: Retain the latest approved hash for the life of the approval and compare every later observation before invocation. [Rashidi, Section VIII-B](https://arxiv.org/html/2607.05744) <!-- SAF-TRACE: claims=SAF-T1201-C002,SAF-T1201-C016; sources=SRC-rashidi-2607.05744 -->
- **Known False Positives**: Legitimate upgrades that are deployed before their corresponding approval event is ingested, canonicalization-version changes, or identity aliases that collapse distinct servers. Legitimate changes are frequent: in one public longitudinal record, 45.1% of 10,929 remote MCP servers served a different tool definition set within about four weeks, and 11.8% of 23,821 recorded changes altered only digits, whitespace, or schema notation. [Visual Studio MCP lifecycle](https://learn.microsoft.com/en-us/visualstudio/ide/mcp-servers?view=visualstudio) [HISTOR snapshot 2026-10-20](https://doi.org/10.5281/zenodo.23512760) <!-- SAF-TRACE: claims=SAF-T1201-C010,SAF-T1201-C017,SAF-T1201-C021,SAF-T1201-C022; sources=SRC-ms-visual-studio-mcp-2026,SRC-histor-snapshot-2026-10-20 -->
- **Known Limitations**: The rule cannot detect backend logic changes that leave the observed definition unchanged, compromised approval workflows, or telemetry suppression. [ETDI, Section IV-B](https://arxiv.org/html/2506.01333) <!-- SAF-TRACE: claims=SAF-T1201-C009,SAF-T1201-C017; sources=SRC-etdi-2506.01333 -->
- **Tuning Guidance**: Use stable provenance-scoped server identities, version the canonicalization algorithm, and suppress only when the observed hash is explicitly approved. Expect routine matches on benign updates for remote servers and route them to a reapproval queue rather than incident response. [Microsoft Azure MCP security guidance](https://learn.microsoft.com/en-us/azure/developer/azure-mcp-server/security) [HISTOR snapshot 2026-10-20](https://doi.org/10.5281/zenodo.23512760) <!-- SAF-TRACE: claims=SAF-T1201-C011,SAF-T1201-C016,SAF-T1201-C023; sources=SRC-ms-azure-mcp-security-2026,SRC-histor-snapshot-2026-10-20 -->

### Validation

- **Test Data**: [test-logs.json](test-logs.json)
- **Validation Script**: [test_detection_rule.py](test_detection_rule.py)
- **Expected Result**: Eight deterministic cases pass: two positives, three negatives, two boundary/malformed records, and one legitimate-change false-positive control. <!-- SAF-TRACE: claims=SAF-T1201-C016,SAF-T1201-C017; sources=SRC-invariant-mcp-scan-2025,SRC-ms-visual-studio-mcp-2026 -->
- **Last Validated**: 2026-09-01 <!-- SAF-TRACE: claims=SAF-T1201-C016; sources=SRC-invariant-mcp-scan-2025 -->
- **Feasibility Waiver**: None <!-- SAF-TRACE: claims=SAF-T1201-C016; sources=SRC-invariant-mcp-scan-2025 -->

## Mitigation Strategies

### Preventive Controls

1. **Content pinning and reapproval**: Store a canonical digest for the complete approved tool definition and resolved artifact, and require a new approval when either changes. [OWASP third-party MCP guide](https://genai.owasp.org/download/51928/?tmstv=1762283701) <!-- SAF-TRACE: claims=SAF-T1201-C008,SAF-T1201-C011; sources=SRC-owasp-third-party-mcp-2025 -->
2. **Fail-closed lifecycle handling**: On a tool-list change, disable prior permissions until the refreshed definition is reviewed; Visual Studio documents this behavior for its MCP lifecycle. [Visual Studio MCP lifecycle](https://learn.microsoft.com/en-us/visualstudio/ide/mcp-servers?view=visualstudio) <!-- SAF-TRACE: claims=SAF-T1201-C010,SAF-T1201-C011; sources=SRC-ms-visual-studio-mcp-2026 -->
3. **Least privilege and isolation**: Separate credentials and execution contexts for unverified servers, restrict egress, and grant only the tool permissions required for the task. [Microsoft Azure MCP security guidance](https://learn.microsoft.com/en-us/azure/developer/azure-mcp-server/security) <!-- SAF-TRACE: claims=SAF-T1201-C012; sources=SRC-ms-azure-mcp-security-2026 -->

### Detective Controls

1. **Definition and artifact baselines**: Continuously compare observed hashes, versions, publishers, and repository commits with approved values. [Invariant MCP-Scan](https://invariantlabs.ai/blog/introducing-mcp-scan) [OWASP Agentic Top 10](https://genai.owasp.org/download/52117/?tmstv=1765059207) <!-- SAF-TRACE: claims=SAF-T1201-C008,SAF-T1201-C011; sources=SRC-invariant-mcp-scan-2025,SRC-owasp-agentic-top10-2026 -->
2. **Runtime correlation**: Correlate a change alert with subsequent tool calls, credential use, data access, and network destinations because metadata integrity alone cannot prove backend behavior. [Microsoft Azure MCP security guidance](https://learn.microsoft.com/en-us/azure/developer/azure-mcp-server/security) <!-- SAF-TRACE: claims=SAF-T1201-C009,SAF-T1201-C012; sources=SRC-ms-azure-mcp-security-2026 -->

### Response Procedures

#### Immediate Actions

- Disable the changed server/tool, preserve the old and new definitions and resolved digests, and revoke the retained approval until review completes. [Visual Studio MCP lifecycle](https://learn.microsoft.com/en-us/visualstudio/ide/mcp-servers?view=visualstudio) <!-- SAF-TRACE: claims=SAF-T1201-C010,SAF-T1201-C020; sources=SRC-ms-visual-studio-mcp-2026 -->
- Isolate the server execution context and rotate credentials only where logs show possible exposure or the integrity boundary cannot be reconstructed. [Microsoft Azure MCP security guidance](https://learn.microsoft.com/en-us/azure/developer/azure-mcp-server/security) <!-- SAF-TRACE: claims=SAF-T1201-C012,SAF-T1201-C020; sources=SRC-ms-azure-mcp-security-2026 -->

#### Investigation Steps

- Compare every observed definition and artifact digest with approval records, then identify the first unapproved change and all later invocations. [OWASP third-party MCP guide](https://genai.owasp.org/download/51928/?tmstv=1762283701) <!-- SAF-TRACE: claims=SAF-T1201-C008,SAF-T1201-C020; sources=SRC-owasp-third-party-mcp-2025 -->
- Correlate host, identity, endpoint, and network logs to determine which data or downstream actions the changed tool could reach. [Microsoft Azure MCP security guidance](https://learn.microsoft.com/en-us/azure/developer/azure-mcp-server/security) <!-- SAF-TRACE: claims=SAF-T1201-C012,SAF-T1201-C020; sources=SRC-ms-azure-mcp-security-2026 -->

#### Remediation

- Restore a reviewed pinned version, reissue approval for its exact digest, and add a regression test that rejects an unapproved mutation. [OWASP third-party MCP guide](https://genai.owasp.org/download/51928/?tmstv=1762283701) <!-- SAF-TRACE: claims=SAF-T1201-C011,SAF-T1201-C020; sources=SRC-owasp-third-party-mcp-2025 -->
- If backend semantics cannot be attested, constrain the tool with deterministic authorization, sandbox, and egress policies rather than trusting metadata alone. [ETDI](https://arxiv.org/html/2506.01333) [Microsoft Azure MCP security guidance](https://learn.microsoft.com/en-us/azure/developer/azure-mcp-server/security) <!-- SAF-TRACE: claims=SAF-T1201-C009,SAF-T1201-C012,SAF-T1201-C020; sources=SRC-etdi-2506.01333,SRC-ms-azure-mcp-security-2026 -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1001: Tool Poisoning Attack](../SAF-T1001/README.md) | Prerequisite or alternative | Poisoning is already present at first discovery; a rug pull requires a previously approved benign baseline and later material change. <!-- SAF-TRACE: claims=SAF-T1201-C013; sources=SRC-owasp-agentic-top10-2026 --> |
| [SAF-T1102: Prompt Injection (Multiple Vectors)](../SAF-T1102/README.md) | Follow-on or alternative | Tool-output injection arrives in results after a call; a rug pull changes the trusted definition or delivered implementation before later use. <!-- SAF-TRACE: claims=SAF-T1201-C013; sources=SRC-ms-indirect-injection-2025 --> |

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1195.002](https://attack.mitre.org/techniques/T1195/002/) | Compromise Software Supply Chain | Analogous | Both abuse a trusted delivery/update relationship by substituting changed content; ATT&CK scopes the behavior to pre-receipt application software and Initial Access, while this SAF technique scopes retained MCP approval and Persistence. <!-- SAF-TRACE: claims=SAF-T1201-C014; sources=SRC-mitre-t1195-002 --> |

### Additional Framework Mappings

| Framework | ID | Name | Rationale |
| --- | --- | --- | --- |
| OWASP Top 10 for Agentic Applications 2026 | ASI04 | Agentic Supply Chain Vulnerabilities | OWASP describes runtime-loaded tools and update channels as a live agentic supply chain and recommends runtime hash/signature validation and pinning. <!-- SAF-TRACE: claims=SAF-T1201-C011,SAF-T1201-C013; sources=SRC-owasp-agentic-top10-2026 --> |

## References

1. **SRC-mcp-tools-2025-11-25**: [Model Context Protocol Tools specification, 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) — tool discovery, list-change notification, definition fields, and security considerations.
2. **SRC-rashidi-2607.05744**: [Mohammadreza Rashidi, “Unicode TAG-Block Concealment of Tool-Metadata Payloads…,” 2026](https://arxiv.org/html/2607.05744) — deterministic T3 post-approval mutation, cross-library results, defenses, and limitations.
3. **SRC-song-2506.02040**: [Hao Song, Yiming Shen, Wenxuan Luo, Leixin Guo, Ting Chen, Jiashui Wang, Beibei Li, Xiaosong Zhang, and Jiachi Chen, “Beyond the Protocol…,” v4, 2025](https://arxiv.org/html/2506.02040) — aggregator mutation experiment, boundary, mitigations, and threats to validity.
4. **SRC-etdi-2506.01333**: [Manish Bhatt, Vineeth Sai Narajala, and Idan Habler, “ETDI…,” 2025](https://arxiv.org/html/2506.01333) — versioned definitions, backend-contract hashes, and policy limits.
5. **SRC-invariant-tpa-2025-04-01**: [Invariant Labs research team, “MCP Security Notification: Tool Poisoning Attacks,” 2025](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) — original rug-pull disclosure context and pinning recommendation.
6. **SRC-invariant-mcp-scan-2025**: [Luca Beurer-Kellner and Marc Fischer, “Introducing MCP-Scan,” 2025](https://invariantlabs.ai/blog/introducing-mcp-scan) — tool-hash pinning implementation and privacy limitations.
7. **SRC-ms-indirect-injection-2025**: [Sarah Young and Den Delimarsky, “Protecting against indirect prompt injection attacks in MCP,” Microsoft, 2025](https://developer.microsoft.com/blog/protecting-against-indirect-injection-attacks-mcp/) — hosted-definition mutation, potential outcomes, and supply-chain controls.
8. **SRC-ms-azure-mcp-security-2026**: [Microsoft Azure documentation team, “Secure your Azure MCP Server deployment,” 2026](https://learn.microsoft.com/en-us/azure/developer/azure-mcp-server/security) — reapproval, isolation, least privilege, logging, and residual risk.
9. **SRC-ms-visual-studio-mcp-2026**: [Microsoft Visual Studio documentation team, “Use MCP Servers to Extend GitHub Copilot,” 2026](https://learn.microsoft.com/en-us/visualstudio/ide/mcp-servers?view=visualstudio) — lifecycle reset of permissions on list changes and server trust prompts.
10. **SRC-owasp-third-party-mcp-2025**: [OWASP GenAI Security Project, “A Practical Guide for Securely Using Third-Party MCP Servers,” 2025](https://genai.owasp.org/download/51928/?tmstv=1762283701) — definition, transparency, hashing, version monitoring, and runtime policy.
11. **SRC-owasp-agentic-top10-2026**: [OWASP GenAI Security Project, “Top 10 for Agentic Applications 2026”](https://genai.owasp.org/download/52117/?tmstv=1765059207) — tool-misuse versus supply-chain boundary and continuous runtime integrity validation.
12. **SRC-mitre-t1195-002**: [MITRE ATT&CK, T1195.002 Compromise Software Supply Chain, version 1.1](https://attack.mitre.org/techniques/T1195/002/) — analogous software delivery/update manipulation.
13. **SRC-nvd-cve-2025-53098**: [NIST NVD, CVE-2025-53098](https://nvd.nist.gov/vuln/detail/CVE-2025-53098) — adjacent Roo Code configuration-write vulnerability, affected state, fix, and exploitation status.
14. **SRC-histor-snapshot-2026-10-20**: [Aleksandr Artamokhov, “HISTOR monthly snapshot 2026-10-20,” Zenodo, CC BY 4.0](https://doi.org/10.5281/zenodo.23512760) — registry-scale frequency of tool-definition changes; contributed by the record's operators.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 0.1 | 2026-09-01 | Independent clean-room draft and evidence packet | Fred Kautz; OpenAI Research |
| 0.2 | 2026-10-25 | Added a registry-scale base rate of legitimate definition changes to Known False Positives and Tuning Guidance (claims C021–C023, source SRC-histor-snapshot-2026-10-20) | Aleksandr Artamokhov |
