# SAF-T1802: File Collection

## Overview

- **Tactic**: Collection (ATK-TA0009)
- **Technique ID**: SAF-T1802
- **Research Packet**: [research/techniques/SAF-T1802](../../research/techniques/SAF-T1802/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1802/traceability-ledger.yml)
- **Documentation Status**: Under Review
- **Evidence Status**: Demonstrated
- **Severity**: High
- **Severity Rationale**: A successful action can disclose any file readable by the MCP server process; risk is greatest when remote reachability, broad service privileges, automation, or an attached transfer channel reduce attacker friction. <!-- SAF-TRACE: claims=SAF-T1802-C019; sources=SRC-cve-2026-73498,SRC-cve-2026-46555,SRC-cve-2026-40576 -->
- **First Observed**: Not observed in a qualifying file-specific production incident; public controlled demonstrations were reviewed. <!-- SAF-TRACE: claims=SAF-T1802-C007,SAF-T1802-C009,SAF-T1802-C011,SAF-T1802-C012; sources=SRC-ghsa-g5r6-gv6m-f5jv,SRC-ghsa-j98m-w3xp-9f56,SRC-flowguard-2607.14754v1,SRC-anthropic-espionage-2025-11,SRC-cisa-kev-2026-09-01 -->
- **Last Updated**: 2026-09-02

## Scope

File Collection covers obtaining file content through an MCP resource or tool, including use of an intended collection capability and retrieval that exceeds the actor's approved path, authorization, or approval boundary. <!-- SAF-TRACE: claims=SAF-T1802-C001; sources=SRC-mcp-resources-2026,SRC-mcp-tools-2026-07-28,SRC-attack-t1005 -->

### In Scope

- Listing file-bearing resources when it directly prepares selection of content that is then retrieved. <!-- SAF-TRACE: claims=SAF-T1802-C001,SAF-T1802-C002; sources=SRC-mcp-resources-2026 -->
- Reading, returning, staging, converting, or attaching file content through a resource or tool result. <!-- SAF-TRACE: claims=SAF-T1802-C001,SAF-T1802-C002,SAF-T1802-C003; sources=SRC-mcp-resources-2026,SRC-mcp-tools-2026-07-28 -->
- Retrieval outside an approved root or authorization scope through traversal, path-prefix confusion, absolute paths, file URIs, or link resolution. <!-- SAF-TRACE: claims=SAF-T1802-C005,SAF-T1802-C006,SAF-T1802-C007,SAF-T1802-C008,SAF-T1802-C009,SAF-T1802-C010,SAF-T1802-C011; sources=SRC-cwe-22,SRC-cwe-59,SRC-ghsa-g5r6-gv6m-f5jv,SRC-ghsa-7jj9-4qqq-4xc4,SRC-ghsa-j98m-w3xp-9f56,SRC-ghsa-cve-2025-53109,SRC-flowguard-2607.14754v1 -->

### Out of Scope

- Enumeration that returns only names, paths, or metadata belongs to file discovery unless content is subsequently obtained. <!-- SAF-TRACE: claims=SAF-T1802-C014; sources=SRC-attack-t1083,SRC-attack-t1005 -->
- Movement of already collected content without a file-read step is transfer or exfiltration behavior, even when it immediately follows this technique. <!-- SAF-TRACE: claims=SAF-T1802-C001,SAF-T1802-C019; sources=SRC-attack-t1005,SRC-cve-2026-46555 -->
- Command execution, arbitrary repository initialization, and secrets exposed at rest are enabling or adjacent unless a separate operation retrieves file content. <!-- SAF-TRACE: claims=SAF-T1802-C001; sources=SRC-mcp-tools-2026-07-28,SRC-attack-t1005 -->

### Distinguishing Characteristics

The decisive observable is a successful return or staging of file bytes. Enumeration can precede collection, and an attachment can follow it, but neither neighboring behavior alone satisfies this technique. <!-- SAF-TRACE: claims=SAF-T1802-C014,SAF-T1802-C015; sources=SRC-attack-t1083,SRC-attack-t1005,SRC-mcp-resources-2026 -->

## Description

MCP resource servers can enumerate resources and return one or more content items for a URI, including file URIs. MCP tools can also expose file-reading, conversion, upload, or attachment operations and return resource links or embedded resources. <!-- SAF-TRACE: claims=SAF-T1802-C002,SAF-T1802-C003; sources=SRC-mcp-resources-2026,SRC-mcp-tools-2026-07-28 -->

An adversary, compromised model workflow, injected instruction, or unauthorized caller can repurpose those operations to obtain files. The defining security failure occurs when the returned content is not authorized for the actor or operation, or when validation permits a requested path or URI to resolve beyond the approved boundary. <!-- SAF-TRACE: claims=SAF-T1802-C001,SAF-T1802-C005,SAF-T1802-C006; sources=SRC-mcp-resources-2026,SRC-mcp-tools-2026-07-28,SRC-cwe-22,SRC-cwe-59 -->

Roots do not close this boundary: the current MCP specification describes them as deprecated informational hints rather than protocol-enforced access controls. Hosts and servers must apply authorization and filesystem policy independently. <!-- SAF-TRACE: claims=SAF-T1802-C004,SAF-T1802-C018; sources=SRC-mcp-2026-roots,SRC-mcp-resources-2026,SRC-mcp-tools-2026-07-28 -->

## Attack Vectors

- **Primary Vector**: A resource read or file-capable tool call supplies an attacker-selected URI or path that is accepted and returns file content. <!-- SAF-TRACE: claims=SAF-T1802-C001,SAF-T1802-C002,SAF-T1802-C003; sources=SRC-mcp-resources-2026,SRC-mcp-tools-2026-07-28 -->
- **Secondary Vectors**: Prompt-injected agent calls, an authenticated but overprivileged MCP client, an unauthenticated network endpoint, a same-user local process, or browser DNS rebinding can reach the vulnerable operation when the product's conditions permit. <!-- SAF-TRACE: claims=SAF-T1802-C007,SAF-T1802-C008,SAF-T1802-C009; sources=SRC-ghsa-g5r6-gv6m-f5jv,SRC-ghsa-7jj9-4qqq-4xc4,SRC-ghsa-j98m-w3xp-9f56 -->
- **Affected Components**: MCP host, client, resource server, tool server, approval layer, host filesystem, and any attachment or conversion backend. <!-- SAF-TRACE: claims=SAF-T1802-C001,SAF-T1802-C002,SAF-T1802-C003; sources=SRC-mcp-resources-2026,SRC-mcp-tools-2026-07-28 -->
- **Trust Boundary Crossed**: The intended set of files for an actor, session, resource, or tool versus the broader set readable by the server process. <!-- SAF-TRACE: claims=SAF-T1802-C001,SAF-T1802-C019; sources=SRC-attack-t1005,SRC-cve-2026-73498,SRC-cve-2026-46555,SRC-cve-2026-40576 -->

## Technical Details

### Prerequisites

- The deployment exposes a resource or tool that can return, convert, upload, or attach file content. <!-- SAF-TRACE: claims=SAF-T1802-C002,SAF-T1802-C003; sources=SRC-mcp-resources-2026,SRC-mcp-tools-2026-07-28 -->
- The adversary can influence the operation, URI, or file path through a permitted client, injected agent workflow, reachable endpoint, or local caller. <!-- SAF-TRACE: claims=SAF-T1802-C007,SAF-T1802-C008,SAF-T1802-C009,SAF-T1802-C011; sources=SRC-ghsa-g5r6-gv6m-f5jv,SRC-ghsa-7jj9-4qqq-4xc4,SRC-ghsa-j98m-w3xp-9f56,SRC-flowguard-2607.14754v1 -->
- The target file is readable by the server process, and authorization, approval, URI, path, or link-resolution enforcement does not reject the request. <!-- SAF-TRACE: claims=SAF-T1802-C005,SAF-T1802-C006,SAF-T1802-C018; sources=SRC-cwe-22,SRC-cwe-59,SRC-mcp-resources-2026,SRC-mcp-tools-2026-07-28 -->

### Attack Flow

1. **Reconnaissance or Setup**: The actor identifies a file-bearing resource or a tool parameter that reaches a file sink; a benign-looking URI parameter can conceal that capability. <!-- SAF-TRACE: claims=SAF-T1802-C002,SAF-T1802-C003,SAF-T1802-C017; sources=SRC-mcp-resources-2026,SRC-mcp-tools-2026-07-28,SRC-flowguard-2607.14754v1 -->
2. **Delivery**: An attacker-selected path or URI reaches the server through a direct client request, network or local API call, or agent-mediated tool invocation. <!-- SAF-TRACE: claims=SAF-T1802-C007,SAF-T1802-C008,SAF-T1802-C009,SAF-T1802-C011; sources=SRC-ghsa-g5r6-gv6m-f5jv,SRC-ghsa-7jj9-4qqq-4xc4,SRC-ghsa-j98m-w3xp-9f56,SRC-flowguard-2607.14754v1 -->
3. **Trigger or Execution**: The server lists candidates if needed and then performs a resource read or file-capable tool call. <!-- SAF-TRACE: claims=SAF-T1802-C002,SAF-T1802-C003,SAF-T1802-C014; sources=SRC-mcp-resources-2026,SRC-mcp-tools-2026-07-28,SRC-attack-t1083 -->
4. **Boundary Crossing**: Missing authorization, absolute-path acceptance, traversal, string-prefix comparison, a file URI, or symlink resolution causes access outside the intended file set. <!-- SAF-TRACE: claims=SAF-T1802-C005,SAF-T1802-C006,SAF-T1802-C007,SAF-T1802-C008,SAF-T1802-C009,SAF-T1802-C010,SAF-T1802-C011; sources=SRC-cwe-22,SRC-cwe-59,SRC-ghsa-g5r6-gv6m-f5jv,SRC-ghsa-7jj9-4qqq-4xc4,SRC-ghsa-j98m-w3xp-9f56,SRC-ghsa-cve-2025-53109,SRC-ghsa-cve-2025-53110,SRC-flowguard-2607.14754v1 -->
5. **Objective**: The response or backend contains the selected file's content, making it available to the caller or agent. <!-- SAF-TRACE: claims=SAF-T1802-C001,SAF-T1802-C019; sources=SRC-attack-t1005,SRC-cve-2026-73498,SRC-cve-2026-46555,SRC-cve-2026-40576 -->
6. **Follow-On Activity**: The actor can inspect, stage, or transmit the collected content, but those later actions require separate classification when they cross another boundary. <!-- SAF-TRACE: claims=SAF-T1802-C001,SAF-T1802-C019; sources=SRC-attack-t1005,SRC-cve-2026-46555 -->

### Example Scenario

This inert normalized event represents a successful resource read whose requested in-root link resolves outside the approved root; the placeholder response contains no real file data. <!-- SAF-TRACE: claims=SAF-T1802-C006,SAF-T1802-C015,SAF-T1802-C016; sources=SRC-cwe-59,SRC-mcp-resources-2026,SRC-flowguard-2607.14754v1 -->

```json
{
  "timestamp": "2026-09-02T10:00:00Z",
  "actor_id": "example-agent",
  "session_id": "example-session",
  "server_id": "example-files",
  "method": "resources/read",
  "requested_path": "/srv/example/link/report.txt",
  "resolved_path": "/srv/outside/placeholder.txt",
  "approved_roots": ["/srv/example"],
  "result_status": "success",
  "bytes_read": 128,
  "content": "PLACEHOLDER_CONTENT"
}
```

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1802-C001 | MCP resource or tool operations can be combined into file-content collection across an intended boundary. | Research-Derived | SRC-mcp-resources-2026, SRC-mcp-tools-2026-07-28, SRC-attack-t1005 | The combined SAF boundary is an explicit inference. |
| SAF-T1802-C002 | Resources support list/read operations, multiple content items, and file URIs. | Research-Derived | SRC-mcp-resources-2026 | A deployment need not expose file resources. |
| SAF-T1802-C003 | Model-controlled tools can return resource links or embedded resources. | Research-Derived | SRC-mcp-tools-2026-07-28 | No particular file tool is mandatory. |
| SAF-T1802-C004 | Roots are informational, deprecated, and not protocol access control. | Research-Derived | SRC-mcp-2026-roots | Implementations can add independent enforcement. |
| SAF-T1802-C005 | Traversal or incomplete canonicalization can escape a restricted directory. | Research-Derived | SRC-cwe-22 | CWE classification is not product-specific proof. |
| SAF-T1802-C006 | Unsafe link resolution can expose an unintended file. | Research-Derived | SRC-cwe-59, SRC-ghsa-cve-2025-53109 | Platform semantics vary. |
| SAF-T1802-C007 | MCP Atlassian file disclosure was demonstrated through direct, MCP-client, and controlled prompt-injection paths. | Demonstrated | SRC-ghsa-g5r6-gv6m-f5jv, SRC-cve-2026-73498 | No production intrusion is established. |
| SAF-T1802-C008 | WhatsApp MCP could read and attach files under stated local or DNS-rebinding conditions. | Research-Derived | SRC-ghsa-7jj9-4qqq-4xc4, SRC-cve-2026-46555 | No known production exploitation is reported. |
| SAF-T1802-C009 | excel-mcp-server arbitrary file operations were publicly validated through PoC. | Demonstrated | SRC-ghsa-j98m-w3xp-9f56, SRC-cve-2026-40576 | Write impact is outside this technique's defining behavior. |
| SAF-T1802-C010 | MCP Filesystem had symlink and colliding-prefix boundary bypasses. | Research-Derived | SRC-cve-2025-53109, SRC-cve-2025-53110, SRC-ghsa-cve-2025-53109, SRC-ghsa-cve-2025-53110 | Official npm patch metadata conflicts. |
| SAF-T1802-C011 | FlowGuard measured file-access detection and confirmed MarkItDown local-file disclosure. | Demonstrated | SRC-flowguard-2607.14754v1 | Preprint and controlled evidence do not establish production exploitation. |
| SAF-T1802-C012 | The bounded review found no qualifying file-specific production incident. | Research-Derived | SRC-anthropic-espionage-2025-11, SRC-cisa-kev-2026-09-01, SRC-nvd-saturation-file-access, SRC-nvd-saturation-arbitrary-read | Negative public evidence is not universal proof of absence. |
| SAF-T1802-C013 | ATT&CK T1005 is a direct behavioral mapping. | Research-Derived | SRC-attack-t1005, SRC-mcp-resources-2026 | T1005 is not MCP-specific. |
| SAF-T1802-C014 | Enumeration-only discovery is distinct from content retrieval. | Research-Derived | SRC-attack-t1083, SRC-attack-t1005 | One session can contain both behaviors. |
| SAF-T1802-C015 | Detection needs operation, result, identity, path, root, approval, and byte telemetry. | Research-Derived | SRC-mcp-resources-2026, SRC-mcp-tools-2026-07-28, SRC-flowguard-2607.14754v1 | Enrichment is implementation-specific. |
| SAF-T1802-C016 | Boundary escape, unapproved sensitivity, and distinct-file bursts form a testable analytic. | Research-Derived | SRC-attack-t1005, SRC-mcp-tools-2026-07-28, SRC-flowguard-2607.14754v1 | Threshold is illustrative and tunable. |
| SAF-T1802-C017 | Runtime backend evidence is needed to manage benign file operations and misleading tool metadata. | Research-Derived | SRC-flowguard-2607.14754v1 | Reported performance may not generalize. |
| SAF-T1802-C018 | Canonical validation, authorization, link-aware containment, least privilege, sandboxing, and confirmation constrain collection. | Research-Derived | SRC-mcp-resources-2026, SRC-mcp-tools-2026-07-28, SRC-mcp-security-2025-11-25, SRC-cwe-22, SRC-cwe-59 | Hosts and servers must implement the controls. |
| SAF-T1802-C019 | Confidentiality is primary; reachability, privilege, automation, and transfer channels change severity. | Research-Derived | SRC-cve-2026-73498, SRC-cve-2026-46555, SRC-cve-2026-40576, SRC-cwe-22 | Actual harm depends on accessible content. |
| SAF-T1802-C020 | Selected affected products have published fixed releases and conditional credential-response needs. | Research-Derived | SRC-ghsa-g5r6-gv6m-f5jv, SRC-ghsa-7jj9-4qqq-4xc4, SRC-ghsa-j98m-w3xp-9f56, SRC-cve-2025-53109, SRC-cve-2025-53110 | Rotation is conditional on actual exposure. |

### Current State

- **Affected Environments**: File-capable MCP resources and tools are in scope when actor authorization, approval, and the server process's filesystem privilege are not aligned. <!-- SAF-TRACE: claims=SAF-T1802-C001,SAF-T1802-C002,SAF-T1802-C003,SAF-T1802-C019; sources=SRC-mcp-resources-2026,SRC-mcp-tools-2026-07-28,SRC-cve-2026-73498 -->
- **Known Exploitation**: Public demonstrations and disclosed vulnerabilities qualify; no reviewed direct authority established a file-specific production incident or CISA KEV listing for the selected CVEs. <!-- SAF-TRACE: claims=SAF-T1802-C007,SAF-T1802-C009,SAF-T1802-C011,SAF-T1802-C012; sources=SRC-ghsa-g5r6-gv6m-f5jv,SRC-ghsa-j98m-w3xp-9f56,SRC-flowguard-2607.14754v1,SRC-cisa-kev-2026-09-01 -->
- **Available Protections**: Selected products have fixed releases, while protocol and weakness guidance call for per-operation authorization, validation, containment, least privilege, sandboxing, approval, and logging. <!-- SAF-TRACE: claims=SAF-T1802-C018,SAF-T1802-C020; sources=SRC-mcp-resources-2026,SRC-mcp-tools-2026-07-28,SRC-mcp-security-2025-11-25,SRC-cwe-22,SRC-cwe-59,SRC-ghsa-g5r6-gv6m-f5jv,SRC-ghsa-7jj9-4qqq-4xc4,SRC-ghsa-j98m-w3xp-9f56,SRC-cve-2025-53109,SRC-cve-2025-53110 -->
- **Residual Risk**: Legitimate file functions remain dual-use, roots do not enforce access, low-and-slow reads can evade thresholds, and missing resolved-path or result telemetry can prevent reliable adjudication. <!-- SAF-TRACE: claims=SAF-T1802-C004,SAF-T1802-C016,SAF-T1802-C017; sources=SRC-mcp-2026-roots,SRC-flowguard-2607.14754v1,SRC-attack-t1005 -->

### Known Breaches and Vulnerabilities

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| MCP Atlassian, GHSA-g5r6-gv6m-f5jv / CVE-2026-73498 | Published 2026-08-12; versions before 0.22.0 | Process-readable files could be opened and uploaded to Confluence; upgrade to 0.22.0. | Direct vulnerability and public demonstrations. | No production intrusion is documented. <!-- SAF-TRACE: claims=SAF-T1802-C007,SAF-T1802-C020; sources=SRC-ghsa-g5r6-gv6m-f5jv,SRC-cve-2026-73498 --> |
| excel-mcp-server, GHSA-j98m-w3xp-9f56 / CVE-2026-40576 | Published 2026-04-21; versions through 0.1.7 in network transport modes | Unauthenticated arbitrary host-file operations; upgrade to 0.1.8. | Direct vulnerability and public PoC. | Collection uses only the read aspect of a broader read/write flaw. <!-- SAF-TRACE: claims=SAF-T1802-C009,SAF-T1802-C020; sources=SRC-ghsa-j98m-w3xp-9f56,SRC-cve-2026-40576 --> |
| WhatsApp MCP, GHSA-7jj9-4qqq-4xc4 / CVE-2026-46555 | Published 2026-07-20; versions before 0.2.1 | Qualifying local or DNS-rebinding callers could attach process-readable files; upgrade to 0.2.1. | Direct vulnerability with attached transfer. | CVE ADP reports no known exploitation. <!-- SAF-TRACE: claims=SAF-T1802-C008,SAF-T1802-C020; sources=SRC-ghsa-7jj9-4qqq-4xc4,SRC-cve-2026-46555 --> |
| MCP Filesystem, GHSA-q66q-fx2p-7w4m / CVE-2025-53109 | Published 2025-07-02; releases before conservative floor 0.6.4 or 2025.7.01 | Allowed-directory symlinks could expose unintended files; upgrade and enforce post-resolution containment. | Direct vulnerability in the reference filesystem server. | No production exploitation is established; official npm patch metadata conflicts. <!-- SAF-TRACE: claims=SAF-T1802-C006,SAF-T1802-C010,SAF-T1802-C020; sources=SRC-cwe-59,SRC-ghsa-cve-2025-53109,SRC-cve-2025-53109 --> |

No qualifying direct production breach was identified in the bounded authority corpus. The reviewed Anthropic campaign remains adjacent because it describes database and system-information collection but not retrieval of file content. <!-- SAF-TRACE: claims=SAF-T1802-C012; sources=SRC-anthropic-espionage-2025-11,SRC-cisa-kev-2026-09-01,SRC-nvd-saturation-file-access,SRC-nvd-saturation-arbitrary-read -->

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | High | A successful call can expose any file readable by the service; remote reachability, credentials in files, automation, and attachment channels increase harm. <!-- SAF-TRACE: claims=SAF-T1802-C019; sources=SRC-cve-2026-73498,SRC-cve-2026-46555,SRC-cve-2026-40576,SRC-cwe-22 --> |
| Integrity | None | File Collection is defined by obtaining content; writes or altered files require separate behavior even when one vulnerability also permits them. <!-- SAF-TRACE: claims=SAF-T1802-C009,SAF-T1802-C019; sources=SRC-ghsa-j98m-w3xp-9f56,SRC-cve-2026-40576 --> |
| Availability | None | Retrieval alone does not require disruption; destructive or resource-exhaustion effects are outside this contract. <!-- SAF-TRACE: claims=SAF-T1802-C001,SAF-T1802-C019; sources=SRC-attack-t1005,SRC-cwe-22 --> |
| Scope | Multi-System | A host may expose local files and an integrated attachment service may carry them onward, but process privilege and reachable integrations bound the blast radius. <!-- SAF-TRACE: claims=SAF-T1802-C008,SAF-T1802-C019; sources=SRC-ghsa-7jj9-4qqq-4xc4,SRC-cve-2026-46555 --> |

### Severity Conditions

- **Severity increases when**: The endpoint is remotely or locally reachable without strong authentication, the process reads sensitive directories, agent calls are automated, approval is absent, or the operation includes an external attachment channel. <!-- SAF-TRACE: claims=SAF-T1802-C007,SAF-T1802-C008,SAF-T1802-C009,SAF-T1802-C019; sources=SRC-cve-2026-73498,SRC-cve-2026-46555,SRC-cve-2026-40576 -->
- **Severity decreases when**: The server runs with a minimal filesystem view, paths are resolved and contained, per-operation authorization and approval are enforced, and egress or attachment destinations are constrained. <!-- SAF-TRACE: claims=SAF-T1802-C018,SAF-T1802-C019; sources=SRC-mcp-resources-2026,SRC-mcp-tools-2026-07-28,SRC-mcp-security-2025-11-25,SRC-cwe-22,SRC-cwe-59 -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| MCP host, client, and server audit logs | resources/list, resources/read, tools/call, result, and approval events | Timestamp, actor, session, server, method, tool action, arguments, result status, returned bytes, and approval state | Preserve request-result linkage and the model or user that initiated the action. <!-- SAF-TRACE: claims=SAF-T1802-C002,SAF-T1802-C003,SAF-T1802-C015; sources=SRC-mcp-resources-2026,SRC-mcp-tools-2026-07-28,SRC-flowguard-2607.14754v1 --> |
| Host path-policy or endpoint telemetry | Path resolution, file open, and attachment or conversion result | Requested path, resolved path, approved roots, file sensitivity, process identity, and destination | Normalize after canonicalization and link resolution; hash or classify sensitive values instead of logging file content. <!-- SAF-TRACE: claims=SAF-T1802-C005,SAF-T1802-C006,SAF-T1802-C015; sources=SRC-cwe-22,SRC-cwe-59,SRC-flowguard-2607.14754v1 --> |

### Indicators of Compromise (IoCs)

- None known. This behavior has no reliable durable artifact independent of the accessed path, product, and follow-on activity. <!-- SAF-TRACE: claims=SAF-T1802-C012,SAF-T1802-C017; sources=SRC-cisa-kev-2026-09-01,SRC-flowguard-2607.14754v1 -->

### Behavioral Indicators

- A successful file return whose resolved path is outside every approved normalized root. <!-- SAF-TRACE: claims=SAF-T1802-C005,SAF-T1802-C006,SAF-T1802-C016; sources=SRC-cwe-22,SRC-cwe-59,SRC-flowguard-2607.14754v1 -->
- A sensitive-file return without an approval decision, especially from a model-controlled tool. <!-- SAF-TRACE: claims=SAF-T1802-C003,SAF-T1802-C016; sources=SRC-mcp-tools-2026-07-28,SRC-flowguard-2607.14754v1 -->
- Four distinct successful file reads by the same actor, session, and server in five minutes, excluding approved known bulk workloads. <!-- SAF-TRACE: claims=SAF-T1802-C016; sources=SRC-attack-t1005,SRC-flowguard-2607.14754v1 -->
- Resource listing followed by targeted reads and temporary staging raises confidence but is not required for a boundary-escape alert. <!-- SAF-TRACE: claims=SAF-T1802-C014,SAF-T1802-C016; sources=SRC-attack-t1083,SRC-attack-t1005 -->

### Detection Analytic

The standalone example analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Detect successful file retrieval with a resolved-path escape, unapproved sensitive target, or non-allowlisted distinct-file burst. <!-- SAF-TRACE: claims=SAF-T1802-C016; sources=SRC-attack-t1005,SRC-mcp-tools-2026-07-28,SRC-flowguard-2607.14754v1 -->
- **Rule Status**: Experimental; the normalized field model and thresholds require deployment-specific mapping. <!-- SAF-TRACE: claims=SAF-T1802-C015,SAF-T1802-C016; sources=SRC-mcp-resources-2026,SRC-mcp-tools-2026-07-28,SRC-flowguard-2607.14754v1 -->
- **Detection Logic**: Require a successful content-bearing resource read or file tool result, then match boundary escape, sensitive access without approval, or four distinct paths within five minutes. <!-- SAF-TRACE: claims=SAF-T1802-C015,SAF-T1802-C016; sources=SRC-mcp-resources-2026,SRC-mcp-tools-2026-07-28,SRC-attack-t1005 -->
- **Correlation Window**: Five minutes per actor-session-server tuple for the burst branch; boundary and approval branches are single-event. <!-- SAF-TRACE: claims=SAF-T1802-C016; sources=SRC-attack-t1005,SRC-flowguard-2607.14754v1 -->
- **Known False Positives**: Backup, indexing, migration, document conversion, incident response, and telemetry that loses approval or path context. <!-- SAF-TRACE: claims=SAF-T1802-C017; sources=SRC-flowguard-2607.14754v1 -->
- **Known Limitations**: Low-and-slow access, single authorized-looking reads, encrypted or opaque arguments, missing result bytes, absent resolved paths, and cross-session activity can evade or prevent adjudication. <!-- SAF-TRACE: claims=SAF-T1802-C016,SAF-T1802-C017; sources=SRC-flowguard-2607.14754v1,SRC-attack-t1005 -->
- **Tuning Guidance**: Map approved roots after canonicalization, define sensitive-file classes, preserve explicit approvals, baseline bulk workflows, and tune the distinct-file count and window per server role. <!-- SAF-TRACE: claims=SAF-T1802-C015,SAF-T1802-C016,SAF-T1802-C017; sources=SRC-mcp-resources-2026,SRC-mcp-tools-2026-07-28,SRC-attack-t1005,SRC-flowguard-2607.14754v1 -->

### Validation

- **Test Data**: [fixtures.jsonl](../../tests/SAF-T1802/fixtures.jsonl)
- **Detector**: [detect_file_collection.py](../../tests/SAF-T1802/detect_file_collection.py)
- **Validation Script**: [test_detection_rule.py](../../tests/SAF-T1802/test_detection_rule.py)
- **Expected Result**: [Three expected alerts, zero unexpected alerts, and one malformed record skipped](../../research/techniques/SAF-T1802/validation/detection-test.txt)
- **Last Validated**: [2026-09-02](../../research/techniques/SAF-T1802/validation/detection-test.txt)
- **Feasibility Waiver**: [None; the executable local detector and synthetic fixtures pass](../../research/techniques/SAF-T1802/validation/detection-test.txt).

## Mitigation Strategies

### Preventive Controls

1. **[SAF-M-29: Explicit Privilege Boundaries](../../mitigations/SAF-M-29/README.md)**: Canonicalize the requested path, resolve links, compare path components with approved roots, and reject any escape before opening content. <!-- SAF-TRACE: claims=SAF-T1802-C005,SAF-T1802-C006,SAF-T1802-C018; sources=SRC-cwe-22,SRC-cwe-59,SRC-mcp-resources-2026 -->
2. **[SAF-M-69: Out-of-Band Authorization for Privileged Tool Invocations](../../mitigations/SAF-M-69/README.md)**: Restrict the service filesystem view and identity, enforce per-operation authorization, and require confirmation for sensitive file operations. <!-- SAF-TRACE: claims=SAF-T1802-C003,SAF-T1802-C018; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-security-2025-11-25 -->
3. **Patch affected products**: Use MCP Atlassian 0.22.0, WhatsApp MCP 0.2.1, excel-mcp-server 0.1.8, and the conservative MCP Filesystem floor 0.6.4 or 2025.7.01. <!-- SAF-TRACE: claims=SAF-T1802-C010,SAF-T1802-C020; sources=SRC-ghsa-g5r6-gv6m-f5jv,SRC-ghsa-7jj9-4qqq-4xc4,SRC-ghsa-j98m-w3xp-9f56,SRC-cve-2025-53109,SRC-cve-2025-53110 -->

### Detective Controls

1. **Centralize request-result audit data**: Correlate actor, session, server, method, arguments, approval, resolved path, result status, and returned byte count. <!-- SAF-TRACE: claims=SAF-T1802-C015; sources=SRC-mcp-resources-2026,SRC-mcp-tools-2026-07-28,SRC-flowguard-2607.14754v1 -->
2. **Alert on policy deviation and sequence**: Prioritize resolved-root escapes and unapproved sensitive reads, then baseline distinct-file bursts and list-to-read sequences. <!-- SAF-TRACE: claims=SAF-T1802-C016,SAF-T1802-C017; sources=SRC-attack-t1005,SRC-flowguard-2607.14754v1 -->

### Response Procedures

#### Immediate Actions

- Suspend the implicated session, server endpoint, tool, or resource and preserve request-result audit records before changing state. <!-- SAF-TRACE: claims=SAF-T1802-C015,SAF-T1802-C018; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-resources-2026 -->
- If returned content contained a credential, revoke and rotate that credential after preserving necessary evidence. <!-- SAF-TRACE: claims=SAF-T1802-C019,SAF-T1802-C020; sources=SRC-cve-2026-73498,SRC-ghsa-g5r6-gv6m-f5jv -->

#### Investigation Steps

- Reconstruct resource listings, reads, tool calls, approvals, resolved paths, returned bytes, and attachment or conversion destinations for the actor and session. <!-- SAF-TRACE: claims=SAF-T1802-C015,SAF-T1802-C016; sources=SRC-mcp-resources-2026,SRC-mcp-tools-2026-07-28,SRC-attack-t1005 -->
- Determine which files were process-readable, whether content was actually returned, how the request entered the workflow, and whether follow-on transfer occurred. <!-- SAF-TRACE: claims=SAF-T1802-C017,SAF-T1802-C019; sources=SRC-flowguard-2607.14754v1,SRC-cve-2026-46555 -->

#### Remediation

- Upgrade affected software, close unauthenticated reachability, and implement authorization plus canonical post-resolution path containment. <!-- SAF-TRACE: claims=SAF-T1802-C018,SAF-T1802-C020; sources=SRC-mcp-resources-2026,SRC-mcp-tools-2026-07-28,SRC-cwe-22,SRC-cwe-59,SRC-ghsa-g5r6-gv6m-f5jv,SRC-ghsa-7jj9-4qqq-4xc4,SRC-ghsa-j98m-w3xp-9f56 -->
- Re-run the detector fixture suite and add a regression case for the specific entry path before restoring service. <!-- SAF-TRACE: claims=SAF-T1802-C016,SAF-T1802-C017; sources=SRC-flowguard-2607.14754v1,SRC-attack-t1005 -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1606: Directory Listing via File Tool](../SAF-T1606/README.md) | Prerequisite or co-occurring | Enumeration returns names or metadata; File Collection requires returned file content. <!-- SAF-TRACE: claims=SAF-T1802-C014; sources=SRC-attack-t1083,SRC-attack-t1005 --> |
| [SAF-T1801: Automated Data Harvesting](../SAF-T1801/README.md) | Related broader behavior | Automated Data Harvesting requires systematic breadth across repeated retrievals; File Collection can complete with one successful file-content read. [Framework Model v2 taxonomy review](../../research/taxonomy-review.yml) |
| [SAF-T1803: Database Dump](../SAF-T1803/README.md) | Adjacent collection behavior | Database Dump requires dump-equivalent database breadth; File Collection is bounded by retrieval of file content and does not require broad database export. [Framework Model v2 taxonomy review](../../research/taxonomy-review.yml) |
| [SAF-T1913: HTTP POST Exfil](../SAF-T1913/README.md) | Follow-on | Transfer moves already collected content; File Collection's immediate objective is obtaining the content. <!-- SAF-TRACE: claims=SAF-T1802-C001,SAF-T1802-C019; sources=SRC-attack-t1005,SRC-cve-2026-46555 --> |

The isolated placeholders were replaced with canonical neighbors after the clean-room freeze was verified, as recorded in the [integration notes](../../research/techniques/SAF-T1802/integration/integration-notes.yml).

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System | Direct | Both behaviors obtain local-system data; MCP supplies the resource or tool access path and an additional authorization context. <!-- SAF-TRACE: claims=SAF-T1802-C013; sources=SRC-attack-t1005,SRC-mcp-resources-2026 --> |
| [T1083](https://attack.mitre.org/techniques/T1083/) | File and Directory Discovery | Related, not mapped | Enumeration is discovery unless the workflow subsequently retrieves content. <!-- SAF-TRACE: claims=SAF-T1802-C014; sources=SRC-attack-t1083,SRC-attack-t1005 --> |

## References

1. **SRC-mcp-resources-2026**: [MCP Specification — Resources](https://modelcontextprotocol.io/specification/2026-07-28/server/resources) — list/read semantics, file URIs, and resource security guidance.
2. **SRC-mcp-tools-2026-07-28**: [MCP Specification — Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) — model-controlled calls, results, authorization, confirmation, and logging.
3. **SRC-mcp-2026-roots**: [MCP Specification — Roots](https://modelcontextprotocol.io/specification/2026-07-28/client/roots) — informational and non-enforcing status.
4. **SRC-mcp-security-2025-11-25**: [MCP Security Best Practices](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices) — local-server isolation and scope minimization.
5. **SRC-attack-t1005**: [MITRE ATT&CK T1005 — Data from Local System](https://attack.mitre.org/techniques/T1005/) — collection definition and detection strategy; contributors include Austin Clark, Liran Ravich, and William Cain.
6. **SRC-attack-t1083**: [MITRE ATT&CK T1083 — File and Directory Discovery](https://attack.mitre.org/techniques/T1083/) — enumeration distinction.
7. **SRC-cwe-22**: [MITRE CWE-22](https://cwe.mitre.org/data/definitions/22.html) — path traversal, consequences, and mitigations.
8. **SRC-cwe-59**: [MITRE CWE-59](https://cwe.mitre.org/data/definitions/59.html) — unsafe link resolution.
9. **SRC-ghsa-g5r6-gv6m-f5jv**: [MCP Atlassian advisory](https://github.com/sooperset/mcp-atlassian/security/advisories/GHSA-g5r6-gv6m-f5jv) — path-validation failure, demonstrations, and patch; reporter rainfantry.
10. **SRC-cve-2026-73498**: [CVE-2026-73498](https://cveawg.mitre.org/api/cve/CVE-2026-73498) — canonical vulnerability record.
11. **SRC-ghsa-7jj9-4qqq-4xc4**: [WhatsApp MCP advisory](https://github.com/verygoodplugins/whatsapp-mcp/security/advisories/GHSA-7jj9-4qqq-4xc4) — bridge, DNS-rebinding, media-path, and patch facts; reporter Paul van der Klooster / Poker71.
12. **SRC-cve-2026-46555**: [CVE-2026-46555](https://cveawg.mitre.org/api/cve/CVE-2026-46555) — canonical vulnerability record.
13. **SRC-ghsa-j98m-w3xp-9f56**: [excel-mcp-server advisory](https://github.com/haris-musa/excel-mcp-server/security/advisories/GHSA-j98m-w3xp-9f56) — traversal, PoC, impact, and patch.
14. **SRC-cve-2026-40576**: [CVE-2026-40576](https://cveawg.mitre.org/api/cve/CVE-2026-40576) — canonical vulnerability record.
15. **SRC-ghsa-cve-2025-53109**: [MCP Filesystem symlink advisory](https://github.com/modelcontextprotocol/servers/security/advisories/GHSA-q66q-fx2p-7w4m) — link-resolution bypass; reporter Elad Beber.
16. **SRC-cve-2025-53109**: [CVE-2025-53109](https://cveawg.mitre.org/api/cve/CVE-2025-53109) — canonical symlink-bypass record.
17. **SRC-ghsa-cve-2025-53110**: [MCP Filesystem prefix advisory](https://github.com/modelcontextprotocol/servers/security/advisories/GHSA-hc55-p739-j48w) — colliding-prefix bypass; reporter Elad Beber.
18. **SRC-cve-2025-53110**: [CVE-2025-53110](https://cveawg.mitre.org/api/cve/CVE-2025-53110) — canonical prefix-bypass record.
19. **SRC-flowguard-2607.14754v1**: [FlowGuard — Baichao An, Pei Chen, Geng Hong, Yueyue Chen, and Mengying Wu](https://arxiv.org/pdf/2607.14754v1) — runtime evidence, benchmark results, limitations, and MarkItDown case study.
20. **SRC-anthropic-espionage-2025-11**: [Anthropic GTG-1002 campaign report](https://assets.anthropic.com/m/ec212e6566a0d47/original/Disrupting-the-first-reported-AI-orchestrated-cyber-espionage-campaign.pdf) — adjacent incident context and limitation.
21. **SRC-cisa-kev-2026-09-01**: [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) — bounded exploitation-status check.
22. **SRC-nvd-saturation-file-access**: [NVD API — Model Context Protocol file access](https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Model%20Context%20Protocol%20file%20access) — first no-change saturation result.
23. **SRC-nvd-saturation-arbitrary-read**: [NVD API — Model Context Protocol arbitrary file read](https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Model%20Context%20Protocol%20arbitrary%20file%20read) — second no-change saturation result.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 0.1 | 2026-09-02 | Independent clean-room draft, evidence packet, detector, tests, and synthetic strict-validation handoff. | OpenAI Codex clean-room agent |
| 0.2 | 2026-09-02 | Added the reviewed distinction from automated harvesting and database dumping. | OpenAI Codex taxonomy review |
