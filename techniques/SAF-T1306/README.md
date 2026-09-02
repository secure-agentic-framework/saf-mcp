# SAF-T1306: Rogue Authorization Server

## Overview

- **Tactic**: Privilege Escalation (ATK-TA0004)
- **Technique ID**: SAF-T1306
- **Research Packet**: [research/techniques/SAF-T1306](../../research/techniques/SAF-T1306/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1306/traceability-ledger.yml)
- **Lifecycle Status**: Deprecated. [Framework Model v2 taxonomy review](../../research/taxonomy-review.yml)
- **Documentation Status**: Deprecated
- **Evidence Status**: Research-Derived
- **Severity**: High
- **Severity Rationale**: A successful flow can disclose a victim-bound authorization code or token, with consequence bounded by scope, audience, lifetime, sender constraint, and downstream authorization. <!-- SAF-TRACE: claims=SAF-T1306-C018,SAF-T1306-C024; sources=SRC-rfc9700,SRC-mcp-sep-2468,SRC-mcp-authorization-2026-07-28 -->
- **First Observed**: Not observed in an MCP production incident in the authoritative corpus reviewed through 2026-09-01. <!-- SAF-TRACE: claims=SAF-T1306-C009; sources=SRC-mcp-release-2026-07-28,SRC-cisa-kev-2026-09-01,SRC-nvd-cve-2025-10619,SRC-nvd-cve-2025-4143 -->
- **Last Updated**: 2026-09-02

> **Deprecated compatibility ID:** SAF-T1306 is consolidated into [SAF-T1009: Authorization Server Mix-up](../SAF-T1009/README.md). Both frozen contracts define the same issuer-misbinding and cross-issuer credential-disclosure mechanism. This page and its evidence packet remain available for provenance; use SAF-T1009 for new mappings. [Framework Model v2 taxonomy review](../../research/taxonomy-review.yml)

## Scope

This technique covers a multi-authorization-server MCP flow in which a rogue or compromised authorization server causes the client to misassociate an honest server's authorization response and disclose the resulting code or token to the rogue endpoint. <!-- SAF-TRACE: claims=SAF-T1306-C003,SAF-T1306-C006; sources=SRC-mcp-sep-2468,SRC-rfc9700,SRC-rfc9207 -->

### In Scope

- An attacker-controlled authorization server participating in an MCP protected-resource authorization flow. <!-- SAF-TRACE: claims=SAF-T1306-C001,SAF-T1306-C003; sources=SRC-mcp-authorization-2026-07-28,SRC-rfc9728,SRC-mcp-sep-2468,SRC-rfc9700 -->
- Failure to bind the authorization response to the authenticated expected issuer before choosing the token endpoint. <!-- SAF-TRACE: claims=SAF-T1306-C004,SAF-T1306-C005; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-sep-2468,SRC-rfc8414,SRC-rfc9207 -->
- Immediate theft of an authorization code or access token carrying the victim's delegated privileges. <!-- SAF-TRACE: claims=SAF-T1306-C006,SAF-T1306-C018; sources=SRC-rfc9700,SRC-rfc9207,SRC-mcp-sep-2468 -->

### Out of Scope

- Passive authorization-code interception, wrong-resource token acceptance, and discovery command injection when issuer confusion does not occur. <!-- SAF-TRACE: claims=SAF-T1306-C011,SAF-T1306-C023; sources=SRC-nvd-cve-2025-10619,SRC-rfc9700,SRC-mcp-sep-2468 -->
- Open-redirect or redirect URI validation weaknesses without authorization-server mix-up. <!-- SAF-TRACE: claims=SAF-T1306-C013,SAF-T1306-C023; sources=SRC-nvd-cve-2025-4143,SRC-rfc9700,SRC-mcp-sep-2468 -->
- Local modification of an authentication process that does not make the client associate an honest response with a rogue issuer. <!-- SAF-TRACE: claims=SAF-T1306-C017,SAF-T1306-C023; sources=SRC-attack-t1556,SRC-rfc9700,SRC-mcp-sep-2468 -->

### Distinguishing Characteristics

The defining observable is issuer association failure: the expected issuer for a flow differs from, or is required but absent in, the authorization response before code redemption. This separates the technique from [Authorization Code Interception](../SAF-T1507/README.md), [Credential Relay Chain](../SAF-T1304/README.md), and [Metadata Manipulation](../SAF-T1406/README.md). <!-- SAF-TRACE: claims=SAF-T1306-C004,SAF-T1306-C023; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-sep-2468,SRC-rfc9700 -->

## Description

MCP authorization makes the MCP server an OAuth protected resource, the MCP client an OAuth client, and an authorization server the token issuer. Protected-resource metadata can advertise candidate authorization servers, while RFC 9728 leaves secure appropriateness decisions to the deployment. <!-- SAF-TRACE: claims=SAF-T1306-C001,SAF-T1306-C002; sources=SRC-mcp-authorization-2026-07-28,SRC-rfc9728 -->

In the defining attack, at least one honest and one rogue or compromised authorization server are available. The client begins an honest authorization flow but fails to bind the returned response to its validated issuer, then exposes the honest code or token to the rogue server during redemption. <!-- SAF-TRACE: claims=SAF-T1306-C003,SAF-T1306-C006; sources=SRC-mcp-sep-2468,SRC-rfc9700,SRC-rfc9207 -->

Current MCP guidance closes this path by recording the validated metadata issuer, comparing the response issuer exactly, rejecting an advertised-but-missing issuer, and aborting mismatches before redemption. The end-to-end MCP technique remains Research-Derived because the reviewed corpus contains protocol remediation and generic OAuth demonstrations, but no direct MCP production event or MCP-specific public reproduction. <!-- SAF-TRACE: claims=SAF-T1306-C004,SAF-T1306-C007,SAF-T1306-C009,SAF-T1306-C010; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-sep-2468,SRC-fett-oauth-analysis,SRC-mcp-release-2026-07-28,SRC-cisa-kev-2026-09-01,SRC-nvd-cve-2025-10619,SRC-nvd-cve-2025-4143 -->

## Attack Vectors

- **Primary Vector**: A rogue or compromised authorization server participates in a multi-server MCP authorization flow and benefits from missing or incorrect issuer binding. <!-- SAF-TRACE: claims=SAF-T1306-C003,SAF-T1306-C006; sources=SRC-mcp-sep-2468,SRC-rfc9700,SRC-rfc9207 -->
- **Secondary Vectors**: Untrusted protected-resource metadata can steer server selection, or stale and unauthenticated issuer state can create a false expected baseline. <!-- SAF-TRACE: claims=SAF-T1306-C002,SAF-T1306-C019,SAF-T1306-C021; sources=SRC-rfc9728,SRC-mcp-authorization-2026-07-28 -->
- **Affected Components**: MCP client authorization state, protected-resource metadata, authorization response processing, and token endpoint selection. <!-- SAF-TRACE: claims=SAF-T1306-C001,SAF-T1306-C004; sources=SRC-mcp-authorization-2026-07-28,SRC-rfc9728,SRC-mcp-sep-2468 -->
- **Trust Boundary Crossed**: The binding between resource discovery, expected authorization-server issuer, returned authorization response, and redemption endpoint. <!-- SAF-TRACE: claims=SAF-T1306-C002,SAF-T1306-C003; sources=SRC-rfc9728,SRC-mcp-sep-2468,SRC-rfc9700 -->

## Technical Details

### Prerequisites

- The client can authorize against at least two servers, including a rogue or compromised server. <!-- SAF-TRACE: claims=SAF-T1306-C006; sources=SRC-rfc9700,SRC-rfc9207 -->
- The client does not maintain an authentic flow-bound expected issuer or does not enforce exact issuer validation before redemption. <!-- SAF-TRACE: claims=SAF-T1306-C004,SAF-T1306-C005; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-sep-2468,SRC-rfc8414,SRC-rfc9207 -->
- The returned code or token remains usable under its scope, audience, lifetime, client type, and sender constraints. <!-- SAF-TRACE: claims=SAF-T1306-C018,SAF-T1306-C024; sources=SRC-rfc9700,SRC-mcp-sep-2468,SRC-mcp-authorization-2026-07-28 -->

### Attack Flow

1. **Setup**: The adversary controls or compromises one authorization server reachable in a multi-server MCP environment. <!-- SAF-TRACE: claims=SAF-T1306-C003,SAF-T1306-C006; sources=SRC-mcp-sep-2468,SRC-rfc9700 -->
2. **Selection**: The client accepts the server as a candidate through discovery or configuration without a trustworthy appropriateness decision. <!-- SAF-TRACE: claims=SAF-T1306-C001,SAF-T1306-C002; sources=SRC-mcp-authorization-2026-07-28,SRC-rfc9728 -->
3. **Authorization**: The victim authorizes at an honest server, which returns an authorization response for that honest issuer. <!-- SAF-TRACE: claims=SAF-T1306-C003,SAF-T1306-C006; sources=SRC-mcp-sep-2468,SRC-rfc9700,SRC-rfc9207 -->
4. **Boundary Crossing**: The client fails to compare the response issuer with the flow-bound expected issuer, or accepts a required issuer as missing. <!-- SAF-TRACE: claims=SAF-T1306-C004,SAF-T1306-C005; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-sep-2468,SRC-rfc8414,SRC-rfc9207 -->
5. **Objective**: The client sends the honest code or token to the rogue authorization server, exposing delegated credentials. <!-- SAF-TRACE: claims=SAF-T1306-C003,SAF-T1306-C006,SAF-T1306-C018; sources=SRC-mcp-sep-2468,SRC-rfc9700,SRC-rfc9207 -->
6. **Follow-On**: If the credential remains usable, the adversary can exercise its bounded permissions against the intended resource. <!-- SAF-TRACE: claims=SAF-T1306-C016,SAF-T1306-C018,SAF-T1306-C024; sources=SRC-mitre-t1528,SRC-rfc9700,SRC-mcp-sep-2468,SRC-mcp-authorization-2026-07-28 -->

### Example Scenario

An MCP client records `https://auth.good.example.invalid` as the expected issuer, then receives `iss=https://auth.rogue.example.invalid`. A conforming client rejects the mismatch and emits a fatal issuer-validation event before sending any code; a vulnerable client that skips that check could choose the rogue endpoint for redemption. <!-- SAF-TRACE: claims=SAF-T1306-C004,SAF-T1306-C005,SAF-T1306-C008; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-sep-2468,SRC-rfc8414,SRC-rfc9207,SRC-mcp-ts-auth-errors -->

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source and Limitation |
| --- | --- | --- | --- |
| SAF-T1306-C001 | MCP roles and discovery expose a multi-server authorization boundary. | Research-Derived | SRC-mcp-authorization-2026-07-28 and SRC-rfc9728; role definitions alone do not establish exploitation. |
| SAF-T1306-C002 | Server appropriateness requires a secure deployment decision. | Research-Derived | SRC-rfc9728; this is a trust-boundary statement, not an incident. |
| SAF-T1306-C003 | Missing issuer binding can expose an honest credential to a rogue server. | Research-Derived | SRC-mcp-sep-2468 and SRC-rfc9700; MCP production exploitation is not established. |
| SAF-T1306-C004 | Current MCP requires exact response-issuer validation and rejection. | Research-Derived | SRC-mcp-authorization-2026-07-28 and SRC-mcp-sep-2468; legacy compatibility retains a blind spot. |
| SAF-T1306-C005 | OAuth issuer values require exact string comparison. | Research-Derived | SRC-rfc8414 and SRC-rfc9207; an authentic baseline is still required. |
| SAF-T1306-C006 | Generic OAuth mix-up prerequisites and objective are standardized. | Demonstrated | SRC-rfc9700 and SRC-rfc9207; they are not MCP incident reports. |
| SAF-T1306-C007 | OAuth implementation research reproduced the generic mix-up. | Demonstrated | SRC-fett-oauth-analysis; the work predates MCP. |
| SAF-T1306-C008 | MCP SDK documentation defines fatal issuer-mismatch telemetry. | Research-Derived | SRC-mcp-ts-auth-errors; deployment logging is not guaranteed. |
| SAF-T1306-C009 | No direct MCP production event appeared in the reviewed corpus. | Research-Derived | SRC-mcp-release-2026-07-28, SRC-cisa-kev-2026-09-01, and two NVD records; corpus-bounded only. |
| SAF-T1306-C010 | The July 2026 MCP update closed the protocol hole. | Research-Derived | SRC-mcp-release-2026-07-28 and SRC-mcp-sep-2468; remediation is not exploitation evidence. |
| SAF-T1306-C011 | CVE-2025-10619 is a discovery command-injection vulnerability. | Demonstrated | SRC-nvd-cve-2025-10619; adjacent, not issuer mix-up. |
| SAF-T1306-C012 | Actors redirected TACACS+ activity to controlled infrastructure. | Observed | SRC-cisa-aa25-239a; non-MCP historical analogy. |
| SAF-T1306-C013 | CVE-2025-4143 is a redirect validation weakness. | Research-Derived | SRC-nvd-cve-2025-4143; adjacent and exact fixed version omitted. |
| SAF-T1306-C014 | Neither adjacent CVE is in the dated KEV snapshot. | Research-Derived | SRC-cisa-kev-2026-09-01; non-listing is nondispositive. |
| SAF-T1306-C015 | Unexpected authorization-server address monitoring is a historical detection pattern. | Research-Derived | SRC-cisco-security-warnings and SRC-cisa-aa25-239a; technology differs. |
| SAF-T1306-C016 | ATT&CK token theft directly matches the immediate objective. | Research-Derived | SRC-mitre-t1528; ATT&CK does not specify MCP mix-up. |
| SAF-T1306-C017 | Authentication-process modification is only analogous. | Research-Derived | SRC-attack-t1556; local modification is not required here. |
| SAF-T1306-C018 | Credential disclosure creates conditional high confidentiality and integrity risk. | Research-Derived | SRC-rfc9700 and SRC-mcp-sep-2468; impact is token-bound. |
| SAF-T1306-C019 | Authentic baselines, allowlisting, issuer binding, and rejection prevent the mechanism. | Research-Derived | SRC-mcp-authorization-2026-07-28 and SRC-rfc9728; baseline integrity remains essential. |
| SAF-T1306-C020 | Response requires abort, preservation, exposure assessment, and conditional revocation. | Research-Derived | SRC-rfc9207 and SRC-mcp-ts-auth-errors; revocation depends on exposure. |
| SAF-T1306-C021 | Legitimate issuer migration can produce benign mismatch. | Research-Derived | SRC-rfc9728; refresh must remain authenticated. |
| SAF-T1306-C022 | Mismatch analytics have legacy and poisoned-baseline blind spots. | Research-Derived | SRC-mcp-authorization-2026-07-28 and SRC-mcp-ts-auth-errors; fields need normalization. |
| SAF-T1306-C023 | Issuer association distinguishes the technique from its neighbors. | Research-Derived | SRC-rfc9700 and SRC-mcp-sep-2468; canonical framework relationships were reconciled after freeze. |
| SAF-T1306-C024 | Scope and audience controls reduce impact but do not replace issuer binding. | Research-Derived | SRC-mcp-authorization-2026-07-28; consequence reduction is not prevention. |

### Current State

- **Affected Environments**: MCP clients supporting multiple authorization servers are exposed when they lack a trustworthy expected-issuer baseline or do not validate the response issuer before redemption. <!-- SAF-TRACE: claims=SAF-T1306-C003,SAF-T1306-C004,SAF-T1306-C006; sources=SRC-mcp-sep-2468,SRC-mcp-authorization-2026-07-28,SRC-rfc9700,SRC-rfc9207 -->
- **Known Exploitation**: The reviewed authoritative corpus contains generic OAuth implementation demonstrations and non-MCP production analogies, but no qualifying direct MCP production event. <!-- SAF-TRACE: claims=SAF-T1306-C007,SAF-T1306-C009,SAF-T1306-C012; sources=SRC-fett-oauth-analysis,SRC-mcp-release-2026-07-28,SRC-cisa-kev-2026-09-01,SRC-nvd-cve-2025-10619,SRC-nvd-cve-2025-4143,SRC-cisa-aa25-239a -->
- **Available Protections**: The current MCP issuer-validation matrix, exact issuer comparison, trusted authorization-server policy, least-privilege scopes, and token audience restriction constrain the path and consequences. <!-- SAF-TRACE: claims=SAF-T1306-C004,SAF-T1306-C005,SAF-T1306-C019,SAF-T1306-C024; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-sep-2468,SRC-rfc8414,SRC-rfc9207,SRC-rfc9728 -->
- **Residual Risk**: Poisoned baselines, legacy no-issuer compatibility, missing telemetry, or unsafe administrative migration can preserve blind spots. <!-- SAF-TRACE: claims=SAF-T1306-C021,SAF-T1306-C022; sources=SRC-rfc9728,SRC-mcp-authorization-2026-07-28,SRC-mcp-ts-auth-errors -->

### Known Breaches and Vulnerabilities

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| July 2026 MCP authorization update | 2026-07-28; multi-server MCP authorization | Issuer binding closes code or token disclosure path. | Direct protocol vulnerability and remediation. | No exploitation reported. <!-- SAF-TRACE: claims=SAF-T1306-C003,SAF-T1306-C004,SAF-T1306-C010; sources=SRC-mcp-release-2026-07-28,SRC-mcp-sep-2468,SRC-mcp-authorization-2026-07-28,SRC-rfc9700 --> |
| OAuth IdP mix-up implementation study | 2016; OAuth and OpenID Connect implementations | Demonstrated code disclosure; bind and compare issuer identity. | Historical direct demonstration of the generic mechanism. | Predates and does not test MCP. <!-- SAF-TRACE: claims=SAF-T1306-C007; sources=SRC-fett-oauth-analysis --> |
| AA25-239A actor-controlled TACACS+ server | 2025; network infrastructure | Captured administrator authentication attempts; remove unexpected servers and restrict flows. | Observed historical authorization-infrastructure analogy. | Neither OAuth nor MCP. <!-- SAF-TRACE: claims=SAF-T1306-C012,SAF-T1306-C015; sources=SRC-cisa-aa25-239a,SRC-cisco-security-warnings --> |
| CVE-2025-10619 | 2025; sequa-mcp through 1.0.13 | Discovery input can lead to OS command execution; fixed in 1.0.14. | Adjacent discovery vulnerability. | Command injection, not issuer confusion; public proof of concept does not establish production exploitation. <!-- SAF-TRACE: claims=SAF-T1306-C011,SAF-T1306-C014; sources=SRC-nvd-cve-2025-10619,SRC-cisa-kev-2026-09-01 --> |

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | High | A usable stolen credential can expose resources within its delegated scope and audience. <!-- SAF-TRACE: claims=SAF-T1306-C018,SAF-T1306-C024; sources=SRC-rfc9700,SRC-mcp-sep-2468,SRC-mcp-authorization-2026-07-28 --> |
| Integrity | High | The attacker can act with permissions carried by the credential when downstream authorization permits writes. <!-- SAF-TRACE: claims=SAF-T1306-C016,SAF-T1306-C018; sources=SRC-mitre-t1528,SRC-rfc9700,SRC-mcp-sep-2468 --> |
| Availability | Low | Disruption is normally a follow-on consequence rather than the defining objective. <!-- SAF-TRACE: claims=SAF-T1306-C018; sources=SRC-rfc9700,SRC-mcp-sep-2468 --> |
| Scope | Multi-System | Client, authorization server, and protected resource can be affected, but token scope, audience, lifetime, and sender constraints limit blast radius. <!-- SAF-TRACE: claims=SAF-T1306-C018,SAF-T1306-C024; sources=SRC-rfc9700,SRC-mcp-sep-2468,SRC-mcp-authorization-2026-07-28 --> |

### Severity Conditions

- **Severity increases when**: tokens have broad scopes, long lifetimes, weak audience restriction, no sender constraint, and access to high-value resources. <!-- SAF-TRACE: claims=SAF-T1306-C018,SAF-T1306-C024; sources=SRC-rfc9700,SRC-mcp-sep-2468,SRC-mcp-authorization-2026-07-28 -->
- **Severity decreases when**: scopes are minimal, tokens are audience-bound and short-lived, downstream approvals constrain action, and issuer mismatch is rejected before redemption. <!-- SAF-TRACE: claims=SAF-T1306-C004,SAF-T1306-C019,SAF-T1306-C024; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-sep-2468,SRC-rfc9728 -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| MCP client authorization validation | Metadata validation, authorization-response validation, and rejection | timestamp, session_id, resource_uri, expected_issuer, received_issuer, authorization_response_iss_parameter_supported, issuer_match, outcome, error_code, validation_kind, token_endpoint | Preserve a flow-bound expected issuer and emit a fatal event before redemption. <!-- SAF-TRACE: claims=SAF-T1306-C004,SAF-T1306-C008,SAF-T1306-C022; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-sep-2468,SRC-mcp-ts-auth-errors --> |
| Configuration and network audit | Authorization-server metadata change and outbound token-endpoint connection | change actor, prior and new issuer, approval, destination, session_id, timestamp | Correlate changes and unexpected destinations; treat cross-technology AAA guidance only as historical tuning evidence. <!-- SAF-TRACE: claims=SAF-T1306-C015,SAF-T1306-C019,SAF-T1306-C021; sources=SRC-cisco-security-warnings,SRC-cisa-aa25-239a,SRC-mcp-authorization-2026-07-28,SRC-rfc9728 --> |

### Indicators of Compromise (IoCs)

- No durable universal IoC is known; issuer URLs and token endpoints are deployment-specific and attacker-controlled values must not be displayed without sanitization. <!-- SAF-TRACE: claims=SAF-T1306-C008,SAF-T1306-C022; sources=SRC-mcp-ts-auth-errors,SRC-mcp-authorization-2026-07-28 -->

### Behavioral Indicators

- A fatal authorization-response or metadata `issuer_mismatch` event with different expected and received issuer values. <!-- SAF-TRACE: claims=SAF-T1306-C004,SAF-T1306-C008; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-ts-auth-errors -->
- A missing response issuer when issuer support was advertised, followed by a rejected authorization flow. <!-- SAF-TRACE: claims=SAF-T1306-C004,SAF-T1306-C022; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-sep-2468 -->
- An unexpected authorization-server baseline change correlated with an outbound token-endpoint connection raises confidence, while an approved migration lowers it. <!-- SAF-TRACE: claims=SAF-T1306-C015,SAF-T1306-C019,SAF-T1306-C021; sources=SRC-cisco-security-warnings,SRC-cisa-aa25-239a,SRC-mcp-authorization-2026-07-28,SRC-rfc9728 -->

### Detection Analytic

The standalone example analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Detect exact issuer mismatch, a derived mismatch flag, or an advertised-but-missing issuer before credential redemption. <!-- SAF-TRACE: claims=SAF-T1306-C004,SAF-T1306-C008,SAF-T1306-C022; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-sep-2468,SRC-mcp-ts-auth-errors -->
- **Rule Status**: Experimental. <!-- SAF-TRACE: claims=SAF-T1306-C022; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-ts-auth-errors -->
- **Detection Logic**: Alert on fatal issuer validation errors, `issuer_match=false`, or required issuer absence; exact string matching is intentional. <!-- SAF-TRACE: claims=SAF-T1306-C004,SAF-T1306-C005,SAF-T1306-C008,SAF-T1306-C022; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-sep-2468,SRC-rfc8414,SRC-rfc9207,SRC-mcp-ts-auth-errors -->
- **Correlation Window**: One authorization session from protected-resource metadata resolution through code redemption. <!-- SAF-TRACE: claims=SAF-T1306-C003,SAF-T1306-C004; sources=SRC-mcp-sep-2468,SRC-mcp-authorization-2026-07-28,SRC-rfc9700 -->
- **Known False Positives**: Approved authorization-server migration with stale local state can produce a benign mismatch but must still be rejected until the expected issuer is refreshed authentically. <!-- SAF-TRACE: claims=SAF-T1306-C021; sources=SRC-rfc9728 -->
- **Known Limitations**: The analytic misses poisoned expected-issuer baselines, environments without normalized issuer fields, and legacy responses where support is neither advertised nor returned. <!-- SAF-TRACE: claims=SAF-T1306-C022; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-ts-auth-errors -->
- **Tuning Guidance**: Normalize issuer strings without changing their value, retain approved issuer history, correlate resource and token endpoint, and suppress only verified maintenance windows. <!-- SAF-TRACE: claims=SAF-T1306-C005,SAF-T1306-C015,SAF-T1306-C019,SAF-T1306-C021; sources=SRC-rfc8414,SRC-rfc9207,SRC-cisco-security-warnings,SRC-cisa-aa25-239a,SRC-mcp-authorization-2026-07-28,SRC-rfc9728 -->

### Validation

- **Test Data**: [test-logs.json](../../tests/SAF-T1306/test-logs.json)
- **Validation Script**: [test_detection_rule.py](../../tests/SAF-T1306/test_detection_rule.py)
- **Expected Result**: Nine synthetic cases pass, including five alerts, four negatives, and one documented maintenance false positive. <!-- SAF-TRACE: claims=SAF-T1306-C021,SAF-T1306-C022; sources=SRC-rfc9728,SRC-mcp-authorization-2026-07-28,SRC-mcp-ts-auth-errors -->
- **Last Validated**: [2026-09-01 result](../../research/techniques/SAF-T1306/validation/detection-test.txt)
- **Feasibility Waiver**: [None; strict quality review](../../research/techniques/SAF-T1306/quality-review.yml)

## Mitigation Strategies

### Preventive Controls

1. **[SAF-M-13: OAuth Flow Verification](../../mitigations/SAF-M-13/README.md)**: Store an authentic expected issuer per authorization session, require exact response matching, and reject before code redemption. <!-- SAF-TRACE: claims=SAF-T1306-C004,SAF-T1306-C005,SAF-T1306-C019; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-sep-2468,SRC-rfc8414,SRC-rfc9207 -->
2. **[SAF-M-14: Server Allowlisting](../../mitigations/SAF-M-14/README.md)**: Authenticate discovery metadata and allow only approved authorization servers for each protected resource. <!-- SAF-TRACE: claims=SAF-T1306-C002,SAF-T1306-C019; sources=SRC-rfc9728,SRC-mcp-authorization-2026-07-28 -->
3. **Least Privilege and Audience Binding**: Request minimal scopes and enforce audience-bound tokens to reduce consequences without treating these controls as issuer-binding substitutes. <!-- SAF-TRACE: claims=SAF-T1306-C024; sources=SRC-mcp-authorization-2026-07-28 -->

### Detective Controls

1. **[SAF-M-18: OAuth Flow Monitoring](../../mitigations/SAF-M-18/README.md)**: Emit and retain flow-correlated issuer validation, configuration change, and token-endpoint events. <!-- SAF-TRACE: claims=SAF-T1306-C008,SAF-T1306-C015,SAF-T1306-C022; sources=SRC-mcp-ts-auth-errors,SRC-cisco-security-warnings,SRC-cisa-aa25-239a,SRC-mcp-authorization-2026-07-28 -->
2. **Approved-Issuer Drift Review**: Alert on unexpected baseline changes and distinguish authenticated migrations from unapproved issuer changes. <!-- SAF-TRACE: claims=SAF-T1306-C015,SAF-T1306-C019,SAF-T1306-C021; sources=SRC-cisco-security-warnings,SRC-cisa-aa25-239a,SRC-mcp-authorization-2026-07-28,SRC-rfc9728 -->

### Response Procedures

#### Immediate Actions

- Abort the authorization flow and prevent code or token delivery to the mismatched endpoint. <!-- SAF-TRACE: claims=SAF-T1306-C004,SAF-T1306-C020; sources=SRC-mcp-authorization-2026-07-28,SRC-rfc9207,SRC-mcp-ts-auth-errors -->
- If telemetry shows credential exposure, revoke or rotate the affected credential and constrain the associated session. <!-- SAF-TRACE: claims=SAF-T1306-C018,SAF-T1306-C020; sources=SRC-rfc9700,SRC-mcp-sep-2468,SRC-rfc9207,SRC-mcp-ts-auth-errors -->

#### Investigation Steps

- Preserve discovery metadata, expected and received issuer values, redirects, validation outcomes, and token-endpoint connections under a shared session identifier. <!-- SAF-TRACE: claims=SAF-T1306-C008,SAF-T1306-C015,SAF-T1306-C020,SAF-T1306-C022; sources=SRC-mcp-ts-auth-errors,SRC-cisco-security-warnings,SRC-cisa-aa25-239a,SRC-rfc9207,SRC-mcp-authorization-2026-07-28 -->
- Determine whether the expected baseline was poisoned, whether any code reached an untrusted endpoint, and which scopes and audience were exposed. <!-- SAF-TRACE: claims=SAF-T1306-C018,SAF-T1306-C019,SAF-T1306-C020,SAF-T1306-C024; sources=SRC-rfc9700,SRC-mcp-sep-2468,SRC-mcp-authorization-2026-07-28,SRC-rfc9728,SRC-rfc9207,SRC-mcp-ts-auth-errors -->

#### Remediation

- Restore an authenticated issuer baseline, remove unapproved authorization servers, and enforce exact issuer validation before retrying. <!-- SAF-TRACE: claims=SAF-T1306-C004,SAF-T1306-C005,SAF-T1306-C019; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-sep-2468,SRC-rfc8414,SRC-rfc9207,SRC-rfc9728 -->
- Add regression coverage for exact mismatch, required issuer absence, legacy compatibility, and approved migration handling. <!-- SAF-TRACE: claims=SAF-T1306-C004,SAF-T1306-C021,SAF-T1306-C022; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-sep-2468,SRC-rfc9728,SRC-mcp-ts-auth-errors -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1507: Authorization Code Interception](../SAF-T1507/README.md) | Alternative | Interception captures a code in transit; this technique makes the client deliver it to a rogue server through issuer confusion. <!-- SAF-TRACE: claims=SAF-T1306-C023; sources=SRC-rfc9700,SRC-mcp-sep-2468 --> |
| [SAF-T1304: Credential Relay Chain](../SAF-T1304/README.md) | Follow-On or Alternative | Credential relay accepts delegated authority across an unintended hop or resource; this technique discloses a credential during authorization-server selection or redemption. <!-- SAF-TRACE: claims=SAF-T1306-C023,SAF-T1306-C024; sources=SRC-rfc9700,SRC-mcp-sep-2468,SRC-mcp-authorization-2026-07-28 --> |
| [SAF-T1406: Metadata Manipulation](../SAF-T1406/README.md) | Possible Prerequisite | Metadata manipulation can deliver a rogue candidate, but this technique requires the separate issuer-association failure and credential disclosure. <!-- SAF-TRACE: claims=SAF-T1306-C002,SAF-T1306-C023; sources=SRC-rfc9728,SRC-rfc9700,SRC-mcp-sep-2468 --> |

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1528](https://attack.mitre.org/techniques/T1528/) | Steal Application Access Token | Direct | The immediate objective is theft of an application access token or precursor code, although ATT&CK assigns a different tactic and does not specify MCP issuer mix-up. <!-- SAF-TRACE: claims=SAF-T1306-C016; sources=SRC-mitre-t1528 --> |
| [T1556](https://attack.mitre.org/techniques/T1556/) | Modify Authentication Process | Analogous | Both subvert authentication trust, but a rogue server does not require modification of a local authentication process. <!-- SAF-TRACE: claims=SAF-T1306-C017; sources=SRC-attack-t1556 --> |

## References

1. **SRC-mcp-authorization-2026-07-28**: [Model Context Protocol Authorization Specification, 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) — Model Context Protocol contributors; roles, discovery, issuer validation, scopes, and audience.
2. **SRC-mcp-sep-2468**: [Recommend Issuer Claim for Auth](https://modelcontextprotocol.io/seps/2468-recommend-issuer-claim-for-auth) — Emily Lauber; MCP mix-up rationale and exact issuer validation, with working-group acknowledgments in the source.
3. **SRC-mcp-release-2026-07-28**: [July 2026 MCP Specification Update](https://blog.modelcontextprotocol.io/posts/2026-07-28/) — Model Context Protocol project team; protocol-hole closure.
4. **SRC-rfc9700**: [Best Current Practice for OAuth 2.0 Security](https://datatracker.ietf.org/doc/html/rfc9700) — Torsten Lodderstedt, John Bradley, Andrey Labunets, and Daniel Fett; mix-up prerequisites and mitigation.
5. **SRC-rfc9207**: [OAuth 2.0 Authorization Server Issuer Identification](https://datatracker.ietf.org/doc/rfc9207/) — Kristina Meyer zu Selhausen and Daniel Fett; response issuer validation.
6. **SRC-rfc8414**: [OAuth 2.0 Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414) — Michael B. Jones, Yaron Sheffer, and Dick Hardt; issuer metadata.
7. **SRC-rfc9728**: [OAuth 2.0 Protected Resource Metadata](https://datatracker.ietf.org/doc/html/rfc9728) — Michael B. Jones, Phil Hunt, and Aaron Parecki; authorization-server discovery and trust boundary.
8. **SRC-mcp-ts-auth-errors**: [TypeScript SDK Authentication Errors API](https://ts.sdk.modelcontextprotocol.io/v2/api/@modelcontextprotocol/client/client/authErrors.html) — MCP TypeScript SDK maintainers; mismatch telemetry.
9. **SRC-fett-oauth-analysis**: [A Comprehensive Formal Security Analysis of OAuth 2.0](https://arxiv.org/pdf/1601.01229) — Daniel Fett, Ralf Küsters, and Guido Schmitz; formal and implementation mix-up demonstration.
10. **SRC-nvd-cve-2025-10619**: [CVE-2025-10619](https://nvd.nist.gov/vuln/detail/CVE-2025-10619) — VulDB CNA, NIST NVD, and CISA ADP; adjacent discovery command injection.
11. **SRC-nvd-cve-2025-4143**: [CVE-2025-4143](https://nvd.nist.gov/vuln/detail/CVE-2025-4143) — Cloudflare CNA, NIST NVD, and CISA ADP; adjacent redirect validation weakness.
12. **SRC-cisa-kev-2026-09-01**: [Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — CISA Vulnerability Management; dated exploitation-catalog check.
13. **SRC-cisa-aa25-239a**: [Countering Chinese State-Sponsored Actors Compromise of Networks Worldwide](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a) — NSA, CISA, FBI, DC3, and international partners; actor-controlled TACACS+ infrastructure and detection.
14. **SRC-cisco-security-warnings**: [Cisco Resilient Infrastructure Security Warnings Reference](https://www.cisco.com/c/dam/en_us/about/doing_business/trust-center/docs/cisco-resilient-infrastructure-security-warnings-reference.pdf) — Cisco Trust Center; authorization-server address-change monitoring.
15. **SRC-mitre-t1528**: [Steal Application Access Token](https://attack.mitre.org/techniques/T1528/) — MITRE ATT&CK and named contributors; token-theft mapping.
16. **SRC-attack-t1556**: [Modify Authentication Process](https://attack.mitre.org/techniques/T1556/) — MITRE ATT&CK and Chris Ross; analogous mapping.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 0.1 | 2026-09-01 | Initial clean-room research draft | Unattributed; project technique author not established from allowed inputs |
| 0.2 | 2026-09-02 | Deprecated as a compatibility ID after consolidation into SAF-T1009 under SAF-TAX-013; retained the original evidence and attribution record. | The SAF-MCP Authors |
