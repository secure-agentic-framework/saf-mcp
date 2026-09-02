# SAF-T1308: Token Scope Substitution

## Overview

- **Tactic**: Privilege Escalation (ATK-TA0004)
- **Technique ID**: SAF-T1308
- **Research Packet**: [research/techniques/SAF-T1308](../../research/techniques/SAF-T1308/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1308/traceability-ledger.yml)
- **Documentation Status**: Draft
- **Evidence Status**: Research-Derived
- **Severity**: High
- **Severity Rationale**: A successful substitution can authorize protected MCP tools or data under a token context the resource owner did not grant, with impact bounded by the accepted audience, scopes, and reachable backends. <!-- SAF-TRACE: claims=SAF-T1308-C017; sources=SRC-cve-2026-14541,SRC-rfc9700 -->
- **First Observed**: No qualifying production MCP incident was identified in the direct-authority corpus reviewed through 2026-09-01. <!-- SAF-TRACE: claims=SAF-T1308-C011; sources=SRC-nvd-token-scope-corpus,SRC-microsoft-storm-0558 -->
- **Last Updated**: 2026-09-01

## Scope

Token Scope Substitution is the use of a valid token, authorization code, or refresh grant under an audience, resource, or operation-scope context that was not bound to the original authorization. It crosses the grant-to-token or token-to-resource authorization boundary when an authorization server widens the resource, a resource server accepts the wrong audience, or authorization logic treats an audience value as a permission scope. <!-- SAF-TRACE: claims=SAF-T1308-C004,SAF-T1308-C006; sources=SRC-rfc8707,SRC-cve-2026-14541,SRC-ghsa-p2fr-6hmx-4528,SRC-oxdc-adv-2026-0003 -->

### In Scope

- Replacing or widening the authorized resource during code or refresh-token redemption so a token is minted for a resource outside the original grant. <!-- SAF-TRACE: claims=SAF-T1308-C004,SAF-T1308-C008; sources=SRC-rfc8707,SRC-ghsa-p2fr-6hmx-4528 -->
- Presenting a token issued for another audience, or a token whose audience is misread as scope, and obtaining an allowed decision for a protected MCP operation. <!-- SAF-TRACE: claims=SAF-T1308-C006,SAF-T1308-C007,SAF-T1308-C009; sources=SRC-cve-2026-14541,SRC-oxdc-adv-2026-0003 -->

### Out of Scope

- Theft, leakage, or replay of a token that remains within its valid audience and granted permissions; those behaviors concern token acquisition or reuse rather than substitution of authorization context. <!-- SAF-TRACE: claims=SAF-T1308-C018; sources=SRC-mcp-security-2025-11-25,SRC-mitre-t1550-001 -->
- Token passthrough, where an MCP server forwards a client token to a downstream API; it may co-occur but crosses a separate server-to-downstream boundary. <!-- SAF-TRACE: claims=SAF-T1308-C018; sources=SRC-mcp-security-2025-11-25 -->
- Legitimately issued but unnecessarily broad scopes, token forgery, authorization-code theft, or post-escalation tool abuse. <!-- SAF-TRACE: claims=SAF-T1308-C018; sources=SRC-mcp-security-2025-11-25,SRC-microsoft-storm-0558 -->

### Distinguishing Characteristics

The decisive observable is disagreement among the original grant, token audience or effective scope, the MCP server's canonical resource identifier, and the permission required by the attempted operation, followed by issuance or an allow decision. A stolen broad token with consistent bindings is a neighboring behavior; a valid token accepted after a binding changes or is reinterpreted is this technique. <!-- SAF-TRACE: claims=SAF-T1308-C006,SAF-T1308-C012,SAF-T1308-C018; sources=SRC-rfc8707,SRC-rfc9068,SRC-mcp-security-2025-11-25 -->

## Description

MCP's HTTP authorization profile requires clients to identify the target MCP resource in both authorization and token requests, and requires MCP servers to accept only tokens intended for themselves. OAuth resource indicators distinguish where a token is usable from scope, which describes what access is requested. <!-- SAF-TRACE: claims=SAF-T1308-C001,SAF-T1308-C002,SAF-T1308-C004; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc8707 -->

An adversary exploits a broken binding or semantic substitution rather than breaking the token signature. The token can be valid for its issuer yet unauthorized for the target resource or operation. The privilege gain occurs when issuance or resource-server authorization uses the substituted context and permits access beyond the original grant. <!-- SAF-TRACE: claims=SAF-T1308-C005,SAF-T1308-C006; sources=SRC-rfc9068,SRC-cve-2026-14541,SRC-ghsa-p2fr-6hmx-4528 -->

Public records directly establish several vulnerable components, including an MCP toolbox audience-validation failure, but no reviewed source documents a production MCP compromise using the complete behavior. The end-to-end technique is therefore classified as Research-Derived, not Observed or Demonstrated. <!-- SAF-TRACE: claims=SAF-T1308-C007,SAF-T1308-C011,SAF-T1308-C016; sources=SRC-cve-2026-14541,SRC-nvd-token-scope-corpus -->

## Attack Vectors

- **Primary Vector**: A client supplies an otherwise valid bearer token, token request, or refresh request whose resource or scope context differs from the authorization originally granted. <!-- SAF-TRACE: claims=SAF-T1308-C006,SAF-T1308-C008; sources=SRC-rfc8707,SRC-ghsa-p2fr-6hmx-4528 -->
- **Secondary Vectors**: <!-- SAF-TRACE: claims=SAF-T1308-C007,SAF-T1308-C009; sources=SRC-cve-2026-14541,SRC-oxdc-adv-2026-0003 -->
  - An MCP resource server accepts an opaque or JWT token without checking that the intended audience matches the server. <!-- SAF-TRACE: claims=SAF-T1308-C002,SAF-T1308-C007; sources=SRC-mcp-authorization-2025-11-25,SRC-cve-2026-14541 -->
  - Authorization middleware falls back from a missing scope claim to a different claim, or accepts only part of a required scope set. <!-- SAF-TRACE: claims=SAF-T1308-C009,SAF-T1308-C021; sources=SRC-oxdc-adv-2026-0003,SRC-nvd-token-scope-corpus -->
- **Affected Components**: MCP clients, authorization servers, MCP resource servers, OAuth validation middleware, protected tools, and connected data backends. <!-- SAF-TRACE: claims=SAF-T1308-C001,SAF-T1308-C006,SAF-T1308-C007; sources=SRC-mcp-authorization-2025-11-25,SRC-cve-2026-14541 -->
- **Trust Boundary Crossed**: Authorization grant to token issuance, or token validation to the protected MCP operation. <!-- SAF-TRACE: claims=SAF-T1308-C004,SAF-T1308-C006; sources=SRC-rfc8707,SRC-rfc9068 -->

## Technical Details

### Prerequisites

- The adversary can obtain a valid token, complete an OAuth flow as a registered client, or redeem an authorization code or refresh token. <!-- SAF-TRACE: claims=SAF-T1308-C006,SAF-T1308-C008; sources=SRC-ghsa-p2fr-6hmx-4528 -->
- The authorization or resource server fails to preserve the grant's resource set, validate the expected audience, or enforce the complete required scope set. <!-- SAF-TRACE: claims=SAF-T1308-C002,SAF-T1308-C007,SAF-T1308-C008,SAF-T1308-C009; sources=SRC-mcp-authorization-2025-11-25,SRC-cve-2026-14541,SRC-ghsa-p2fr-6hmx-4528,SRC-oxdc-adv-2026-0003 -->
- The substituted context reaches a protected operation whose permissions exceed those actually granted for that token. <!-- SAF-TRACE: claims=SAF-T1308-C006,SAF-T1308-C017; sources=SRC-rfc9700,SRC-ghsa-p2fr-6hmx-4528 -->

### Attack Flow

1. **Setup**: The adversary identifies two accepted resource or scope contexts under a shared issuer or vulnerable authorization path. <!-- SAF-TRACE: claims=SAF-T1308-C006,SAF-T1308-C008; sources=SRC-rfc8707,SRC-ghsa-p2fr-6hmx-4528 -->
2. **Acquire a Valid Grant or Token**: The adversary obtains a legitimate low-privilege token, code, or refresh token without altering its signature. <!-- SAF-TRACE: claims=SAF-T1308-C006,SAF-T1308-C008; sources=SRC-ghsa-p2fr-6hmx-4528,SRC-rfc9068 -->
3. **Substitute Context**: The adversary changes the requested resource during redemption, presents the token to another audience, or relies on scope fallback. <!-- SAF-TRACE: claims=SAF-T1308-C007,SAF-T1308-C008,SAF-T1308-C009; sources=SRC-cve-2026-14541,SRC-ghsa-p2fr-6hmx-4528,SRC-oxdc-adv-2026-0003 -->
4. **Boundary Crossing**: The vulnerable component issues the widened token or returns an allow decision despite a resource or permission mismatch. <!-- SAF-TRACE: claims=SAF-T1308-C006,SAF-T1308-C021; sources=SRC-cve-2026-14541,SRC-ghsa-p2fr-6hmx-4528,SRC-oxdc-adv-2026-0003 -->
5. **Objective**: The adversary invokes a protected tool or reads or changes data outside the original authorization. <!-- SAF-TRACE: claims=SAF-T1308-C007,SAF-T1308-C017; sources=SRC-cve-2026-14541,SRC-rfc9700 -->
6. **Follow-On Activity**: Any later collection, exfiltration, or destructive tool use is a separate follow-on behavior whose feasibility depends on the newly reachable operation. <!-- SAF-TRACE: claims=SAF-T1308-C017,SAF-T1308-C018; sources=SRC-cve-2026-14541,SRC-mcp-security-2025-11-25 -->

### Example Scenario

In this inert scenario, a client authorized only for `https://mcp.example.test/read` redeems a refresh grant while requesting `https://mcp.example.test/admin`; a vulnerable authorization server issues the token instead of rejecting or narrowing the resource, and the MCP server records an allow decision for an administrative tool. <!-- SAF-TRACE: claims=SAF-T1308-C004,SAF-T1308-C006,SAF-T1308-C008; sources=SRC-rfc8707,SRC-ghsa-p2fr-6hmx-4528 -->

```json
{
  "grant_resource": "https://mcp.example.test/read",
  "requested_resource": "https://mcp.example.test/admin",
  "operation": "demo.admin.noop",
  "authorization_decision": "allow"
}
```

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1308-C006 | Broken grant, audience, or scope binding can let a valid token authorize a context outside its original grant. | Research-Derived | SRC-rfc8707, SRC-rfc9068, SRC-cve-2026-14541, SRC-ghsa-p2fr-6hmx-4528, SRC-oxdc-adv-2026-0003 | This is an explicit synthesis across specifications and disclosed vulnerabilities, not a reviewed production MCP incident. <!-- SAF-TRACE: claims=SAF-T1308-C006; sources=SRC-rfc8707,SRC-rfc9068,SRC-cve-2026-14541,SRC-ghsa-p2fr-6hmx-4528,SRC-oxdc-adv-2026-0003 --> |
| SAF-T1308-C007 | Google mcp-toolbox 1.4.0 could accept unrelated Google OAuth access tokens when audience configuration was absent. | Research-Derived | SRC-cve-2026-14541: [Google CNA CVE record](https://cveawg.mitre.org/api/cve/CVE-2026-14541) | The record reports no exploitation and does not name a fixed release. <!-- SAF-TRACE: claims=SAF-T1308-C007; sources=SRC-cve-2026-14541 --> |
| SAF-T1308-C008 | Better Auth allowed a token or refresh request to select an allow-listed resource outside the original grant. | Research-Derived | SRC-ghsa-p2fr-6hmx-4528: [Maintainer advisory](https://github.com/better-auth/better-auth/security/advisories/GHSA-p2fr-6hmx-4528) | The advisory is a disclosed vulnerability, not evidence of production exploitation. <!-- SAF-TRACE: claims=SAF-T1308-C008; sources=SRC-ghsa-p2fr-6hmx-4528 --> |
| SAF-T1308-C009 | OX Dovecot could use `aud` as a fallback for missing `scope`, accepting a token without relevant permissions. | Research-Derived | SRC-oxdc-adv-2026-0003: [Open-Xchange advisory](https://documentation.open-xchange.com/dovecot/security/advisories/html/2026/oxdc-adv-2026-0003.html) | This is a non-MCP product vulnerability and no public exploit was known. <!-- SAF-TRACE: claims=SAF-T1308-C009; sources=SRC-oxdc-adv-2026-0003 --> |
| SAF-T1308-C011 | No qualifying direct production MCP incident was found in the reviewed direct-authority corpus. | Research-Derived | SRC-nvd-token-scope-corpus, SRC-microsoft-storm-0558 | This is a bounded search conclusion through 2026-09-01, not a claim that no incident has ever occurred. <!-- SAF-TRACE: claims=SAF-T1308-C011; sources=SRC-nvd-token-scope-corpus,SRC-microsoft-storm-0558 --> |

### Current State

- **Affected Environments**: HTTP MCP or agentic systems that rely on OAuth authorization servers or token-validation middleware and fail to bind resource and scope through issuance and enforcement. <!-- SAF-TRACE: claims=SAF-T1308-C001,SAF-T1308-C006; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc8707 -->
- **Known Exploitation**: No qualifying direct production MCP incident was identified; CISA's 2026-09-01 KEV catalog did not list the selected CVEs, which does not establish absence of exploitation. <!-- SAF-TRACE: claims=SAF-T1308-C011,SAF-T1308-C020; sources=SRC-cisa-kev-2026-09-01,SRC-nvd-token-scope-corpus -->
- **Available Protections**: Bind resource indicators to the authorization grant, validate token type, issuer, audience, expiry, signature, and operation scopes, and reject context mismatches. <!-- SAF-TRACE: claims=SAF-T1308-C005,SAF-T1308-C014; sources=SRC-rfc8707,SRC-rfc9068,SRC-mcp-authorization-2025-11-25 -->
- **Residual Risk**: Opaque-token deployments or intermediaries that do not expose normalized validation decisions can remain difficult to detect, and legitimate audience aliases can create false positives without canonicalization. <!-- SAF-TRACE: claims=SAF-T1308-C013; sources=SRC-rfc9068,SRC-mcp-authorization-2025-11-25 -->

### Known Breaches and Vulnerabilities

The reviewed corpus contains one direct MCP vulnerability and two closely related authorization vulnerabilities, but no direct production MCP breach; the production incident below is retained only as a non-MCP historical analogy. <!-- SAF-TRACE: claims=SAF-T1308-C007,SAF-T1308-C008,SAF-T1308-C009,SAF-T1308-C010,SAF-T1308-C011; sources=SRC-cve-2026-14541,SRC-ghsa-p2fr-6hmx-4528,SRC-oxdc-adv-2026-0003,SRC-microsoft-storm-0558 -->

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| CVE-2026-14541 | Published 2026-07-31; Google mcp-toolbox 1.4.0 with MCP enabled and no explicit audience or client ID | Unrelated Google OAuth tokens could reach protected tools and data; the CVE points to a patch but does not identify a fixed release. | **Direct vulnerability**: the MCP server skipped audience validation. | Google CNA and CISA record no exploitation; the public record is not a production incident. <!-- SAF-TRACE: claims=SAF-T1308-C007; sources=SRC-cve-2026-14541 --> |
| CVE-2026-67332 / GHSA-p2fr-6hmx-4528 | Published 2026-05-31; `@better-auth/oauth-provider` 1.4.8 through versions before 1.7.0-beta.4 | A client could obtain a token for an allow-listed resource outside the grant; fixed in 1.7.0-beta.4 and 1.7.0, while 1.6.x remained unpatched in the advisory. | **Enabling vulnerability**: authorization-server resource widening can supply the substituted token to an MCP deployment. | No production exploitation is documented; reachable actions remain limited by independently checked scopes. <!-- SAF-TRACE: claims=SAF-T1308-C008; sources=SRC-ghsa-p2fr-6hmx-4528 --> |
| CVE-2026-73208 / OXDC-ADV-2026-0003 | Published 2026-08-28; affected OX Dovecot Pro and CE version ranges | Missing `scope` could fall back to `aud`, permitting access without relevant permissions; fixed in Pro 2.3.22.2, 3.0.7, 3.1.6 and CE 2.4.5. | **Historical analogy**: it directly demonstrates audience-to-scope semantic substitution outside MCP. | Open-Xchange reported no publicly available exploit and no MCP environment. <!-- SAF-TRACE: claims=SAF-T1308-C009; sources=SRC-oxdc-adv-2026-0003 --> |
| Storm-0558 Exchange Online intrusion | Activity began 2023-05-15; Microsoft public cloud | Forged tokens enabled email access at about 25 organizations; Microsoft corrected the validation issue, restricted token renewal, blocked the key, and replaced signing keys. | **Historical analogy**: an observed token-validation boundary failure, not Token Scope Substitution. | The actor forged tokens and abused a separate renewal design flaw; the incident was neither MCP nor a valid-token scope substitution. <!-- SAF-TRACE: claims=SAF-T1308-C010; sources=SRC-microsoft-storm-0558 --> |

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | High | A mismatched token can expose protected tools or backends when the accepted privilege context authorizes read access. <!-- SAF-TRACE: claims=SAF-T1308-C007,SAF-T1308-C009,SAF-T1308-C017; sources=SRC-cve-2026-14541,SRC-oxdc-adv-2026-0003 --> |
| Integrity | High | The same boundary failure can authorize state-changing operations when substituted scopes or audiences carry write-capable privileges. <!-- SAF-TRACE: claims=SAF-T1308-C007,SAF-T1308-C009,SAF-T1308-C017; sources=SRC-cve-2026-14541,SRC-oxdc-adv-2026-0003 --> |
| Availability | Low | Availability impact is not inherent; it requires a newly reachable operation capable of disrupting service. <!-- SAF-TRACE: claims=SAF-T1308-C017; sources=SRC-cve-2026-14541,SRC-rfc9700 --> |
| Scope | Multi-System | Cross-resource acceptance can extend across services sharing an issuer or authorization server, while strict audience and scope validation confines the blast radius. <!-- SAF-TRACE: claims=SAF-T1308-C004,SAF-T1308-C017; sources=SRC-rfc8707,SRC-rfc9700 --> |

### Severity Conditions

- **Severity increases when** multiple high-value MCP resources share an issuer, operations depend on broad or ambiguous scopes, or the target accepts opaque tokens without audience validation. <!-- SAF-TRACE: claims=SAF-T1308-C007,SAF-T1308-C013,SAF-T1308-C017; sources=SRC-cve-2026-14541,SRC-rfc8707 -->
- **Severity decreases when** authorization grants bind a single resource, servers canonicalize and validate their audience, and each operation enforces the minimum required scopes. <!-- SAF-TRACE: claims=SAF-T1308-C014,SAF-T1308-C015; sources=SRC-rfc8707,SRC-rfc9700,SRC-mcp-security-2025-11-25 -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| Authorization server | Authorization, code redemption, refresh redemption, token issuance | Timestamp, grant ID, client ID, requested resource, originally authorized resources, effective scope, token ID | Preserve whether the requested resource was equal to or a subset of the original grant. <!-- SAF-TRACE: claims=SAF-T1308-C004,SAF-T1308-C012; sources=SRC-rfc8707 --> |
| MCP resource server or gateway | Token validation and protected-operation authorization | Timestamp, session or correlation ID, issuer, token type, token ID, presented audience, expected audience, effective scopes, required scopes, decision, operation | Log normalized validation results without recording the bearer token itself. <!-- SAF-TRACE: claims=SAF-T1308-C002,SAF-T1308-C005,SAF-T1308-C012; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc9068,SRC-mcp-security-2025-11-25 --> |

### Indicators of Compromise (IoCs)

- No durable static indicator is inherent; token values are sensitive and should not be copied into detection content. <!-- SAF-TRACE: claims=SAF-T1308-C013; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc9068 -->

### Behavioral Indicators

- A successful token-issuance event where the requested resource is not within the resources recorded on the grant. <!-- SAF-TRACE: claims=SAF-T1308-C008,SAF-T1308-C012; sources=SRC-ghsa-p2fr-6hmx-4528,SRC-rfc8707 -->
- An allow decision where the presented audience does not canonicalize to the MCP server's expected resource identifier. <!-- SAF-TRACE: claims=SAF-T1308-C002,SAF-T1308-C007,SAF-T1308-C012; sources=SRC-mcp-authorization-2025-11-25,SRC-cve-2026-14541 -->
- An allowed protected operation when the token's effective scope does not satisfy the operation's complete required scope set. <!-- SAF-TRACE: claims=SAF-T1308-C009,SAF-T1308-C012,SAF-T1308-C021; sources=SRC-oxdc-adv-2026-0003,SRC-nvd-token-scope-corpus -->

### Detection Analytic

The standalone analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Detect successful issuance or authorization despite a grant-resource, audience, or required-scope mismatch. <!-- SAF-TRACE: claims=SAF-T1308-C012; sources=SRC-rfc8707,SRC-rfc9068 -->
- **Rule Status**: Experimental. <!-- SAF-TRACE: claims=SAF-T1308-C013; sources=SRC-rfc9068 -->
- **Detection Logic**: Match an allow or issuance decision when the normalized resource-binding, audience-match, or scope-satisfaction result is false. <!-- SAF-TRACE: claims=SAF-T1308-C012,SAF-T1308-C021; sources=SRC-rfc8707,SRC-rfc9068,SRC-nvd-token-scope-corpus -->
- **Correlation Window**: Evaluate each authorization decision atomically; use the grant or token identifier only to enrich related events. <!-- SAF-TRACE: claims=SAF-T1308-C012; sources=SRC-rfc8707,SRC-rfc9068 -->
- **Known False Positives**: Unnormalized aliases, migration periods, or stale resource metadata can make equivalent audiences appear different. <!-- SAF-TRACE: claims=SAF-T1308-C013; sources=SRC-rfc8707,SRC-mcp-authorization-2025-11-25 -->
- **Known Limitations**: The analytic is blind when token-validation output, original grant resources, or operation-required scopes are not logged; opaque tokens require equivalent introspection or validator results. <!-- SAF-TRACE: claims=SAF-T1308-C013; sources=SRC-rfc9068,SRC-mcp-authorization-2025-11-25 -->
- **Tuning Guidance**: Canonicalize resource URIs, maintain narrowly reviewed audience aliases, and compare complete scope sets rather than individual scope membership. <!-- SAF-TRACE: claims=SAF-T1308-C004,SAF-T1308-C009,SAF-T1308-C013; sources=SRC-rfc8707,SRC-oxdc-adv-2026-0003 -->

### Validation

- **Test Data**: [test-logs.json](../../tests/SAF-T1308/test-logs.json)
- **Validation Script**: [test_detection_rule.py](../../tests/SAF-T1308/test_detection_rule.py)
- **Expected Result**: The [test data](../../tests/SAF-T1308/test-logs.json) defines eight deterministic cases covering three positives, a normal negative, a denied mismatch, a missing-field boundary, an expected alias false positive, and a scope-set boundary.
- **Last Validated**: 2026-09-01 via the recorded [quality review](../../research/techniques/SAF-T1308/quality-review.yml).
- **Feasibility Waiver**: None; the passing status is recorded in the [quality review](../../research/techniques/SAF-T1308/quality-review.yml).

## Mitigation Strategies

### Preventive Controls

1. **[SAF-M-13: OAuth Flow Verification](../../mitigations/SAF-M-13/README.md)**: Validate token type, issuer, signature, expiry, expected audience, and effective permissions before processing every protected MCP request. <!-- SAF-TRACE: claims=SAF-T1308-C002,SAF-T1308-C005,SAF-T1308-C014; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc9068 -->
2. **[SAF-M-16: Token Scope Limiting](../../mitigations/SAF-M-16/README.md)**: Bind requested resources to the authorization grant, permit only narrowing during code or refresh redemption, and issue only the scopes needed by the target resource. <!-- SAF-TRACE: claims=SAF-T1308-C004,SAF-T1308-C014,SAF-T1308-C015; sources=SRC-rfc8707,SRC-rfc9700,SRC-mcp-security-2025-11-25 -->
3. **Fail Closed on Missing Claims**: Reject missing or ambiguous audience and scope information instead of substituting one claim for another. <!-- SAF-TRACE: claims=SAF-T1308-C005,SAF-T1308-C009,SAF-T1308-C014; sources=SRC-rfc9068,SRC-oxdc-adv-2026-0003 -->

### Detective Controls

1. **[SAF-M-13: OAuth Flow Verification](../../mitigations/SAF-M-13/README.md)**: Emit structured validation outcomes for audience, issuer, token type, and scope, including the final allow or deny decision. <!-- SAF-TRACE: claims=SAF-T1308-C012,SAF-T1308-C014; sources=SRC-rfc9068,SRC-mcp-authorization-2025-11-25 -->
2. **[SAF-M-16: Token Scope Limiting](../../mitigations/SAF-M-16/README.md)**: Log scope elevation requests, granted subsets, and correlation identifiers so defenders can reconstruct changes in privilege context. <!-- SAF-TRACE: claims=SAF-T1308-C015; sources=SRC-mcp-security-2025-11-25 -->

### Response Procedures

#### Immediate Actions

- Reject the mismatched request with the protocol-appropriate invalid-token or insufficient-scope response and contain the affected client session. <!-- SAF-TRACE: claims=SAF-T1308-C003,SAF-T1308-C014; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc9068 -->
- Identify other uses of the same token or grant identifier and revoke exposed credentials when misuse is confirmed. <!-- SAF-TRACE: claims=SAF-T1308-C012,SAF-T1308-C014; sources=SRC-mcp-authorization-2025-11-25 -->

#### Investigation Steps

- Compare the original authorization resources and scopes with token issuance, validation, and protected-operation decisions for the same correlation chain. <!-- SAF-TRACE: claims=SAF-T1308-C004,SAF-T1308-C012; sources=SRC-rfc8707,SRC-mcp-security-2025-11-25 -->
- Determine whether the defect is grant widening, audience nonvalidation, scope fallback, or partial-scope enforcement before assigning this technique. <!-- SAF-TRACE: claims=SAF-T1308-C007,SAF-T1308-C008,SAF-T1308-C009,SAF-T1308-C021; sources=SRC-cve-2026-14541,SRC-ghsa-p2fr-6hmx-4528,SRC-oxdc-adv-2026-0003,SRC-nvd-token-scope-corpus -->

#### Remediation

- Correct the binding or validation defect, update affected products to a non-vulnerable release where one is documented, and retest missing, mismatched, and multi-scope cases. <!-- SAF-TRACE: claims=SAF-T1308-C007,SAF-T1308-C008,SAF-T1308-C009,SAF-T1308-C014; sources=SRC-cve-2026-14541,SRC-ghsa-p2fr-6hmx-4528,SRC-oxdc-adv-2026-0003 -->
- Preserve regression coverage for the exact grant, audience, and scope boundary that failed. <!-- SAF-TRACE: claims=SAF-T1308-C012,SAF-T1308-C022; sources=SRC-rfc8707,SRC-rfc9068 -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1202: OAuth Token Persistence](../SAF-T1202/README.md) | Prerequisite or alternative | Acquires or reuses a token within its valid context; Token Scope Substitution changes or misinterprets the authorization context. <!-- SAF-TRACE: claims=SAF-T1308-C018; sources=SRC-mitre-t1550-001 --> |
| [SAF-T1304: Credential Relay Chain](../SAF-T1304/README.md) | Co-occurring | Propagates a credential across a downstream authorization boundary; substitution can occur without forwarding. <!-- SAF-TRACE: claims=SAF-T1308-C018; sources=SRC-mcp-security-2025-11-25 --> |
| [SAF-T1009: Authorization Server Mix-up](../SAF-T1009/README.md) | Overlapping | Uses attacker-controlled authorization infrastructure and issuer misbinding; substitution authorizes a resource or operation outside the binding actually granted. <!-- SAF-TRACE: claims=SAF-T1308-C018; sources=SRC-mcp-security-2025-11-25 --> |

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1550.001](https://attack.mitre.org/techniques/T1550/001/) | Use Alternate Authentication Material: Application Access Token | Analogous | Both concern application tokens used to access protected services, but ATT&CK emphasizes stolen tokens while this technique can begin with a legitimately obtained token accepted under an unauthorized resource or scope context. <!-- SAF-TRACE: claims=SAF-T1308-C019; sources=SRC-mitre-t1550-001 --> |

## References

1. **SRC-mcp-authorization-2025-11-25**: [MCP Authorization specification, 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) — Model Context Protocol contributors; resource parameters, token handling, scope errors, and audience validation.
2. **SRC-mcp-security-2025-11-25**: [MCP Security Best Practices, 2025-11-25](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices) — Model Context Protocol contributors; token passthrough, scope minimization, and logging guidance.
3. **SRC-rfc8707**: [RFC 8707: Resource Indicators for OAuth 2.0](https://www.rfc-editor.org/rfc/rfc8707.html) — Brian Campbell, John Bradley, and Hannes Tschofenig; grant-resource binding and downscoping.
4. **SRC-rfc9068**: [RFC 9068: JWT Profile for OAuth 2.0 Access Tokens](https://www.rfc-editor.org/rfc/rfc9068.html) — Vittorio Bertocci; token typing, audience, scope, and validation requirements.
5. **SRC-rfc9700**: [RFC 9700: Best Current Practice for OAuth 2.0 Security](https://www.rfc-editor.org/rfc/rfc9700.html) — Torsten Lodderstedt, John Bradley, Andrey Labunets, and Daniel Fett; token privilege restriction.
6. **SRC-cve-2026-14541**: [CVE-2026-14541](https://cveawg.mitre.org/api/cve/CVE-2026-14541) — Google CNA; finder credit to HE WEI (ギカク).
7. **SRC-ghsa-p2fr-6hmx-4528**: [GHSA-p2fr-6hmx-4528](https://github.com/better-auth/better-auth/security/advisories/GHSA-p2fr-6hmx-4528) — published by gustavovalverde; reported and fixed by dvanmali; exact URL discovered through the non-GitHub CVE record.
8. **SRC-oxdc-adv-2026-0003**: [OXDC-ADV-2026-0003](https://documentation.open-xchange.com/dovecot/security/advisories/html/2026/oxdc-adv-2026-0003.html) — Open-Xchange GmbH Security Team.
9. **SRC-microsoft-storm-0558**: [Analysis of Storm-0558 techniques for unauthorized email access](https://www.microsoft.com/en-us/security/blog/2023/07/14/analysis-of-storm-0558-techniques-for-unauthorized-email-access/) — Microsoft Threat Intelligence.
10. **SRC-mitre-t1550-001**: [ATT&CK T1550.001: Application Access Token](https://attack.mitre.org/techniques/T1550/001/) — MITRE ATT&CK contributors, version 2.0.
11. **SRC-cisa-kev-2026-09-01**: [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) — CISA, catalog version 2026.09.01.
12. **SRC-nvd-token-scope-corpus**: [NVD CVE API](https://services.nvd.nist.gov/rest/json/cves/2.0) — NVD team; direct-authority query corpus and saturation results reviewed 2026-09-01.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 0.1 | 2026-09-01 | Independent clean-room draft with current vulnerability, incident, detection, and rights research | OpenAI Codex (`cleanroom_saf_t1308`) |
