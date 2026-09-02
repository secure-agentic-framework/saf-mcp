# SAF-T1408: OAuth Protocol Downgrade

## Overview

- **Tactic**: Defense Evasion (ATK-TA0005)
- **Technique ID**: SAF-T1408
- **Research Packet**: [research/techniques/SAF-T1408](../../research/techniques/SAF-T1408/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1408/traceability-ledger.yml)
- **Documentation Status**: Stable
- **Evidence Status**: Research-Derived
- **Severity**: High
- **Severity Rationale**: High applies when an exposed MCP authorization flow accepts weaker PKCE and the resulting code or token reaches sensitive resources; fail-closed handling or absent attacker influence lowers the risk. [better-auth advisory](https://github.com/better-auth/better-auth/security/advisories/GHSA-9h47-pqcx-hjr4) <!-- SAF-TRACE: claims=SAF-T1408-C017; sources=SRC-ghsa-9h47-pqcx-hjr4,SRC-rfc9700 -->
- **First Observed**: Not observed in a qualifying production MCP incident in the authority corpus reviewed through 2026-09-01. [CISA KEV catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) <!-- SAF-TRACE: claims=SAF-T1408-C011; sources=SRC-cisa-kev-2026-09-01,SRC-nvd-2026-67336 -->
- **Last Updated**: 2026-09-01

## Scope

OAuth Protocol Downgrade covers attacker-influenced weakening of PKCE from S256 to plain or from PKCE to no challenge during an HTTP-based MCP authorization flow, when the client or authorization server accepts that weaker state and defeats the intended code binding. [MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) [OAuth Security BCP](https://www.rfc-editor.org/rfc/rfc9700.html#name-pkce-downgrade-attack) <!-- SAF-TRACE: claims=SAF-T1408-C006; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc9700,SRC-ghsa-9h47-pqcx-hjr4 -->

### In Scope

- Removal of `code_challenge` or fallback from `S256` to `plain` before a vulnerable authorization decision. [OAuth Security BCP](https://www.rfc-editor.org/rfc/rfc9700.html#name-pkce-downgrade-attack) <!-- SAF-TRACE: claims=SAF-T1408-C002,SAF-T1408-C003; sources=SRC-rfc7636,SRC-rfc9700 -->
- Acceptance or redemption of an authorization code after the MCP OAuth protection state has been weakened. [MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) <!-- SAF-TRACE: claims=SAF-T1408-C001,SAF-T1408-C006; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc9700 -->

### Out of Scope

- Authorization-server mix-up changes the issuer or credential destination rather than weakening PKCE. [OAuth Security BCP, Section 4.4](https://www.rfc-editor.org/rfc/rfc9700.html#name-mix-up-attacks) <!-- SAF-TRACE: claims=SAF-T1408-C016; sources=SRC-rfc9700 -->
- OAuth metadata SSRF and unsafe authorization URLs change destinations or execute unsafe URL handling rather than changing the accepted protection method. [MCP Security Best Practices](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices) <!-- SAF-TRACE: claims=SAF-T1408-C016; sources=SRC-mcp-security-2025-11-25 -->
- Token theft, replay, or passthrough without attacker-influenced PKCE weakening is a different immediate mechanism. [MITRE ATT&CK T1528](https://attack.mitre.org/techniques/T1528/) <!-- SAF-TRACE: claims=SAF-T1408-C018; sources=SRC-mitre-t1528 -->

### Distinguishing Characteristics

The distinguishing observable is a weaker PKCE state inside the intended OAuth flow: `plain`, a missing method that is treated as plain, or a token exchange whose original request lacked a challenge. Endpoint substitution, malicious URL schemes, and post-issuance token use remain neighboring behavior. [RFC 7636, Section 7.2](https://www.rfc-editor.org/rfc/rfc7636.html#section-7.2) [OAuth Security BCP, Section 4.8.2](https://www.rfc-editor.org/rfc/rfc9700.html#name-countermeasures-7) <!-- SAF-TRACE: claims=SAF-T1408-C002,SAF-T1408-C004,SAF-T1408-C016; sources=SRC-rfc7636,SRC-rfc9700,SRC-mcp-security-2025-11-25 -->

## Description

MCP authorization uses OAuth for HTTP transports. The current specification requires clients to implement PKCE, verify support before authorization, refuse when the capability metadata is absent, and use S256 when technically capable. [MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414.html#section-2) <!-- SAF-TRACE: claims=SAF-T1408-C001,SAF-T1408-C005; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc8414 -->

An adversary seeks a flow that accepts less protection than the client intended. RFC 7636 prohibits falling back to `plain` after trying S256, while RFC 9700 describes challenge removal against a server that treats PKCE as optional; weak or absent state validation then permits code injection into the victim's client session. [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html#section-7.2) [OAuth Security BCP](https://www.rfc-editor.org/rfc/rfc9700.html#name-pkce-downgrade-attack) <!-- SAF-TRACE: claims=SAF-T1408-C002,SAF-T1408-C003; sources=SRC-rfc7636,SRC-rfc9700 -->

The MCP-specific end-to-end behavior is an inference, not a reported breach: the OAuth mechanism is standardized, and CVE-2026-67336 documents an MCP plugin that advertised S256 while accepting plain and silently rewriting a missing method to plain, but no reviewed source documents all attack stages in a production MCP environment. [better-auth advisory](https://github.com/better-auth/better-auth/security/advisories/GHSA-9h47-pqcx-hjr4) <!-- SAF-TRACE: claims=SAF-T1408-C006,SAF-T1408-C007,SAF-T1408-C011; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc9700,SRC-ghsa-9h47-pqcx-hjr4,SRC-cisa-kev-2026-09-01,SRC-nvd-2026-67336 -->

## Attack Vectors

- **Primary Vector**: Attacker-controlled or attacker-modified authorization initiation causes the authorization server to accept `plain` or no PKCE challenge. [OAuth Security BCP](https://www.rfc-editor.org/rfc/rfc9700.html#name-attack-description-7) <!-- SAF-TRACE: claims=SAF-T1408-C003,SAF-T1408-C012; sources=SRC-rfc9700,SRC-rfc7636 -->
- **Secondary Vectors**: A missing method silently interpreted as plain, or retry logic that changes S256 after failure. [better-auth advisory](https://github.com/better-auth/better-auth/security/advisories/GHSA-9h47-pqcx-hjr4) [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html#section-7.2) <!-- SAF-TRACE: claims=SAF-T1408-C002,SAF-T1408-C007; sources=SRC-ghsa-9h47-pqcx-hjr4,SRC-rfc7636 -->
- **Affected Components**: MCP client, user-agent redirect path, OAuth authorization server, and the authorization integration protecting the MCP server. [MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) <!-- SAF-TRACE: claims=SAF-T1408-C001,SAF-T1408-C006; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc9700 -->
- **Trust Boundary Crossed**: The binding between the initiating MCP OAuth client flow and the authorization code accepted at token exchange. [OAuth Security BCP](https://www.rfc-editor.org/rfc/rfc9700.html#name-pkce-downgrade-attack) <!-- SAF-TRACE: claims=SAF-T1408-C003,SAF-T1408-C006; sources=SRC-rfc9700,SRC-mcp-authorization-2025-11-25 -->

## Technical Details

### Prerequisites

- The attacker can influence an authorization request, induce a victim to follow an attacker-controlled initiation, or observe a plain challenge. [authentik advisory](https://github.com/goauthentik/authentik/security/advisories/GHSA-mrx3-gxjx-hjqj) [better-auth advisory](https://github.com/better-auth/better-auth/security/advisories/GHSA-9h47-pqcx-hjr4) <!-- SAF-TRACE: claims=SAF-T1408-C009,SAF-T1408-C012; sources=SRC-ghsa-mrx3-gxjx-hjqj,SRC-ghsa-9h47-pqcx-hjr4 -->
- The authorization server or client accepts `plain`, missing PKCE, or a missing method instead of failing closed. [OAuth Security BCP](https://www.rfc-editor.org/rfc/rfc9700.html#name-pkce-downgrade-attack) <!-- SAF-TRACE: claims=SAF-T1408-C003,SAF-T1408-C007; sources=SRC-rfc9700,SRC-ghsa-9h47-pqcx-hjr4 -->
- For the RFC 9700 injection variant, state is unused or checked incorrectly; the Spring example additionally requires a confidential client. [OAuth Security BCP](https://www.rfc-editor.org/rfc/rfc9700.html#name-pkce-downgrade-attack) [Spring advisory](https://spring.io/security/cve-2024-22258/) <!-- SAF-TRACE: claims=SAF-T1408-C003,SAF-T1408-C010; sources=SRC-rfc9700,SRC-spring-cve-2024-22258 -->

### Attack Flow

1. **Setup**: The attacker initiates or alters an OAuth request associated with an MCP authorization path. [OAuth Security BCP](https://www.rfc-editor.org/rfc/rfc9700.html#name-attack-description-7) <!-- SAF-TRACE: claims=SAF-T1408-C003,SAF-T1408-C006; sources=SRC-rfc9700,SRC-mcp-authorization-2025-11-25 -->
2. **Weakening**: The request removes `code_challenge`, selects `plain`, or omits a method that a vulnerable implementation rewrites to plain. [better-auth advisory](https://github.com/better-auth/better-auth/security/advisories/GHSA-9h47-pqcx-hjr4) <!-- SAF-TRACE: claims=SAF-T1408-C003,SAF-T1408-C007; sources=SRC-rfc9700,SRC-ghsa-9h47-pqcx-hjr4 -->
3. **Acceptance**: The authorization server processes the flow without the S256 binding that the client or metadata indicated. [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html#section-7.2) <!-- SAF-TRACE: claims=SAF-T1408-C002,SAF-T1408-C005; sources=SRC-rfc7636,SRC-rfc8414,SRC-mcp-authorization-2025-11-25 -->
4. **Boundary Crossing**: A code or token exchange succeeds despite the weakened or inconsistent PKCE state. [OAuth Security BCP](https://www.rfc-editor.org/rfc/rfc9700.html#name-countermeasures-7) <!-- SAF-TRACE: claims=SAF-T1408-C004,SAF-T1408-C006; sources=SRC-rfc9700,SRC-ghsa-9h47-pqcx-hjr4 -->
5. **Objective**: Depending on the variant, the attacker can inject an attacker-bound authorization result into the victim's session or use an observed plain verifier to intercept a code. [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html#section-7.2) [OAuth Security BCP](https://www.rfc-editor.org/rfc/rfc9700.html#name-pkce-downgrade-attack) <!-- SAF-TRACE: claims=SAF-T1408-C003,SAF-T1408-C012; sources=SRC-rfc7636,SRC-rfc9700,SRC-ghsa-9h47-pqcx-hjr4 -->
6. **Follow-On Activity**: Any later resource access depends on the scopes and audience of the resulting token and is outside the defining downgrade mechanism. [MITRE ATT&CK T1528](https://attack.mitre.org/techniques/T1528/) <!-- SAF-TRACE: claims=SAF-T1408-C012,SAF-T1408-C018; sources=SRC-mitre-t1528,SRC-ghsa-9h47-pqcx-hjr4 -->

### Example Scenario

An inert synthetic MCP client `client.example` first attempts S256, receives a failure, and then records a successful authorization for the same session with a missing method that the server treats as plain. The analytic alerts on the transition; it does not reproduce a verifier, code, token, phishing link, or interception procedure. [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html#section-7.2) [detector cases](../../tests/SAF-T1408/test-cases.json) <!-- SAF-TRACE: claims=SAF-T1408-C002,SAF-T1408-C013; sources=SRC-rfc7636,SRC-ghsa-9h47-pqcx-hjr4 -->

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1408-C001 | Current MCP requires PKCE verification and fail-closed handling. | Research-Derived | SRC-mcp-authorization-2025-11-25: [MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) | Deployment behavior is not established. |
| SAF-T1408-C002 | S256 must not fall back to plain; plain exposes the verifier in the challenge. | Demonstrated | SRC-rfc7636: [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html#section-7.2) | OAuth-wide, not MCP incident evidence. |
| SAF-T1408-C003 | RFC 9700 describes challenge-removal PKCE downgrade and code injection. | Demonstrated | SRC-rfc9700: [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html#name-pkce-downgrade-attack) | Not an MCP-specific evaluation. |
| SAF-T1408-C004 | Verifier-without-prior-challenge must be rejected and is detectable through correlation. | Research-Derived | SRC-rfc9700: [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html#name-countermeasures-7) | No standardized log schema. |
| SAF-T1408-C005 | RFC 8414 metadata omission means no PKCE; MCP requires refusal. | Research-Derived | SRC-rfc8414 and SRC-mcp-authorization-2025-11-25: [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414.html#section-2) | Runtime can contradict metadata. |
| SAF-T1408-C006 | The bounded MCP end-to-end technique follows from protocol, attack, and component evidence. | Research-Derived | SRC-mcp-authorization-2025-11-25, SRC-rfc9700, SRC-ghsa-9h47-pqcx-hjr4 | Explicit inference; no production MCP incident. |
| SAF-T1408-C007 | better-auth's legacy MCP plugin accepted plain and missing-method fallback before 1.6.11. | Research-Derived | SRC-cve-2026-67336 and SRC-ghsa-9h47-pqcx-hjr4: [advisory](https://github.com/better-auth/better-auth/security/advisories/GHSA-9h47-pqcx-hjr4) | No production exploitation documented. |
| SAF-T1408-C008 | 1.6.11 fixed secure defaults; CISA SSVC reported no exploitation. | Research-Derived | SRC-ghsa-9h47-pqcx-hjr4 and SRC-nvd-2026-67336: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-67336) | Status is time-bounded. |
| SAF-T1408-C009 | authentik allowed challenge-removal downgrade before fixed 2023.8.7 and 2023.10.7. | Research-Derived | SRC-cve-2024-23647 and SRC-ghsa-mrx3-gxjx-hjqj: [advisory](https://github.com/goauthentik/authentik/security/advisories/GHSA-mrx3-gxjx-hjqj) | No MCP deployment established. |
| SAF-T1408-C010 | Spring Authorization Server downgrade affected specified confidential-client versions only. | Research-Derived | SRC-cve-2024-22258 and SRC-spring-cve-2024-22258: [Spring advisory](https://spring.io/security/cve-2024-22258/) | Public clients were unaffected; not MCP-specific. |
| SAF-T1408-C011 | No qualifying production incident was found; selected CVEs were absent from dated KEV. | Research-Derived | SRC-cisa-kev-2026-09-01 and SRC-nvd-2026-67336: [CISA KEV](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) | Bounded reviewed-corpus conclusion. |
| SAF-T1408-C012 | Confidentiality or integrity impact requires request influence or plain exposure plus weak acceptance. | Research-Derived | SRC-rfc7636, SRC-rfc9700, SRC-ghsa-9h47-pqcx-hjr4 | No availability impact established. |
| SAF-T1408-C013 | Three correlated downgrade states support a testable analytic. | Research-Derived | SRC-rfc9700, SRC-rfc7636, SRC-ghsa-9h47-pqcx-hjr4 | Ten-minute window is an analytic choice. |
| SAF-T1408-C014 | Approved legacy plain behavior is a lookalike; missing fields are a blind spot. | Research-Derived | SRC-rfc7636 and SRC-ghsa-9h47-pqcx-hjr4 | Allowlists require local governance. |
| SAF-T1408-C015 | Fail-closed support checks, S256, and server-side binding prevent the mechanism. | Research-Derived | SRC-mcp-authorization-2025-11-25, SRC-rfc7636, SRC-rfc9700 | Other OAuth attacks remain possible. |
| SAF-T1408-C016 | Issuer mix-up and metadata URL abuse are distinct neighboring mechanisms. | Research-Derived | SRC-rfc9700 and SRC-mcp-security-2025-11-25 | Canonical SAF neighbor IDs are post-freeze repository-alignment joins. |
| SAF-T1408-C017 | High severity is conditional on weak acceptance and sensitive reach. | Research-Derived | SRC-ghsa-9h47-pqcx-hjr4 and SRC-rfc9700 | Not uniform across deployments. |
| SAF-T1408-C018 | ATT&CK T1528 is analogous; CWE-757 directly describes downgrade weakness. | Research-Derived | SRC-mitre-t1528 and SRC-cwe-757 | ATT&CK mapping is downstream, not mechanistic. |

### Current State

- **Affected Environments**: HTTP-based MCP deployments whose client or authorization server can accept plain, absent, or inconsistently recorded PKCE state; CVE-2026-67336 directly names a legacy MCP plugin before 1.6.11. [CVE List](https://cveawg.mitre.org/api/cve/CVE-2026-67336) <!-- SAF-TRACE: claims=SAF-T1408-C001,SAF-T1408-C007; sources=SRC-mcp-authorization-2025-11-25,SRC-cve-2026-67336,SRC-ghsa-9h47-pqcx-hjr4 -->
- **Known Exploitation**: No qualifying production MCP incident was identified; NVD recorded no exploitation for CVE-2026-67336 and none of the selected CVEs appeared in CISA KEV version 2026.09.01. [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-67336) [CISA KEV](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) <!-- SAF-TRACE: claims=SAF-T1408-C008,SAF-T1408-C011; sources=SRC-nvd-2026-67336,SRC-cisa-kev-2026-09-01 -->
- **Available Protections**: Verify PKCE support, refuse missing capability metadata, keep S256, bind challenge state through exchange, and reject inconsistent verifier/challenge records. [MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) [OAuth Security BCP](https://www.rfc-editor.org/rfc/rfc9700.html#name-countermeasures-7) <!-- SAF-TRACE: claims=SAF-T1408-C004,SAF-T1408-C005,SAF-T1408-C015; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc8414,SRC-rfc9700,SRC-rfc7636 -->
- **Residual Risk**: Discovery metadata can claim S256 while runtime accepts weaker input, so metadata verification without runtime enforcement remains insufficient. [better-auth advisory](https://github.com/better-auth/better-auth/security/advisories/GHSA-9h47-pqcx-hjr4) <!-- SAF-TRACE: claims=SAF-T1408-C005,SAF-T1408-C007; sources=SRC-ghsa-9h47-pqcx-hjr4,SRC-mcp-authorization-2025-11-25,SRC-rfc8414 -->

### Known Breaches and Vulnerabilities

No direct production breach qualified; the table retains one direct MCP-plugin vulnerability and two enabling authorization-server vulnerabilities, without using the latter to raise the technique's evidence status. [CISA KEV](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) <!-- SAF-TRACE: claims=SAF-T1408-C006,SAF-T1408-C011; sources=SRC-cisa-kev-2026-09-01,SRC-nvd-2026-67336,SRC-ghsa-9h47-pqcx-hjr4 -->

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| CVE-2026-67336 / GHSA-9h47-pqcx-hjr4 | Published 2026-05-31; better-auth legacy `oidcProvider` and `mcp` plugins before 1.6.11 | Plain or missing-method fallback could expose codes when the URL was observable; upgrade to 1.6.11 or migrate to the replacement provider. | Direct vulnerability; reported by subhanUmer and published by gustavovalverde for the better-auth team. | No production exploitation documented; CISA SSVC reported none. <!-- SAF-TRACE: claims=SAF-T1408-C007,SAF-T1408-C008; sources=SRC-cve-2026-67336,SRC-ghsa-9h47-pqcx-hjr4,SRC-nvd-2026-67336 --> |
| CVE-2024-23647 / GHSA-mrx3-gxjx-hjqj | Published 2024-01-29; authentik before 2023.8.7 and in the 2023.10 line before 2023.10.7 | Challenge removal bypassed PKCE; fixed in 2023.8.7 and 2023.10.7. | Enabling vulnerability; BeryJu published the maintainer advisory and credited Pieter Philippaerts. | No MCP deployment or production exploitation documented. <!-- SAF-TRACE: claims=SAF-T1408-C009; sources=SRC-cve-2024-23647,SRC-ghsa-mrx3-gxjx-hjqj --> |
| CVE-2024-22258 | Published 2024-03-19; specified Spring Authorization Server releases with confidential clients | PKCE downgrade affected confidential clients; fixed in 1.0.6, 1.1.6, and 1.2.3. | Enabling vulnerability; the Spring Security Team credited Pieter Philippaerts. | Public clients were explicitly unaffected, and no MCP deployment or production exploitation was documented. <!-- SAF-TRACE: claims=SAF-T1408-C010; sources=SRC-cve-2024-22258,SRC-spring-cve-2024-22258 --> |

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | High | An observed plain challenge can expose the verifier and enable code interception when the implementation accepts the weaker state. <!-- SAF-TRACE: claims=SAF-T1408-C012,SAF-T1408-C017; sources=SRC-rfc7636,SRC-ghsa-9h47-pqcx-hjr4 --> |
| Integrity | High | The RFC 9700 variant can associate an attacker-bound authorization result with the victim's client session when state protection is absent or faulty. <!-- SAF-TRACE: claims=SAF-T1408-C003,SAF-T1408-C017; sources=SRC-rfc9700,SRC-ghsa-9h47-pqcx-hjr4 --> |
| Availability | None established | The reviewed downgrade evidence does not establish an availability consequence. <!-- SAF-TRACE: claims=SAF-T1408-C012; sources=SRC-rfc7636,SRC-rfc9700,SRC-ghsa-9h47-pqcx-hjr4 --> |
| Scope | Adjacent | Immediate impact is bounded by the code's token audience and scopes; later token use is downstream activity. <!-- SAF-TRACE: claims=SAF-T1408-C012,SAF-T1408-C018; sources=SRC-ghsa-9h47-pqcx-hjr4,SRC-mitre-t1528 --> |

### Severity Conditions

- **Severity increases when**: Authorization requests are observable or attacker-influenced, weak modes succeed, and issued tokens reach sensitive resources. [better-auth advisory](https://github.com/better-auth/better-auth/security/advisories/GHSA-9h47-pqcx-hjr4) <!-- SAF-TRACE: claims=SAF-T1408-C012,SAF-T1408-C017; sources=SRC-ghsa-9h47-pqcx-hjr4,SRC-rfc9700 -->
- **Severity decreases when**: The client and authorization server fail closed on missing support, plain, missing methods, or inconsistent verifier/challenge state. [MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) <!-- SAF-TRACE: claims=SAF-T1408-C004,SAF-T1408-C015,SAF-T1408-C017; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc9700,SRC-rfc7636 -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| MCP client or authorization-server audit log | Authorization initiation, rejection, retry, and acceptance | Timestamp, client, session or transaction, MCP scope, challenge presence, method, outcome | Preserve normalized and raw method values for at least the correlation interval. <!-- SAF-TRACE: claims=SAF-T1408-C013,SAF-T1408-C014; sources=SRC-rfc7636,SRC-rfc9700,SRC-ghsa-9h47-pqcx-hjr4 --> |
| OAuth token endpoint log | Code exchange and token outcome | Transaction, code-verifier presence, original challenge presence, method, outcome, approved legacy-policy state | Join to the initiating authorization record; absent join fields are a blind spot. <!-- SAF-TRACE: claims=SAF-T1408-C004,SAF-T1408-C013,SAF-T1408-C014; sources=SRC-rfc9700,SRC-ghsa-9h47-pqcx-hjr4 --> |

### Indicators of Compromise (IoCs)

- No validated durable artifact uniquely identifies this behavior; detection depends on correlated OAuth flow state. [OAuth Security BCP](https://www.rfc-editor.org/rfc/rfc9700.html#name-countermeasures-7) <!-- SAF-TRACE: claims=SAF-T1408-C004,SAF-T1408-C013; sources=SRC-rfc9700,SRC-rfc7636 -->

### Behavioral Indicators

- A successful MCP authorization request uses `plain` or supplies a challenge without a method, outside an approved legacy exception. [better-auth advisory](https://github.com/better-auth/better-auth/security/advisories/GHSA-9h47-pqcx-hjr4) <!-- SAF-TRACE: claims=SAF-T1408-C007,SAF-T1408-C013,SAF-T1408-C014; sources=SRC-ghsa-9h47-pqcx-hjr4,SRC-rfc7636 -->
- A token request supplies a verifier although the corresponding authorization record has no challenge. [OAuth Security BCP](https://www.rfc-editor.org/rfc/rfc9700.html#name-countermeasures-7) <!-- SAF-TRACE: claims=SAF-T1408-C004,SAF-T1408-C013; sources=SRC-rfc9700 -->
- The same MCP client and session move from failed S256 to successful plain or missing method within ten minutes. [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html#section-7.2) <!-- SAF-TRACE: claims=SAF-T1408-C002,SAF-T1408-C013; sources=SRC-rfc7636,SRC-ghsa-9h47-pqcx-hjr4 -->

### Detection Analytic

The standalone experimental analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Identify successful weaker PKCE state or a rapid S256-to-weaker transition in MCP-scoped authorization telemetry. [OAuth Security BCP](https://www.rfc-editor.org/rfc/rfc9700.html#name-countermeasures-7) <!-- SAF-TRACE: claims=SAF-T1408-C013; sources=SRC-rfc9700,SRC-rfc7636,SRC-ghsa-9h47-pqcx-hjr4 -->
- **Rule Status**: Experimental; validated against the isolated synthetic corpus and integrated repository. [quality review](../../research/techniques/SAF-T1408/quality-review.yml)
- **Detection Logic**: Alert on successful MCP plain or missing-method authorization, verifier-without-challenge exchange, or failed S256 followed by weaker success for the same client and session. [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html#section-7.2) <!-- SAF-TRACE: claims=SAF-T1408-C004,SAF-T1408-C013; sources=SRC-rfc7636,SRC-rfc9700,SRC-ghsa-9h47-pqcx-hjr4 -->
- **Correlation Window**: Ten minutes, inclusive; the boundary is a documented analytic choice. [detector cases](../../tests/SAF-T1408/test-cases.json) <!-- SAF-TRACE: claims=SAF-T1408-C013; sources=SRC-rfc9700,SRC-rfc7636 -->
- **Known False Positives**: Explicitly approved legacy clients may intentionally use plain and must be suppressed only through a narrow approval flag. [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html#section-7.2) <!-- SAF-TRACE: claims=SAF-T1408-C014; sources=SRC-rfc7636,SRC-ghsa-9h47-pqcx-hjr4 -->
- **Known Limitations**: Missing flow joins, unlogged raw values, out-of-band exchanges, or a downgrade that fails before the logged authorization decision can evade the analytic. [OAuth Security BCP](https://www.rfc-editor.org/rfc/rfc9700.html#name-countermeasures-7) <!-- SAF-TRACE: claims=SAF-T1408-C004,SAF-T1408-C013,SAF-T1408-C014; sources=SRC-rfc9700,SRC-ghsa-9h47-pqcx-hjr4 -->
- **Tuning Guidance**: Restrict to known MCP OAuth clients, preserve case-normalized methods, and expire legacy exceptions. [better-auth advisory](https://github.com/better-auth/better-auth/security/advisories/GHSA-9h47-pqcx-hjr4) <!-- SAF-TRACE: claims=SAF-T1408-C013,SAF-T1408-C014; sources=SRC-ghsa-9h47-pqcx-hjr4,SRC-rfc7636 -->

### Validation

- **Test Data**: [test-cases.json](../../tests/SAF-T1408/test-cases.json)
- **Validation Script**: [test_detection_rule.py](../../tests/SAF-T1408/test_detection_rule.py)
- **Expected Result**: Eleven positive, negative, boundary, malformed, normalization, and expected-lookalike cases pass. [quality review](../../research/techniques/SAF-T1408/quality-review.yml)
- **Last Validated**: 2026-09-01. [quality review](../../research/techniques/SAF-T1408/quality-review.yml)
- **Feasibility Waiver**: None. [quality review](../../research/techniques/SAF-T1408/quality-review.yml)

## Mitigation Strategies

### Preventive Controls

1. **Fail closed on capability**: Refuse authorization when PKCE support is absent, and do not infer support from a retry. [MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) <!-- SAF-TRACE: claims=SAF-T1408-C001,SAF-T1408-C005,SAF-T1408-C015; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc8414 -->
2. **Require S256**: Do not fall back to `plain` after an S256 failure; reject plain unless a documented legacy exception is unavoidable. [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html#section-7.2) <!-- SAF-TRACE: claims=SAF-T1408-C002,SAF-T1408-C014,SAF-T1408-C015; sources=SRC-rfc7636,SRC-ghsa-9h47-pqcx-hjr4 -->
3. **Bind transaction state**: Retain challenge presence and method with the code, and reject a verifier when the initiating request lacked a challenge. [OAuth Security BCP](https://www.rfc-editor.org/rfc/rfc9700.html#name-countermeasures-7) <!-- SAF-TRACE: claims=SAF-T1408-C004,SAF-T1408-C015; sources=SRC-rfc9700 -->

### Detective Controls

1. **Correlate authorization and exchange**: Join request and token endpoint events by transaction and client before evaluating method consistency. [OAuth Security BCP](https://www.rfc-editor.org/rfc/rfc9700.html#name-countermeasures-7) <!-- SAF-TRACE: claims=SAF-T1408-C004,SAF-T1408-C013; sources=SRC-rfc9700 -->
2. **Audit runtime against metadata**: Test that S256-only discovery is matched by runtime rejection of plain and missing methods. [better-auth advisory](https://github.com/better-auth/better-auth/security/advisories/GHSA-9h47-pqcx-hjr4) <!-- SAF-TRACE: claims=SAF-T1408-C005,SAF-T1408-C007,SAF-T1408-C015; sources=SRC-ghsa-9h47-pqcx-hjr4,SRC-rfc8414,SRC-mcp-authorization-2025-11-25 -->

### Response Procedures

#### Immediate Actions

- Stop the affected authorization flow, disable plain or missing-method fallback, and revoke tokens issued from inconsistent transactions. [OAuth Security BCP](https://www.rfc-editor.org/rfc/rfc9700.html#name-countermeasures-7) <!-- SAF-TRACE: claims=SAF-T1408-C004,SAF-T1408-C015; sources=SRC-rfc9700,SRC-rfc7636 -->
- Upgrade affected better-auth, authentik, or Spring Authorization Server versions when the corresponding advisory conditions match. [better-auth advisory](https://github.com/better-auth/better-auth/security/advisories/GHSA-9h47-pqcx-hjr4) [authentik advisory](https://github.com/goauthentik/authentik/security/advisories/GHSA-mrx3-gxjx-hjqj) [Spring advisory](https://spring.io/security/cve-2024-22258/) <!-- SAF-TRACE: claims=SAF-T1408-C008,SAF-T1408-C009,SAF-T1408-C010; sources=SRC-ghsa-9h47-pqcx-hjr4,SRC-cve-2024-23647,SRC-ghsa-mrx3-gxjx-hjqj,SRC-cve-2024-22258,SRC-spring-cve-2024-22258 -->

#### Investigation Steps

- Preserve discovery metadata, authorization requests, retries, redirect callbacks, token exchanges, and resource-access logs for the same client and transaction. [OAuth Security BCP](https://www.rfc-editor.org/rfc/rfc9700.html#name-pkce-downgrade-attack) <!-- SAF-TRACE: claims=SAF-T1408-C003,SAF-T1408-C004,SAF-T1408-C013; sources=SRC-rfc9700,SRC-rfc7636 -->
- Determine whether plain was explicitly approved, whether S256 previously failed, and whether issued tokens reached resources within their audience and scopes. [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html#section-7.2) <!-- SAF-TRACE: claims=SAF-T1408-C012,SAF-T1408-C013,SAF-T1408-C014,SAF-T1408-C018; sources=SRC-rfc7636,SRC-ghsa-9h47-pqcx-hjr4,SRC-mitre-t1528 -->

#### Remediation

- Make S256 enforcement and challenge-method binding fail closed, then repeat the synthetic regression cases. [OAuth Security BCP](https://www.rfc-editor.org/rfc/rfc9700.html#name-countermeasures-7) [detector cases](../../tests/SAF-T1408/test-cases.json) <!-- SAF-TRACE: claims=SAF-T1408-C004,SAF-T1408-C015; sources=SRC-rfc9700,SRC-rfc7636 -->
- Remove obsolete legacy exceptions or document their owner, client scope, and expiry while maintaining compensating monitoring. [better-auth advisory](https://github.com/better-auth/better-auth/security/advisories/GHSA-9h47-pqcx-hjr4) <!-- SAF-TRACE: claims=SAF-T1408-C014,SAF-T1408-C015; sources=SRC-ghsa-9h47-pqcx-hjr4,SRC-rfc7636 -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1009: Authorization Server Mix-up](../SAF-T1009/README.md) | Alternative or co-occurring | Changes the issuer or credential endpoint; this technique weakens PKCE inside the selected flow. <!-- SAF-TRACE: claims=SAF-T1408-C016; sources=SRC-rfc9700 --> |

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1528](https://attack.mitre.org/techniques/T1528/) | Steal Application Access Token | Analogous | A successful downgrade can lead to code or token compromise, but T1528 describes the downstream credential objective rather than PKCE negotiation. <!-- SAF-TRACE: claims=SAF-T1408-C018; sources=SRC-mitre-t1528 --> |

### Additional Framework Mappings

| Framework | ID | Name | Rationale |
| --- | --- | --- | --- |
| MITRE CWE | [CWE-757](https://cwe.mitre.org/data/definitions/757.html) | Selection of Less-Secure Algorithm During Negotiation | Direct weakness correspondence because the implementation accepts a weaker available protection mode. <!-- SAF-TRACE: claims=SAF-T1408-C018; sources=SRC-cwe-757 --> |

## References

1. **SRC-mcp-authorization-2025-11-25**: [Model Context Protocol Authorization, 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) — MCP specification team; current PKCE and fail-closed requirements.
2. **SRC-mcp-security-2025-11-25**: [MCP Security Best Practices, 2025-11-25](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices) — MCP security documentation team; neighbor mechanisms.
3. **SRC-rfc9700**: [Best Current Practice for OAuth 2.0 Security](https://www.rfc-editor.org/rfc/rfc9700.html) — Torsten Lodderstedt, John Bradley, Andrey Labunets, and Daniel Fett; downgrade attack and countermeasures.
4. **SRC-rfc7636**: [Proof Key for Code Exchange by OAuth Public Clients](https://www.rfc-editor.org/rfc/rfc7636.html) — Nat Sakimura, John Bradley, and Naveen Agarwal; S256 and plain security properties.
5. **SRC-rfc8414**: [OAuth 2.0 Authorization Server Metadata](https://www.rfc-editor.org/rfc/rfc8414.html) — Michael B. Jones, Nat Sakimura, and John Bradley; PKCE capability metadata.
6. **SRC-cwe-757**: [CWE-757](https://cwe.mitre.org/data/definitions/757.html) — MITRE CWE Team; downgrade weakness mapping.
7. **SRC-mitre-t1528**: [ATT&CK T1528](https://attack.mitre.org/techniques/T1528/) — MITRE ATT&CK Team and source-manifest-listed contributors; analogous token objective.
8. **SRC-cisa-kev-2026-09-01**: [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) — CISA Vulnerability Management team; dated exploitation-catalog check.
9. **SRC-cve-2026-67336**: [CVE-2026-67336 CVE List Record](https://cveawg.mitre.org/api/cve/CVE-2026-67336) — VulnCheck CNA; reporter subhanUmer; affected MCP-plugin range.
10. **SRC-nvd-2026-67336**: [NVD CVE-2026-67336](https://nvd.nist.gov/vuln/detail/CVE-2026-67336) — NVD and CISA Coordinator; dated exploitation status.
11. **SRC-ghsa-9h47-pqcx-hjr4**: [better-auth advisory](https://github.com/better-auth/better-auth/security/advisories/GHSA-9h47-pqcx-hjr4) — published by gustavovalverde; reported by subhanUmer; mechanism and fixes.
12. **SRC-cve-2024-23647**: [CVE-2024-23647 CVE List Record](https://cveawg.mitre.org/api/cve/CVE-2024-23647) — authentik security team; affected versions.
13. **SRC-ghsa-mrx3-gxjx-hjqj**: [authentik advisory](https://github.com/goauthentik/authentik/security/advisories/GHSA-mrx3-gxjx-hjqj) — published by BeryJu; reported by Pieter Philippaerts; challenge-removal downgrade.
14. **SRC-cve-2024-22258**: [CVE-2024-22258 CVE List Record](https://cveawg.mitre.org/api/cve/CVE-2024-22258) — Spring Security Team; confidential-client scope.
15. **SRC-spring-cve-2024-22258**: [Spring CVE-2024-22258 advisory](https://spring.io/security/cve-2024-22258/) — Spring Security Team; reported by Pieter Philippaerts; fixed versions.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 1.0 | 2026-09-01 | Clean-room research-derived technique, evidence packet, and tested analytic. | OpenAI Codex clean-room generator `/root/cleanroom_saf_t1408` |
