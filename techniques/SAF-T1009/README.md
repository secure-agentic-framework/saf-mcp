# SAF-T1009: Authorization Server Mix-up

## Overview

- **Tactic**: Initial Access (ATK-TA0001); Privilege Escalation (ATK-TA0004)
- **Technique ID**: SAF-T1009
- **Research Packet**: [research/techniques/SAF-T1009](../../research/techniques/SAF-T1009/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1009/traceability-ledger.yml)
- **Documentation Status**: Under Review
- **Evidence Status**: Research-Derived
- **Severity**: High
- **Severity Rationale**: A successful mix-up can disclose an authorization code or access token for an honest issuer, with confidentiality and integrity impact bounded by the credential's permissions and the downstream resource controls. [RFC 9207](https://www.rfc-editor.org/rfc/rfc9207.html) <!-- SAF-TRACE: claims=SAF-T1009-C005; sources=SRC-rfc9207 -->
- **First Observed**: Not observed in MCP production in the reviewed corpus; the generic OAuth behavior was demonstrated on concrete clients by Fett, Küsters, and Schmitz in 2016. [Formal OAuth analysis](https://arxiv.org/abs/1601.01229) <!-- SAF-TRACE: claims=SAF-T1009-C012,SAF-T1009-C017; sources=SRC-fett-oauth-analysis,SRC-nvd-oauth-mixup-query -->
- **Last Updated**: 2026-09-02

## Scope

This technique covers an attacker-controlled or compromised authorization server causing a multi-authorization-server MCP client to misattribute a browser-delivered response from an honest issuer and send the resulting code or token to the attacker-controlled server. The crossed boundary is the client's per-request binding among the validated expected issuer, callback, and token endpoint. [MCP authorization security considerations](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations) [OAuth Security BCP](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.4) <!-- SAF-TRACE: claims=SAF-T1009-C003,SAF-T1009-C004; sources=SRC-mcp-auth-security-2026-07-28,SRC-rfc9700 -->

### In Scope

- A client supports two or more authorization servers, at least one controlled or compromised by the attacker. [RFC 9700 §4.4](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.4) <!-- SAF-TRACE: claims=SAF-T1009-C003; sources=SRC-rfc9700 -->
- The client fails to preserve and verify the honest response's issuer before selecting where to send the authorization credential. [MCP Authorization Response Validation](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#authorization-response-validation) <!-- SAF-TRACE: claims=SAF-T1009-C004,SAF-T1009-C006; sources=SRC-mcp-authorization-2026-07-28,SRC-fett-oauth-analysis -->
- The immediate objective is cross-issuer disclosure of an honest authorization code or access token. [RFC 9207 §1](https://www.rfc-editor.org/rfc/rfc9207.html#section-1) <!-- SAF-TRACE: claims=SAF-T1009-C003,SAF-T1009-C005; sources=SRC-rfc9207 -->

### Out of Scope

- Authorization-code injection is follow-on use of an already obtained code; this technique ends at issuer misbinding and credential disclosure. [RFC 9700 §§4.4-4.5](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.4) <!-- SAF-TRACE: claims=SAF-T1009-C003; sources=SRC-rfc9700 -->
- Token audience confusion occurs when a resource accepts a token intended elsewhere, while this technique occurs at the client's response-to-endpoint binding. [RFC 8707 §3](https://www.rfc-editor.org/rfc/rfc8707.html#section-3) <!-- SAF-TRACE: claims=SAF-T1009-C011; sources=SRC-rfc8707 -->
- Malicious discovery endpoints, callback-state confusion, and client-assertion audience injection remain adjacent unless they produce the defining browser-response credential disclosure. [Malicious Endpoints research](https://arxiv.org/abs/1508.04324) <!-- SAF-TRACE: claims=SAF-T1009-C013,SAF-T1009-C014,SAF-T1009-C016; sources=SRC-mainka-oidc-endpoints,SRC-ghsa-authjs-provider-binding,SRC-oidf-private-key-jwt-disclosure -->
- A client that interacts with only one authorization server is outside this technique's prerequisite. [RFC 9207 §4](https://www.rfc-editor.org/rfc/rfc9207.html#section-4) <!-- SAF-TRACE: claims=SAF-T1009-C003; sources=SRC-rfc9207 -->

### Distinguishing Characteristics

The decisive observable is a disagreement between the issuer recorded for a specific authorization request and the issuer associated with its browser-delivered response or token endpoint. A valid token presented to the wrong resource is audience confusion, and a stolen code inserted into another session is code injection; neither requires this cross-issuer callback misbinding. [RFC 9700 §4.4.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.4.2) [MCP response validation](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#authorization-response-validation) <!-- SAF-TRACE: claims=SAF-T1009-C004,SAF-T1009-C006,SAF-T1009-C011; sources=SRC-rfc9700,SRC-mcp-authorization-2026-07-28,SRC-rfc8707 -->

## Description

In MCP authorization over HTTP, the MCP server is an OAuth resource server, the MCP client is an OAuth client, and the authorization server may be separate. Current MCP discovery permits a protected resource to identify multiple independent authorization servers, requiring the client to maintain separate registration and credential state for each. [MCP Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) [MCP Authorization Server Discovery](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/authorization-server-discovery) <!-- SAF-TRACE: claims=SAF-T1009-C001,SAF-T1009-C002; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-auth-discovery-2026-07-28 -->

An attacker controlling one supported authorization server can redirect the authorization journey through an honest server. If the client still associates the callback with the attacker-controlled issuer, it can transmit the honest server's code or token to the attacker's endpoint. This is Research-Derived for MCP: the exact generic OAuth behavior has been demonstrated, and MCP supplies the multi-issuer boundary, but no complete MCP demonstration or production incident was found. [OAuth Security BCP](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.4.1) [Fett, Küsters, and Schmitz](https://arxiv.org/abs/1601.01229) <!-- SAF-TRACE: claims=SAF-T1009-C003,SAF-T1009-C004,SAF-T1009-C012,SAF-T1009-C017; sources=SRC-rfc9700,SRC-fett-oauth-analysis,SRC-nvd-oauth-mixup-query,SRC-arxiv-mcp-mixup-query -->

## Attack Vectors

- **Primary Vector**: A user or automated flow starts with an attacker-controlled authorization server supported by the client, and the browser is redirected through an honest authorization server whose response the client misattributes. [RFC 9700 §4.4.1](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.4.1) <!-- SAF-TRACE: claims=SAF-T1009-C003; sources=SRC-rfc9700 -->
- **Secondary Vector**: A supported authorization server is compromised, or the client's initial issuer selection is altered, producing the same cross-issuer state error. [RFC 9700 §4.4](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.4) <!-- SAF-TRACE: claims=SAF-T1009-C003; sources=SRC-rfc9700 -->
- **Affected Components**: MCP client authorization state, browser callback handler, authorization-server metadata cache, authorization endpoint, and token endpoint. [MCP authorization flow](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#authorization-flow-steps) <!-- SAF-TRACE: claims=SAF-T1009-C001,SAF-T1009-C006; sources=SRC-mcp-authorization-2026-07-28 -->
- **Trust Boundary Crossed**: The binding between a validated issuer and the endpoints and callback assigned to one authorization request. [RFC 9700 §4.4.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.4.2) <!-- SAF-TRACE: claims=SAF-T1009-C004,SAF-T1009-C018; sources=SRC-rfc9700,SRC-rfc9207 -->

## Technical Details

### Prerequisites

- The MCP client can interact with at least two authorization servers. [RFC 9207 §1](https://www.rfc-editor.org/rfc/rfc9207.html#section-1) <!-- SAF-TRACE: claims=SAF-T1009-C002,SAF-T1009-C003; sources=SRC-rfc9207,SRC-mcp-auth-discovery-2026-07-28 -->
- One supported authorization server is attacker-controlled or compromised. [RFC 9700 §4.4](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.4) <!-- SAF-TRACE: claims=SAF-T1009-C003; sources=SRC-rfc9700 -->
- The client does not reliably bind and compare the expected issuer before choosing the token endpoint. [MCP response validation](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#authorization-response-validation) <!-- SAF-TRACE: claims=SAF-T1009-C004,SAF-T1009-C006,SAF-T1009-C008; sources=SRC-mcp-authorization-2026-07-28,SRC-rfc9207 -->

### Attack Flow

1. **Setup**: The attacker operates or compromises an authorization server the multi-server client is willing to use. [RFC 9700 §4.4](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.4) <!-- SAF-TRACE: claims=SAF-T1009-C003; sources=SRC-rfc9700 -->
2. **Initiation**: A flow is recorded as using the attacker-controlled issuer. [Fett, Küsters, and Schmitz §3.2](https://arxiv.org/abs/1601.01229) <!-- SAF-TRACE: claims=SAF-T1009-C003,SAF-T1009-C012; sources=SRC-fett-oauth-analysis -->
3. **Redirection**: The attacker-controlled server sends the browser to an honest authorization endpoint using the client's honest-server registration context. [RFC 9700 §4.4.1](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.4.1) <!-- SAF-TRACE: claims=SAF-T1009-C003; sources=SRC-rfc9700 -->
4. **Honest Response**: The honest server authorizes and returns a code or token through the browser to the client callback. [RFC 9700 §4.4.1](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.4.1) <!-- SAF-TRACE: claims=SAF-T1009-C003; sources=SRC-rfc9700 -->
5. **Misbinding**: The client treats the honest response as belonging to the attacker-controlled issuer because the per-request issuer check is absent or ineffective. [RFC 9207 §§1, 2.4](https://www.rfc-editor.org/rfc/rfc9207.html#section-2.4) <!-- SAF-TRACE: claims=SAF-T1009-C003,SAF-T1009-C008; sources=SRC-rfc9207 -->
6. **Objective**: The client sends the honest code or token to the attacker-controlled endpoint, disclosing the credential and enabling bounded follow-on access. [RFC 9207 §1](https://www.rfc-editor.org/rfc/rfc9207.html#section-1) <!-- SAF-TRACE: claims=SAF-T1009-C005; sources=SRC-rfc9207 -->

### Example Scenario

An MCP client has independently validated `https://honest.as.example` and `https://attacker.as.example`. For flow `flow-042`, it recorded the attacker issuer, but the browser returns an inert placeholder response identifying the honest issuer. A conforming client rejects the mismatch before any token request; an affected client would instead risk sending the honest credential to the attacker endpoint. [MCP Authorization Response Validation](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#authorization-response-validation) <!-- SAF-TRACE: claims=SAF-T1009-C004,SAF-T1009-C006,SAF-T1009-C008; sources=SRC-mcp-authorization-2026-07-28 -->

The following synthetic event contains no redeemable credential and illustrates the defensive decision point. <!-- SAF-TRACE: claims=SAF-T1009-C019,SAF-T1009-C020; sources=SRC-mcp-authorization-2026-07-28 -->

```json
{
  "flow_id": "flow-042",
  "recorded_expected_issuer": "https://attacker.as.example",
  "response_iss": "https://honest.as.example",
  "authorization_response_iss_parameter_supported": true,
  "metadata_validated": true,
  "validation_outcome": "rejected",
  "code": "NON-REDEEMABLE-EXAMPLE"
}
```

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1009-C001 | MCP uses OAuth client, resource-server, and authorization-server roles. | Research-Derived | SRC-mcp-authorization-2026-07-28: [MCP Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) | Roles do not establish exploitation. |
| SAF-T1009-C002 | MCP can advertise multiple independent authorization servers with separate client state. | Research-Derived | SRC-mcp-auth-discovery-2026-07-28: [Discovery](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/authorization-server-discovery); SRC-rfc9728: [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html) | Multiple servers are a prerequisite only. |
| SAF-T1009-C003 | Mix-up requires multiple servers and an attacker-controlled server, and targets an honest code or token. | Research-Derived | SRC-rfc9700: [RFC 9700 §4.4](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.4) | General OAuth, not an MCP incident. |
| SAF-T1009-C004 | The demonstrated OAuth mechanism applies to an MCP client that fails issuer binding. | Research-Derived | SRC-mcp-auth-security-2026-07-28: [MCP security](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations); SRC-fett-oauth-analysis: [formal analysis](https://arxiv.org/abs/1601.01229) | Explicit MCP inference; no MCP reproduction. |
| SAF-T1009-C005 | Credential disclosure can affect confidentiality and integrity. | Demonstrated | SRC-rfc9207: [RFC 9207 §1](https://www.rfc-editor.org/rfc/rfc9207.html#section-1) | Scope depends on credential and controls. |
| SAF-T1009-C006 | MCP binds the validated expected issuer to per-request state and validates before token exchange. | Research-Derived | SRC-mcp-authorization-2026-07-28: [response validation](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#authorization-response-validation) | Requires authentic expected metadata. |
| SAF-T1009-C007 | Authorization-server metadata issuer must exactly match the issuer used for discovery. | Research-Derived | SRC-rfc8414: [RFC 8414 §3.3](https://www.rfc-editor.org/rfc/rfc8414.html#section-3.3) | Does not choose the appropriate issuer. |
| SAF-T1009-C008 | Present mismatch or advertised-but-missing iss must be rejected. | Research-Derived | SRC-mcp-authorization-2026-07-28: [decision table](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#authorization-response-validation) | Legacy non-advertised absence can proceed. |
| SAF-T1009-C009 | Current MCP permits non-advertised issuer absence and anticipates a stricter future revision. | Research-Derived | SRC-mcp-authorization-2026-07-28: [response validation](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#authorization-response-validation) | Compatibility condition is not universal exploitability. |
| SAF-T1009-C010 | RFC 9700 requires a defense and treats distinct redirects as a limited alternative. | Research-Derived | SRC-rfc9700: [RFC 9700 §4.4.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.4.2) | Not MCP's primary response check. |
| SAF-T1009-C011 | Resource indicators and audience checks constrain cross-resource token reuse. | Research-Derived | SRC-rfc8707: [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html) | Does not stop disclosure for the intended resource. |
| SAF-T1009-C012 | The attack was verified on mod_auth_openidc and pyoidc. | Demonstrated | SRC-fett-oauth-analysis: [Fett, Küsters, Schmitz](https://arxiv.org/abs/1601.01229) | OAuth/OpenID demonstration, not MCP production. |
| SAF-T1009-C013 | Malicious OpenID discovery endpoints are a demonstrated adjacent behavior. | Demonstrated | SRC-mainka-oidc-endpoints: [Mainka, Mladenov, Schwenk](https://arxiv.org/abs/1508.04324) | Endpoint substitution, not necessarily callback mix-up. |
| SAF-T1009-C014 | Auth.js provider-unbound callback checks enabled adjacent account-link confusion. | Demonstrated | SRC-ghsa-authjs-provider-binding: [GHSA-x445-f3h2-j279](https://github.com/nextauthjs/next-auth/security/advisories/GHSA-x445-f3h2-j279) | Adjacent; no honest code-to-malicious-AS disclosure documented. |
| SAF-T1009-C015 | MCP Toolbox skipped configured issuer validation on issuer-less introspection. | Demonstrated | SRC-nvd-cve-2026-11718: [NVD CVE-2026-11718](https://nvd.nist.gov/vuln/detail/CVE-2026-11718); SRC-mcp-toolbox-pr3360: [patch](https://github.com/googleapis/mcp-toolbox/pull/3360) | Adjacent resource-server token validation. |
| SAF-T1009-C016 | CVE-2025-27370 enabled adjacent cross-AS private-key assertion use. | Demonstrated | SRC-oidf-private-key-jwt-disclosure: [OpenID disclosure](https://openid.net/wp-content/uploads/2025/01/OIDF-Responsible-Disclosure-Notice-on-Security-Vulnerability-for-private_key_jwt.pdf); SRC-oidf-private-key-jwt-notice: [public notice](https://openid.net/notice-of-a-security-vulnerability/) | Adjacent client-authentication assertion, not callback credential. |
| SAF-T1009-C017 | No qualifying MCP production incident was found as of 2026-09-01. | Research-Derived | SRC-nvd-oauth-mixup-query: [NVD API query](https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=OAuth%20mix-up); SRC-arxiv-mcp-mixup-query: [arXiv search](https://arxiv.org/search/?query=%22Model+Context+Protocol%22+%22mix-up%22&searchtype=all) | Bounded reviewed-corpus absence claim. |
| SAF-T1009-C018 | Validated metadata, unique issuers, per-request binding, exact comparison, and abort are the direct controls. | Research-Derived | SRC-rfc9207: [RFC 9207](https://www.rfc-editor.org/rfc/rfc9207.html) | Forged expected metadata defeats the comparison. |
| SAF-T1009-C019 | Issuer comparison is exact and does not apply URI normalization. | Research-Derived | SRC-mcp-authorization-2026-07-28: [response validation](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#authorization-response-validation) | Logs must preserve compared values. |
| SAF-T1009-C020 | Per-flow validation fields support a high-confidence mismatch analytic. | Research-Derived | SRC-mcp-authorization-2026-07-28: [response validation](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#authorization-response-validation) | Requires client-side correlation telemetry. |
| SAF-T1009-C021 | Non-advertised missing iss is an expected legitimate compatibility case. | Research-Derived | SRC-mcp-authorization-2026-07-28: [decision table](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#authorization-response-validation) | Stricter local policy may reject it. |
| SAF-T1009-C022 | ATT&CK T1528 is analogous to the token-theft objective, not the issuer-misbinding mechanism. | Research-Derived | SRC-mitre-t1528: [MITRE ATT&CK T1528](https://attack.mitre.org/techniques/T1528/) | ATT&CK places it under Credential Access. |

### Current State

- **Affected Environments**: Multi-authorization-server MCP clients whose issuer, callback, and token-endpoint state is not reliably bound per request. [MCP Discovery](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/authorization-server-discovery) <!-- SAF-TRACE: claims=SAF-T1009-C002,SAF-T1009-C004; sources=SRC-mcp-auth-discovery-2026-07-28,SRC-fett-oauth-analysis -->
- **Known Exploitation**: No qualifying MCP production incident was identified; one generic OAuth attack was reproduced on two concrete client implementations. [Formal OAuth analysis](https://arxiv.org/abs/1601.01229) <!-- SAF-TRACE: claims=SAF-T1009-C012,SAF-T1009-C017; sources=SRC-fett-oauth-analysis,SRC-nvd-oauth-mixup-query,SRC-arxiv-mcp-mixup-query -->
- **Available Protections**: Current MCP requires validated metadata, per-request issuer recording, and response-issuer checking before code transmission. [MCP response validation](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#authorization-response-validation) <!-- SAF-TRACE: claims=SAF-T1009-C006,SAF-T1009-C007,SAF-T1009-C008,SAF-T1009-C018; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-auth-discovery-2026-07-28,SRC-rfc9207 -->
- **Residual Risk**: The expected issuer provides no protection if its metadata was not validated, and current MCP permits issuer-less responses from servers that did not advertise response-issuer support. [MCP response validation](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#authorization-response-validation) <!-- SAF-TRACE: claims=SAF-T1009-C007,SAF-T1009-C009; sources=SRC-mcp-authorization-2026-07-28,SRC-rfc8414 -->

### Known Breaches and Vulnerabilities

No direct MCP production breach was identified in the reviewed corpus; the following examples are ordered by relationship, then operational relevance. [NVD exact query](https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=OAuth%20mix-up) [arXiv MCP search](https://arxiv.org/search/?query=%22Model+Context+Protocol%22+%22mix-up%22&searchtype=all) <!-- SAF-TRACE: claims=SAF-T1009-C017; sources=SRC-nvd-oauth-mixup-query,SRC-arxiv-mcp-mixup-query -->

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| Fett-Küsters-Schmitz IdP Mix-Up demonstration | 2016; mod_auth_openidc and pyoidc | Demonstrated code/token disclosure; issuer identity binding was proposed and later standardized. | Direct demonstration of generic OAuth behavior. | Not MCP and not a production incident. [Paper](https://arxiv.org/abs/1601.01229) <!-- SAF-TRACE: claims=SAF-T1009-C012; sources=SRC-fett-oauth-analysis --> |
| CVE-2026-73419 / GHSA-x445-f3h2-j279 | 2026; multi-provider Auth.js with account linking and stated PKCE conditions | Persistent unauthorized provider-account linking; fixed in @auth/core 0.41.3, next-auth 4.24.15, and 5.0.0-beta.32. | Adjacent callback-provider state confusion. | Does not document sending an honest issuer's code to a malicious authorization server. Credit: reported by Nadav0077; published by Gustavo Valverde. [Advisory](https://github.com/nextauthjs/next-auth/security/advisories/GHSA-x445-f3h2-j279) <!-- SAF-TRACE: claims=SAF-T1009-C014; sources=SRC-ghsa-authjs-provider-binding --> |
| CVE-2026-11718 | 2026; googleapis/mcp-toolbox generic opaque-token validation | Tokens from unintended identity providers could be accepted; issuer-presence enforcement and tests shipped in 1.4.0. | Adjacent MCP resource-server issuer validation. | Does not involve browser-response issuer misbinding. Credit: reported by HaoNH of VinCSS; patch by Wenxin Du with review/release contribution from Yuan Teoh. [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-11718) [patch](https://github.com/googleapis/mcp-toolbox/pull/3360) <!-- SAF-TRACE: claims=SAF-T1009-C015; sources=SRC-nvd-cve-2026-11718,SRC-mcp-toolbox-pr3360 --> |
| CVE-2025-27370 | 2025; private_key_jwt with multiple authorization servers and shared client key | A malicious server could obtain an assertion usable to impersonate the client at an honest server; issuer-identifier audience binding was prescribed. | Adjacent cross-AS client-assertion vulnerability. | The OpenID Foundation reported no known compromises; the stolen object is not a browser-delivered code or access token. Credit: Pedram Hosseyni, Ralf Küsters, and Tim Würtele. [OpenID notice](https://openid.net/notice-of-a-security-vulnerability/) <!-- SAF-TRACE: claims=SAF-T1009-C016; sources=SRC-oidf-private-key-jwt-notice,SRC-oidf-private-key-jwt-disclosure --> |

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | High | The attacker can obtain an authorization code or token for the honest issuer; reachable data remains bounded by grant, scope, audience, and downstream checks. [RFC 9207 §1](https://www.rfc-editor.org/rfc/rfc9207.html#section-1) <!-- SAF-TRACE: claims=SAF-T1009-C005,SAF-T1009-C011; sources=SRC-rfc9207,SRC-rfc8707 --> |
| Integrity | High | A redeemed credential can authorize actions within its permissions or support identity/session compromise in affected client modes. [Formal OAuth analysis §3.2](https://arxiv.org/abs/1601.01229) <!-- SAF-TRACE: claims=SAF-T1009-C005; sources=SRC-fett-oauth-analysis --> |
| Availability | None | Availability loss is not a defining outcome of the standards-described mix-up; the immediate documented consequences are credential confidentiality and resource integrity. [RFC 9207 §1](https://www.rfc-editor.org/rfc/rfc9207.html#section-1) <!-- SAF-TRACE: claims=SAF-T1009-C005; sources=SRC-rfc9207 --> |
| Scope | Multi-System | The flow spans an MCP client, at least two authorization servers, a browser callback, and potentially the intended MCP resource. [MCP authorization flow](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#authorization-flow-steps) <!-- SAF-TRACE: claims=SAF-T1009-C001,SAF-T1009-C002,SAF-T1009-C004; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-auth-discovery-2026-07-28,SRC-fett-oauth-analysis --> |

### Severity Conditions

- **Severity increases when** the stolen credential reaches sensitive MCP capabilities, broad scopes, or long-lived access and the attacker can satisfy the honest server's redemption conditions. [RFC 9207 §1](https://www.rfc-editor.org/rfc/rfc9207.html#section-1) <!-- SAF-TRACE: claims=SAF-T1009-C005; sources=SRC-rfc9207 -->
- **Severity decreases when** issuer mismatch aborts the flow before a token request and resource/audience checks confine any resulting token. [MCP response validation](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#authorization-response-validation) [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html) <!-- SAF-TRACE: claims=SAF-T1009-C008,SAF-T1009-C011,SAF-T1009-C018; sources=SRC-mcp-authorization-2026-07-28,SRC-rfc8707 -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| MCP client authorization callback validation | Expected-issuer recording, metadata-validation result, callback parsing, issuer comparison, and rejection | timestamp, flow_id, recorded_expected_issuer, response_iss, authorization_response_iss_parameter_supported, metadata_validated, comparison_mode, validation_outcome | Preserve raw decoded issuer strings and correlate before any token request. [MCP response validation](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#authorization-response-validation) <!-- SAF-TRACE: claims=SAF-T1009-C019,SAF-T1009-C020; sources=SRC-mcp-authorization-2026-07-28 --> |
| MCP client outbound token request | Endpoint selection and whether an authorization code was forwarded | timestamp, flow_id, bound_issuer, selected_token_endpoint, prior_validation_outcome, code_forwarded | Alert if a request follows failed or absent issuer validation for the same flow. [RFC 9207 §2.4](https://www.rfc-editor.org/rfc/rfc9207.html#section-2.4) <!-- SAF-TRACE: claims=SAF-T1009-C008,SAF-T1009-C020; sources=SRC-rfc9207,SRC-mcp-authorization-2026-07-28 --> |

### Indicators of Compromise (IoCs)

- No durable technique-specific artifact is established; issuer values and endpoints are deployment-specific and should be treated as correlated behavior rather than static IoCs. [RFC 9207 §4](https://www.rfc-editor.org/rfc/rfc9207.html#section-4) <!-- SAF-TRACE: claims=SAF-T1009-C020; sources=SRC-rfc9207 -->

### Behavioral Indicators

- A present `response_iss` differs byte-for-byte from the recorded expected issuer after form decoding. [MCP response validation](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#authorization-response-validation) <!-- SAF-TRACE: claims=SAF-T1009-C008,SAF-T1009-C019; sources=SRC-mcp-authorization-2026-07-28 -->
- The server advertised response-issuer support but a callback lacks `iss`. [MCP response validation](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#authorization-response-validation) <!-- SAF-TRACE: claims=SAF-T1009-C008; sources=SRC-mcp-authorization-2026-07-28 -->
- The expected issuer came from unvalidated metadata, or a token request carrying a code follows failed or missing validation for the same flow. [MCP response validation](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#authorization-response-validation) <!-- SAF-TRACE: claims=SAF-T1009-C006,SAF-T1009-C007,SAF-T1009-C020; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-auth-discovery-2026-07-28 -->
- A missing `iss` with no advertised support is a current compatibility case, not a high-confidence attack signal by itself. [MCP response validation](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#authorization-response-validation) <!-- SAF-TRACE: claims=SAF-T1009-C009,SAF-T1009-C021; sources=SRC-mcp-authorization-2026-07-28 -->

### Detection Analytic

The standalone experimental analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Detect issuer-binding violations before credential transmission and identify a token request that follows failed validation. [MCP response validation](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#authorization-response-validation) <!-- SAF-TRACE: claims=SAF-T1009-C020; sources=SRC-mcp-authorization-2026-07-28 -->
- **Rule Status**: Experimental, because no standardized MCP audit-event schema or accuracy study was identified in the reviewed corpus. [source-coverage.yml](../../research/techniques/SAF-T1009/source-coverage.yml)
- **Detection Logic**: Match exact issuer disagreement, advertised-but-missing issuer, unvalidated expected metadata, or outbound code forwarding after a non-passing validation outcome. [MCP response validation](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#authorization-response-validation) <!-- SAF-TRACE: claims=SAF-T1009-C008,SAF-T1009-C020; sources=SRC-mcp-authorization-2026-07-28 -->
- **Correlation Window**: Correlate by `flow_id` for the lifetime of the single authorization request; elapsed-time tuning is implementation-specific. [MCP per-request record](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#authorization-response-validation) <!-- SAF-TRACE: claims=SAF-T1009-C006,SAF-T1009-C020; sources=SRC-mcp-authorization-2026-07-28 -->
- **Known False Positives**: Missing `iss` when support is false or absent is allowed by the current MCP decision table and is not selected by the rule. [MCP response validation](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#authorization-response-validation) <!-- SAF-TRACE: claims=SAF-T1009-C009,SAF-T1009-C021; sources=SRC-mcp-authorization-2026-07-28 -->
- **Known Limitations**: The analytic cannot evaluate clients that do not emit per-flow issuer, metadata-validation, callback, and token-request events; a forged expected issuer can also make equal values misleading. [MCP response-validation dependency](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#authorization-response-validation) <!-- SAF-TRACE: claims=SAF-T1009-C007,SAF-T1009-C020; sources=SRC-mcp-authorization-2026-07-28,SRC-rfc8414 -->
- **Tuning Guidance**: Preserve exact decoded strings, do not URI-normalize them, and apply any stricter local policy for issuer-less responses as an explicit extension. [MCP comparison rules](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#authorization-response-validation) <!-- SAF-TRACE: claims=SAF-T1009-C019,SAF-T1009-C021; sources=SRC-mcp-authorization-2026-07-28 -->

### Validation

- **Test Data**: [test-logs.json](test-logs.json)
- **Validation Script**: [test_detection_rule.py](test_detection_rule.py)
- **Expected Result**: Eight fixtures cover mismatch, advertised absence, unvalidated metadata, post-failure code forwarding, valid equality, permitted legacy absence, exact-string boundary, and malformed missing flow state. [test-logs.json](test-logs.json)
- **Last Validated**: 2026-09-01. [quality-review.yml](../../research/techniques/SAF-T1009/quality-review.yml)
- **Feasibility Waiver**: None. [quality-review.yml](../../research/techniques/SAF-T1009/quality-review.yml)

## Mitigation Strategies

### Preventive Controls

1. Validate authorization-server metadata by requiring its issuer to exactly match the issuer used to construct the discovery URL; do not use mismatched metadata. [RFC 8414 §3.3](https://www.rfc-editor.org/rfc/rfc8414.html#section-3.3) <!-- SAF-TRACE: claims=SAF-T1009-C007,SAF-T1009-C018; sources=SRC-rfc8414 -->
2. Store the validated expected issuer in the same per-request state as PKCE and state, compare a returned issuer exactly, and abort before token transmission on mismatch. [MCP Authorization Response Validation](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#authorization-response-validation) <!-- SAF-TRACE: claims=SAF-T1009-C006,SAF-T1009-C008,SAF-T1009-C018,SAF-T1009-C019; sources=SRC-mcp-authorization-2026-07-28 -->
3. Require unique issuer identifiers for configured authorization servers; where issuer responses cannot be used, distinct per-issuer redirect URIs are a limited alternative. [RFC 9207 §4](https://www.rfc-editor.org/rfc/rfc9207.html#section-4) [RFC 9700 §4.4.2.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.4.2.2) <!-- SAF-TRACE: claims=SAF-T1009-C010,SAF-T1009-C018; sources=SRC-rfc9207,SRC-rfc9700 -->
4. Include MCP resource indicators and enforce token audience restrictions to constrain cross-resource use if a token is obtained. [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html) <!-- SAF-TRACE: claims=SAF-T1009-C011; sources=SRC-rfc8707,SRC-mcp-authorization-2026-07-28 -->

### Detective Controls

1. Emit and correlate the exact per-flow validation and token-request fields used by the tested analytic. [detection-rule.yml](detection-rule.yml)
2. Measure use of issuer-less compatibility flows and adopt a stricter local rejection policy where interoperability permits. [MCP response validation](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#authorization-response-validation) <!-- SAF-TRACE: claims=SAF-T1009-C009,SAF-T1009-C021; sources=SRC-mcp-authorization-2026-07-28 -->

### Response Procedures

#### Immediate Actions

- Stop the affected authorization flow and prevent any code or token request after issuer mismatch or advertised issuer absence. [RFC 9207 §2.4](https://www.rfc-editor.org/rfc/rfc9207.html#section-2.4) <!-- SAF-TRACE: claims=SAF-T1009-C008,SAF-T1009-C018; sources=SRC-rfc9207 -->
- Preserve the per-flow expected issuer, returned issuer, metadata-validation state, endpoint selection, and validation outcome for investigation. [detection-rule.yml](detection-rule.yml)

#### Investigation Steps

- Confirm that the expected issuer came from metadata whose issuer exactly matched the discovery issuer and that authorization-server identifiers are unique. [RFC 8414 §3.3](https://www.rfc-editor.org/rfc/rfc8414.html#section-3.3) [RFC 9207 §4](https://www.rfc-editor.org/rfc/rfc9207.html#section-4) <!-- SAF-TRACE: claims=SAF-T1009-C007,SAF-T1009-C018; sources=SRC-rfc8414,SRC-rfc9207 -->
- Correlate callback validation to any outbound token request by `flow_id` and determine whether an authorization credential was forwarded after a failed decision. [detection-rule.yml](detection-rule.yml)

#### Remediation

- Implement or repair validated metadata, per-request issuer binding, exact comparison, and abort-before-token-request behavior. [MCP response validation](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#authorization-response-validation) <!-- SAF-TRACE: claims=SAF-T1009-C006,SAF-T1009-C007,SAF-T1009-C008,SAF-T1009-C018; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-auth-discovery-2026-07-28 -->
- If an adjacent selected product flaw is present, apply its documented fixed release or control without treating that fix as proof of direct SAF-T1009 exploitation. [Auth.js advisory](https://github.com/nextauthjs/next-auth/security/advisories/GHSA-x445-f3h2-j279) [mcp-toolbox patch](https://github.com/googleapis/mcp-toolbox/pull/3360) [OpenID notice](https://openid.net/notice-of-a-security-vulnerability/) <!-- SAF-TRACE: claims=SAF-T1009-C014,SAF-T1009-C015,SAF-T1009-C016; sources=SRC-ghsa-authjs-provider-binding,SRC-mcp-toolbox-pr3360,SRC-oidf-private-key-jwt-notice -->
- Add regression coverage for exact mismatch, advertised absence, unvalidated metadata, and post-failure token requests. [test-logs.json](test-logs.json)

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1507: Authorization Code Interception](../SAF-T1507/README.md) | Follow-on or adjacent | Obtains an authorization code through interception; SAF-T1009 instead causes cross-issuer response misbinding and can then disclose the code. [RFC 9700 §§4.4-4.5](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.4) <!-- SAF-TRACE: claims=SAF-T1009-C003; sources=SRC-rfc9700 --> |
| [SAF-T1706: OAuth Token Pivot Replay](../SAF-T1706/README.md) | Alternative boundary failure | Reuses an issued token across contexts; SAF-T1009 occurs earlier at issuer and endpoint binding. [RFC 8707 §3](https://www.rfc-editor.org/rfc/rfc8707.html#section-3) <!-- SAF-TRACE: claims=SAF-T1009-C011; sources=SRC-rfc8707 --> |
| [SAF-T1306: Rogue Authorization Server](../SAF-T1306/README.md) | Deprecated compatibility ID | Its frozen contract describes the same cross-issuer response-misbinding and credential-disclosure mechanism. Use SAF-T1009 for new mappings. [Framework Model v2 taxonomy review](../../research/taxonomy-review.yml) |

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1528](https://attack.mitre.org/techniques/T1528/) | Steal Application Access Token | Analogous | Both cover acquisition of an application credential that can reach remote resources, but T1528 does not define cross-issuer response misbinding and belongs to Credential Access. <!-- SAF-TRACE: claims=SAF-T1009-C005,SAF-T1009-C022; sources=SRC-mitre-t1528,SRC-rfc9207 --> |

## References

1. **SRC-mcp-authorization-2026-07-28**: [Model Context Protocol Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) — Model Context Protocol maintainers; roles, response validation, resource indicator, and token handling.
2. **SRC-mcp-auth-discovery-2026-07-28**: [Authorization Server Discovery](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/authorization-server-discovery) — Model Context Protocol maintainers; multiple servers and metadata validation.
3. **SRC-mcp-auth-security-2026-07-28**: [Authorization Security Considerations](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations) — Model Context Protocol maintainers; MCP mix-up threat and required mitigation.
4. **SRC-rfc9700**: [Best Current Practice for OAuth 2.0 Security](https://www.rfc-editor.org/rfc/rfc9700.html) — Torsten Lodderstedt, John Bradley, Andrey Labunets, and Daniel Fett; §§2.1 and 4.4.
5. **SRC-rfc9207**: [OAuth 2.0 Authorization Server Issuer Identification](https://www.rfc-editor.org/rfc/rfc9207.html) — Karsten Meyer zu Selhausen and Daniel Fett; §§1-4.
6. **SRC-rfc8414**: [OAuth 2.0 Authorization Server Metadata](https://www.rfc-editor.org/rfc/rfc8414.html) — Michael B. Jones, Nat Sakimura, and John Bradley; §§3.3 and 6.2.
7. **SRC-rfc8707**: [Resource Indicators for OAuth 2.0](https://www.rfc-editor.org/rfc/rfc8707.html) — Brian Campbell and Philippe De Ryck; §§2-3.
8. **SRC-rfc9728**: [OAuth 2.0 Protected Resource Metadata](https://www.rfc-editor.org/rfc/rfc9728.html) — Michael B. Jones, Phil Hunt, and Aaron Parecki; §§2 and 7.6.
9. **SRC-fett-oauth-analysis**: [A Comprehensive Formal Security Analysis of OAuth 2.0](https://arxiv.org/abs/1601.01229) — Daniel Fett, Ralf Küsters, and Guido Schmitz; §§3.2 and 3.6.
10. **SRC-mainka-oidc-endpoints**: [On the Security of Modern Single Sign-On Protocols](https://arxiv.org/abs/1508.04324) — Christian Mainka, Vladislav Mladenov, and Jörg Schwenk; malicious endpoints and issuer binding.
11. **SRC-ghsa-authjs-provider-binding**: [GHSA-x445-f3h2-j279](https://github.com/nextauthjs/next-auth/security/advisories/GHSA-x445-f3h2-j279) — Auth.js maintainers; published by Gustavo Valverde and reported by Nadav0077.
12. **SRC-nvd-cve-2026-11718**: [CVE-2026-11718](https://nvd.nist.gov/vuln/detail/CVE-2026-11718) — Google CNA, NVD, and CISA assessment.
13. **SRC-mcp-toolbox-pr3360**: [mcp-toolbox PR 3360](https://github.com/googleapis/mcp-toolbox/pull/3360) — patch by Wenxin Du; reporter HaoNH of VinCSS; review/release contribution by Yuan Teoh.
14. **SRC-oidf-private-key-jwt-notice**: [OpenID Foundation public notice](https://openid.net/notice-of-a-security-vulnerability/) — credits Ralf Küsters, Tim Würtele, and Pedram Hosseyni.
15. **SRC-oidf-private-key-jwt-disclosure**: [Responsible disclosure for private_key_jwt](https://openid.net/wp-content/uploads/2025/01/OIDF-Responsible-Disclosure-Notice-on-Security-Vulnerability-for-private_key_jwt.pdf) — OpenID Foundation; Pedram Hosseyni, Ralf Küsters, and Tim Würtele.
16. **SRC-nvd-oauth-mixup-query**: [NVD OAuth mix-up query](https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=OAuth%20mix-up) — zero results on 2026-09-01.
17. **SRC-arxiv-mcp-mixup-query**: [arXiv MCP mix-up search](https://arxiv.org/search/?query=%22Model+Context+Protocol%22+%22mix-up%22&searchtype=all) — no results on 2026-09-01.
18. **SRC-mitre-t1528**: [MITRE ATT&CK T1528](https://attack.mitre.org/techniques/T1528/) — Version 1.5; MITRE ATT&CK team and named contributors recorded in the source manifest.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 0.1 | 2026-09-01 | Independent clean-room research draft and tested analytic. | OpenAI Codex clean-room agent |
| 0.2 | 2026-09-02 | Consolidated the duplicate SAF-T1306 compatibility ID and reconciled tactics and relationships under SAF-TAX-013. | The SAF-MCP Authors |
