# SAF-T1506: Infrastructure Token Theft

## Overview
**Tactic**: Credential Access (ATK-TA0006)
**Technique ID**: SAF-T1506
**Severity**: High
**First Observed**: Not observed as a distinct MCP incident; derived from established bearer-token and infrastructure-log exposure patterns
**Last Updated**: 2026-08-01

## Description
Infrastructure Token Theft occurs when an adversary obtains MCP access tokens, upstream service tokens, session identifiers, API keys, or authorization codes from infrastructure that processes or observes MCP traffic. Exposure points include application and proxy logs, tracing systems, error reports, TLS termination layers, support exports, crash dumps, and telemetry pipelines.

The technique is especially dangerous for bearer credentials. RFC 6750 states that any party possessing a bearer token can use it, so a token copied from infrastructure may be replayed without proving possession of a separate key. In an MCP deployment, one leaked credential can also cross an intended trust boundary when the same token is accepted by multiple servers, tenants, tools, or upstream services.

## Attack Vectors
- **Primary Vector**: Retrieve bearer tokens or API keys from logs, traces, error reports, or proxy metadata and replay them against the intended MCP server or upstream service.
- **Secondary Vectors**:
  - Read authorization headers from reverse-proxy, API-gateway, or service-mesh logs.
  - Extract query-string credentials from access logs, browser history, referrer data, or support exports.
  - Obtain tokens from crash dumps, debug bundles, APM spans, or exception metadata.
  - Abuse overly broad observability access to search across multiple tenants or environments.
  - Steal upstream credentials stored by an MCP gateway and use them outside the gateway's policy layer.

## Technical Details

### Prerequisites
- A reusable credential reaches infrastructure controlled by or accessible to the adversary.
- The credential is recorded, exported, cached, or retained in recoverable form.
- The adversary can read the relevant logging, tracing, proxy, support, or diagnostic system.
- The target accepts the credential before it expires or is revoked.

### Attack Flow

```mermaid
sequenceDiagram
    participant C as MCP Client
    participant P as Proxy or Gateway
    participant S as MCP Server
    participant O as Logs or Traces
    participant A as Adversary

    C->>P: Request with bearer credential
    P->>O: Records header, URL, or span attribute
    P->>S: Forwards request
    A->>O: Reads exported telemetry
    O-->>A: Exposes reusable credential
    A->>S: Replays credential
    S-->>A: Grants credential-bound access
```

1. **Credential Transit**: An MCP client or gateway sends an access token, API key, authorization code, or session identifier.
2. **Infrastructure Capture**: A proxy, logger, tracing SDK, exception handler, or support workflow records the credential or a request containing it.
3. **Collection**: The adversary gains read access to the infrastructure store or an exported diagnostic artifact.
4. **Replay**: The adversary presents the recovered credential to the MCP server or an upstream service.
5. **Expansion**: Broad scopes, long lifetimes, shared credentials, or missing audience validation increase the reachable tools, data, tenants, or services.

### Example Scenario

An organization operates a remote MCP gateway behind a reverse proxy. Debug logging is temporarily enabled during an integration incident and records the complete `Authorization` header. The log stream is copied into a broadly accessible observability project.

```text
POST /mcp HTTP/1.1
Host: mcp.example.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...REDACTED
Content-Type: application/json
```

An adversary with read-only access to that observability project retrieves the token and replays it before expiry. If the MCP server validates only the signature and expiration but not the token audience, the same token may also be accepted at an unintended resource server. If an upstream API credential was exposed instead, replay may bypass MCP-specific tool and operation controls entirely.

### MCP-Specific Boundary Failure

Transport authentication, MCP authorization, and upstream-service authorization are separate boundaries. A secure deployment should not assume that one credential safely represents all three:

- A client token identifies or authorizes the caller to the MCP server.
- MCP policy determines which tools, resources, and operations that caller may invoke.
- An upstream credential determines what the backing database or API permits.

Logging or forwarding an upstream credential can let an attacker bypass the narrower MCP policy. Forwarding a client token to an upstream service creates the token-passthrough problem explicitly prohibited by the MCP security guidance.

## Impact Assessment
- **Confidentiality**: High - Replayed credentials can expose MCP resources, tool output, databases, APIs, or cross-tenant data.
- **Integrity**: High - Write-capable tokens or upstream credentials can authorize data modification or destructive tool calls.
- **Availability**: Medium - Stolen credentials may be used for deletion, quota exhaustion, or service disruption when their grants permit it.
- **Scope**: Adjacent to network-wide - Impact depends on token audience, scope, lifetime, tenant binding, and whether credentials are reused across services.

## Detection Methods

### Indicators of Compromise
- Authorization headers, API keys, session identifiers, or authorization codes present in logs or trace attributes.
- Successful token use from a new source immediately after an observability or support export was accessed.
- The same token identifier used from unrelated networks, regions, clients, or tenant contexts.
- A client token accepted by more than one resource server or audience.
- Direct upstream API activity that matches a stored gateway credential but has no corresponding MCP request.
- Credential use after the associated MCP link, session, or client authorization was revoked.

### Detection Rule

The repository includes an example Sigma-compatible rule in [`detection-rule.yml`](detection-rule.yml). It detects telemetry events that indicate sensitive authorization material was written to logs. Field names and redaction markers must be adapted to the local logging schema.

### Behavioral Indicators
- A read-only observability identity searches for `Authorization`, `Bearer`, `api_key`, or token-shaped values across production logs.
- Token replay follows access to crash dumps, debug bundles, proxy logs, or tracing exports.
- A token is used outside its expected audience, client, network boundary, or normal time window.
- An upstream service receives requests that cannot be correlated to an authenticated MCP client and authorized tool invocation.

## Mitigation Strategies

### Preventive Controls
1. **[SAF-M-16: Token Scope Limiting](../../mitigations/SAF-M-16/README.md)**: Use narrowly scoped, short-lived credentials bound to the intended resource and tenant. Validate issuer and audience on every request.
2. **[SAF-M-31: Proof of Possession Tokens](../../mitigations/SAF-M-31/README.md)**: Prefer sender-constrained tokens such as DPoP or mutual-TLS-bound access tokens where the ecosystem supports them, reducing the value of a copied bearer token.
3. **Credential Redaction**: Do not record access tokens, authorization codes, session identifiers, passwords, private keys, or database connection strings. Redact sensitive headers and URL parameters before logs or traces leave the request process.
4. **Server-Side Credential Isolation**: Keep upstream credentials in a secret manager or encrypted server-side store. Never return them to MCP clients, place them in tool results, or forward client bearer tokens to upstream APIs.
5. **Independent Authorization Layers**: Enforce MCP tool and operation policy separately from backend grants. Use distinct credentials per environment, tenant, connection, or integration where feasible.
6. **Telemetry Access Control**: Restrict production logs, traces, support exports, and crash dumps using least privilege, short retention, encryption, and audited export workflows.
7. **Safe URL Design**: Do not place credentials in URLs. RFC 6750 warns that URLs are likely to be logged; use the `Authorization` request header and redact it before telemetry capture.

### Detective Controls
1. **[SAF-M-19: Token Usage Tracking](../../mitigations/SAF-M-19/README.md)**: Correlate token identifiers, clients, audiences, tenants, source networks, and MCP link IDs without storing raw credentials.
2. **Secret Scanning for Telemetry**: Continuously scan log and trace schemas plus sampled exports for credential patterns, then treat matches as security incidents rather than ordinary data-quality findings.
3. **Request Correlation**: Require every upstream operation to map to an authenticated MCP request, authorized tool call, and policy decision.
4. **Revocation Verification**: Alert when a revoked link, token, client grant, or upstream credential continues to produce successful activity.

### Response Procedures
1. **Immediate Actions**:
   - Revoke or rotate every exposed credential; do not rely only on deleting the log entry.
   - Disable affected MCP links, sessions, clients, and upstream grants until scope is understood.
   - Restrict access to the implicated logs, traces, exports, or diagnostic artifacts.
2. **Investigation Steps**:
   - Determine which credential types, scopes, audiences, tenants, and retention windows were exposed.
   - Correlate log access with token-use records and upstream service activity.
   - Search downstream copies, backups, tickets, chat attachments, and exported support bundles.
3. **Remediation**:
   - Add redaction before serialization and export, not only at the log viewer.
   - Reduce token lifetime and scope, separate credentials by boundary, and add audience validation.
   - Test revocation end to end at the MCP server and every upstream service.

## Related Techniques
- [SAF-T1307](../SAF-T1307/README.md): Confused Deputy Attack can misuse tokens at unintended recipients or through prohibited token passthrough.
- [SAF-T1502](../SAF-T1502/README.md): File-Based Credential Harvest targets credential files rather than infrastructure telemetry.
- [SAF-T1504](../SAF-T1504/README.md): Token Theft via API Response exposes credentials in application responses rather than logs or proxies.
- [SAF-T1507](../SAF-T1507/README.md): Authorization Code Interception steals codes during the OAuth redirect flow.
- [SAF-T1706](../SAF-T1706/README.md): OAuth Token Pivot Replay covers subsequent replay and pivoting with a stolen token.

## References
- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/draft/basic/security_best_practices)
- [MCP Authorization](https://modelcontextprotocol.io/specification/draft/basic/authorization)
- [RFC 6750: The OAuth 2.0 Authorization Framework — Bearer Token Usage](https://www.rfc-editor.org/rfc/rfc6750)
- [RFC 8705: OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens](https://www.rfc-editor.org/rfc/rfc8705)
- [RFC 9449: OAuth 2.0 Demonstrating Proof of Possession](https://www.rfc-editor.org/rfc/rfc9449)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)

## MITRE ATT&CK Mapping
- [T1552: Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)
- [T1552.001: Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)
- [T1528: Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)
- [T1550.001: Use Alternate Authentication Material — Application Access Token](https://attack.mitre.org/techniques/T1550/001/)

## Version History
| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2026-08-01 | Initial documentation, detection guidance, mitigations, and response procedures | Andrei Mironov |
