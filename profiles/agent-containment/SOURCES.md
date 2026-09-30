# Sources, inference, and publication scope

This is an original deployment proposal. The normative MUST statements define this proposed profile; they are not assertions that MCP already implements these controls. The attack items are design scenarios and the validation cases are a planned acceptance program. No production breach, performance percentage, product certification, or proof of an escape-free runtime is claimed.

Existing SAF classifications are reused without changing their evidence status. `procedure_example` means the scenario instantiates the named mechanism under its stated preconditions. `related_context` means the mechanism differs and the existing ID supplies context only. Ordinary input capture and non-OAuth approval replay are not relabeled as OAuth attacks.

MITRE ATT&CK mappings are explicitly analogous and retain the live external identifier reviewed on the date below. In particular, the reviewed firewall page uses T1686 and the external tactic name Defense Impairment; this proposal preserves SAF's existing tactic registry rather than silently migrating it.

The source manuscripts are identified by filename and digest in [provenance.yml](provenance.yml). They provide the project's proposed construction and conditions, not independent evidence that a runtime or device realizes them. Source text and code are not redistributed here.

## Reviewed external sources

### ACP-S001: MCP Tools

[MCP Tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) — Model Context Protocol contributors. 2025-11-25. Reviewed 2026-09-16.

**Locator:** Security Considerations. **Use:** Baseline for validating tool requests and presenting sensitive operations. The stronger profile requirements are proposed design choices.

### ACP-S002: MCP Authorization

[MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) — Model Context Protocol contributors. 2025-11-25. Reviewed 2026-09-16.

**Locator:** Security Considerations: Token Audience Binding and Validation; Token Theft; Authorization Code Protection. **Use:** Existing MCP audience and token-handling baseline; not a new ENI6MA transport specification.

### ACP-S003: MCP Security Best Practices

[MCP Security Best Practices](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices) — Model Context Protocol contributors. 2025-11-25 path, mutable guidance. Reviewed 2026-09-16.

**Locator:** Token Passthrough; Server-Side Request Forgery; Local MCP Server Compromise. **Use:** Related broker, destination, and local-runtime boundaries. Do not interpret the profile as a change to MCP.

### ACP-S004: RFC 9449: OAuth 2.0 Demonstrating Proof of Possession (DPoP)

[RFC 9449: OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://www.rfc-editor.org/rfc/rfc9449.html) — D. Fett, B. Campbell, J. Bradley, T. Lodderstedt, M. Jones, D. Waite. September 2023. Reviewed 2026-09-16.

**Locator:** Sections 4.3, 11.1, 11.4, and 11.7. **Use:** Related proof binding and replay considerations. DPoP alone is not exact transaction authorization or ENI6MA.

### ACP-S005: Escape to Host

[Escape to Host](https://attack.mitre.org/techniques/T1611/) — MITRE ATT&CK team. Live page reviewed 2026-09-16. Reviewed 2026-09-16.

**Locator:** Description and technique identifier. **Use:** Analogous conventional behavior only; no endorsement or observed agentic incident is inferred.

### ACP-S006: Input Capture: Keylogging

[Input Capture: Keylogging](https://attack.mitre.org/techniques/T1056/001/) — MITRE ATT&CK team. Live page reviewed 2026-09-16. Reviewed 2026-09-16.

**Locator:** Description and technique identifier. **Use:** Analogous conventional behavior only; no endorsement or observed agentic incident is inferred.

### ACP-S007: Input Capture: GUI Input Capture

[Input Capture: GUI Input Capture](https://attack.mitre.org/techniques/T1056/002/) — MITRE ATT&CK team. Live page reviewed 2026-09-16. Reviewed 2026-09-16.

**Locator:** Description and technique identifier. **Use:** Analogous conventional behavior only; no endorsement or observed agentic incident is inferred.

### ACP-S008: Disable or Modify System Firewall

[Disable or Modify System Firewall](https://attack.mitre.org/techniques/T1686/) — MITRE ATT&CK team. Live page reviewed 2026-09-16. Reviewed 2026-09-16.

**Locator:** Description and technique identifier. **Use:** Analogous conventional behavior only; no endorsement or observed agentic incident is inferred.

### ACP-S009: Use Alternate Authentication Material: Application Access Token

[Use Alternate Authentication Material: Application Access Token](https://attack.mitre.org/techniques/T1550/001/) — MITRE ATT&CK team. Live page reviewed 2026-09-16. Reviewed 2026-09-16.

**Locator:** Description and technique identifier. **Use:** Analogous conventional behavior only; no endorsement or observed agentic incident is inferred.

### ACP-S010: Exfiltration Over Web Service

[Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/) — MITRE ATT&CK team. Live page reviewed 2026-09-16. Reviewed 2026-09-16.

**Locator:** Description and technique identifier. **Use:** Analogous conventional behavior only; no endorsement or observed agentic incident is inferred.

## Limits and excluded claims

- No source was used to claim that ENI6MA is the sole possible approval mechanism.
- The profile's illustrative scenarios are design cases, not incident reports.
- No method here establishes an absolute prohibition on every physical or covert channel.
- No finite energy or quantum-computing argument is used to prove runtime isolation.
- No new canonical technique is claimed complete without its separate repository research gates.
- Patent ownership, journal acceptance, and standards endorsement are not asserted.

## License and authorship

The new general documentation is offered under the repository's CC BY 4.0 terms. New mitigation specifications follow CSL 1.0 and validation scripts follow Apache 2.0. Sources are linked and discussed in original language; no third-party code, figures, or source snapshots are included. Requirements and concept: Franciscus Dylan Rosario. Drafting and repository integration assistance: Codex.
