# SAF-T1003: Malicious MCP-Server Distribution

- **Tactic**: Initial Access (`ATK-TA0001`)
- **Technique ID**: SAF-T1003
- **Research Packet**: [research packet](../../research/techniques/SAF-T1003/)
- **Traceability Ledger**: [traceability ledger](../../research/techniques/SAF-T1003/traceability-ledger.yml)
- **Documentation Status**: Under Review
- **Evidence Status**: observed
- **Severity**: High, conditional on installation or activation authority
- **Last Updated**: 2026-09-02

## Overview

Malicious MCP-Server Distribution is the deliberate placement or continued delivery of an MCP server whose package, binary, container, endpoint, or installation configuration contains attacker-controlled behavior. The adversary uses an MCP discovery or software-delivery path so that a person, host application, or automated process acquires and activates the server. <!-- SAF-TRACE: claims=SAF-T1003-C001, SAF-T1003-C002 ; sources=SRC-mcp-registry-about, SRC-mcp-registry-package-types, SRC-mcp-sep-1024, SRC-mitre-t1195-002 -->

The technique ends at malicious delivery and activation. Subsequent command execution, credential access, exfiltration, or persistence are separate outcomes, and a listing, package name, or missing attestation alone is not proof of maliciousness. <!-- SAF-TRACE: claims=SAF-T1003-C004, SAF-T1003-C015 ; sources=SRC-mcp-registry-about, SRC-mitre-t1195-002, SRC-openssf-provenance, SRC-chen-etal-mcpzoo-2026 -->

## Scope

In scope are initial malicious publication, delivery of a malicious release through a package or MCP registry, marketplace, release location, direct configuration, or remote endpoint, and continued availability through a private mirror or cache after public takedown. <!-- SAF-TRACE: claims=SAF-T1003-C001, SAF-T1003-C002, SAF-T1003-C008 ; sources=SRC-mcp-registry-about, SRC-mcp-registry-package-types, SRC-mcp-sep-1024, SRC-mitre-t1195-002, SRC-checkmarx-runcommand -->

Out of scope are a merely vulnerable server absent evidence of adversarial distribution, deceptive naming or persuasion as the defining mechanism, compromise of an update path as the defining mechanism, and post-activation payload effects. <!-- SAF-TRACE: claims=SAF-T1003-C004 ; sources=SRC-mcp-registry-about, SRC-mitre-t1195-002 -->

## Description

The official MCP Registry stores metadata that points to packages or remote servers, while package registries host code and binaries. Namespace checks establish control of a claimed namespace, but server-code scanning is delegated to upstream package registries and downstream aggregators. <!-- SAF-TRACE: claims=SAF-T1003-C005 ; sources=SRC-mcp-registry-about, SRC-mcp-registry-package-types -->

The Registry’s moderation policy tells consumers to assume minimal-to-no moderation. It removes identified malware but does not promise complete detection and generally does not remove servers merely because they contain vulnerabilities. <!-- SAF-TRACE: claims=SAF-T1003-C006 ; sources=SRC-mcp-registry-moderation -->

MCP tools are server-exposed functions that clients can discover and invoke. For local one-click configuration, final SEP-1024 requires display of the complete command and arguments and explicit consent before execution because crafted configurations can be distributed through repositories, documentation, or social channels and can execute arbitrary commands. <!-- SAF-TRACE: claims=SAF-T1003-C003, SAF-T1003-C007 ; sources=SRC-mcp-tools-2025-11-25, SRC-mcp-sep-1024 -->

## Attack Vectors

- Publish an intentionally malicious server package, binary, container, or bundle through a channel reachable by MCP consumers. <!-- SAF-TRACE: claims=SAF-T1003-C001, SAF-T1003-C002 ; sources=SRC-mcp-registry-about, SRC-mcp-registry-package-types, SRC-mitre-t1195-002 -->
- Publish a malicious version after earlier non-malicious releases while retaining the package or server identity. <!-- SAF-TRACE: claims=SAF-T1003-C008 ; sources=SRC-checkmarx-runcommand -->
- Distribute a crafted local-server configuration that causes installation or execution after approval or through a deficient approval flow. <!-- SAF-TRACE: claims=SAF-T1003-C003, SAF-T1003-C007 ; sources=SRC-mcp-sep-1024 -->
- Keep a removed artifact reachable through private repositories, mirrors, or caches. <!-- SAF-TRACE: claims=SAF-T1003-C008, SAF-T1003-C019 ; sources=SRC-checkmarx-runcommand, SRC-mitre-det0537 -->

## Technical Details

1. The adversary prepares or modifies an MCP server artifact or configuration so installation, startup, or later tool use triggers attacker-selected behavior. <!-- SAF-TRACE: claims=SAF-T1003-C002, SAF-T1003-C008 ; sources=SRC-mcp-registry-about, SRC-checkmarx-runcommand -->
2. The adversary exposes it through a package registry, MCP metadata registry or marketplace, release location, remote endpoint, or configuration link. <!-- SAF-TRACE: claims=SAF-T1003-C002, SAF-T1003-C005, SAF-T1003-C007 ; sources=SRC-mcp-registry-about, SRC-mcp-registry-package-types, SRC-mcp-sep-1024, SRC-mitre-t1195-002 -->
3. A consumer resolves the reference to a concrete artifact or endpoint and installs, updates, configures, or activates it. <!-- SAF-TRACE: claims=SAF-T1003-C003, SAF-T1003-C005 ; sources=SRC-mcp-registry-about, SRC-mcp-registry-package-types, SRC-mcp-sep-1024, SRC-mcp-tools-2025-11-25 -->
4. The malicious server executes with the permissions, credentials, accessible data, and network reach of its host context; downstream effects depend on that context. <!-- SAF-TRACE: claims=SAF-T1003-C003, SAF-T1003-C010 ; sources=SRC-checkmarx-runcommand, SRC-jfrog-cve-2025-6514, SRC-mcp-sep-1024 -->

Necessary preconditions are a reachable delivery path, acquisition or activation, and insufficient admission control for the specific source, version, digest, signature, or publisher transition. <!-- SAF-TRACE: claims=SAF-T1003-C002, SAF-T1003-C003, SAF-T1003-C011 ; sources=SRC-mcp-registry-about, SRC-mcp-sep-1024, SRC-npm-provenance, SRC-openssf-provenance, SRC-mitre-det0537 -->

## Evidence and Current State

### Evidence Summary

| Claim ID | Status | Summary |
|---|---|---|
| SAF-T1003-C008 | observed | A malicious MCP-labeled npm package was publicly available, analyzed, reported, and removed. |
| SAF-T1003-C009 | observed | The incident establishes distribution and controlled analysis, not a named production victim or prevalence. |
| SAF-T1003-C010 | demonstrated | CVE-2025-6514 demonstrates an enabling client-side command-execution path from an untrusted server. |
| SAF-T1003-C013 | research-derived | A DSN 2026 study measured registry-level malicious-publication, hijack, and naming risks across six registries. |
| SAF-T1003-C014 | research-derived | The MCPZoo preprint measured substantial scanner disagreement and limited accuracy. |

Checkmarx author Darren Meyer reports that Checkmarx Zero researcher Bruno Dias identified and reported `@lanyer640/mcp-runcommand-server` to npm on 2025-10-01. Version 1.0.6 and later contained an install-time reverse shell, the code was demonstrated in a safe detonation environment, npm removed the package, and cached copies could remain available. <!-- SAF-TRACE: claims=SAF-T1003-C008 ; sources=SRC-checkmarx-runcommand -->

This is direct evidence of malicious MCP-server distribution in a production public registry. The report does not identify a compromised production victim, quantify affected organizations, or establish how many installations executed the malicious version. <!-- SAF-TRACE: claims=SAF-T1003-C009 ; sources=SRC-checkmarx-runcommand -->

JFrog researcher Or Peles disclosed CVE-2025-6514 in `mcp-remote`: an affected client connecting to an untrusted or hijacked server could execute operating-system commands from crafted authorization metadata. Versions 0.0.5 through 0.1.15 were affected and 0.1.16 fixed the issue; the report credits maintainer Glen Maddern. The source demonstrates an enabling exploitation path, not production exploitation or distribution. <!-- SAF-TRACE: claims=SAF-T1003-C010 ; sources=SRC-jfrog-cve-2025-6514 -->

Li and Gao measured 67,057 MCP servers across six registries and described malicious-publication, hijackable-link, and naming risks. Their MCPInspect evaluation sampled 41 servers and reported 90.24% precision; the paper notes incomplete dynamic extraction, inaccessible servers, and a short 2025 collection window. <!-- SAF-TRACE: claims=SAF-T1003-C013 ; sources=SRC-li-gao-dsn-2026 -->

Chen and colleagues built MCPZoo with 64,611 unique servers, more than 37,288 supporting dynamic analysis. Across eight scanners, 96.89% were flagged by at least one scanner, while average precision was 45.53%, inter-scanner Jaccard similarity was 15.66%, and recall against a ten-CVE ground truth was 24.17%. <!-- SAF-TRACE: claims=SAF-T1003-C014 ; sources=SRC-chen-etal-mcpzoo-2026 -->

These results support correlating admission and integrity failures with activation and first-run behavior, not treating a generic capability, keyword, missing optional provenance, or one scanner alert as proof of maliciousness. <!-- SAF-TRACE: claims=SAF-T1003-C015, SAF-T1003-C016 ; sources=SRC-chen-etal-mcpzoo-2026, SRC-openssf-provenance, SRC-mitre-det0537 -->

## Impact Assessment

Impact is high when a malicious server is activated with an identity that has valuable credentials, writable files, tool permissions, or network access. The immediate consequence is attacker-selected behavior under that authority; later execution, credential theft, exfiltration, and persistence require separate evidence. <!-- SAF-TRACE: claims=SAF-T1003-C003, SAF-T1003-C010, SAF-T1003-C018 ; sources=SRC-checkmarx-runcommand, SRC-jfrog-cve-2025-6514, SRC-mcp-sep-1024, SRC-mitre-t1195-002 -->

Observed distribution does not establish prevalence or realized loss, so severity remains conditional on activation and authority rather than availability alone. <!-- SAF-TRACE: claims=SAF-T1003-C009, SAF-T1003-C018 ; sources=SRC-checkmarx-runcommand, SRC-mcp-sep-1024, SRC-mitre-t1195-002 -->

## Detection Methods

Collect MCP configuration and activation events; package-manager install and update records; resolved names, versions, sources, digests, and lockfile decisions; publisher and provenance history; process creation; and first-run network flows. Preserve a correlation identifier joining approval, acquisition, and execution. <!-- SAF-TRACE: claims=SAF-T1003-C011, SAF-T1003-C016 ; sources=SRC-mitre-det0537, SRC-npm-provenance, SRC-mcp-sep-1024 -->

Alert when activation follows a digest or signature mismatch, or when several weaker anomalies combine, such as an unapproved source, version, and publisher transition. Raise confidence for unusual first-run child processes or outbound connections; do not alert on absent optional provenance alone. <!-- SAF-TRACE: claims=SAF-T1003-C012, SAF-T1003-C015, SAF-T1003-C016 ; sources=SRC-mitre-det0537, SRC-openssf-provenance, SRC-npm-provenance, SRC-chen-etal-mcpzoo-2026 -->

The portable analytic is in [detection-rule.yml](detection-rule.yml), with deterministic coverage in [tests/test_detection.py](tests/test_detection.py).

It consumes normalized correlation summaries and requires local field mapping, baselines, threshold tuning, and production-like replay. <!-- SAF-TRACE: claims=SAF-T1003-C020 ; sources=SRC-mitre-det0537, SRC-chen-etal-mcpzoo-2026 -->

## Mitigation Strategies

- Require approval for each new server, publisher, source, and version; display the exact local-install command and arguments. <!-- SAF-TRACE: claims=SAF-T1003-C007, SAF-T1003-C011 ; sources=SRC-mcp-sep-1024, SRC-npm-provenance -->
- Use an approved internal catalog, pin immutable versions or digests, retain acquisition records, and reject integrity mismatches. <!-- SAF-TRACE: claims=SAF-T1003-C011 ; sources=SRC-npm-provenance, SRC-openssf-provenance, SRC-mitre-det0537 -->
- Treat provenance as origin and build evidence rather than a safety verdict; combine it with review, behavioral analysis, publisher history, and policy. <!-- SAF-TRACE: claims=SAF-T1003-C012 ; sources=SRC-npm-provenance, SRC-openssf-provenance -->
- Run third-party servers with least privilege, constrained credentials, restricted filesystem and network access, and appropriate sandboxing. <!-- SAF-TRACE: claims=SAF-T1003-C018 ; sources=SRC-mcp-sep-1024, SRC-mitre-t1195-002 -->
- Preserve the ability to deny an exact artifact or version in internal caches and monitor first-run behavior. <!-- SAF-TRACE: claims=SAF-T1003-C016, SAF-T1003-C019 ; sources=SRC-checkmarx-runcommand, SRC-mitre-det0537 -->

For response, disable the server, preserve configuration and acquisition evidence, block exact artifacts without deleting evidence, identify every host and cache that retained the artifact, distinguish availability from execution, investigate downstream behavior, and recover from trusted inputs. <!-- SAF-TRACE: claims=SAF-T1003-C019 ; sources=SRC-checkmarx-runcommand, SRC-mitre-det0537 -->

## Related Techniques

| Technique | Boundary |
|---|---|
| SAF-T1002 — Supply Chain Compromise | Broader supply-chain behavior; SAF-T1003 is MCP-server-specific and centers on malicious delivery. | <!-- SAF-TRACE: claims=SAF-T1003-C004 ; sources=SRC-mcp-registry-about, SRC-mitre-t1195-002 -->
| SAF-T1004 — Server Impersonation / Name-Collision | Deceptive identity is defining for the neighbor but not required here. | <!-- SAF-TRACE: claims=SAF-T1003-C004 ; sources=SRC-mcp-registry-about, SRC-mitre-t1195-002 -->
| SAF-T1006 — User-Social-Engineering Install | Persuasion is defining for the neighbor; distribution can exist without a persuasion step. | <!-- SAF-TRACE: claims=SAF-T1003-C004 ; sources=SRC-mcp-sep-1024, SRC-mitre-t1195-002 -->
| SAF-T1201 — MCP Rug Pull Attack | A trusted-to-malicious transition is defining for the neighbor; this technique describes delivery of the malicious release. | <!-- SAF-TRACE: claims=SAF-T1003-C004, SAF-T1003-C008 ; sources=SRC-checkmarx-runcommand, SRC-mitre-t1195-002 -->
| SAF-T1203 — Backdoored Server Binary | The neighbor describes malicious artifact state; this technique describes delivery. | <!-- SAF-TRACE: claims=SAF-T1003-C004 ; sources=SRC-mcp-registry-about, SRC-mitre-t1195-002 -->
| SAF-T1207 — Hijack Update Mechanism | Update-path compromise is defining for the neighbor; this technique does not require mechanism hijack. | <!-- SAF-TRACE: claims=SAF-T1003-C004 ; sources=SRC-mcp-registry-about, SRC-mitre-t1195-002 -->

Neighbor names came only from the permitted catalog ID/name projection and were registered after freeze, as recorded in the [integration notes](../../research/techniques/SAF-T1003/integration/integration-notes.yml).

## MITRE ATT&CK Mapping

MITRE ATT&CK T1195.002, Compromise Software Supply Chain, is a direct external mapping for malicious manipulation or replacement of software before consumer receipt; SAF-T1003 narrows the object and context to MCP servers. <!-- SAF-TRACE: claims=SAF-T1003-C017 ; sources=SRC-mitre-t1195-002 -->

MITRE ATT&CK DET0537 is an adjacent detection strategy correlating atypical delivery, integrity failures, installation, first run, child processes, and egress. <!-- SAF-TRACE: claims=SAF-T1003-C016, SAF-T1003-C017 ; sources=SRC-mitre-det0537, SRC-mitre-t1195-002 -->

## References

- **SRC-mcp-registry-about** — [The MCP Registry](https://modelcontextprotocol.io/registry/about), Model Context Protocol contributors.
- **SRC-mcp-registry-moderation** — [The MCP Registry Moderation Policy](https://modelcontextprotocol.io/registry/moderation-policy), Model Context Protocol contributors.
- **SRC-mcp-registry-package-types** — [MCP Registry Supported Package Types](https://modelcontextprotocol.io/registry/package-types), Model Context Protocol contributors.
- **SRC-mcp-sep-1024** — [SEP-1024](https://modelcontextprotocol.io/seps/1024-mcp-client-security-requirements-for-local-server-), Den Delimarsky, Final, 2025-07-22.
- **SRC-mcp-tools-2025-11-25** — [Tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools), specification 2025-11-25.
- **SRC-checkmarx-runcommand** — [NPM Malware Alert](https://checkmarx.com/zero-post/npm-malware-alert-lanyer640-mcp-runcommand-server-with-reverse-shell/), Darren Meyer; discovery credited to Bruno Dias, 2025-10-02.
- **SRC-jfrog-cve-2025-6514** — [CVE-2025-6514 Threatens LLM Clients](https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/), Or Peles, 2025-07-09.
- **SRC-li-gao-dsn-2026** — [A First Look at the Security Issues in the Model Context Protocol Ecosystem](https://arxiv.org/pdf/2510.16558), Xiaofan Li and Xing Gao, DSN 2026.
- **SRC-chen-etal-mcpzoo-2026** — [Rethinking MCP Security](https://arxiv.org/pdf/2607.11086), Pei Chen et al., 2026-07-13 preprint.
- **SRC-npm-provenance** — [Viewing package provenance](https://docs.npmjs.com/viewing-package-provenance/), npm Docs contributors.
- **SRC-openssf-provenance** — [Build Provenance for All Package Registries](https://repos.openssf.org/build-provenance-for-all-package-registries.html), OpenSSF working group.
- **SRC-mitre-t1195-002** — [Compromise Software Supply Chain](https://attack.mitre.org/techniques/T1195/002/), MITRE ATT&CK T1195.002 v1.1.
- **SRC-mitre-det0537** — [Behavioral detection for Supply Chain Compromise](https://attack.mitre.org/detectionstrategies/DET0537/), MITRE ATT&CK DET0537 v1.0.

## Version History

| Version | Date | Changes |
|---|---|---|
| 0.1 | 2026-09-01 | Strict clean-room rewrite with source and framework joins complete; final validation awaits cataloged neighbor SAF-T1207. |
| 0.2 | 2026-09-02 | Reconciled the supply-chain family after SAF-T1207 received its clean-room technique directory. |
