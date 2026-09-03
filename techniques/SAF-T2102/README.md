# SAF-T2102: Service Disruption

- **Tactic**: ATK-TA0040
- **Technique ID**: SAF-T2102
- **Research Packet**: [research/techniques/SAF-T2102/](../../research/techniques/SAF-T2102/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T2102/traceability-ledger.yml)
- **Documentation Status**: Under Review
- **Evidence Status**: Demonstrated
- **Severity**: High
- **Severity Rationale**: A single attacker-controlled request can terminate a service process, cancel another principal's work, or amplify agent-resource use enough to reduce service capacity. <!-- SAF-TRACE: claims=SAF-T2102-C001; sources=SRC-ghsa-j975-95f5-7wqh,SRC-ghsa-python-hvrp,SRC-arxiv-resource-amplification-2026 -->
- **First Observed**: No adversarial production incident was validated; the earliest selected direct public demonstration in this packet was disclosed in July 2025. <!-- SAF-TRACE: claims=SAF-T2102-C011; sources=SRC-nvd-cve-2025-53365,SRC-github-availability-2026-07 -->
- **Last Updated**: 2026-09-02

## Overview

Service Disruption is the deliberate use of MCP or agentic-system requests, task controls, or tool-mediated resource consumption to make a shared service or another principal's in-flight work unavailable or materially degraded. <!-- SAF-TRACE: claims=SAF-T2102-C001; sources=SRC-ghsa-j975-95f5-7wqh,SRC-ghsa-python-hvrp,SRC-arxiv-resource-amplification-2026 -->

## Scope

The defining boundary is crossed when attacker-controlled activity at an MCP or agent interface causes measurable loss of availability, capacity, or task continuity beyond the attacker's own work. <!-- SAF-TRACE: claims=SAF-T2102-C001; sources=SRC-ghsa-j975-95f5-7wqh,SRC-ghsa-python-hvrp,SRC-arxiv-resource-amplification-2026 -->

This technique excludes ordinary provider failures, volumetric network denial outside the MCP interface, downstream data destruction without an availability outcome, and high resource cost that has not produced measurable degradation. <!-- SAF-TRACE: claims=SAF-T2102-C010; sources=SRC-github-availability-2026-07,SRC-arxiv-aegis-2026,SRC-nist-sp800-228-upd1 -->

> **Classification note:** This technique is retained provisionally as an availability family. Its current contract spans fault-triggered termination, cross-principal task cancellation, and resource pressure; those mechanisms must not be treated as interchangeable, and each now requires a separate clean-room admission review before any narrower technique ID is assigned. [Framework Model v2 taxonomy review](../../research/taxonomy-review.yml)

## Description

An adversary may submit a request that reaches a faulty transport or lifecycle path, issue a task-control operation against work owned by another principal, or induce long agent-tool chains whose aggregate compute and memory use reduces throughput. <!-- SAF-TRACE: claims=SAF-T2102-C001; sources=SRC-ghsa-j975-95f5-7wqh,SRC-ghsa-python-hvrp,SRC-arxiv-resource-amplification-2026 -->

Current MCP tool guidance places validation, access control, rate limiting, timeouts, and usage logging at the implementation boundary; those controls are therefore prerequisites for safely exposing tool calls rather than guarantees supplied by the transport alone. <!-- SAF-TRACE: claims=SAF-T2102-C003; sources=SRC-mcp-tools-2026-07-28 -->

## Attack Vectors

- **Fault-triggered service termination**: a remote client reaches an exception path that escapes request handling and stops the server process. <!-- SAF-TRACE: claims=SAF-T2102-C005; sources=SRC-ghsa-j975-95f5-7wqh,SRC-nvd-cve-2025-53365 -->
- **Cross-principal task cancellation**: a connected client enumerates or addresses another client's task and causes it to be cancelled. <!-- SAF-TRACE: claims=SAF-T2102-C006; sources=SRC-ghsa-python-hvrp,SRC-nvd-cve-2026-52870 -->
- **Agent-tool resource amplification**: a malicious or attacker-influenced tool response steers an agent into prolonged calls that consume tokens, energy, and accelerator cache while preserving a superficially successful result. <!-- SAF-TRACE: claims=SAF-T2102-C007; sources=SRC-arxiv-resource-amplification-2026 -->

## Technical Details

MCP exposes model-controlled tools through `tools/list` and `tools/call`; servers execute the named tool using caller-supplied arguments, so availability controls must be enforced at or behind that invocation point. <!-- SAF-TRACE: claims=SAF-T2102-C002; sources=SRC-mcp-tools-2026-07-28 -->

The legacy 2025-11-25 task design required authorization-context binding and rejection of cross-context `tasks/cancel`, while also recommending per-requestor concurrency, TTL, cleanup, rate limits, resource monitoring, and lifecycle logs. <!-- SAF-TRACE: claims=SAF-T2102-C004; sources=SRC-mcp-tasks-2025-11 -->

The current Tasks extension removed `tasks/list`, requires authorization checks for each task-related request, and permits rate limiting of clients that poll faster than the advertised interval; the 2026 redesign is not wire-compatible with the legacy task surface affected by CVE-2026-52870. <!-- SAF-TRACE: claims=SAF-T2102-C012; sources=SRC-mcp-sep2663-2026 -->

## Evidence and Current State

The end-to-end technique is Demonstrated, not Observed: public advisories and controlled studies show the mechanisms and bounded consequences, but the reviewed production record did not establish adversarial causation. <!-- SAF-TRACE: claims=SAF-T2102-C001,SAF-T2102-C011; sources=SRC-ghsa-j975-95f5-7wqh,SRC-ghsa-python-hvrp,SRC-arxiv-resource-amplification-2026,SRC-github-availability-2026-07 -->

### Evidence Summary

| Claim ID | Evidence | Status |
|---|---|---|
| SAF-T2102-C001 | Direct service crash, unauthorized task cancellation, and controlled resource-amplification results establish the mechanism. | Validated |
| SAF-T2102-C002 | MCP tool invocation creates the relevant execution boundary. | Validated |
| SAF-T2102-C003 | Current tool guidance assigns rate limiting, timeouts, and logging to implementations. | Validated |
| SAF-T2102-C004 | The affected legacy task protocol specified isolation and resource controls. | Validated |
| SAF-T2102-C005 | CVE-2025-53365 documents remotely triggerable server termination. | Validated |
| SAF-T2102-C006 | CVE-2026-52870 documents cross-client task cancellation. | Validated |
| SAF-T2102-C007 | Controlled MCP-compatible tool-chain testing measured resource and throughput amplification. | Validated |
| SAF-T2102-C008 | Detection needs actor, operation, ownership, error, status, and resource telemetry. | Validated |
| SAF-T2102-C009 | The repository analytic combines cross-context cancellation, crash, and pressure signals. | Validated |
| SAF-T2102-C010 | Preventive controls include quotas, timeouts, circuit breakers, validation, and monitoring. | Validated |
| SAF-T2102-C011 | No qualifying adversarial production incident was validated in the reviewed corpus. | Validated with explicit gap |
| SAF-T2102-C012 | Current Tasks requirements narrow the legacy cross-client cancellation surface. | Validated |
| SAF-T2102-C013 | ATT&CK Endpoint Denial of Service is the closest external mapping. | Validated |

### Selected Examples

| Example | Relationship | Evidence-bounded impact | Remediation or status |
|---|---|---|---|
| CVE-2025-53365 / GHSA-j975-95f5-7wqh | Direct vulnerability | A deliberate post-session exception could crash an MCP Python SDK server and require restart; the advisory rates availability impact High. | Fixed in version 1.10.0. | <!-- SAF-TRACE: claims=SAF-T2102-C005; sources=SRC-ghsa-j975-95f5-7wqh,SRC-nvd-cve-2025-53365 -->
| CVE-2026-52870 / GHSA-hvrp-rf83-w775 | Direct vulnerability | Default experimental task handlers allowed one connected client to cancel another client's task. | Fixed in version 1.27.2; current Tasks semantics require per-request authorization. | <!-- SAF-TRACE: claims=SAF-T2102-C006,SAF-T2102-C012; sources=SRC-ghsa-python-hvrp,SRC-nvd-cve-2026-52870,SRC-mcp-sep2663-2026 -->
| Beyond Max Tokens | Direct controlled demonstration | Across six models, a protocol-compatible tool-layer attack produced trajectories above 60,000 tokens, up to 658-fold cost, 100–560-fold energy, 35–74% accelerator-cache occupancy, and about 50% lower co-running throughput. | Research prototype; no production exploitation claim was made. | <!-- SAF-TRACE: claims=SAF-T2102-C007; sources=SRC-arxiv-resource-amplification-2026 -->

## Impact Assessment

Successful disruption can terminate a server, interrupt another user's job, increase latency or error rates, reduce shared throughput, and amplify operating cost; actual blast radius depends on process isolation, restart behavior, task authorization, quotas, and infrastructure resilience. <!-- SAF-TRACE: claims=SAF-T2102-C001; sources=SRC-ghsa-j975-95f5-7wqh,SRC-ghsa-python-hvrp,SRC-arxiv-resource-amplification-2026 -->

## Detection Methods

Collect normalized MCP method and tool names, actor and task-owner identifiers, cancellation outcome, server error class, restart or health state, per-actor request counts, concurrent-task utilization, latency, and policy-enforcement events. <!-- SAF-TRACE: claims=SAF-T2102-C008; sources=SRC-nist-sp800-228-upd1,SRC-mcp-tools-2026-07-28,SRC-mcp-tasks-2025-11 -->

Alert on successful cross-owner cancellation, a transport-lifecycle error followed by service unavailability, or an actor-specific request burst at the configured concurrency-pressure boundary; suppress approved maintenance roles and tune thresholds to local baselines. <!-- SAF-TRACE: claims=SAF-T2102-C009; sources=SRC-nist-sp800-228-upd1,SRC-mitre-attack-t1499 -->

The analytic is deterministic but not exhaustive: distributed low-rate activity, failures lacking owner or health telemetry, and application-specific resource types can evade it; legitimate load tests and incident recovery can resemble disruption. <!-- SAF-TRACE: claims=SAF-T2102-C009; sources=SRC-arxiv-aegis-2026,SRC-github-availability-2026-07,SRC-nist-sp800-228-upd1 -->

### Validation

- **Test Data**: [test-logs.json](test-logs.json)
- **Validation Script**: [test_detection_rule.py](test_detection_rule.py)
- **Last Validated**: [2026-09-02 destination detector and strict-validator run](../../research/techniques/SAF-T2102/validation/canonical-validation.txt)
- **Expected Result**: [All 13 positive, negative, boundary, malformed, false-positive, normalization, and documented-evasion cases pass](../../research/techniques/SAF-T2102/validation/canonical-validation.txt).

## Mitigation Strategies

- Validate tool arguments and enforce access control and per-caller rate limits before execution; authorize every task operation against the task owner. <!-- SAF-TRACE: claims=SAF-T2102-C003,SAF-T2102-C012; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-sep2663-2026 -->
- Bound concurrency, retained task lifetime, payload size, execution time, retries, and total resource use; fail closed with circuit breakers before shared capacity is exhausted. <!-- SAF-TRACE: claims=SAF-T2102-C010; sources=SRC-nist-sp800-228-upd1,SRC-mcp-tasks-2025-11 -->
- Isolate workers, restart failed processes safely, monitor request/error/latency/resource signals, and retain actor-attributed audit events for investigation and tuning. <!-- SAF-TRACE: claims=SAF-T2102-C010; sources=SRC-nist-sp800-228-upd1,SRC-github-availability-2026-07 -->

## Related Techniques

- **[SAF-T1106: Autonomous Loop Exploit](../SAF-T1106/README.md)**: requires induced recursive or repeated agent execution; Service Disruption covers measurable unavailability across crash, cross-owner cancellation, and resource-pressure mechanisms. <!-- SAF-TRACE: claims=SAF-T2102-C010; sources=SRC-arxiv-aegis-2026,SRC-nist-sp800-228-upd1 -->
- **[SAF-T2101: Data Destruction](../SAF-T2101/README.md)**: requires deletion or irreversible corruption of stored state; Service Disruption covers unavailable or degraded service without requiring data destruction. <!-- SAF-TRACE: claims=SAF-T2102-C006,SAF-T2102-C012; sources=SRC-mcp-sep2663-2026,SRC-ghsa-python-hvrp -->

## MITRE ATT&CK Mapping

- **T1499 — Endpoint Denial of Service**: direct mapping for attacker-driven resource exhaustion or persistent crash that blocks or degrades service; SAF-T2102 specializes that outcome to MCP and agentic execution boundaries. <!-- SAF-TRACE: claims=SAF-T2102-C013; sources=SRC-mitre-attack-t1499 -->

## References

- `SRC-mcp-tools-2026-07-28` — Model Context Protocol Core Maintainers, “Tools,” specification version 2026-07-28.
- `SRC-mcp-tasks-2025-11` — Model Context Protocol Core Maintainers, “Tasks,” specification version 2025-11-25.
- `SRC-mcp-sep2663-2026` — Luca Chang and Caitie McCaffrey for the Agents Working Group, “SEP-2663: Tasks Extension.”
- `SRC-nist-sp800-228-upd1` — Ramaswamy Chandramouli and Zack Butcher, NIST SP 800-228 upd1.
- `SRC-ghsa-j975-95f5-7wqh` — Jenn Newton; Rich Harang (reporter), GitHub Security Advisory.
- `SRC-nvd-cve-2025-53365` — NIST National Vulnerability Database, CVE-2025-53365 change record.
- `SRC-ghsa-python-hvrp` — maxisbey; cjmielke, dewankpant, and shrutilohani (reporters), GitHub Security Advisory.
- `SRC-nvd-cve-2026-52870` — NIST National Vulnerability Database and CISA ADP, CVE-2026-52870 record.
- `SRC-arxiv-resource-amplification-2026` — Kaiyu Zhou, Yongsen Zheng, Yicheng He, Meng Xue, Xueluan Gong, Yuji Wang, Xuanye Zhang, and Kwok-Yan Lam, arXiv:2601.10955v2.
- `SRC-arxiv-aegis-2026` — Shriti Priya, Teryl Taylor, and Frederico Araujo, arXiv:2608.20481v1.
- `SRC-github-availability-2026-07` — Jakub Oleksy, GitHub availability report: July 2026.
- `SRC-mitre-attack-t1499` — Alfredo Oliveira, David Fiser, Magno Logan, Vishwas Manral, and Yossi Weizman with the Azure Defender Research Team, ATT&CK T1499.

## Version History

| Version | Date | Changes |
|---|---|---|
| 1.0 | 2026-09-02 | Clean-room research draft with tested detection and frozen evidence packet. |
| 1.1 | 2026-09-02 | Returned the technique to Under Review and recorded its provisional availability-family classification pending three atomic admission reviews. |
