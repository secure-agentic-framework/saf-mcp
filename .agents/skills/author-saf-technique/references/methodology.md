# SAF Technique Authoring Methodology

Use this sequence for one new, rewritten, or refreshed technique. Complete the
research records as the work proceeds; do not reconstruct them from memory
after drafting.

## 1. Inspect and establish provenance

If the user requests clean-room generation, replace this section's ordinary
inspection procedure with `clean-room-generation.md`. Read that reference
before opening any technique-specific path. Do not inspect the current or
historical technique, its research packet, detection assets, pull request, or
conversation-derived technique content before the independent draft is frozen.

Read repository instructions, the current technique, detection assets, nearest
neighbors, linked mitigations, framework records, open alignment issues, and
git status. Preserve user changes. For an existing technique, record its prior
claims and citations as leads to revalidate rather than accepted evidence.

Record the human authors already credited in the technique's version history.
When reviewing every external page, paper, advisory, repository, or dataset,
inspect its byline, author footer, contributor credits, acknowledgments, and
canonical citation metadata. Carry those credits into the source manifest,
publication-rights record, References, and any example that depends materially
on the source.

## 2. Write the technique contract

Complete `technique-contract.yml` before prose. Define:

- one immediate adversary objective;
- the MCP or agentic component and trust boundary;
- in-scope mechanism, preconditions, and immediate outcome;
- out-of-scope delivery, adjacent behavior, downstream impact, and mitigation;
- nearest SAF neighbors and operational distinctions;
- required protocol, incident, vulnerability, demonstration, detection, and
  defense evidence;
- detection telemetry or a proposed feasibility waiver;
- safe-publication constraints; and
- completion conditions.

A product CVE is evidence for a technique only when its root cause and attack
path satisfy the contract. Shared impact or vocabulary is insufficient.

## 3. Build the claim inventory

List every externally verifiable proposition before drafting, including
low-severity or contextual statements. Include protocol behavior, defining
mechanism, prerequisites, attack flow, evidence classification, incident and
vulnerability relationships, impact conditions, detection, limitations,
mitigations, and framework mappings. “Material claim” is not an exception that
permits unsourced explanatory prose.

Use the repository claim classes. For each claim record materiality, support
relationship, exact locator, corroboration, limitations, conflicts, whether it
is an inference, and validation status. Split compound claims when one source
does not support the whole proposition.

Treat absence claims narrowly. “No qualifying production incident was found in
the reviewed corpus as of DATE” can be supported by a documented search;
“this has never happened” cannot.

Create `traceability-ledger.yml` at the same time. Its policy is
`source_or_omit`. Identify repository artifacts that support internal status,
test results, and revision provenance. Put every candidate proposition that
cannot be validated in the exclusion list with its origin, attempted searches,
consulted source IDs, exclusion reason, prohibited publishable wording, and
`omitted_from_publishable_technique` disposition. The ledger preserves the
research lead, not permission to publish it.

## 4. Research in five passes

Open and review complete sources. Search results, snippets, abstracts, citation
lists, AI summaries, vulnerability database scores, and repository metadata are
discovery aids rather than evidence for substantive claims.

### A. Protocol and authority

Review current versioned MCP specifications, official implementation guidance,
applicable RFCs and standards, and first-party security requirements. Record
versions and exact sections. Establish what the protocol requires separately
from how a particular client behaves.

### B. Known breaches and vulnerabilities

Follow
[breach-and-vulnerability-research.md](breach-and-vulnerability-research.md).
Search production incidents, postmortems, vendor advisories, CVE records,
GitHub Security Advisories, maintainers' fixes, affected versions, exploitation
status, and high-quality disclosure reports. Classify and rank examples before
selecting two to four for publication.

### C. Demonstration and empirical research

Find original disclosures, reproducible proofs of concept, source code, tests,
benchmarks, peer-reviewed work, and methodologically transparent evaluations.
Distinguish an end-to-end demonstration from a component-only result and a
realistic test environment from production exploitation.

### D. Detection and defense

Find the telemetry, identifiers, event sequences, platform controls, patches,
and mitigation limits needed to make operational claims. Prefer first-party
schemas and control documentation. Seek accuracy evaluations before claiming a
scanner or detector is effective.

### E. Gap and challenge

Search for fixed behavior, failed reproductions, contrary results, false
positives, alternate explanations, missing preconditions, unaffected versions,
and neighboring SAF techniques. Attempt to falsify the scope, evidence label,
impact, and detection claims. Record consulted-but-rejected sources and why
they do not support the technique.

## 5. Reach and record saturation

After the five passes, run narrower and synonymous queries, official-site
searches, version variants, backward and forward citation trails, and advisory
cross-references. Stop only after two consecutive follow-up passes add no new:

- controlling requirement;
- direct incident or vulnerability relationship;
- high-impact qualifying example;
- material fact or independent corroboration;
- exception, conflict, or changed remediation status;
- detection or mitigation constraint;
- source for an unsupported publishable proposition; or
- distinction from a neighboring technique.

Record queries, dates, changes, both no-change passes, rejected sources,
blocked sources, conflicts, and the saturation rationale in
`source-coverage.yml`. A blocked source is an unresolved gap, not saturation.

## 6. Acquire sources and review publication rights

Prefer sources in this order: current standards; primary incident reports and
official advisories; first-party code, fixes, tests, and release notes;
peer-reviewed or transparent empirical research; technically reviewable
practitioner analysis; and secondary context.

For every consulted source, record canonical URL, publisher, named authors,
date or version, access and review dates, review method, exact locators, what
was verified, and archive state in `source-manifest.yml`. Archive lawful,
redistributable material when practical. Never commit credentials, gated
copies, unsafe exploit artifacts, or third-party material the project cannot
redistribute.

Complete `publication-rights.yml` for cited sources and any quotation, code,
image, diagram, table, dataset, or trademark. Direct review permits factual
citation; it does not grant republication rights. Prefer original paraphrase
with close citation.

## 7. Classify the evidence

Set the technique evidence label from the defining end-to-end behavior:

- **Observed**: a directly reviewed primary source documents the behavior in a
  real MCP or agentic-system production incident.
- **Demonstrated**: the complete behavior was reproduced publicly or in a
  controlled evaluation.
- **Research-Derived**: independently supported components justify the complete
  behavior only as an explicit inference.
- **Hypothesized**: the behavior is plausible but lacks direct or sufficient
  component evidence.

An enabling CVE, adjacent breach, historical analogy, scanner finding, or
marketing statement cannot raise this label. Document unresolved uncertainty
next to the affected claim.

## 8. Draft from validated claims

Follow `techniques/TEMPLATE.md`; keep all required sections. Cite each
substantive externally verifiable statement inline, including prose presented
as context, limitations, table cells, detection guidance, and response
procedures. In the Evidence Summary, expose the claim ID, source ID, evidence
type, and limitation.

Follow `readable-trace-format.md`. Keep ordinary rendered prose free of bare
claim and source IDs. Use semantic citation labels and attach claim/source joins
as same-line `SAF-TRACE` HTML comments. Set `trace_format: hidden_html_v1` in
the contract. The Evidence Summary and References remain the visible audit
indexes; hiding identifiers must not hide uncertainty, limitations, or source
attribution.

In the current-state material, include a concise **Known Breaches and
Vulnerabilities** subsection. Present the selected examples in descending
relevance and impact. For each, give the date, affected product or environment,
observed or potential impact, remediation state, relationship to this
technique, and evidence limitation. Use “None identified in the reviewed
corpus” when no direct production breach qualifies; do not fill the section
with adjacent events merely to make it look complete.

Keep historical analogy and adjacent vulnerabilities separate from direct
evidence. Include only safe, minimal technical detail. Credit source authors in
the prose when their work is the basis of a named discovery or demonstration,
and include full attribution in References.

Perform a source-or-omit audit after drafting. Treat each paragraph, list item,
table row, diagram, code block, and analytic choice as a publishable unit.
External units must expose at least one validated claim ID. Repository-derived
units must link a local artifact declared in the traceability ledger. Structural
headings and table labels are not propositions. A diagram or safe synthetic
example must have an immediately adjacent traced explanation. The validator
must resolve every hidden trace claim and source pair before the source-or-omit
gate passes. Delete unsupported content from the technique and record the
omitted lead in the ledger.

## 9. Make detection testable

Name required telemetry and fields. Explain the analytic goal, logic,
correlation window, false positives, blind spots, evasion opportunities, and
tuning assumptions. Keep the executable analytic in
`techniques/SAF-TXXXX/detection-rule.yml`, beside the technique README rather
than inside the research packet.

When feasible, add deterministic tests covering true positives, true
negatives, threshold or sequence boundaries, malformed or missing fields,
expected legitimate lookalikes, and relevant encoding or normalization cases.
Record the exact commands and results in `quality-review.yml`. Syntax validity
alone is not detection validation.

## 10. Reconcile and complete

Reconcile the technique with `framework-model.yml`, nearest SAF techniques,
tactics, mitigations, detection artifacts, ATT&CK and ATLAS mappings, and
evidence status. Add cross-document work to `alignment-ledger.yml`; resolve
high-severity issues before completion.

Run the technique-specific detection tests, the research validator, and the
workflow regression tests. Then complete every gate in `quality-review.yml`.
Do not mark a gate passed while a substantive statement, source, conflict, right,
alignment issue, test, or required example classification remains unresolved.

The source-or-omit gate passes only when the publishable-unit audit has no
untraced unit, every claim ID and source ID resolves, every local evidence link
is declared, every exclusion remains absent from publishable prose, and the
ledger has no unresolved item.

For a clean-room run, complete `clean-room-attestation.yml` and pass the
`clean_room_integrity` gate. Integration may begin only after the independently
sourced draft and evidence set are frozen. Never use a comparison with the old
technique as a source of facts, examples, citations, wording, or omissions.

When authorized to prepare a pull request, inspect the full diff, preserve
existing authorship, commit only scoped files, push the intended branch, and
verify that a requested draft pull request is still a draft.
