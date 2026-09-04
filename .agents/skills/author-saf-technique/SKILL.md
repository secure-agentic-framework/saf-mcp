---
name: author-saf-technique
description: Research, author, rewrite, validate, and prepare exactly one SAF-MCP technique and its evidence packet. Use for new or existing SAF technique work that requires source-or-omit traceability, an exclusion ledger, current breach and vulnerability research, tested detection, framework reconciliation, publication-rights review, and author attribution.
---

# Author a SAF Technique

Produce one reviewable SAF technique whose substantive publishable content can
be traced to directly reviewed external evidence or an identified repository
artifact. Do not use this skill for a framework-wide rewrite, mitigation-only
work, or a generic security literature review.

Before changing a technique, read [references/methodology.md](references/methodology.md)
completely. During the breach and vulnerability pass, also read
[references/breach-and-vulnerability-research.md](references/breach-and-vulnerability-research.md)
completely.

For standard (non-clean-room) work, read
[references/impact-classification-examples.md](references/impact-classification-examples.md)
when calibrating incident and vulnerability classifications. A clean-room
generator must not read that example reference before its draft and evidence
set are frozen, because it may expose prior technique-specific research leads.

When the user requests clean-room generation or prohibits use of a prior
technique, also read
[references/clean-room-generation.md](references/clean-room-generation.md)
completely before any technique-specific file is opened. Clean-room work must
use the isolated-input procedure and attestation defined there. If a fresh
agent is requested or authorized, give it no inherited conversation history.

Before drafting or rewriting publishable prose, read
[references/readable-trace-format.md](references/readable-trace-format.md)
completely. Use its hidden trace-comment format so rendered prose remains
readable while every substantive unit retains its claim and source joins.

After the evidence set and draft are frozen, read
[references/framework-reconciliation.md](references/framework-reconciliation.md)
completely and run its separate ontology pass. Framework reconciliation must
not leak an existing technique's factual content into a clean-room draft.

## Repository contract

Treat these repository files as canonical:

- `techniques/TEMPLATE.md` for publishable structure;
- `research/README.md` for repository joins and evidence states;
- `research/templates/technique/` for the research packet schema;
- `research/techniques/SAF-TXXXX/traceability-ledger.yml` for the source-or-omit
  audit and excluded leads;
- `research/source-manifest.yml` for source acquisition records;
- `research/framework-model.yml` and `research/alignment-ledger.yml` for
  framework reconciliation; and
- `scripts/validate-technique-research.py` for deterministic evidence gates;
- `scripts/validate-framework-model.py` for taxonomy and operational gates; and
- `scripts/generate-technique-catalog.py` for the model-derived public catalog.

Before freezing a clean-room bundle, validate it in an isolated mock repository
against the current `scripts/validate-technique-research.py`. The mock repository
must contain only generic templates, validators, the independently generated
bundle, and minimal synthetic registry records needed to exercise joins. The
bundle must use the validator's exact README headings, full claim and source ID
syntax, packet fields, detection-rule schema, hidden trace format, and completion
statuses. Only real shared-registry collision resolution, local framework joins,
and an honest repository-history SHA may remain for post-freeze integration.
The frozen handoff must also follow the exact canonical layout and
`FREEZE.sha256` format in `references/clean-room-generation.md`; otherwise use
a separate no-research normalization agent and re-freeze before integration.

If the skill and repository disagree, preserve the stricter evidence,
traceability, safety, and publication-rights requirement and reconcile the
repository documentation as part of the same authorized technique change.

## Non-negotiable outcomes

- Bound one adversary behavior and distinguish its nearest SAF neighbors before
  drafting prose.
- Search current authoritative sources. Existing citations are research leads,
  not proof that the corpus is current or complete.
- Search separately for known production breaches, disclosed vulnerabilities,
  public advisories, and controlled demonstrations. Never use one label for
  another.
- Select two to four of the highest-impact relevant examples when the evidence
  supports them. State whether each is a direct instance, an enabling
  vulnerability, an adjacent behavior, or a rejected analogy. If no qualifying
  example exists, say so and preserve the gap.
- Apply a source-or-omit rule to every substantive sentence, list item, table
  row, diagram, example, detection choice, and response action. Connect
  external propositions to a claim ID, source ID, and exact locator. Connect
  internal status, tests, and provenance to named repository artifacts.
- Keep audit identifiers out of ordinary rendered prose. Use semantic citation
  labels and same-line `SAF-TRACE` HTML comments; expose claim and source IDs
  visibly only in the Evidence Summary, References, and research packet.
- Maintain `traceability-ledger.yml`. Record unverified candidate claims and
  examples there with their origin, attempted searches, consulted sources,
  reason for exclusion, and an `omitted_from_publishable_technique`
  disposition. Never retain an untraceable proposition in publishable prose.
- Credit named authors or research teams shown by the source, including author
  footers and advisory credits. Do not replace named authors with only the
  publisher.
- Keep examples inert and non-deployable. Describe impact without reproducing
  harmful payloads, live secrets, or destructive instructions.
- Test detection with representative positive, negative, boundary, and expected
  false-positive cases, or record a justified feasibility waiver.
- Complete source coverage, evidence classification, framework alignment,
  rights review, and quality gates before calling the technique complete.
- Apply the strict admission rule, explicit SAF Core and domain profiles, typed
  relationships, conservative detection maturity, and evidence, taxonomy, and
  operational release gates during post-freeze reconciliation.
- Preserve permanent IDs as deprecated compatibility records when a technique
  is consolidated or reclassified; never delete or reuse them.

## Rerunning an existing technique

Invalidate its prior saturation conclusion until the required current searches
are rerun. Preserve valid historical evidence, but recheck mutable sources,
advisory status, affected and fixed versions, exploitation status, framework
mappings, and neighboring techniques. Record material additions, removals,
reclassifications, excluded untraceable leads, and no-change passes in the
research packet.

This ordinary rerun procedure does not apply to clean-room generation. In
clean-room mode, do not inspect, preserve, revalidate, compare, diff, or derive
research leads from the existing technique or its technique-specific artifacts
before the independently sourced draft is frozen. Follow the contamination and
restart rules in `references/clean-room-generation.md`.

Commit, push, or open/update a pull request only when the user has authorized
that external mutation. A requested draft pull request must remain a draft.
