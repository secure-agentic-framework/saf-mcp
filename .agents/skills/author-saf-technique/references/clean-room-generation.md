# Clean-Room Technique Generation

Use this mode only when the user asks for a technique to be generated without
consulting its current or historical content. The goal is independent
derivation from authoritative external evidence, not merely different wording.

## Isolation boundary

Before opening any technique-specific repository path, record the target ID and
a neutral name supplied by the user or a non-prose registry. A clean-room
generator may use only:

- this skill and its routed references, except
  `impact-classification-examples.md` before freeze;
- repository-wide instructions and the canonical `techniques/TEMPLATE.md`;
- the blank schemas under `research/templates/technique/` and the general
  research protocol in `research/README.md`;
- repository-wide framework identifiers needed to join the new work, provided
  they do not contain prior technique prose or technique-specific research
  leads; and
- external sources the generator independently searches for, opens, and
  reviews in full.

Until the independent draft and evidence set are frozen, the generator must not
open or derive information from:

- the target's current or historical `README.md`;
- the target's existing research packet, traceability ledger, detection rule,
  tests, test logs, source-coverage audit, or claim inventory;
- git history, diffs, blame, stashes, commits, branches, or review comments that
  expose any prior target artifact;
- a pull request, issue, cached page, conversation, summary, or agent context
  that contains prior technique content; or
- a source list copied from the prior target artifacts; or
- `impact-classification-examples.md` or any other methodology example that
  names the target technique or supplies candidate sources for it.

The shared source manifest may be consulted only after independent searches,
source opening, and the draft evidence set have been recorded. At that point it
may be used solely to reuse stable source IDs and avoid duplicate registry
entries; it is not evidence and must not introduce a new research lead.

Use whitelist-only discovery searches. Limit each query to one or more
standards-body, government, academic-publisher, or first-party vendor or
researcher domains that cannot host the prior SAF technique. Never use an
unrestricted web query in clean-room mode. Reject
`secureagenticframework.org`, `safemcp.org`, SAF-MCP repositories and forks,
and any result whose URL, title, or snippet contains the target SAF identifier
before inspecting its substantive content.

Do not use GitHub search or GitHub-scoped discovery in clean-room mode: domain
filters and negative terms can still return the prohibited SAF repository and
expose prior target prose in a result snippet. Open an exact GitHub advisory,
release, code, or maintainer security-page URL only after its identifier and
canonical URL were obtained from a directly reviewed, non-GitHub authoritative
source such as NVD, CVE, CISA, a vendor bulletin, or a paper. Record that
provenance in the source manifest. When a target is especially prone to
search-result collisions, prefer direct authoritative URLs and first-party
catalog endpoints over a general search operation.

## Fresh-agent procedure

When the user requests a new agent, start an agent with no inherited
conversation turns. Give it only the target ID, neutral name, clean-room rules,
general templates, and authorized deliverables. The agent must read this skill
and all routed references itself. Do not send it prior conclusions, candidate
sources, intended classifications, existing prose, diffs, or summaries of the
old technique.

The generator must conduct all five research passes from scratch, including
separate searches for known production breaches, vulnerabilities, advisories,
exploitation status, demonstrations, detection, defenses, contrary evidence,
and neighboring behaviors. It must directly review sources, preserve named
authors and research teams, use exact locators, apply source-or-omit, and record
excluded leads.

Generate replacement artifacts without first reading their current contents.
Work in fresh temporary paths or replace whole target files atomically from
newly created content. Do not perform a content-preserving edit against a prior
target file.

## Contamination rule

If the generator opens any prohibited input before the independent draft is
frozen, it must stop immediately, mark the run contaminated, discard every
artifact produced by that run, and restart with a different fresh agent. A
warning, memory claim, or partial rewrite cannot cure contamination.

## Attestation and freeze

Create `research/techniques/SAF-TXXXX/clean-room-attestation.yml`. Record:

- the generation mode, target ID and neutral name, date, and fresh-agent
  identity;
- that no conversation history was inherited;
- allowed and prohibited input classes;
- exact independent search queries and the source IDs opened before manifest
  reconciliation;
- whether any prior artifact access was detected and details of any incident;
- that the independent draft and evidence set were frozen before integration;
- integration constraints; and
- unresolved integrity concerns.

`scripts/validate-technique-research.py` requires `prohibited_inputs` to
contain each of the following strings verbatim, with the target ID
substituted (matched case-insensitively as substrings); entries phrased only in
this reference's descriptive wording fail validation:

- `techniques/SAF-TXXXX/README.md`
- `research/techniques/SAF-TXXXX/`
- `techniques/SAF-TXXXX/detection-rule.yml`
- `git history`
- `pull request`
- `previous conversation`

The blank `research/templates/technique/clean-room-attestation.yml` carries
these entries as a commented block; uncomment them, replacing the standard-mode
placeholder, when setting `generation_mode: clean_room`.

The attestation may pass only when prior-artifact access is `false`, its details
are empty, the independent searches and reviewed source set are nonempty, the
draft was frozen before integration, and there are no unresolved concerns.

Before calculating freeze hashes, copy the independently generated bundle into
an isolated mock repository and run the canonical research validator there in
its default mode (without `--draft`). The
mock may use newly created minimal framework, source-manifest, and repository-
history records solely to exercise validation; it must not copy or open the real
target or shared registries. A clean-room bundle is not freeze-ready if it uses
short claim IDs, noncanonical source records, alternate packet field names,
missing required README headings, JSON-style trace comments, a noncanonical
detection rule, or deferred quality-gate names. Record the mock validation
command, result, and any deliberately deferred real-repository joins in the
attestation. A draft-mode-only pass is insufficient when failures concern
bundle-owned fields or files.

### Canonical clean-room handoff layout

Every fresh-agent run must freeze the same merge-ready layout under a scratch
root. The root is `$SAF_CLEANROOM_ROOT` when that variable is set and
`${TMPDIR:-/tmp}/saf-all-cleanroom` otherwise, which resolves to
`/tmp/saf-all-cleanroom` on Linux CI. Do not hardcode a platform-specific path
such as `/private/tmp`. The resolved root must be an absolute path outside the
repository checkout and outside every prohibited-input tree; if it is not,
stop and set `$SAF_CLEANROOM_ROOT` explicitly. A first run freezes at
`<root>/SAF-TXXXX/bundle/`. A retry or a no-research normalization re-freeze
uses `<root>/SAF-TXXXX-rN/bundle/`, with `N` starting at 2 and incrementing
per attempt. Create the root with `mkdir -p`, then create the attempt
directory with a plain `mkdir` (no `-p`) so that it fails if the directory
already exists; on collision take the next `N` rather than reusing, emptying,
or writing into an existing directory, so a stale attempt or a concurrent run
can never mix artifacts under one `FREEZE.sha256`. Record the resolved root,
the attempt directory, and the reason for any re-freeze in
`integration-notes.yml`, which is bundle-owned and already enumerates path
joins. Use no other suffix for a freeze directory:

```text
bundle/
  techniques/SAF-TXXXX/
  research/techniques/SAF-TXXXX/
  tests/SAF-TXXXX/                 # when tests are not technique-local
  validation/                      # test and default-mode validator proofs
  source-manifest-fragment.yml
  framework-fragment.yml
  alignment-fragment.yml
  integration-notes.yml
  FREEZE.sha256
```

`source-manifest-fragment.yml` must use the canonical shared-manifest schema;
`framework-fragment.yml` must use the canonical framework-model schema; and
`alignment-fragment.yml` must use the canonical alignment-ledger schema.
`integration-notes.yml` must enumerate every synthetic tactic, neighbor,
mitigation, source-ID, history-SHA, and path join that remains mechanical after
freeze, plus the freeze provenance: resolved scratch root, attempt directory,
and the reason for any re-freeze. Do not put a copied mock repository, source-
acquisition corpus, cache, or validator dependency tree inside `bundle/`;
retain those outside the bundle and record their hashes separately when needed.

`FREEZE.sha256` must contain one sorted `sha256  relative/path` line for every
bundle-owned file except `FREEZE.sha256` itself. Verify it from the bundle root
before handoff. Report the SHA-256 of `FREEZE.sha256`, the number of listed
files, the detection result, and the isolated-validator result in default
(non-`--draft`) mode. A
different handoff layout is not canonical and must be normalized and re-frozen
by a separate no-research agent before repository integration.

After the freeze, integration may mechanically replace target files, reconcile
stable source IDs, register framework joins, and run validators. Review the new
files and validation output directly. Do not inspect a diff that reveals the
old content, and do not use old prose to revise the new work. Record the passing
attestation in the `clean_room_integrity` quality gate.
