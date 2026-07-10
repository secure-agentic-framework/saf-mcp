# External Detection Coverage Registry

This directory maps SAF techniques to detection rules maintained by upstream
projects, as proposed in issue #207. It parallels the technique registry
pattern: one YAML file per SAF-T ID that has external detection coverage.

## Ownership boundary

SAFE-MCP records the pointer. Upstream projects own rule correctness.

- Each entry carries a GitHub handle as `maintainer` (maintainer-of-record),
  so stale entries have an owner to bump or remove.
- Entries are community-contributed and do not block taxonomy releases.
- This registry is distinct from `techniques/SAF-T*/detection-rule.yml`,
  which are SAFE-MCP-owned example rules living with each technique.

## File format

One file per technique, named `<SAF-T-ID>.yaml`:

```yaml
safe_t_id: SAF-T1105
detections:
  - project: atr
    rule_id: ATR-2026-00569
    version: ">=3.1.0"
    maintainer: eeee2345
    last_validated: 2026-07-10
    notes: One-line description of what the upstream rule detects.
```

| Field | Required | Meaning |
| --- | --- | --- |
| `project` | yes | Upstream project slug (lowercase). Known slugs and their rule-ID formats are listed in `validate.py`. |
| `rule_id` | yes | Stable rule identifier in the upstream project's namespace. |
| `version` | yes | Semver range of upstream releases that contain the rule (e.g. `">=3.1.0"`). |
| `maintainer` | yes | GitHub handle of the maintainer-of-record for this entry. |
| `last_validated` | yes | ISO date (YYYY-MM-DD) the mapping was last checked against both the technique description and the upstream rule content. |
| `notes` | no | Short factual description of what the upstream rule detects, so reviewers can check the mapping without leaving the file. |

## Mapping quality bar

An entry means: the referenced upstream rule detects the attack described by
the technique — verified by reading both the technique description and the
rule's detection logic, not by keyword match. When adding entries, cite what
the rule actually matches in `notes`.

## Validation

```bash
python3 detections/validate.py            # schema, ID formats, semver ranges, technique dirs
python3 detections/validate.py --online   # additionally resolve rule IDs against upstream repos
```

Requires Python 3.9+ and PyYAML (`pip install pyyaml`). The script exits
non-zero on any failure, so it can run in CI on every PR touching this
directory.

## Adding or updating entries

1. Add or edit `detections/<SAF-T-ID>.yaml` following the format above.
2. Run `python3 detections/validate.py`.
3. Open a PR. If you are updating an entry you do not maintain, tag the
   entry's maintainer-of-record.

Stale or broken entries (rule removed upstream, project archived) should be
removed by — or after pinging — the maintainer-of-record.
