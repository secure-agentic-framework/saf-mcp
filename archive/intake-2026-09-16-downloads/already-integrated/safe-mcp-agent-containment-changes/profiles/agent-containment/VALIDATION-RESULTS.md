# Repository validation results

Validation date: 2026-09-16. Repository base: `d3d40297c478d2680d315399b6aaf317e5aa15b8`.

This record describes checks executed on the changed repository. It does not claim deployment, cryptographic, incident-reproduction, or production detection validation. All 34 deployment acceptance cases remain planned.

| Check | Result |
| --- | --- |
| `python3 -m unittest discover -s scripts -p 'test_*.py'` | PASS: 30 tests, including 15 new containment metadata regression cases |
| `python3 scripts/validate-technique-research.py --all` | PASS: all 86 registered technique packets |
| `python3 scripts/validate-framework-model.py` | PASS: 86 registered IDs, 78 active techniques |
| `python3 scripts/validate-detection-registry.py` | PASS: 78 active native mappings; existing coverage unchanged |
| `python3 scripts/generate-detection-coverage.py --check` | PASS |
| `python3 scripts/generate-technique-catalog.py --check` | PASS |
| `python3 scripts/generate-mitigation-catalog.py --check` | PASS: 59 mitigation documents after eight additions |
| `python3 scripts/validate-containment-profile.py` | PASS: IDs, mappings, requirement/test joins, mitigation joins, and local links |
| `python3 scripts/generate-containment-profile.py --check` | PASS: generated profile documents match the catalog |
| `git diff --check` | PASS |
| Comparison against the base framework model | PASS: existing technique IDs, names, scope, lifecycle, evidence status, and detection maturity preserved; only proposed mitigation references added |

The new regression cases reject duplicate identifiers and YAML keys, deprecated or unknown techniques, unknown requirements and tactics, unsupported evidence or detection promotions, unreviewed ATT&CK IDs, mismatched test and mitigation joins, and broken document links. These checks establish consistency, not security effectiveness.

The changed-files archive contains 33 repository-relative paths: five replacements and 28 additions, with no deletions. Its [manifest](OVERWRITE-MANIFEST.json) records content hashes and the original hashes of replaced files. The manifest excludes its own hash to avoid circularity. Archive integrity, entry paths, manifest hashes, and byte-for-byte agreement with the final working files are checked during packaging.

See [APPLY.md](APPLY.md) for extraction instructions and [VALIDATION.md](VALIDATION.md) for the separate deployment acceptance plan.
