# Apply the changed-files ZIP

The archive contains only new and modified files, using paths relative to the root of `soltrinox/safe-mcp`. There is no enclosing `safe-mcp/` directory. It contains no `.git` directory, credentials, manuscript attachments, or deletion instructions.

The base is `main` at commit `d3d40297c478d2680d315399b6aaf317e5aa15b8`. The local preparation branch is `feat/agent-containment-owner-authorization`. This archive does not create a GitHub branch, make a commit, or push changes.

1. Save or commit any local work first: extracting the ZIP replaces matching paths rather than merging their contents.
2. Open the existing repository root, the folder containing `README.md`, `techniques/`, and `mitigations/`.
3. Optionally create a local branch:

   ```bash
   git switch -c feat/agent-containment-owner-authorization
   ```

4. Extract the archive into that repository root and allow replacement of the listed files.
5. Review `git diff --stat` and the profile's [overwrite manifest](OVERWRITE-MANIFEST.json). If your local branch has newer changes in the same files, reconcile them rather than discarding them.
6. Install the existing development requirements if needed and validate:

   ```bash
   python3 -m pip install -r requirements-dev.txt
   python3 -m unittest discover -s scripts -p 'test_*.py'
   python3 scripts/validate-containment-profile.py
   python3 scripts/generate-containment-profile.py --check
   python3 scripts/validate-framework-model.py
   python3 scripts/validate-detection-registry.py
   python3 scripts/generate-detection-coverage.py --check
   python3 scripts/generate-mitigation-catalog.py --check
   python3 scripts/generate-technique-catalog.py --check
   python3 scripts/validate-technique-research.py --all
   ```

The ZIP adds 28 contextual attack-assessment items, 34 requirements and planned deployment tests, eight proposed mitigation controls, and metadata validation. The original canonical technique count and evidence statuses are unchanged. The validation workflow is extended to run the new profile checks.

The included [validation report](VALIDATION-RESULTS.md) describes repository checks executed before packaging. It does not report deployment or cryptographic validation. The separate [acceptance plan](VALIDATION.md) lists the security evaluations still needed for an implementation.

When ready to commit, follow [CONTRIBUTING.md](../../CONTRIBUTING.md), including its DCO sign-off requirement and the repository's licenses. Use your own configured contributor identity.
