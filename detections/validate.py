#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate detections/ registry files.

Checks (offline, default):
  - filename is <SAF-T-ID>.yaml and matches the safe_t_id field
  - techniques/<SAF-T-ID>/ exists in this repository
  - every entry has project / rule_id / version / maintainer / last_validated
  - rule_id matches the known format for the project (when known)
  - version is a valid semver range (space-separated comparators)
  - maintainer looks like a GitHub handle
  - last_validated is an ISO date (YYYY-MM-DD)

With --online, additionally resolves each rule_id against the upstream
repository to confirm the referenced rule file exists.

Usage:
  python3 detections/validate.py [--online]

Requires Python 3.9+ and PyYAML.
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import sys
import urllib.request
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("PyYAML is required: pip install pyyaml")

DETECTIONS_DIR = Path(__file__).resolve().parent
REPO_ROOT = DETECTIONS_DIR.parent

FILENAME_RE = re.compile(r"^SAF-T\d{4}\.yaml$")
SEMVER_COMPARATOR_RE = re.compile(r"^(>=|<=|>|<|=|~|\^)?\d+\.\d+\.\d+$")
GITHUB_HANDLE_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$")

REQUIRED_FIELDS = ("project", "rule_id", "version", "maintainer", "last_validated")
OPTIONAL_FIELDS = ("notes",)

# Known upstream projects: rule-ID format and an online resolver.
# The resolver returns the set of rule IDs present in the upstream repo.
KNOWN_PROJECTS = {
    "atr": {
        "rule_id_re": re.compile(r"^ATR-\d{4}-\d{4,5}$"),
        "tree_url": (
            "https://api.github.com/repos/Agent-Threat-Rule/"
            "agent-threat-rules/git/trees/main?recursive=1"
        ),
        "rule_path_re": re.compile(r"^rules/.+/(ATR-\d{4}-\d{4,5})-.+\.yaml$"),
    },
}


def check_entry(entry: object, source: str) -> list[str]:
    """Validate one detection entry; returns a list of error strings."""
    if not isinstance(entry, dict):
        return [f"{source}: entry is not a mapping"]

    errors = []
    unknown = set(entry) - set(REQUIRED_FIELDS) - set(OPTIONAL_FIELDS)
    if unknown:
        errors.append(f"{source}: unknown field(s): {', '.join(sorted(unknown))}")

    missing = [f for f in REQUIRED_FIELDS if f not in entry]
    if missing:
        errors.append(f"{source}: missing field(s): {', '.join(missing)}")
        return errors

    project = entry["project"]
    if not isinstance(project, str) or not re.match(r"^[a-z0-9][a-z0-9-]{0,40}$", project):
        errors.append(f"{source}: project must be a lowercase slug, got {project!r}")

    rule_id = entry["rule_id"]
    if not isinstance(rule_id, str) or not rule_id:
        errors.append(f"{source}: rule_id must be a non-empty string")
    elif isinstance(project, str) and project in KNOWN_PROJECTS:
        pattern = KNOWN_PROJECTS[project]["rule_id_re"]
        if not pattern.match(rule_id):
            errors.append(
                f"{source}: rule_id {rule_id!r} does not match the "
                f"{project} format {pattern.pattern}"
            )

    version = entry["version"]
    if not isinstance(version, str) or not version.strip():
        errors.append(f"{source}: version must be a non-empty semver range string")
    else:
        bad = [t for t in version.split() if not SEMVER_COMPARATOR_RE.match(t)]
        if bad:
            errors.append(
                f"{source}: invalid semver comparator(s) {bad} in version {version!r} "
                '(expected e.g. ">=3.1.0" or ">=3.1.0 <4.0.0")'
            )

    maintainer = entry["maintainer"]
    if not isinstance(maintainer, str) or not GITHUB_HANDLE_RE.match(maintainer):
        errors.append(f"{source}: maintainer must be a GitHub handle, got {maintainer!r}")

    last_validated = entry["last_validated"]
    date_str = (
        last_validated.isoformat()
        if isinstance(last_validated, datetime.date)
        else last_validated
    )
    try:
        datetime.date.fromisoformat(str(date_str))
    except ValueError:
        errors.append(f"{source}: last_validated must be YYYY-MM-DD, got {last_validated!r}")

    notes = entry.get("notes")
    if notes is not None and not isinstance(notes, str):
        errors.append(f"{source}: notes must be a string")

    return errors


def check_file(path: Path) -> tuple[list[str], list[dict]]:
    """Validate one registry file; returns (errors, entries)."""
    if not FILENAME_RE.match(path.name):
        return ([f"{path.name}: filename must be <SAF-T-ID>.yaml"], [])

    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return ([f"{path.name}: YAML parse error: {exc}"], [])

    if not isinstance(data, dict):
        return ([f"{path.name}: top level must be a mapping"], [])

    errors = []
    expected_id = path.stem
    if data.get("safe_t_id") != expected_id:
        errors.append(
            f"{path.name}: safe_t_id {data.get('safe_t_id')!r} does not match "
            f"filename (expected {expected_id!r})"
        )

    technique_dir = REPO_ROOT / "techniques" / expected_id
    if not technique_dir.is_dir():
        errors.append(f"{path.name}: no technique directory at techniques/{expected_id}/")

    unknown_top = set(data) - {"safe_t_id", "detections"}
    if unknown_top:
        errors.append(f"{path.name}: unknown top-level field(s): {', '.join(sorted(unknown_top))}")

    entries = data.get("detections")
    if not isinstance(entries, list) or not entries:
        errors.append(f"{path.name}: detections must be a non-empty list")
        return (errors, [])

    for i, entry in enumerate(entries):
        errors.extend(check_entry(entry, f"{path.name}: detections[{i}]"))

    return (errors, [e for e in entries if isinstance(e, dict)])


def fetch_upstream_rule_ids(project: str) -> set[str] | None:
    """Fetch the set of rule IDs published by a known upstream project."""
    config = KNOWN_PROJECTS.get(project)
    if config is None:
        return None
    request = urllib.request.Request(
        config["tree_url"], headers={"Accept": "application/vnd.github+json"}
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        tree = json.load(response).get("tree", [])
    matches = (config["rule_path_re"].match(node.get("path", "")) for node in tree)
    return {m.group(1) for m in matches if m}


def check_online(entries: list[dict]) -> list[str]:
    """Resolve rule IDs against upstream repos; returns error strings."""
    errors = []
    projects = {e["project"] for e in entries if e.get("project") in KNOWN_PROJECTS}
    for project in sorted(projects):
        try:
            upstream_ids = fetch_upstream_rule_ids(project)
        except OSError as exc:
            errors.append(f"online: could not fetch {project} rule index: {exc}")
            continue
        for entry in entries:
            if entry.get("project") == project and entry["rule_id"] not in upstream_ids:
                errors.append(
                    f"online: {entry['rule_id']} not found in upstream {project} repository"
                )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--online",
        action="store_true",
        help="also resolve rule IDs against upstream repositories",
    )
    args = parser.parse_args()

    files = sorted(p for p in DETECTIONS_DIR.glob("*.yaml"))
    if not files:
        print("no registry files found in detections/")
        return 1

    all_errors = []
    all_entries = []
    for path in files:
        errors, entries = check_file(path)
        all_errors.extend(errors)
        all_entries.extend(entries)

    if args.online and not all_errors:
        all_errors.extend(check_online(all_entries))

    if all_errors:
        for error in all_errors:
            print(f"FAIL {error}")
        print(f"\n{len(all_errors)} error(s) across {len(files)} file(s)")
        return 1

    print(f"OK {len(files)} file(s), {len(all_entries)} detection entr(y/ies) valid")
    return 0


if __name__ == "__main__":
    sys.exit(main())
