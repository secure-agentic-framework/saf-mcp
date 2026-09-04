#!/usr/bin/env python3
"""Validate SAF technique research packets and their joined artifacts."""

from __future__ import annotations

import argparse
import re
import sys
import uuid
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError as exc:  # pragma: no cover - depends on contributor environment
    raise SystemExit("PyYAML is required: python3 -m pip install PyYAML") from exc


TECHNIQUE_ID = re.compile(r"SAF-T[1-9][0-9]{3}$")
CLAIM_ID = re.compile(r"SAF-T[1-9][0-9]{3}-C[0-9]{3}$")
SOURCE_ID = re.compile(r"SRC-[a-z0-9][a-z0-9._-]*$")
TACTIC_ID = re.compile(r"ATK-TA[0-9]{4}$")
CLAIM_REFERENCE = re.compile(r"SAF-T[1-9][0-9]{3}-C[0-9]{3}")
SOURCE_REFERENCE = re.compile(r"SRC-[a-z0-9][a-z0-9._-]*")
EXCLUSION_ID = re.compile(r"SAF-T[1-9][0-9]{3}-X[0-9]{3}$")
MARKDOWN_LINK = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
TRACE_COMMENT_START = re.compile(r"<!--\s*SAF-TRACE:")
TRACE_COMMENT = re.compile(
    rf"<!--\s*SAF-TRACE:\s*"
    rf"claims=(?P<claims>{CLAIM_REFERENCE.pattern}(?:\s*,\s*{CLAIM_REFERENCE.pattern})*)"
    rf"\s*;\s*"
    rf"sources=(?P<sources>{SOURCE_REFERENCE.pattern}(?:\s*,\s*{SOURCE_REFERENCE.pattern})*)"
    rf"\s*-->"
)
HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)

CLAIM_CLASSES = {
    "protocol_normative",
    "observed_incident",
    "disclosed_vulnerability",
    "demonstrated_exploit",
    "research_finding",
    "implementation_fact",
    "historical_analogy",
    "framework_inference",
}
EVIDENCE_STATUSES = {"observed", "demonstrated", "research-derived", "hypothesized"}
SOURCE_CLASSES = {
    "protocol_or_standard",
    "official_advisory",
    "incident_report",
    "implementation_artifact",
    "research",
    "credible_practice",
    "secondary",
}
ARCHIVE_STATUSES = {
    "archived",
    "gated_not_archived",
    "remote_reviewed_not_archived",
    "pending",
}
REQUIRED_PACKET_FILES = (
    "clean-room-attestation.yml",
    "technique-contract.yml",
    "claim-inventory.yml",
    "source-coverage.yml",
    "publication-rights.yml",
    "quality-review.yml",
    "traceability-ledger.yml",
)
REQUIRED_HEADINGS = (
    "## Overview",
    "## Scope",
    "## Description",
    "## Attack Vectors",
    "## Technical Details",
    "## Evidence and Current State",
    "## Impact Assessment",
    "## Detection Methods",
    "## Mitigation Strategies",
    "## Related Techniques",
    "## MITRE ATT&CK Mapping",
    "## References",
    "## Version History",
)
REQUIRED_GATES = {
    "clean_room_integrity",
    "contract_and_scope",
    "technical_accuracy",
    "claim_traceability",
    "source_or_omit",
    "evidence_classification",
    "research_saturation",
    "breach_and_vulnerability_coverage",
    "detection_quality",
    "mitigation_quality",
    "framework_alignment",
    "publication_rights",
    "safe_publication",
}
RESEARCH_PASSES = {
    "protocol_and_authority",
    "known_breaches_and_vulnerabilities",
    "demonstration_and_empirical_research",
    "detection_and_defense",
    "gap_and_challenge",
}
BREACH_RELATIONSHIPS = {
    "direct_production_incident",
    "direct_vulnerability",
    "direct_demonstration",
    "enabling_vulnerability",
    "adjacent_incident_or_vulnerability",
    "historical_analogy",
    "rejected",
}


class Check:
    def __init__(self, technique_id: str) -> None:
        self.technique_id = technique_id
        self.errors: list[str] = []

    def require(self, condition: Any, message: str) -> None:
        if not condition:
            self.errors.append(message)


def load_yaml(path: Path, check: Check) -> dict[str, Any]:
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        check.errors.append(f"{path}: cannot load YAML: {exc}")
        return {}
    if not isinstance(value, dict):
        check.errors.append(f"{path}: top-level value must be a mapping")
        return {}
    return value


def nonempty_list(value: Any) -> bool:
    return (
        isinstance(value, list)
        and bool(value)
        and all(item not in (None, "") for item in value)
    )


def is_table_separator(line: str) -> bool:
    stripped = line.strip()
    if not stripped.startswith("|") or not stripped.endswith("|"):
        return False
    cells = [cell.strip() for cell in stripped.strip("|").split("|")]
    return bool(cells) and all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells)


def declared_local_link(
    line: str, root: Path, readme_path: Path, declared_paths: set[str]
) -> bool:
    for target in MARKDOWN_LINK.findall(line):
        target = target.split("#", 1)[0]
        if not target or target.startswith(("http://", "https://", "#")):
            continue
        resolved = (readme_path.parent / target).resolve()
        try:
            repository_path = resolved.relative_to(root.resolve()).as_posix()
        except ValueError:
            continue
        if repository_path in declared_paths:
            return True
    return False


def visible_claim_lines_outside_evidence_summary(readme: str) -> list[int]:
    """Find rendered claim IDs outside the intentionally visible audit table."""

    without_comments = HTML_COMMENT.sub(
        lambda match: "\n" * match.group(0).count("\n"), readme
    )
    failures: list[int] = []
    current_section = ""
    current_subsection = ""
    for index, line in enumerate(without_comments.splitlines()):
        stripped = line.strip()
        if stripped.startswith("## "):
            current_section = stripped
            current_subsection = ""
        elif stripped.startswith("### "):
            current_subsection = stripped
        in_evidence_summary = (
            current_section == "## Evidence and Current State"
            and current_subsection == "### Evidence Summary"
        )
        if not in_evidence_summary and CLAIM_REFERENCE.search(line):
            failures.append(index + 1)
    return failures


def untraced_publishable_lines(
    readme: str,
    root: Path,
    readme_path: Path,
    claim_ids: set[str],
    declared_paths: set[str],
) -> list[int]:
    """Return substantive README lines that expose no approved trace."""

    lines = readme.splitlines()
    failures: list[int] = []
    in_fence = False
    in_comment = False
    previous_nonblank = ""
    current_section = ""
    internal_metadata = re.compile(
        r"^- \*\*(?:Tactic|Technique ID|Research Packet|Traceability Ledger|"
        r"Documentation Status|Evidence Status|Severity|Last Updated)\*\*:"
    )
    structural_list_label = re.compile(r"^\s*[-*]\s+\*\*[^*]+\*\*:\s*$")

    def traced(line: str) -> bool:
        references = set(CLAIM_REFERENCE.findall(line))
        return bool(references & claim_ids) or declared_local_link(
            line, root, readme_path, declared_paths
        )

    for index, line in enumerate(lines):
        stripped = line.strip()
        line_number = index + 1

        if in_comment:
            if "-->" in stripped:
                in_comment = False
            continue
        if stripped.startswith("<!--"):
            if "-->" not in stripped:
                in_comment = True
            continue
        if stripped.startswith(("```", "~~~")):
            if not in_fence and not traced(previous_nonblank):
                failures.append(line_number)
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        if not stripped:
            continue
        if stripped.startswith("#"):
            if stripped.startswith("## "):
                current_section = stripped
            previous_nonblank = line
            continue
        if stripped == "---" or is_table_separator(line):
            continue
        if index + 1 < len(lines) and is_table_separator(lines[index + 1]):
            previous_nonblank = line
            continue
        if internal_metadata.match(stripped) or structural_list_label.match(stripped):
            previous_nonblank = line
            continue
        if current_section == "## Version History" and stripped.startswith("|"):
            previous_nonblank = line
            continue

        claim_references = set(CLAIM_REFERENCE.findall(line))
        if claim_references & claim_ids:
            previous_nonblank = line
            continue
        if current_section == "## References" and SOURCE_REFERENCE.search(line):
            previous_nonblank = line
            continue
        if declared_local_link(line, root, readme_path, declared_paths):
            previous_nonblank = line
            continue

        failures.append(line_number)
        previous_nonblank = line

    return failures


def records_by_id(
    records: Any, key: str, check: Check, label: str
) -> dict[str, dict[str, Any]]:
    if not isinstance(records, list):
        check.errors.append(f"{label} must be a list")
        return {}
    result: dict[str, dict[str, Any]] = {}
    for record in records:
        if not isinstance(record, dict) or not record.get(key):
            check.errors.append(f"every {label} record must have {key}")
            continue
        record_id = str(record[key])
        if record_id in result:
            check.errors.append(f"duplicate {label} ID: {record_id}")
        result[record_id] = record
    return result


def validate_source(
    source_id: str, source: dict[str, Any], strict: bool, check: Check
) -> None:
    check.require(
        bool(SOURCE_ID.fullmatch(source_id)), f"invalid source ID: {source_id}"
    )
    for field in (
        "title",
        "publisher",
        "version_or_date",
        "official_url",
        "accessed_on",
        "reviewed_on",
        "review_method",
        "review_notes",
    ):
        check.require(bool(source.get(field)), f"{source_id}: missing {field}")
    check.require(nonempty_list(source.get("authors")), f"{source_id}: authors required")
    check.require(
        source.get("source_class") in SOURCE_CLASSES,
        f"{source_id}: invalid source_class",
    )
    check.require(
        str(source.get("official_url", "")).startswith(("https://", "http://")),
        f"{source_id}: official_url must be an HTTP(S) URL",
    )
    check.require(
        nonempty_list(source.get("locators")), f"{source_id}: exact locators required"
    )
    if strict:
        check.require(
            source.get("review_status") == "opened_reviewed",
            f"{source_id}: review_status must be opened_reviewed",
        )
    archive = source.get("archive")
    check.require(isinstance(archive, dict), f"{source_id}: archive record required")
    if not isinstance(archive, dict):
        return
    status = archive.get("status")
    check.require(status in ARCHIVE_STATUSES, f"{source_id}: invalid archive status")
    if strict:
        check.require(status != "pending", f"{source_id}: archive status is pending")
    if status == "archived":
        for field in ("path", "retrieved_on", "sha256", "bytes", "mime_type"):
            check.require(
                bool(archive.get(field)),
                f"{source_id}: archived source missing {field}",
            )
        check.require(
            bool(re.fullmatch(r"[0-9a-f]{64}", str(archive.get("sha256", "")))),
            f"{source_id}: archive sha256 must be 64 lowercase hexadecimal characters",
        )
        check.require(
            isinstance(archive.get("bytes"), int) and archive["bytes"] > 0,
            f"{source_id}: archive bytes must be a positive integer",
        )
        extraction = source.get("extracted_text")
        check.require(
            isinstance(extraction, dict), f"{source_id}: extracted_text required"
        )
        if isinstance(extraction, dict):
            for field in ("path", "method", "sha256", "bytes"):
                check.require(
                    bool(extraction.get(field)),
                    f"{source_id}: extraction missing {field}",
                )
            check.require(
                bool(re.fullmatch(r"[0-9a-f]{64}", str(extraction.get("sha256", "")))),
                f"{source_id}: extraction sha256 must be 64 lowercase hexadecimal characters",
            )
            check.require(
                isinstance(extraction.get("bytes"), int) and extraction["bytes"] > 0,
                f"{source_id}: extraction bytes must be a positive integer",
            )
    elif status in {"gated_not_archived", "remote_reviewed_not_archived"}:
        check.require(
            bool(archive.get("reason")), f"{source_id}: archive exception needs reason"
        )
        check.require(
            isinstance(archive.get("review_evidence"), dict),
            f"{source_id}: archive exception needs review_evidence",
        )


def validate_technique(root: Path, technique_id: str, strict: bool = True) -> list[str]:
    check = Check(technique_id)
    check.require(
        bool(TECHNIQUE_ID.fullmatch(technique_id)),
        f"invalid technique ID: {technique_id}",
    )
    if check.errors:
        return check.errors

    technique_dir = root / "techniques" / technique_id
    packet_dir = root / "research" / "techniques" / technique_id
    readme_path = technique_dir / "README.md"
    rule_path = technique_dir / "detection-rule.yml"
    check.require(readme_path.is_file(), f"{readme_path}: missing")
    check.require(rule_path.is_file(), f"{rule_path}: missing")
    for filename in REQUIRED_PACKET_FILES:
        check.require(
            (packet_dir / filename).is_file(), f"{packet_dir / filename}: missing"
        )
    if check.errors:
        return check.errors

    readme = readme_path.read_text(encoding="utf-8")
    for heading in REQUIRED_HEADINGS:
        check.require(heading in readme, f"README missing heading: {heading}")
    check.require(
        f"- **Technique ID**: {technique_id}" in readme,
        "README Technique ID does not match directory",
    )
    check.require(
        f"../../research/techniques/{technique_id}/" in readme,
        "README does not link its research packet",
    )
    readme_title_match = re.search(
        rf"^# {re.escape(technique_id)}: (.+)$", readme, re.MULTILINE
    )
    check.require(
        bool(readme_title_match), "README title must contain the technique ID and name"
    )
    readme_status_match = re.search(
        r"^- \*\*Evidence Status\*\*: ([^\n]+)$", readme, re.MULTILINE
    )
    readme_evidence_status = (
        readme_status_match.group(1).strip().lower() if readme_status_match else None
    )
    check.require(
        readme_evidence_status in EVIDENCE_STATUSES,
        "README has invalid Evidence Status",
    )
    readme_documentation_match = re.search(
        r"^- \*\*Documentation Status\*\*: ([^\n]+)$", readme, re.MULTILINE
    )
    readme_documentation_status = (
        re.sub(
            r"[ -]+",
            "_",
            readme_documentation_match.group(1).strip().lower(),
        )
        if readme_documentation_match
        else None
    )
    check.require(
        readme_documentation_status
        in {"draft", "under_review", "stable", "deprecated"},
        "README has invalid Documentation Status",
    )

    clean_room = load_yaml(packet_dir / "clean-room-attestation.yml", check)
    contract = load_yaml(packet_dir / "technique-contract.yml", check)
    inventory = load_yaml(packet_dir / "claim-inventory.yml", check)
    coverage = load_yaml(packet_dir / "source-coverage.yml", check)
    rights = load_yaml(packet_dir / "publication-rights.yml", check)
    review = load_yaml(packet_dir / "quality-review.yml", check)
    traceability = load_yaml(packet_dir / "traceability-ledger.yml", check)
    for filename, data in (
        ("clean-room-attestation.yml", clean_room),
        ("technique-contract.yml", contract),
        ("claim-inventory.yml", inventory),
        ("source-coverage.yml", coverage),
        ("publication-rights.yml", rights),
        ("quality-review.yml", review),
        ("traceability-ledger.yml", traceability),
    ):
        check.require(
            data.get("version") == 1, f"{filename}: unsupported or missing version"
        )
        check.require(
            data.get("technique_id") == technique_id,
            f"{filename}: technique_id mismatch",
        )

    generation_mode = contract.get("generation_mode")
    check.require(
        generation_mode in {"standard", "clean_room"},
        "contract: generation_mode must be standard or clean_room",
    )
    check.require(
        clean_room.get("generation_mode") == generation_mode,
        "clean-room attestation and contract generation modes differ",
    )
    trace_format = contract.get("trace_format", "legacy_inline")
    check.require(
        trace_format in {"legacy_inline", "hidden_html_v1"},
        "contract: trace_format must be legacy_inline or hidden_html_v1",
    )
    target = clean_room.get("target") or {}
    check.require(
        isinstance(target, dict) and target.get("id") == technique_id,
        "clean-room attestation target ID mismatch",
    )
    if generation_mode == "clean_room":
        generator = clean_room.get("generator") or {}
        independent = clean_room.get("independent_research") or {}
        prior_access = clean_room.get("prior_artifact_access") or {}
        check.require(
            isinstance(generator, dict) and generator.get("type") == "fresh_agent",
            "clean-room generation requires a fresh_agent generator",
        )
        check.require(
            isinstance(generator, dict) and generator.get("inherited_context") is False,
            "clean-room generator must not inherit conversation context",
        )
        check.require(
            isinstance(target, dict) and bool(target.get("neutral_name")),
            "clean-room attestation requires a neutral target name",
        )
        check.require(
            nonempty_list(clean_room.get("allowed_inputs")),
            "clean-room attestation requires allowed_inputs",
        )
        prohibited_inputs = clean_room.get("prohibited_inputs") or []
        check.require(
            nonempty_list(prohibited_inputs),
            "clean-room attestation requires prohibited_inputs",
        )
        prohibited_text = "\n".join(str(item).casefold() for item in prohibited_inputs)
        for required_fragment in (
            f"techniques/{technique_id}/readme.md".casefold(),
            f"research/techniques/{technique_id}/".casefold(),
            f"techniques/{technique_id}/detection-rule.yml".casefold(),
            "git history",
            "pull request",
            "previous conversation",
        ):
            check.require(
                required_fragment in prohibited_text,
                f"clean-room prohibited_inputs missing {required_fragment}",
            )
        searches = independent.get("searches") if isinstance(independent, dict) else None
        opened_source_ids = (
            independent.get("opened_source_ids")
            if isinstance(independent, dict)
            else None
        )
        check.require(
            nonempty_list(searches),
            "clean-room attestation requires independent search queries",
        )
        check.require(
            nonempty_list(opened_source_ids),
            "clean-room attestation requires independently opened source IDs",
        )
        check.require(
            isinstance(prior_access, dict) and prior_access.get("detected") is False,
            "clean-room attestation must report no prior-artifact access",
        )
        check.require(
            isinstance(prior_access, dict) and prior_access.get("details") == [],
            "clean-room prior-artifact access details must be empty",
        )
        check.require(
            clean_room.get("draft_frozen_before_integration") is True,
            "clean-room draft must be frozen before integration",
        )
        check.require(
            nonempty_list(clean_room.get("integration_constraints")),
            "clean-room attestation requires integration constraints",
        )
        check.require(
            bool(clean_room.get("attestation")),
            "clean-room attestation statement required",
        )
        if strict:
            check.require(
                clean_room.get("status") == "passed",
                "clean-room attestation must pass",
            )
            check.require(
                bool(clean_room.get("generated_on")),
                "clean-room generation date required",
            )
            check.require(
                not clean_room.get("unresolved"),
                "clean-room attestation has unresolved concerns",
            )

    tactics = contract.get("tactics")
    check.require(nonempty_list(tactics), "contract: at least one tactic is required")
    for tactic in tactics if isinstance(tactics, list) else []:
        check.require(
            bool(TACTIC_ID.fullmatch(str(tactic))), f"contract: invalid tactic {tactic}"
        )
    scope = contract.get("scope")
    check.require(isinstance(scope, dict), "contract: scope is required")
    if isinstance(scope, dict):
        check.require(
            bool(scope.get("security_boundary")),
            "contract: security_boundary is required",
        )
        check.require(
            nonempty_list(scope.get("in_scope")), "contract: in_scope is required"
        )
        check.require(
            nonempty_list(scope.get("out_of_scope")),
            "contract: out_of_scope is required",
        )
        check.require(
            nonempty_list(scope.get("affected_components")),
            "contract: affected_components required",
        )
    check.require(
        nonempty_list(contract.get("nearest_neighbors")),
        "contract: nearest_neighbors required",
    )
    check.require(
        bool(contract.get("adversary_objective")),
        "contract: adversary_objective required",
    )
    check.require(
        nonempty_list(contract.get("required_evidence")),
        "contract: required_evidence required",
    )
    check.require(
        nonempty_list(contract.get("safe_example_constraints")),
        "contract: safe_example_constraints required",
    )
    check.require(
        nonempty_list(contract.get("completion_evidence")),
        "contract: completion_evidence required",
    )
    contract_name = contract.get("name")
    if readme_title_match:
        check.require(
            readme_title_match.group(1).strip() == contract_name,
            "README and contract names differ",
        )
    neighbor_ids: set[str] = set()
    for neighbor in contract.get("nearest_neighbors") or []:
        check.require(
            isinstance(neighbor, dict), "contract: nearest neighbor must be a mapping"
        )
        if not isinstance(neighbor, dict):
            continue
        neighbor_id = str(neighbor.get("technique_id", ""))
        check.require(
            bool(TECHNIQUE_ID.fullmatch(neighbor_id)),
            f"contract: invalid neighbor {neighbor_id}",
        )
        check.require(
            neighbor_id != technique_id,
            "contract: technique cannot be its own neighbor",
        )
        check.require(
            bool(neighbor.get("distinction")),
            f"contract: {neighbor_id} needs a distinction",
        )
        if TECHNIQUE_ID.fullmatch(neighbor_id):
            neighbor_ids.add(neighbor_id)
            check.require(
                (root / "techniques" / neighbor_id / "README.md").is_file(),
                f"contract: unknown neighboring technique {neighbor_id}",
            )
    if strict:
        check.require(
            contract.get("status") in {"ready_for_review", "complete"},
            "contract: status must be ready_for_review or complete",
        )

    claims = records_by_id(inventory.get("claims"), "id", check, "claim")
    check.require(bool(claims), "claim inventory must contain at least one claim")
    referenced_sources: set[str] = set()
    claim_source_ids: dict[str, set[str]] = {}
    for claim_id, claim in claims.items():
        check.require(
            bool(CLAIM_ID.fullmatch(claim_id)), f"invalid claim ID: {claim_id}"
        )
        check.require(
            claim_id.startswith(f"{technique_id}-C"),
            f"claim belongs to another technique: {claim_id}",
        )
        check.require(bool(claim.get("statement")), f"{claim_id}: statement required")
        check.require(claim.get("class") in CLAIM_CLASSES, f"{claim_id}: invalid class")
        check.require(
            claim.get("materiality") in {"high", "medium", "low"},
            f"{claim_id}: invalid materiality",
        )
        check.require(
            claim.get("evidence_status") in EVIDENCE_STATUSES,
            f"{claim_id}: invalid evidence_status",
        )
        sources = claim.get("sources")
        check.require(
            nonempty_list(sources), f"{claim_id}: at least one source required"
        )
        claim_source_ids[claim_id] = set()
        for relation in sources if isinstance(sources, list) else []:
            check.require(
                isinstance(relation, dict),
                f"{claim_id}: source relation must be a mapping",
            )
            if not isinstance(relation, dict):
                continue
            source_id = relation.get("source_id")
            check.require(bool(source_id), f"{claim_id}: source_id required")
            if source_id:
                referenced_sources.add(str(source_id))
                claim_source_ids[claim_id].add(str(source_id))
            check.require(
                relation.get("support") in {"direct", "corroborating", "context"},
                f"{claim_id}: invalid support classification",
            )
            check.require(
                nonempty_list(relation.get("exact_locators")),
                f"{claim_id}: exact locators required",
            )
        check.require(
            nonempty_list(claim.get("limitations")), f"{claim_id}: limitations required"
        )
        inference = claim.get("inference")
        check.require(
            isinstance(inference, dict), f"{claim_id}: inference record required"
        )
        if isinstance(inference, dict) and inference.get("is_inference"):
            check.require(
                bool(inference.get("rationale")),
                f"{claim_id}: inference rationale required",
            )
        if strict:
            check.require(
                claim.get("status") == "validated",
                f"{claim_id}: status must be validated",
            )
        check.require(claim_id in readme, f"README does not expose claim ID {claim_id}")

    manifest = load_yaml(root / "research" / "source-manifest.yml", check)
    check.require(
        manifest.get("version") == 1, "source manifest: unsupported or missing version"
    )
    sources = records_by_id(manifest.get("sources"), "id", check, "source")
    for source_id in referenced_sources:
        check.require(
            source_id in sources, f"claim references unknown source {source_id}"
        )

    consulted = set(coverage.get("sources_consulted") or [])
    cited = set(coverage.get("sources_cited") or [])
    trace_comments = list(TRACE_COMMENT.finditer(readme))
    check.require(
        len(trace_comments) == len(TRACE_COMMENT_START.findall(readme)),
        "README contains a malformed SAF-TRACE comment",
    )
    if trace_format == "hidden_html_v1" and strict:
        check.require(
            bool(trace_comments),
            "hidden_html_v1 requires at least one SAF-TRACE comment",
        )
        for line_number in visible_claim_lines_outside_evidence_summary(readme):
            check.errors.append(
                f"README line {line_number} exposes a claim ID outside the "
                "Evidence Summary; use a same-line SAF-TRACE comment"
            )
    for trace in trace_comments:
        trace_claims = set(CLAIM_REFERENCE.findall(trace.group("claims")))
        trace_sources = set(SOURCE_REFERENCE.findall(trace.group("sources")))
        check.require(
            trace_claims <= set(claims),
            "SAF-TRACE comment references a claim absent from claim-inventory.yml",
        )
        supporting_sources: set[str] = set()
        for claim_id in trace_claims:
            supporting_sources.update(claim_source_ids.get(claim_id, set()))
        check.require(
            trace_sources <= supporting_sources,
            "SAF-TRACE source does not support any of the comment's traced claims",
        )
        check.require(
            trace_sources <= cited,
            "SAF-TRACE comment references a source absent from sources_cited",
        )
    if generation_mode == "clean_room":
        independently_opened = set(
            (clean_room.get("independent_research") or {}).get(
                "opened_source_ids", []
            )
        )
        check.require(
            independently_opened <= consulted,
            "clean-room opened source IDs must be in sources_consulted",
        )
    check.require(
        referenced_sources <= consulted,
        "all claim sources must be in sources_consulted",
    )
    check.require(
        cited <= consulted, "sources_cited must be a subset of sources_consulted"
    )
    check.require(
        cited <= referenced_sources,
        "every cited source must support an inventoried claim",
    )
    rejected_records = coverage.get("sources_rejected") or []
    blocked_records = coverage.get("sources_blocked") or []
    rejected_ids = {
        str(item.get("source_id"))
        for item in rejected_records
        if isinstance(item, dict) and item.get("source_id")
    }
    blocked_ids = {
        str(item.get("source_id"))
        for item in blocked_records
        if isinstance(item, dict) and item.get("source_id")
    }
    check.require(
        rejected_ids <= consulted, "rejected sources must be in sources_consulted"
    )
    check.require(
        blocked_ids <= consulted, "blocked sources must be in sources_consulted"
    )
    for item in [*rejected_records, *blocked_records]:
        check.require(
            isinstance(item, dict),
            "rejected and blocked source records must be mappings",
        )
        if isinstance(item, dict):
            check.require(
                bool(item.get("reason")), "rejected and blocked sources need reasons"
            )
    for source_id in consulted:
        check.require(
            source_id in sources,
            f"sources_consulted contains unknown source {source_id}",
        )
        if source_id in sources:
            validate_source(source_id, sources[source_id], strict, check)
    for source_id in cited:
        check.require(
            source_id in readme, f"README does not expose cited source ID {source_id}"
        )

    check.require(
        traceability.get("policy") == "source_or_omit",
        "traceability ledger policy must be source_or_omit",
    )
    check.require(
        traceability.get("publishable_artifact")
        == f"techniques/{technique_id}/README.md",
        "traceability ledger publishable_artifact mismatch",
    )
    check.require(
        traceability.get("coverage") == "all_substantive_publishable_content",
        "traceability ledger must cover all substantive publishable content",
    )
    repository_source_records = traceability.get("repository_sources") or []
    check.require(
        nonempty_list(repository_source_records),
        "traceability ledger repository_sources required",
    )
    declared_paths: set[str] = set()
    repository_source_ids: set[str] = set()
    for item in (
        repository_source_records if isinstance(repository_source_records, list) else []
    ):
        check.require(
            isinstance(item, dict), "traceability repository source must be a mapping"
        )
        if not isinstance(item, dict):
            continue
        local_source_id = str(item.get("id", ""))
        check.require(
            bool(re.fullmatch(r"LOCAL-[A-Za-z0-9][A-Za-z0-9._-]*", local_source_id)),
            f"invalid traceability repository source ID: {local_source_id}",
        )
        check.require(
            local_source_id not in repository_source_ids,
            f"duplicate traceability repository source ID: {local_source_id}",
        )
        repository_source_ids.add(local_source_id)
        for field in ("id", "path", "supports"):
            check.require(
                bool(item.get(field)),
                f"traceability repository source missing {field}",
            )
        path = str(item.get("path", ""))
        if path:
            declared_paths.add(path)
            resolved_path = (root / path).resolve()
            try:
                resolved_path.relative_to(root.resolve())
                inside_repository = True
            except ValueError:
                inside_repository = False
            check.require(
                inside_repository,
                f"traceability repository source escapes the repository: {path}",
            )
            check.require(
                resolved_path.is_file(),
                f"traceability repository source does not exist: {path}",
            )

    history_records = traceability.get("repository_history") or []
    check.require(
        nonempty_list(history_records),
        "traceability ledger repository_history required",
    )
    for item in history_records if isinstance(history_records, list) else []:
        check.require(
            isinstance(item, dict), "traceability history record must be a mapping"
        )
        if not isinstance(item, dict):
            continue
        commit = str(item.get("commit", ""))
        check.require(
            bool(re.fullmatch(r"[0-9a-f]{40}", commit)),
            "traceability history commit must be a 40-character SHA",
        )
        if strict and re.fullmatch(r"[0-9a-f]{40}", commit):
            check.require(
                int(commit, 16) != 0,
                "traceability history commit must not use the zero SHA",
            )
        check.require(
            bool(item.get("supports")), "traceability history record needs supports"
        )

    excluded_records = traceability.get("excluded_items") or []
    check.require(
        isinstance(excluded_records, list),
        "traceability excluded_items must be a list",
    )
    exclusion_ids: set[str] = set()
    for item in excluded_records if isinstance(excluded_records, list) else []:
        check.require(
            isinstance(item, dict), "traceability excluded item must be a mapping"
        )
        if not isinstance(item, dict):
            continue
        exclusion_id = str(item.get("id", ""))
        check.require(
            bool(EXCLUSION_ID.fullmatch(exclusion_id)),
            f"invalid exclusion ID: {exclusion_id}",
        )
        check.require(
            exclusion_id not in exclusion_ids,
            f"duplicate exclusion ID: {exclusion_id}",
        )
        exclusion_ids.add(exclusion_id)
        for field in ("candidate", "origin", "reason"):
            check.require(
                bool(item.get(field)), f"{exclusion_id}: missing {field}"
            )
        check.require(
            nonempty_list(item.get("attempted_searches")),
            f"{exclusion_id}: attempted_searches required",
        )
        excluded_source_ids = set(item.get("consulted_source_ids") or [])
        check.require(
            excluded_source_ids <= consulted,
            f"{exclusion_id}: consulted_source_ids must be in sources_consulted",
        )
        prohibited = item.get("prohibited_publishable_text")
        check.require(
            nonempty_list(prohibited),
            f"{exclusion_id}: prohibited_publishable_text required",
        )
        for fragment in prohibited if isinstance(prohibited, list) else []:
            check.require(
                str(fragment).casefold() not in readme.casefold(),
                f"{exclusion_id}: prohibited text appears in README: {fragment}",
            )
        check.require(
            item.get("disposition") == "omitted_from_publishable_technique",
            f"{exclusion_id}: disposition must omit the item from the technique",
        )
        if strict:
            check.require(
                item.get("status") == "excluded",
                f"{exclusion_id}: status must be excluded",
            )

    all_readme_claim_ids = set(CLAIM_REFERENCE.findall(readme))
    check.require(
        all_readme_claim_ids <= set(claims),
        "README references a claim absent from claim-inventory.yml",
    )
    all_readme_source_ids = set(SOURCE_REFERENCE.findall(readme))
    check.require(
        all_readme_source_ids <= cited,
        "README references a source absent from sources_cited",
    )
    if strict:
        check.require(
            traceability.get("review_status") == "passed",
            "traceability ledger review must pass",
        )
        check.require(
            bool(traceability.get("reviewed_on")),
            "traceability ledger review date required",
        )
        check.require(
            not traceability.get("unresolved"),
            "traceability ledger has unresolved items",
        )
        untraced_lines = untraced_publishable_lines(
            readme, root, readme_path, set(claims), declared_paths
        )
        for line_number in untraced_lines:
            check.errors.append(
                f"README line {line_number} has substantive content without a "
                "validated claim ID or declared repository source"
            )

    saturation = coverage.get("saturation")
    check.require(
        isinstance(saturation, dict), "source coverage: saturation record required"
    )
    if isinstance(saturation, dict) and strict:
        check.require(
            saturation.get("reached") is True, "research saturation not reached"
        )
        check.require(
            isinstance(saturation.get("consecutive_no_change_passes"), int)
            and saturation["consecutive_no_change_passes"] >= 2,
            "research saturation needs two consecutive no-change passes",
        )
        check.require(
            bool(saturation.get("rationale")), "research saturation rationale required"
        )
        pass_records = saturation.get("passes") or []
        pass_names = {
            item.get("pass") for item in pass_records if isinstance(item, dict)
        }
        check.require(
            RESEARCH_PASSES <= pass_names, "all five research passes must be recorded"
        )
        for item in pass_records:
            if isinstance(item, dict):
                check.require(
                    bool(item.get("completed_on")),
                    f"research pass {item.get('pass')} needs completed_on",
                )
        check.require(
            len(pass_records) >= 2, "saturation requires two recorded follow-up passes"
        )
        for item in pass_records[-2:]:
            check.require(
                isinstance(item, dict) and item.get("material_changes") == [],
                "the final two research passes must record no material changes",
            )
    if strict:
        check.require(
            coverage.get("research_status") == "saturated",
            "research_status must be saturated",
        )

    breach_assessment = coverage.get("breach_and_vulnerability_assessment")
    check.require(
        isinstance(breach_assessment, dict),
        "breach_and_vulnerability_assessment required",
    )
    if isinstance(breach_assessment, dict):
        check.require(
            bool(breach_assessment.get("searched_on")),
            "breach and vulnerability search date required",
        )
        candidates = breach_assessment.get("candidates") or []
        check.require(
            nonempty_list(candidates),
            "breach and vulnerability candidates required",
        )
        selected_source_ids: set[str] = set()
        for candidate in candidates if isinstance(candidates, list) else []:
            check.require(
                isinstance(candidate, dict),
                "breach and vulnerability candidate must be a mapping",
            )
            if not isinstance(candidate, dict):
                continue
            source_id = str(candidate.get("source_id", ""))
            check.require(
                source_id in consulted,
                f"breach candidate references unconsulted source {source_id}",
            )
            check.require(
                candidate.get("relationship") in BREACH_RELATIONSHIPS,
                f"{source_id}: invalid breach relationship",
            )
            for field in (
                "identifier",
                "exploitation_status",
                "impact",
                "remediation",
                "rationale",
            ):
                check.require(
                    bool(candidate.get(field)),
                    f"{source_id}: breach candidate missing {field}",
                )
            check.require(
                candidate.get("selected") in {True, False},
                f"{source_id}: selected must be true or false",
            )
            if candidate.get("selected"):
                selected_source_ids.add(source_id)
        declared_selected = set(breach_assessment.get("selected_examples") or [])
        check.require(
            declared_selected == selected_source_ids,
            "selected breach examples must match selected candidates",
        )
        check.require(
            breach_assessment.get("candidate_count") == len(candidates),
            "breach candidate_count does not match candidates",
        )
        check.require(
            len(selected_source_ids) <= 4,
            "select no more than four breach and vulnerability examples",
        )
        if len(selected_source_ids) < 2:
            check.require(
                bool(breach_assessment.get("no_qualifying_examples_rationale")),
                "fewer than two selected examples requires a rationale",
            )

    assessment = coverage.get("evidence_assessment")
    check.require(isinstance(assessment, dict), "evidence_assessment required")
    if isinstance(assessment, dict):
        overall_status = assessment.get("overall_status")
        core_claim_ids = assessment.get("core_claim_ids") or []
        check.require(
            overall_status in EVIDENCE_STATUSES, "invalid overall evidence status"
        )
        check.require(
            nonempty_list(core_claim_ids), "at least one core claim is required"
        )
        for claim_id in core_claim_ids:
            check.require(claim_id in claims, f"unknown core claim {claim_id}")
        check.require(
            overall_status == readme_evidence_status,
            "README and research evidence statuses differ",
        )
        check.require(
            bool(assessment.get("rationale")), "evidence assessment rationale required"
        )
        core_claims = [claims[item] for item in core_claim_ids if item in claims]
        if overall_status == "observed":
            check.require(
                any(
                    item.get("class") == "observed_incident"
                    and item.get("evidence_status") == "observed"
                    for item in core_claims
                ),
                "Observed status requires an observed_incident core claim",
            )
        elif overall_status == "demonstrated":
            check.require(
                any(
                    item.get("class") == "demonstrated_exploit"
                    and item.get("evidence_status") == "demonstrated"
                    for item in core_claims
                ),
                "Demonstrated status requires a demonstrated_exploit core claim",
            )
        elif overall_status == "research-derived":
            check.require(
                any(
                    item.get("evidence_status") == "research-derived"
                    and (item.get("inference") or {}).get("is_inference")
                    for item in core_claims
                ),
                "Research-Derived status requires an explicitly inferred core claim",
            )
        elif overall_status == "hypothesized":
            check.require(
                any(
                    item.get("evidence_status") == "hypothesized"
                    for item in core_claims
                ),
                "Hypothesized status requires a hypothesized core claim",
            )

    if strict:
        check.require(
            (coverage.get("source_archive") or {}).get("validation_status") == "passed",
            "source archive validation must pass",
        )
        check.require(
            (coverage.get("rights_review") or {}).get("status") == "passed",
            "source coverage rights review must pass",
        )

    rights_uses = records_by_id(
        rights.get("source_uses"), "source_id", check, "rights source use"
    )
    check.require(
        cited <= set(rights_uses),
        "every cited source needs a publication-rights record",
    )
    for source_id in cited:
        use = rights_uses.get(source_id, {})
        for field in (
            "rights_owner",
            "access_status",
            "rights_status",
            "use_mode",
            "basis",
            "permission_status",
            "attribution",
            "notes",
        ):
            check.require(
                bool(use.get(field)), f"{source_id}: rights record missing {field}"
            )
        check.require(
            use.get("protected_expression_used") in {True, False},
            f"{source_id}: protected_expression_used must be true or false",
        )
        check.require(
            use.get("permission_required") in {True, False},
            f"{source_id}: permission_required must be true or false",
        )
        if use.get("permission_required") and strict:
            check.require(
                use.get("permission_status") == "granted",
                f"{source_id}: required permission has not been granted",
            )
    if strict:
        check.require(
            rights.get("review_status") == "passed",
            "publication-rights review must pass",
        )
        check.require(
            bool(rights.get("reviewed_on")), "publication-rights review date required"
        )
        check.require(
            not rights.get("unresolved"),
            "publication-rights review has unresolved issues",
        )

    detection = contract.get("detection") or {}
    check.require(
        isinstance(contract.get("detection"), dict),
        "contract: detection record required",
    )
    expectation = detection.get("expectation")
    check.require(
        expectation in {"required", "waived"},
        "detection expectation must be required or waived",
    )
    check.require(
        nonempty_list(detection.get("required_telemetry")),
        "contract: detection required_telemetry must not be empty",
    )
    detection_review = review.get("validation", {}).get("detection_tests", {})
    if strict and expectation == "required":
        check.require(
            detection_review.get("status") == "passed",
            "required detection tests must pass",
        )
        check.require(
            bool(detection_review.get("command")), "detection test command required"
        )
        check.require(
            bool(detection_review.get("result")), "detection test result required"
        )
    elif expectation == "waived":
        check.require(
            bool(detection.get("waiver_rationale")),
            "detection waiver rationale required",
        )
        if strict:
            check.require(
                detection_review.get("status") == "waived",
                "quality review must record detection waiver",
            )
            check.require(
                bool(detection_review.get("waiver")),
                "quality review waiver rationale required",
            )

    rule = load_yaml(rule_path, check)
    for field in (
        "title",
        "status",
        "description",
        "logsource",
        "detection",
        "falsepositives",
        "level",
    ):
        check.require(bool(rule.get(field)), f"detection rule missing {field}")
    try:
        rule_uuid = uuid.UUID(str(rule.get("id")))
        check.require(rule_uuid.int != 0, "detection rule must not use the zero UUID")
    except (ValueError, TypeError, AttributeError):
        check.errors.append("detection rule id must be a UUID")
    expected_tag = technique_id.lower().replace("-", ".")
    check.require(
        expected_tag in (rule.get("tags") or []),
        f"detection rule missing tag {expected_tag}",
    )
    rule_traceability = rule.get("traceability")
    check.require(
        isinstance(rule_traceability, dict),
        "detection rule traceability record required",
    )
    if isinstance(rule_traceability, dict):
        check.require(
            rule_traceability.get("policy") == "source_or_omit",
            "detection rule traceability policy must be source_or_omit",
        )
        for field in (
            "design_claim_ids",
            "telemetry_claim_ids",
            "limitation_claim_ids",
        ):
            claim_references = rule_traceability.get(field)
            check.require(
                nonempty_list(claim_references),
                f"detection rule traceability {field} required",
            )
            for claim_id in claim_references if isinstance(claim_references, list) else []:
                check.require(
                    claim_id in claims,
                    f"detection rule traceability references unknown claim {claim_id}",
                )
        validation_artifacts = rule_traceability.get("validation_artifacts")
        check.require(
            nonempty_list(validation_artifacts),
            "detection rule traceability validation_artifacts required",
        )
        for artifact in (
            validation_artifacts if isinstance(validation_artifacts, list) else []
        ):
            check.require(
                artifact in declared_paths,
                f"detection traceability artifact is not ledgered: {artifact}",
            )
        components = rule_traceability.get("components")
        check.require(
            isinstance(components, dict),
            "detection rule traceability components required",
        )
        required_components = set((rule.get("detection") or {}).keys()) | {
            "logsource",
            "falsepositives",
        }
        if rule.get("fields"):
            required_components.add("fields")
        if isinstance(components, dict):
            check.require(
                required_components <= set(components),
                "every detection component must have a traceability record",
            )
            for component_name in required_components:
                component = components.get(component_name)
                check.require(
                    isinstance(component, dict),
                    f"detection traceability component {component_name} must be a mapping",
                )
                if not isinstance(component, dict):
                    continue
                component_claims = component.get("claim_ids")
                check.require(
                    nonempty_list(component_claims),
                    f"detection component {component_name} claim_ids required",
                )
                for claim_id in (
                    component_claims if isinstance(component_claims, list) else []
                ):
                    check.require(
                        claim_id in claims,
                        f"detection component {component_name} references unknown claim {claim_id}",
                    )
                check.require(
                    bool(component.get("rationale")),
                    f"detection component {component_name} rationale required",
                )
    if strict:
        check.require(
            "replace-with" not in rule_path.read_text(encoding="utf-8").lower(),
            "detection rule still contains scaffold placeholders",
        )

    model = load_yaml(root / "research" / "framework-model.yml", check)
    check.require(
        model.get("version") in {1, 2},
        "framework model: unsupported or missing version",
    )
    model_records = records_by_id(
        model.get("techniques"), "technique_id", check, "framework technique"
    )
    check.require(
        technique_id in model_records, "framework model does not contain the technique"
    )
    model_record = model_records.get(technique_id, {})
    if model_record:
        if model.get("version") == 2:
            framework_relationships = model_record.get("relationships") or []
            related_ids = {
                relationship.get("target")
                for relationship in framework_relationships
                if isinstance(relationship, dict) and relationship.get("target")
            }
        else:
            related_ids = set(model_record.get("related_techniques") or [])
        check.require(
            model_record.get("name") == contract_name,
            "framework and contract names differ",
        )
        check.require(
            model_record.get("documentation_status") == readme_documentation_status,
            "framework documentation_status mismatch",
        )
        check.require(
            model_record.get("evidence_status") == readme_evidence_status,
            "framework evidence_status mismatch",
        )
        check.require(
            model_record.get("tactics") == tactics,
            "framework tactics differ from contract",
        )
        check.require(
            model_record.get("technique_path")
            == f"techniques/{technique_id}/README.md",
            "framework technique_path mismatch",
        )
        check.require(
            model_record.get("research_packet")
            == f"research/techniques/{technique_id}",
            "framework research_packet mismatch",
        )
        check.require(
            neighbor_ids <= related_ids,
            "framework relationships must include contract neighbors",
        )
        for related_id in related_ids:
            check.require(
                (root / "techniques" / related_id / "README.md").is_file(),
                f"unknown related technique {related_id}",
            )
        for mitigation_id in model_record.get("mitigations") or []:
            check.require(
                (root / "mitigations" / mitigation_id / "README.md").is_file(),
                f"unknown mitigation {mitigation_id}",
            )
        if strict:
            model_detection = model_record.get("detection") or {}
            expected_test_status = "passed" if expectation == "required" else "waived"
            check.require(
                model_detection.get("test_status") == expected_test_status,
                "framework detection status mismatch",
            )
            test_artifacts = model_detection.get("test_artifacts") or []
            if expectation == "required":
                check.require(
                    nonempty_list(test_artifacts),
                    "framework detection test artifacts required",
                )
            check.require(
                model_detection.get("rule")
                == f"techniques/{technique_id}/detection-rule.yml",
                "framework detection rule path mismatch",
            )
            for artifact in test_artifacts:
                check.require(
                    (root / artifact).is_file(),
                    f"missing detection test artifact {artifact}",
                )

    alignment = load_yaml(root / "research" / "alignment-ledger.yml", check)
    check.require(
        alignment.get("version") == 1,
        "alignment ledger: unsupported or missing version",
    )
    for issue in alignment.get("issues") or []:
        if not isinstance(issue, dict):
            check.errors.append("alignment issue must be a mapping")
            continue
        relevant = issue.get("triggered_by") == technique_id or technique_id in (
            issue.get("affects") or []
        )
        if strict and relevant and issue.get("severity") == "high":
            check.require(
                issue.get("status") == "resolved",
                f"unresolved high-severity alignment issue {issue.get('id')}",
            )

    gates = review.get("gates")
    check.require(
        isinstance(gates, dict) and bool(gates), "quality review gates required"
    )
    if isinstance(gates, dict):
        check.require(
            REQUIRED_GATES <= set(gates), "quality review is missing required gates"
        )
    if strict:
        check.require(
            review.get("review_status") == "passed", "quality review must pass"
        )
        check.require(bool(review.get("reviewed_on")), "quality review date required")
        check.require(bool(review.get("reviewer")), "quality review reviewer required")
        for gate_name, gate in gates.items() if isinstance(gates, dict) else []:
            check.require(
                isinstance(gate, dict) and gate.get("status") == "passed",
                f"quality gate {gate_name} must pass",
            )
        check.require(
            not review.get("unresolved"), "quality review has unresolved issues"
        )
        commands = (review.get("validation") or {}).get("commands") or []
        check.require(
            nonempty_list(commands), "quality review must record validation commands"
        )
        check.require(
            any(
                isinstance(item, dict)
                and "validate-technique-research.py" in str(item.get("command", ""))
                and item.get("result") == "passed"
                for item in commands
            ),
            "quality review must record a passing research-validator command",
        )

    return check.errors


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("technique_ids", nargs="*", help="One or more SAF-TXXXX IDs")
    parser.add_argument(
        "--all", action="store_true", help="Validate every research packet"
    )
    parser.add_argument(
        "--draft",
        action="store_true",
        help=(
            "Relax strict-only completion and release checks: completion "
            "statuses, hidden-trace coverage, untraced publishable prose, "
            "saturation, publication permissions, and high-severity alignment "
            "issues; the placeholder zero repository-history SHA is accepted. "
            "Schema, cross-file joins, and core clean-room assertions are still "
            "enforced. A draft PASS is not release validation."
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = Path(__file__).resolve().parents[1]
    technique_ids = list(args.technique_ids)
    if args.all:
        packet_root = root / "research" / "techniques"
        technique_ids.extend(
            path.name
            for path in sorted(packet_root.glob("SAF-T[0-9][0-9][0-9][0-9]"))
            if path.is_dir()
        )
    technique_ids = list(dict.fromkeys(technique_ids))
    if not technique_ids and not args.all:
        raise SystemExit("provide a technique ID or use --all")
    if not technique_ids:
        print("PASS no technique research packets found")
        return 0

    failed = False
    for technique_id in technique_ids:
        errors = validate_technique(root, technique_id, strict=not args.draft)
        if errors:
            failed = True
            print(f"FAIL {technique_id}")
            for error in errors:
                print(f"  - {error}")
        else:
            print(f"PASS {technique_id}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
