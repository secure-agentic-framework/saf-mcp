#!/usr/bin/env python3
"""Validate containment-profile metadata, joins, and local document links.

This validator never evaluates runtime security or cryptographic properties.
SPDX-License-Identifier: Apache-2.0
"""
from __future__ import annotations

from pathlib import Path
import re
from urllib.parse import unquote
import yaml


class UniqueKeyLoader(yaml.SafeLoader):
    pass


def unique_mapping(loader, node, deep=False):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ValueError(f"duplicate YAML key: {key}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)


def check_catalog(catalog: dict, model: dict, root: Path) -> list[str]:
    errors = []

    def require(condition, message):
        if not condition:
            errors.append(message)

    def records(key, pattern):
        result = {}
        values = catalog.get(key)
        if not isinstance(values, list) or not values:
            errors.append(f"{key}: nonempty list required")
            return result
        for item in values:
            if not isinstance(item, dict):
                errors.append(f"{key}: mapping required")
                continue
            identifier = item.get("id", "")
            if not isinstance(identifier, str) or not re.fullmatch(pattern, identifier):
                errors.append(f"{key}: invalid ID {identifier!r}")
                continue
            require(identifier not in result, f"{key}: duplicate ID {identifier}")
            result[identifier] = item
        return result

    require(catalog.get("schema_version") == 1, "unsupported profile schema")
    require(catalog.get("profile_id") == "ACP", "profile ID must be ACP")
    require(catalog.get("status") == "proposal", "this package must retain proposal status")
    require(bool(re.fullmatch(r"[a-f0-9]{40}", str(catalog.get("base_commit", "")))), "missing full base commit")
    groups = records("groups", r"[a-z]+(?:-[a-z]+)*")
    reqs = records("requirements", r"ACP-R\d{3}")
    attacks = records("attack_items", r"ACP-A\d{3}")
    sources = records("sources", r"ACP-S\d{3}")
    techniques = {t["technique_id"]: t for t in model["techniques"]}
    tactics = {t["id"] for t in model["tactics"]}
    profiles = {p["id"] for p in model["profiles"]}
    mitigation_ids = set()
    for gid, group in groups.items():
        mid = group.get("mitigation", "")
        require(bool(re.fullmatch(r"SAF-M-\d+", str(mid))), f"{gid}: invalid mitigation ID")
        require(mid not in mitigation_ids, f"{gid}: duplicate group mitigation")
        mitigation_ids.add(mid)
        path = root / "mitigations" / str(mid) / "README.md"
        require(path.is_file(), f"{gid}: missing mitigation {mid}")
        if path.is_file():
            require(path.read_text(encoding="utf-8").startswith(f'# {mid}: {group.get("control_name")}\n'), f"{gid}: mitigation title mismatch")
        require(any(r.get("group") == gid for r in reqs.values()), f"{gid}: no requirements")
        require(any(a.get("group") == gid for a in attacks.values()), f"{gid}: no attack items")
    attack_ids = {s.get("attack_id") for s in sources.values() if s.get("attack_id")}
    for sid, source in sources.items():
        for field in ("title", "authors", "url", "locator", "use", "reviewed_on", "publication_use"):
            require(bool(source.get(field)), f"{sid}: missing {field}")
        require(str(source.get("url", "")).startswith("https://"), f"{sid}: expected direct HTTPS source")
    seen_tests = set()
    covered = set()
    for rid, req in reqs.items():
        require(req.get("group") in groups, f"{rid}: unknown group")
        require(bool(req.get("title")) and bool(req.get("requirement")), f"{rid}: missing requirement")
        test = req.get("test_id", "")
        require(bool(re.fullmatch(r"ACP-V\d{3}", str(test))) and test not in seen_tests, f"{rid}: invalid or duplicate test ID")
        seen_tests.add(test)
        require(bool(req.get("mitigations")), f"{rid}: missing mitigation")
        require(set(req.get("mitigations", [])) <= mitigation_ids, f"{rid}: unknown mitigation")
        validation = req.get("validation", {})
        require(validation.get("status") == "planned", f"{rid}: deployment test must remain planned")
        require(bool(validation.get("procedure")) and bool(validation.get("expected")), f"{rid}: missing acceptance conditions")
    for aid, attack in attacks.items():
        require(attack.get("group") in groups, f"{aid}: unknown group")
        for field in ("title", "preconditions", "procedure", "observables", "false_positives"):
            require(bool(attack.get(field)), f"{aid}: missing {field}")
        require(attack.get("evidence_status") == "design_scenario", f"{aid}: unsupported evidence promotion")
        require(attack.get("detection_maturity") == "proposed", f"{aid}: untested detection must remain proposed")
        require(attack.get("test_status") == "planned", f"{aid}: deployment test must remain planned")
        require(bool(attack.get("tactics")) and set(attack.get("tactics", [])) <= tactics, f"{aid}: unknown or missing tactic")
        require(bool(attack.get("domain_profiles")) and set(attack.get("domain_profiles", [])) <= profiles, f"{aid}: unknown or missing domain profile")
        required = attack.get("requirements", [])
        require(bool(required) and set(required) <= set(reqs), f"{aid}: unknown or missing requirement")
        covered.update(required)
        if set(required) <= set(reqs):
            expected_tests = {reqs[r]["test_id"] for r in required}
            require(set(attack.get("acceptance_tests", [])) == expected_tests, f"{aid}: acceptance test join differs")
            expected_controls = {m for r in required for m in reqs[r]["mitigations"]}
            require(set(attack.get("mitigations", [])) == expected_controls, f"{aid}: mitigation join differs")
        require(bool(attack.get("saf_mappings")), f"{aid}: missing SAF context")
        for mapping in attack.get("saf_mappings", []):
            tid, relation = mapping.get("technique_id"), mapping.get("relationship")
            require(tid in techniques and techniques[tid].get("lifecycle_status") == "active", f"{aid}: inactive or unknown technique {tid}")
            require(relation in {"procedure_example", "related_context"}, f"{aid}: invalid relationship")
            require(bool(mapping.get("rationale")), f"{aid}: missing mapping rationale")
            if tid in techniques and relation == "procedure_example":
                require(set(attack.get("mitigations", [])) <= set(techniques[tid].get("mitigations", [])), f"{aid}: missing canonical mitigation join")
        for mapping in attack.get("mitre_attack", []):
            require(mapping.get("id") in attack_ids, f"{aid}: unreviewed ATT&CK ID")
            require(mapping.get("relationship") == "analogous" and bool(mapping.get("scope")), f"{aid}: unsupported ATT&CK mapping strength")
    require(set(reqs) <= covered, "one or more requirements have no assessment item")
    return errors


def check_links(root: Path, paths: list[Path]) -> list[str]:
    errors = []
    for path in paths:
        for raw in re.findall(r"(?<!!)\[[^\]]*\]\(([^)]+)\)", path.read_text(encoding="utf-8")):
            if raw.startswith(("http://", "https://", "mailto:")):
                continue
            target, _, fragment = raw.partition("#")
            dest = (path.parent / unquote(target)).resolve() if target else path.resolve()
            if not dest.is_relative_to(root.resolve()) or not dest.is_file():
                errors.append(f"{path.relative_to(root)}: missing or out-of-repository target {raw}")
            elif fragment and dest.name == "VALIDATION.md":
                if f"## {fragment.upper()}\n" not in dest.read_text(encoding="utf-8"):
                    errors.append(f"{path.relative_to(root)}: missing acceptance anchor {fragment}")
    return errors


def validate(root: Path) -> list[str]:
    try:
        catalog = yaml.load((root / "profiles/agent-containment/catalog.yml").read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
        model = yaml.safe_load((root / "research/framework-model.yml").read_text(encoding="utf-8"))
        if not isinstance(catalog, dict):
            return ["catalog must be a mapping"]
        errors = check_catalog(catalog, model, root)
        paths = list((root / "profiles/agent-containment").rglob("*.md"))
        paths += [root / "mitigations" / g["mitigation"] / "README.md" for g in catalog.get("groups", []) if (root / "mitigations" / g.get("mitigation", "") / "README.md").is_file()]
        errors.extend(check_links(root, paths))
        return errors
    except (OSError, yaml.YAMLError, KeyError, TypeError, ValueError) as exc:
        return [f"invalid containment package: {exc}"]


if __name__ == "__main__":
    issues = validate(Path(__file__).resolve().parents[1])
    if issues:
        print("\n".join("FAIL: " + e for e in issues))
        raise SystemExit(1)
    print("PASS: containment metadata, references, and local links (deployment security not evaluated)")
