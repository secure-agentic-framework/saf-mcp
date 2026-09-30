#!/usr/bin/env python3
"""Generate the containment profile's readable indexes and acceptance plan.

SPDX-License-Identifier: Apache-2.0
"""
from __future__ import annotations

import argparse
from pathlib import Path
import yaml


def build(root: Path) -> dict[Path, str]:
    base = root / "profiles/agent-containment"
    catalog = yaml.safe_load((base / "catalog.yml").read_text(encoding="utf-8"))
    model = yaml.safe_load((root / "research/framework-model.yml").read_text(encoding="utf-8"))
    techniques = {x["technique_id"]: x for x in model["techniques"]}
    tactics = {x["id"]: x["name"] for x in model["tactics"]}
    groups = {x["id"]: x for x in catalog["groups"]}
    requirements, attacks = catalog["requirements"], catalog["attack_items"]
    attack_sources = {x["attack_id"]: x for x in catalog["sources"] if "attack_id" in x}
    output = {}

    def technique_link(identifier: str, prefix: str) -> str:
        return f'[{identifier}: {techniques[identifier]["name"]}]({prefix}techniques/{identifier}/README.md)'

    index = [
        "# Agent Containment and Owner Authorization", "",
        "**Status:** proposed deployment profile. **Namespace:** `ACP` identifies local requirements and assessment items, not new SAF or MITRE techniques.", "",
        "This profile translates *The Machine Behind the Door* into reviewable boundaries for an MCP-enabled agent that can request external work only through an independent broker. The model, tools, descendants, and ordinary workspace remain inside the enclosure. The broker owns external connections; the enrolled owner controls policy changes through a protected approval path.", "",
        "It applies across SAF Core, MCP, Code-Agent, and Financial-Agent deployments as relevant. These are applicability views of existing mechanisms, not additional canonical framework profiles. Each item states whether its existing SAF classification is a procedure example or related context.", "",
        f'**Package:** {len(attacks)} attack-assessment items; {len(requirements)} requirements and planned acceptance tests; {len(groups)} proposed mitigations. The canonical SAF technique count and technique evidence states are unchanged.', "",
        "**Validation boundary:** automated checks validate catalog integrity and repository integration. No secure runtime, cryptographic verifier, telemetry detector, or deployment acceptance test is implemented or field-validated by this package.", "",
        "## Architecture", "", "```mermaid", "flowchart TD",
        '  A["Agent, tools, and descendants"] -->|"Typed request only"| B["Independent broker"]',
        '  O["Protected owner approval"] -->|"Bound, one-use authority"| B',
        '  B -->|"Permitted external effect"| S["Registered service"]',
        '  B -->|"Decision and execution evidence"| L["Independent audit"]',
        "```", "",
        "The broker enforces policy independently of model judgment. All agent-caused external effects, including remote inference and diagnostic uploads, must be mediated. An approved output remains a disclosure; this profile does not claim that arbitrary output can carry no information.", "",
        "## Contextual groups", "",
        "| Boundary group | Attack items | Requirements | New mitigation |",
        "| --- | ---: | ---: | --- |",
    ]
    for gid, group in groups.items():
        count_a = sum(x["group"] == gid for x in attacks)
        count_r = sum(x["group"] == gid for x in requirements)
        mid = group["mitigation"]
        index.append(f'| [{group["name"]}](groups/{gid}.md) | {count_a} | {count_r} | [{mid}: {group["control_name"]}](../../mitigations/{mid}/README.md) |')
    index += ["", "## Attack items by SAF tactic", "",
              "The local scenario tactic is separate from its linked technique's canonical tactics. `related_context` must not be counted as direct technique coverage. External ATT&CK mappings are analogous and do not change the SAF tactic registry.", ""]
    for tactic, name in tactics.items():
        selected = [a for a in attacks if tactic in a["tactics"]]
        if not selected:
            continue
        index += ["", f"### {name}", "", "| Item | Scenario | Existing SAF context | Relationship |", "| --- | --- | --- | --- |"]
        for item in selected:
            mapping = item["saf_mappings"][0]
            index.append(f'| [{item["id"]}](groups/{item["group"]}.md) | {item["title"]} | {technique_link(mapping["technique_id"], "../../")} | `{mapping["relationship"]}` |')
    index += ["", "## Requirements and use", "",
              "1. Select the contextual groups that apply, then implement all requirements needed for the claimed boundary. MUST describes this proposed profile, not a new MCP protocol requirement.",
              "2. Execute the [deployment acceptance plan](VALIDATION.md) using independent observations and authorized control cases. All cases are initially marked planned.",
              "3. Keep the owner, agent, verifier, and broker distinct. Retain request binding, attempt consumption, and downstream execution evidence through crashes and revocation.",
              "4. Record measured limitations and excluded channels. Do not equate a passed catalog check with tested runtime security.", "",
              "The [machine-readable catalog](catalog.yml) is the source of truth for these indexes. The [source notes](SOURCES.md) and [provenance record](provenance.yml) distinguish standards baselines from original design requirements.", "",
              "## Optional Rosario–Wang ENI6MA realization", "",
              "[ENI6MA implementation conditions](ENI6MA.md) describe a candidate protected approval component. This profile remains implementation-neutral: perfect privacy of a specified released exchange does not establish isolation, owner attribution, phishing resistance, or action authorization by itself.", "",
              "## Repository checks", "", "```bash",
              "python3 scripts/validate-containment-profile.py",
              "python3 scripts/generate-containment-profile.py --check",
              "python3 -m unittest discover -s scripts -p 'test_*.py'", "```", "",
              "[Apply the overwrite package](APPLY.md) when using the changed-files ZIP. Follow the repository's [contribution and DCO rules](../../CONTRIBUTING.md) when committing or submitting the result.", "",
              "## Version history", "", "| Version | Date | Change | Author |", "| --- | --- | --- | --- |",
              f'| 0.1 | {catalog["reviewed_on"]} | Initial requirements and contextual assessment proposal | Franciscus Dylan Rosario; Codex drafting assistance |', ""]
    output[base / "README.md"] = "\n".join(index)

    for gid, group in groups.items():
        selected = [a for a in attacks if a["group"] == gid]
        reqs = [r for r in requirements if r["group"] == gid]
        mid = group["mitigation"]
        lines = [f'# {group["name"]}', "", "[Profile index](../README.md) | [Machine-readable catalog](../catalog.yml)", "",
                 "These are proposed, inert deployment assessments, not new canonical techniques or observed incidents. Detection ideas are proposed; acceptance tests require a deployed system.", "",
                 f'**Primary control:** [{mid}: {group["control_name"]}](../../../mitigations/{mid}/README.md)', "",
                 "## Requirements", "", "| Requirement | Required behavior | Acceptance test |", "| --- | --- | --- |"]
        for req in reqs:
            test = req["test_id"]
            lines.append(f'| {req["id"]}: {req["title"]} | {req["requirement"]} | [{test}](../VALIDATION.md#{test.lower()}) |')
        for item in selected:
            mapping = item["saf_mappings"][0]
            lines += ["", f'## {item["id"]}: {item["title"]}', "",
                      f'**Context:** {", ".join(tactics[t] for t in item["tactics"])}; SAF Core and MCP deployment views.', "",
                      f'**Classification:** {technique_link(mapping["technique_id"], "../../../")} — `{mapping["relationship"]}`. {mapping["rationale"]}', "",
                      f'**Preconditions:** {item["preconditions"]}', "", f'**Inert procedure:** {item["procedure"]}', "",
                      f'**Proposed detection evidence:** {item["observables"]}', "",
                      f'**Legitimate lookalikes and limits:** {item["false_positives"]} Agent-authored logs alone cannot establish the boundary decision.', "",
                      '**Required controls:** ' + ', '.join(f'[{m}](../../../mitigations/{m}/README.md)' for m in item["mitigations"]) + '.', "",
                      '**Acceptance:** ' + ', '.join(f'[{v}](../VALIDATION.md#{v.lower()})' for v in item["acceptance_tests"]) + '. Tests are planned, not executed.']
            if item["mitre_attack"]:
                labels = [f'[{m["id"]}: {attack_sources[m["id"]]["title"]}]({attack_sources[m["id"]]["url"]}) (analogous)' for m in item["mitre_attack"]]
                lines += ["", '**MITRE ATT&CK context:** ' + '; '.join(labels) + '. These external mappings do not alter the repository\'s canonical tactic model.']
        output[base / "groups" / f"{gid}.md"] = "\n".join(lines) + "\n"

    lines = ["# Deployment acceptance plan", "",
             "These are proposed tests for an actual isolated agent, independent broker, approval component, and downstream services. **None has been executed against a deployed containment system in this contribution.** Repository validation checks IDs, mappings, required fields, and generated catalog consistency only.", "",
             "Use synthetic credentials, inert local endpoints, non-destructive operations, and independent observations. Record configuration, enforcement version, expected and actual results, downstream receipts, failure evidence, and reviewer. Agent-controlled logs and a passed unit test do not establish containment.", "",
             "For each negative case, demonstrate the corresponding authorized operation. Replay evaluations must include concurrency, restart, stale replicas, expiry, and uncertain downstream execution. Keep secret values out of retained evidence.", ""]
    for req in requirements:
        lines += [f'## {req["test_id"]}', "", f'**Requirement:** {req["id"]} — {req["title"]}. **Status:** planned.', "",
                  f'**Procedure:** {req["validation"]["procedure"]}', "", f'**Pass condition:** {req["validation"]["expected"]}', "",
                  "**Evidence to retain:** independent enforcement and destination observations, current identity/policy bindings, correlation IDs, and the allowed control case. Redact private material.", ""]
    output[base / "VALIDATION.md"] = "\n".join(lines)
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    stale = []
    for path, rendered in build(root).items():
        if args.check:
            if not path.exists() or path.read_text(encoding="utf-8") != rendered:
                stale.append(str(path.relative_to(root)))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(rendered, encoding="utf-8")
    if stale:
        print("FAIL: stale containment documents: " + ", ".join(stale))
        return 1
    print("PASS: containment documents are current" if args.check else "Updated containment profile documents")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
