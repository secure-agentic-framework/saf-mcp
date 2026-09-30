"""Regression tests for profile admission and cross-reference integrity.

These are repository-content tests, not tests of a deployed isolation system.
SPDX-License-Identifier: Apache-2.0
"""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("containment_validator", ROOT / "scripts/validate-containment-profile.py")
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


class ContainmentCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = yaml.safe_load((ROOT / "profiles/agent-containment/catalog.yml").read_text())
        cls.model = yaml.safe_load((ROOT / "research/framework-model.yml").read_text())

    def setUp(self):
        self.catalog = copy.deepcopy(self.original)

    def errors(self):
        return validator.check_catalog(self.catalog, self.model, ROOT)

    def assert_rejected(self, fragment):
        self.assertTrue(any(fragment in e for e in self.errors()), self.errors())

    def test_valid_catalog(self):
        self.assertEqual(self.errors(), [])

    def test_duplicate_item_rejected(self):
        self.catalog["attack_items"].append(copy.deepcopy(self.catalog["attack_items"][0]))
        self.assert_rejected("duplicate ID")

    def test_deprecated_technique_rejected(self):
        self.catalog["attack_items"][0]["saf_mappings"][0]["technique_id"] = "SAF-T1104"
        self.assert_rejected("inactive or unknown technique")

    def test_unknown_requirement_rejected(self):
        self.catalog["attack_items"][0]["requirements"].append("ACP-R999")
        self.assert_rejected("unknown or missing requirement")

    def test_requirement_without_assessment_rejected(self):
        candidate = copy.deepcopy(self.catalog["requirements"][0])
        candidate.update(id="ACP-R999", test_id="ACP-V999")
        self.catalog["requirements"].append(candidate)
        self.assert_rejected("no assessment item")

    def test_mismatched_test_join_rejected(self):
        self.catalog["attack_items"][0]["acceptance_tests"] = ["ACP-V999"]
        self.assert_rejected("acceptance test join differs")

    def test_missing_mitigation_join_rejected(self):
        self.catalog["attack_items"][0]["mitigations"] = []
        self.assert_rejected("mitigation join differs")

    def test_unmeasured_detection_cannot_be_promoted(self):
        self.catalog["attack_items"][0]["detection_maturity"] = "field_evaluated"
        self.assert_rejected("must remain proposed")

    def test_design_scenario_cannot_be_called_observed(self):
        self.catalog["attack_items"][0]["evidence_status"] = "observed"
        self.assert_rejected("unsupported evidence promotion")

    def test_planned_deployment_test_cannot_be_marked_passed(self):
        self.catalog["requirements"][0]["validation"]["status"] = "passed"
        self.assert_rejected("must remain planned")

    def test_unreviewed_attack_mapping_rejected(self):
        self.catalog["attack_items"][0]["mitre_attack"] = [{"id":"T9999", "relationship":"analogous", "scope":"example"}]
        self.assert_rejected("unreviewed ATT&CK ID")

    def test_unsupported_mapping_strength_rejected(self):
        self.catalog["attack_items"][0]["saf_mappings"][0]["relationship"] = "certified"
        self.assert_rejected("invalid relationship")

    def test_duplicate_yaml_keys_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate YAML key"):
            yaml.load("profile_id: ACP\nprofile_id: OTHER\n", Loader=validator.UniqueKeyLoader)

    def test_unknown_tactic_rejected(self):
        self.catalog["attack_items"][0]["tactics"] = ["ATK-TA9999"]
        self.assert_rejected("unknown or missing tactic")

    def test_broken_link_and_bad_anchor_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            doc = root / "README.md"
            doc.write_text("[missing](missing.md)\n[test](VALIDATION.md#acp-v999)\n")
            (root / "VALIDATION.md").write_text("## ACP-V001\n")
            errors = validator.check_links(root, [doc])
            self.assertEqual(len(errors), 2)


if __name__ == "__main__":
    unittest.main()
