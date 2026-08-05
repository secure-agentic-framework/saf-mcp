#!/usr/bin/env python3
"""Test script for SAF-T1001 detection rule validation.

This harness models real Sigma backend semantics:
- A plain string value with '*' wildcards is a literal glob. A backslash-u
  escape inside such a value is matched as literal text (backslash, u, ...),
  NOT as the Unicode codepoint. No production Sigma engine decodes it.
- The '|re' modifier value is a regex. We translate PCRE/RE2 \\x{...} codepoint
  escapes into Python-native \\uXXXX / \\UXXXXXXXX so Python's re can evaluate
  the exact same codepoints a real backend would.
"""

import json
import re
import yaml
from pathlib import Path


def glob_to_regex(pattern):
    """Convert a Sigma wildcard glob to a regex, treating everything except '*'
    literally (no unicode-escape decoding, since a real backend does not do that)."""
    return re.escape(pattern).replace(r'\*', '.*')


def pcre_codepoints_to_python(pattern):
    """Translate PCRE/RE2 \\x{HHHH} codepoint escapes to Python-native escapes."""
    def repl(match):
        cp = int(match.group(1), 16)
        return '\\u%04x' % cp if cp <= 0xFFFF else '\\U%08x' % cp
    return re.sub(r'\\x\{([0-9a-fA-F]+)\}', repl, pattern)


def build_matchers(rule):
    """Build labelled (compiled_regex, source_label) matchers from all selections."""
    matchers = []
    for sel_name, sel in rule['detection'].items():
        if sel_name == 'condition' or not isinstance(sel, dict):
            continue
        for field, value in sel.items():
            if field.endswith('|re'):
                values = value if isinstance(value, list) else [value]
                for v in values:
                    matchers.append((re.compile(pcre_codepoints_to_python(v)), f'{field}: {v}'))
            else:
                values = value if isinstance(value, list) else [value]
                for v in values:
                    matchers.append((re.compile(glob_to_regex(v), re.IGNORECASE), f'{field}: {v}'))
    return matchers


def test_detection_rule():
    """Test the detection rule against known samples."""
    rule_path = Path(__file__).parent / 'detection-rule.yml'
    with open(rule_path, 'r') as f:
        rule = yaml.safe_load(f)

    matchers = build_matchers(rule)

    expected_detections = {
        "data_processor": True,   # Has <!-- SYSTEM:
        "api_client": True,       # Has <|system|>
        "analyzer": True,         # Has [INST]
        "formatter": True,        # Has ### Instruction:
        "helper": True,           # Has real zero-width space (U+200B)
        "rtl_override": True,     # Has real right-to-left override (U+202E)
        "unicode_tag": True,      # Has real Unicode tag char (U+E0041)
        "word_joiner": True,      # Has real word joiner (U+2060)
        "file_reader": False,     # Clean
        "validator": False,       # Normal HTML comment
        "converter": False,       # Clean
        "logger": False,          # Has [INFO] not [INST]
        "scanner": False          # Has ### Features not ### Instruction
    }

    test_logs_path = Path(__file__).parent / 'test-logs.json'
    results = {}
    with open(test_logs_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            log = json.loads(line)
            tool_name = log['tool_name']
            description = log['tool_description']

            detected = False
            matched_pattern = None
            for regex, label in matchers:
                if regex.search(description):
                    detected = True
                    matched_pattern = label
                    break

            results[tool_name] = {
                'detected': detected,
                'expected': expected_detections.get(tool_name, False),
                'matched_pattern': matched_pattern,
                'description': description
            }

    print("SAF-T1001 Detection Rule Test Results")
    print("=" * 50)

    total_tests = len(results)
    correct = 0
    false_positives = []
    false_negatives = []

    for tool_name, result in results.items():
        status = "PASS" if result['detected'] == result['expected'] else "FAIL"
        print(f"{status} {tool_name}: Detected={result['detected']}, Expected={result['expected']}")

        if result['detected'] == result['expected']:
            correct += 1
        elif result['detected'] and not result['expected']:
            false_positives.append(tool_name)
        elif not result['detected'] and result['expected']:
            false_negatives.append(tool_name)

        if result['matched_pattern']:
            print(f"  Matched pattern: {result['matched_pattern']}")

    print("\n" + "=" * 50)
    print(f"Test Summary: {correct}/{total_tests} tests passed ({correct/total_tests*100:.1f}%)")

    if false_positives:
        print(f"\nFalse Positives ({len(false_positives)}):")
        for fp in false_positives:
            print(f"  - {fp}: {results[fp]['description']!r}")

    if false_negatives:
        print(f"\nFalse Negatives ({len(false_negatives)}):")
        for fn in false_negatives:
            print(f"  - {fn}: {results[fn]['description']!r}")

    print("\n" + "=" * 50)
    print("Pattern Coverage Test:")
    covered = {label: False for _, label in matchers}
    for result in results.values():
        if result['matched_pattern'] is not None:
            covered[result['matched_pattern']] = True
    for label, is_covered in covered.items():
        status = "PASS" if is_covered else "FAIL"
        print(f"{status} Pattern '{label}' - {'Tested' if is_covered else 'Not tested'}")

    return correct == total_tests


if __name__ == "__main__":
    success = test_detection_rule()
    exit(0 if success else 1)
