"""tests/test_importers.py"""

import tempfile
from pathlib import Path

import pytest

from app.db import RuleStore
from app.importers import (import_sigma_directory, import_wazuh_xml,
                           normalize_technique_id, parse_sigma_file)

SAMPLE_SIGMA = """
title: Test PowerShell
id: 11111111-1111-1111-1111-111111111111
status: test
description: A test rule
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\\\powershell.exe'
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense_evasion
  - attack.t1027
"""

SAMPLE_WAZUH = """
<group name="custom,">
  <rule id="100200" level="10">
    <description>Test rule</description>
    <mitre>
      <id>T1059.001</id>
      <id>T1027</id>
    </mitre>
  </rule>
</group>
"""


@pytest.fixture
def store():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        yield RuleStore(f.name)


def test_normalize_technique_id():
    assert normalize_technique_id("attack.t1059.001") == "T1059.001"
    assert normalize_technique_id("attack.t1059") == "T1059"
    assert normalize_technique_id("T1059.001") == "T1059.001"
    assert normalize_technique_id("not-a-tag") is None
    assert normalize_technique_id("attack.privilege_escalation") is None


def test_parse_sigma_file(tmp_path):
    p = tmp_path / "rule.yml"
    p.write_text(SAMPLE_SIGMA)
    parsed = parse_sigma_file(p)
    assert parsed is not None
    assert parsed["name"] == "Test PowerShell"
    assert parsed["severity"] == "high"
    assert "T1059.001" in parsed["technique_ids"]
    assert "T1027" in parsed["technique_ids"]


def test_parse_sigma_file_no_attack_tags(tmp_path):
    p = tmp_path / "no_tags.yml"
    p.write_text("title: x\ntags: [not.a.tag]\ndetection: {}\n")
    assert parse_sigma_file(p) is None


def test_import_sigma_directory(tmp_path, store):
    (tmp_path / "rule1.yml").write_text(SAMPLE_SIGMA)
    (tmp_path / "junk.txt").write_text("not yaml")
    result = import_sigma_directory(str(tmp_path), store)
    assert result["imported"] == 1
    assert store.all_rules().iloc[0]["technique_count"] == 2


def test_import_wazuh_xml(tmp_path, store):
    p = tmp_path / "rules.xml"
    p.write_text(SAMPLE_WAZUH)
    result = import_wazuh_xml(str(p), store)
    assert result["imported"] == 1
    rule = store.all_rules().iloc[0]
    assert "T1059.001" in rule["technique_ids"]
    assert "T1027" in rule["technique_ids"]
