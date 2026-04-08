"""tests/test_db.py"""

import tempfile

import pytest

from app.db import RuleStore


@pytest.fixture
def store():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        yield RuleStore(f.name)


def test_add_and_list(store):
    rid = store.add_rule(
        name="Test rule",
        description="d",
        source="Sigma",
        severity="high",
        technique_ids=["T1059", "T1059.001"],
    )
    assert rid
    rules = store.all_rules()
    assert len(rules) == 1
    assert rules.iloc[0]["technique_count"] == 2


def test_covered_set(store):
    store.add_rule("a", "", "Sigma", "high", ["T1059", "T1027"])
    store.add_rule("b", "", "Wazuh", "medium", ["T1059", "T1003.001"])
    covered = store.covered_techniques()
    assert covered == {"T1059", "T1027", "T1003.001"}


def test_delete_rule(store):
    rid = store.add_rule("a", "", "Sigma", "high", ["T1059"])
    assert store.delete_rule(rid) is True
    assert store.delete_rule("nope") is False
    assert store.all_rules().empty


def test_rules_for_technique(store):
    store.add_rule("a", "", "Sigma", "high", ["T1059"])
    store.add_rule("b", "", "Wazuh", "medium", ["T1059", "T1003"])
    store.add_rule("c", "", "Splunk", "low", ["T1027"])
    found = store.rules_for_technique("T1059")
    assert len(found) == 2


def test_data_source_management(store):
    store.set_data_source("Process Creation", enabled=True, quality=1.0)
    store.set_data_source("Process Memory", enabled=False, quality=0.0)
    ds = store.available_data_sources()
    assert len(ds) == 2
    pm = ds[ds["name"] == "Process Memory"].iloc[0]
    assert pm["enabled"] == 0


def test_stats(store):
    store.add_rule("a", "", "Sigma", "high", ["T1059"])
    store.add_rule("b", "", "Sigma", "low", ["T1027"])
    s = store.stats()
    assert s["rule_count"] == 2
    assert s["covered_techniques"] == 2
    assert s["by_source"]["Sigma"] == 2
