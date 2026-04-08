"""tests/test_coverage.py"""

import pandas as pd

from app.coverage import (compute_coverage, coverage_by_tactic,
                          coverage_for_group)


def make_techniques():
    return pd.DataFrame([
        {"id": "T1059", "name": "CmdLine",
         "tactics": ["execution"], "primary_tactic": "execution",
         "data_sources": ["Process Creation"], "is_subtechnique": False},
        {"id": "T1003", "name": "OS Cred Dumping",
         "tactics": ["credential-access"],
         "primary_tactic": "credential-access",
         "data_sources": ["Process Memory", "Process Access"],
         "is_subtechnique": False},
        {"id": "T1190", "name": "Exploit Public App",
         "tactics": ["initial-access"],
         "primary_tactic": "initial-access",
         "data_sources": [], "is_subtechnique": False},
    ])


def make_rules(technique_lists):
    return pd.DataFrame([
        {"id": f"r{i}", "name": f"r{i}", "technique_ids": tids}
        for i, tids in enumerate(technique_lists)
    ])


def make_data_sources(names_with_state):
    return pd.DataFrame([
        {"name": n, "enabled": e, "quality": q, "notes": ""}
        for n, e, q in names_with_state
    ])


def test_coverage_naive():
    techs = make_techniques()
    rules = make_rules([["T1059"], ["T1190"]])
    cov = compute_coverage(techs, rules)
    assert int(cov[cov["id"] == "T1059"].iloc[0]["is_covered"]) == 1
    assert int(cov[cov["id"] == "T1190"].iloc[0]["is_covered"]) == 1
    assert int(cov[cov["id"] == "T1003"].iloc[0]["is_covered"]) == 0


def test_weighted_score_drops_for_missing_data_source():
    techs = make_techniques()
    rules = make_rules([["T1003"]])
    ds = make_data_sources([
        ("Process Creation", 1, 1.0),
        # Process Memory and Process Access NOT enabled
    ])
    cov = compute_coverage(techs, rules, ds)
    t1003 = cov[cov["id"] == "T1003"].iloc[0]
    assert t1003["is_covered"] is True
    assert t1003["weighted_score"] == 0.0  # no data sources available
    assert "Process Memory" in t1003["missing_data_sources"]


def test_weighted_score_full_when_all_data_sources_present():
    techs = make_techniques()
    rules = make_rules([["T1003"]])
    ds = make_data_sources([
        ("Process Memory", 1, 1.0),
        ("Process Access", 1, 1.0),
    ])
    cov = compute_coverage(techs, rules, ds)
    t1003 = cov[cov["id"] == "T1003"].iloc[0]
    assert t1003["weighted_score"] == 1.0


def test_coverage_by_tactic():
    techs = make_techniques()
    rules = make_rules([["T1059"]])
    cov = compute_coverage(techs, rules)
    by_tactic = coverage_by_tactic(
        cov, ["execution", "credential-access", "initial-access"])
    exec_row = by_tactic[by_tactic["tactic_raw"] == "execution"].iloc[0]
    assert exec_row["covered"] == 1
    assert exec_row["naive_pct"] == 100.0


def test_coverage_for_group():
    techs = make_techniques()
    rules = make_rules([["T1059"], ["T1190"]])
    cov = compute_coverage(techs, rules)
    group_techniques = ["T1059", "T1003", "T1190"]
    result = coverage_for_group(cov, group_techniques)
    assert result["total"] == 3
    assert result["covered"] == 2
    assert result["pct"] == round(200 / 3, 1)
    assert "T1003" in result["missing_ids"]
