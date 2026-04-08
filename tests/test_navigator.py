"""tests/test_navigator.py"""

import json

import pandas as pd

from app.navigator import coverage_to_layer, layer_to_json_string


def test_layer_structure():
    coverage = pd.DataFrame([
        {"id": "T1059", "is_covered": True, "rule_count": 3,
         "weighted_score": 1.0, "missing_data_sources": []},
        {"id": "T1003", "is_covered": True, "rule_count": 1,
         "weighted_score": 0.5, "missing_data_sources": ["Process Memory"]},
        {"id": "T1190", "is_covered": False, "rule_count": 0,
         "weighted_score": 0.0, "missing_data_sources": []},
    ])
    layer = coverage_to_layer(coverage, name="Test")
    assert layer["domain"] == "enterprise-attack"
    assert layer["name"] == "Test"
    # Only covered techniques are exported
    assert len(layer["techniques"]) == 2
    ids = [t["techniqueID"] for t in layer["techniques"]]
    assert "T1059" in ids
    assert "T1003" in ids
    assert "T1190" not in ids


def test_layer_serializes_to_valid_json():
    coverage = pd.DataFrame([
        {"id": "T1059", "is_covered": True, "rule_count": 1,
         "weighted_score": 1.0, "missing_data_sources": []},
    ])
    layer = coverage_to_layer(coverage)
    s = layer_to_json_string(layer)
    parsed = json.loads(s)
    assert parsed["versions"]["attack"] == "14"


def test_layer_color_reflects_weighted_score():
    coverage = pd.DataFrame([
        {"id": "T1059", "is_covered": True, "rule_count": 1,
         "weighted_score": 1.0, "missing_data_sources": []},
        {"id": "T1003", "is_covered": True, "rule_count": 1,
         "weighted_score": 0.5, "missing_data_sources": []},
        {"id": "T1027", "is_covered": True, "rule_count": 1,
         "weighted_score": 0.1, "missing_data_sources": []},
    ])
    layer = coverage_to_layer(coverage)
    by_id = {t["techniqueID"]: t["color"] for t in layer["techniques"]}
    # Different weighted scores should produce different colors
    assert len({by_id["T1059"], by_id["T1003"], by_id["T1027"]}) == 3
