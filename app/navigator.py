"""
app/navigator.py
Export coverage data as a MITRE ATT&CK Navigator layer JSON.

The Navigator (https://mitre-attack.github.io/attack-navigator/) is the de
facto standard tool for visualizing ATT&CK coverage. Producing a layer file
means analysts can open your coverage in the canonical UI without needing
this dashboard at all, and you can diff layers across teams or quarters.

Layer format reference: https://github.com/mitre-attack/attack-navigator/blob/master/layers/LAYERFORMAT.md
"""

from __future__ import annotations

import json
from datetime import datetime

import pandas as pd

NAVIGATOR_VERSION = "4.5"
ATTACK_VERSION = "14"


def coverage_to_layer(
    coverage: pd.DataFrame,
    name: str = "Coverage",
    description: str = "Detection coverage exported from ATT&CK Coverage Dashboard",
) -> dict:
    """Build a Navigator layer from a coverage DataFrame."""
    techniques_layer = []
    for _, row in coverage.iterrows():
        if not row["is_covered"]:
            continue
        score = int(row.get("rule_count", 0))
        weighted = float(row.get("weighted_score", 0))
        comment_parts = [f"{score} rule(s)"]
        if row.get("missing_data_sources"):
            comment_parts.append(
                f"missing data sources: {', '.join(row['missing_data_sources'])}")

        techniques_layer.append({
            "techniqueID": row["id"],
            "score": score,
            "color": _color_for(weighted),
            "comment": " | ".join(comment_parts),
            "enabled": True,
            "metadata": [
                {"name": "weighted_score", "value": str(weighted)},
                {"name": "rule_count", "value": str(score)},
            ],
        })

    return {
        "name": name,
        "versions": {
            "attack": ATTACK_VERSION,
            "navigator": NAVIGATOR_VERSION,
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": description,
        "filters": {"platforms": [
            "Windows", "Linux", "macOS",
            "Network", "Containers", "Office 365",
            "SaaS", "IaaS", "Google Workspace", "Azure AD",
        ]},
        "sorting": 0,
        "layout": {
            "layout": "side",
            "showID": True,
            "showName": True,
        },
        "hideDisabled": False,
        "techniques": techniques_layer,
        "gradient": {
            "colors": ["#fff5f0", "#fb6a4a", "#67000d"],
            "minValue": 0,
            "maxValue": 10,
        },
        "legendItems": [
            {"label": "Covered (full data)", "color": "#67000d"},
            {"label": "Covered (partial data)", "color": "#fb6a4a"},
            {"label": "Covered (no data)", "color": "#fff5f0"},
        ],
        "metadata": [
            {"name": "exported_at", "value": datetime.utcnow().isoformat()},
            {"name": "tool", "value": "attack-coverage-dashboard"},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
    }


def _color_for(weighted: float) -> str:
    if weighted >= 0.8:
        return "#67000d"
    if weighted >= 0.4:
        return "#fb6a4a"
    if weighted > 0:
        return "#fff5f0"
    return "#ffffff"


def layer_to_json_string(layer: dict) -> str:
    return json.dumps(layer, indent=2)
