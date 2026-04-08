"""
app/coverage.py
Coverage math.

Two scoring modes:
  1. Naive: a technique is covered if any rule mentions it
  2. Weighted: coverage is reduced for techniques that depend on data sources
     the user has marked as unavailable or low quality

The weighted score is what makes this useful for real assessments. There is
no point claiming you cover T1003 (OS Credential Dumping) if you do not collect
process memory. The dashboard tells you that.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

import pandas as pd


@dataclass
class CoverageScore:
    technique_id: str
    name: str
    primary_tactic: str
    is_covered: bool
    rule_count: int
    weighted_score: float           # 0.0 to 1.0
    required_data_sources: list[str]
    missing_data_sources: list[str]


def compute_coverage(
    techniques: pd.DataFrame,
    rules: pd.DataFrame,
    available_data_sources: pd.DataFrame | None = None,
) -> pd.DataFrame:
    """Return a per-technique coverage DataFrame."""
    # Build a covered set and a per-technique rule count
    rule_count: dict[str, int] = defaultdict(int)
    if not rules.empty:
        for _, r in rules.iterrows():
            for tid in r.get("technique_ids", []) or []:
                rule_count[tid] += 1

    # Available data sources lookup
    ds_quality: dict[str, float] = {}
    if available_data_sources is not None and not available_data_sources.empty:
        for _, row in available_data_sources.iterrows():
            if row["enabled"]:
                ds_quality[row["name"].lower()] = float(row["quality"])

    rows = []
    for _, t in techniques.iterrows():
        tid = t["id"]
        required = t.get("data_sources", []) or []
        missing = [
            ds for ds in required
            if ds.lower() not in ds_quality
        ]
        if not required:
            ds_factor = 1.0
        else:
            available_ratio = sum(
                ds_quality.get(ds.lower(), 0.0) for ds in required
            ) / len(required)
            ds_factor = available_ratio

        is_covered = rule_count[tid] > 0
        weighted = (1.0 if is_covered else 0.0) * ds_factor

        rows.append({
            "id": tid,
            "name": t["name"],
            "primary_tactic": t.get("primary_tactic", "unknown"),
            "is_covered": is_covered,
            "rule_count": rule_count[tid],
            "weighted_score": round(weighted, 3),
            "required_data_sources": required,
            "missing_data_sources": missing,
            "is_subtechnique": t.get("is_subtechnique", False),
        })
    return pd.DataFrame(rows)


def coverage_by_tactic(coverage: pd.DataFrame,
                       tactic_order: list[str]) -> pd.DataFrame:
    rows = []
    for tac in tactic_order:
        sub = coverage[coverage["primary_tactic"] == tac]
        if sub.empty:
            continue
        total = len(sub)
        covered = int(sub["is_covered"].sum())
        weighted = float(sub["weighted_score"].sum())
        rows.append({
            "tactic": tac.replace("-", " ").title(),
            "tactic_raw": tac,
            "total": total,
            "covered": covered,
            "uncovered": total - covered,
            "naive_pct": round(100 * covered / total, 1),
            "weighted_pct": round(100 * weighted / total, 1),
        })
    return pd.DataFrame(rows)


def coverage_for_group(coverage: pd.DataFrame,
                       group_techniques: list[str]) -> dict:
    if not group_techniques:
        return {"total": 0, "covered": 0, "pct": 0.0,
                "covered_ids": [], "missing_ids": []}
    sub = coverage[coverage["id"].isin(group_techniques)]
    covered_ids = sub[sub["is_covered"]]["id"].tolist()
    missing_ids = sub[~sub["is_covered"]]["id"].tolist()
    total = len(group_techniques)
    return {
        "total": total,
        "covered": len(covered_ids),
        "pct": round(100 * len(covered_ids) / total, 1),
        "covered_ids": covered_ids,
        "missing_ids": missing_ids,
    }
