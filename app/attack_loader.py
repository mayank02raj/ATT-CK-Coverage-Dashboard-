"""
app/attack_loader.py
Pulls the MITRE ATT&CK Enterprise STIX 2.1 bundle and parses it into
clean Python objects. Caches to disk for 24h.

Extracts:
  - Tactics (with kill chain order)
  - Techniques and sub-techniques
  - Threat groups (intrusion-sets) with their used techniques
  - Data sources and components
  - Software (malware + tool) used by groups
"""

from __future__ import annotations

import json
import logging
import os
import time
from collections import defaultdict
from pathlib import Path

import pandas as pd
import requests

log = logging.getLogger(__name__)

ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
CACHE_PATH = Path("data/enterprise-attack.json")
CACHE_TTL_HOURS = 24

# MITRE ATT&CK tactic order (the canonical kill chain from initial access
# through impact). Hard-coded because it's stable and STIX phases are not
# guaranteed to come back in order.
TACTIC_ORDER = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]


# ---------------------------------------------------------------- fetch

def _cache_fresh(path: Path, ttl_hours: int) -> bool:
    if not path.exists():
        return False
    return (time.time() - path.stat().st_mtime) < ttl_hours * 3600


def fetch_bundle(force: bool = False) -> dict:
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not force and _cache_fresh(CACHE_PATH, CACHE_TTL_HOURS):
        with open(CACHE_PATH) as f:
            return json.load(f)
    log.info("Fetching ATT&CK bundle from %s", ATTACK_URL)
    r = requests.get(ATTACK_URL, timeout=60)
    r.raise_for_status()
    bundle = r.json()
    CACHE_PATH.write_text(json.dumps(bundle))
    return bundle


# ---------------------------------------------------------------- parse

def _ext_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def parse_techniques(bundle: dict) -> pd.DataFrame:
    rows = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        tid = _ext_id(obj)
        if not tid:
            continue
        tactics = [
            p["phase_name"]
            for p in obj.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack"
        ]
        rows.append({
            "id": tid,
            "stix_id": obj["id"],
            "name": obj.get("name", ""),
            "description": (obj.get("description", "") or "").split("\n")[0][:300],
            "tactics": tactics,
            "primary_tactic": tactics[0] if tactics else "unknown",
            "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
            "parent_id": tid.split(".")[0] if "." in tid else None,
            "platforms": obj.get("x_mitre_platforms", []),
            "data_sources": obj.get("x_mitre_data_sources", []),
            "detection": (obj.get("x_mitre_detection") or "")[:500],
        })
    return pd.DataFrame(rows).sort_values("id").reset_index(drop=True)


def parse_groups(bundle: dict) -> pd.DataFrame:
    """Threat groups (intrusion-set) with the techniques they use."""
    groups = {}
    techniques_by_stix = {}

    for obj in bundle.get("objects", []):
        if obj.get("type") == "intrusion-set" and not obj.get("revoked"):
            gid = _ext_id(obj)
            if gid:
                groups[obj["id"]] = {
                    "id": gid,
                    "stix_id": obj["id"],
                    "name": obj.get("name", ""),
                    "aliases": obj.get("aliases", []),
                    "description": (obj.get("description", "") or "")[:500],
                    "techniques": [],
                }
        if obj.get("type") == "attack-pattern":
            tid = _ext_id(obj)
            if tid:
                techniques_by_stix[obj["id"]] = tid

    # Relationships: group "uses" technique
    for obj in bundle.get("objects", []):
        if obj.get("type") != "relationship":
            continue
        if obj.get("relationship_type") != "uses":
            continue
        src = obj.get("source_ref", "")
        tgt = obj.get("target_ref", "")
        if src in groups and tgt in techniques_by_stix:
            groups[src]["techniques"].append(techniques_by_stix[tgt])

    rows = []
    for g in groups.values():
        g["techniques"] = sorted(set(g["techniques"]))
        g["technique_count"] = len(g["techniques"])
        rows.append(g)
    return (pd.DataFrame(rows)
            .sort_values("technique_count", ascending=False)
            .reset_index(drop=True))


def parse_data_sources(bundle: dict) -> pd.DataFrame:
    rows = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "x-mitre-data-source":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        rows.append({
            "id": _ext_id(obj),
            "name": obj.get("name", ""),
            "description": (obj.get("description", "") or "")[:300],
            "platforms": obj.get("x_mitre_platforms", []),
            "collection_layers": obj.get("x_mitre_collection_layers", []),
        })
    return pd.DataFrame(rows)


def techniques_per_tactic(techniques: pd.DataFrame) -> dict[str, list[str]]:
    out: dict[str, list[str]] = defaultdict(list)
    for _, row in techniques.iterrows():
        for t in row["tactics"]:
            out[t].append(row["id"])
    return dict(out)


# ---------------------------------------------------------------- public API

class AttackData:
    """One-shot loader that exposes everything as DataFrames."""

    def __init__(self, force_refresh: bool = False):
        bundle = fetch_bundle(force=force_refresh)
        self.techniques = parse_techniques(bundle)
        self.groups = parse_groups(bundle)
        self.data_sources = parse_data_sources(bundle)
        self.tactic_order = TACTIC_ORDER
        log.info(
            "Loaded %d techniques, %d groups, %d data sources",
            len(self.techniques), len(self.groups), len(self.data_sources))

    def technique(self, tid: str) -> dict | None:
        row = self.techniques[self.techniques["id"] == tid]
        return row.iloc[0].to_dict() if not row.empty else None

    def group(self, gid: str) -> dict | None:
        row = self.groups[self.groups["id"] == gid]
        return row.iloc[0].to_dict() if not row.empty else None
