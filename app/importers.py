"""
app/importers.py
Multi-format detection rule importer.

Supported sources:
  - Sigma YAML (parses attack.tXXXX tags from the tags field)
  - Plain JSON list of rule objects
  - Wazuh local_rules.xml (extracts rule metadata blocks)

Each importer normalizes to the canonical schema used by RuleStore:
    name, description, source, severity, technique_ids, raw_content
"""

from __future__ import annotations

import json
import logging
import re
import xml.etree.ElementTree as ET
from pathlib import Path

import yaml

from app.db import RuleStore

log = logging.getLogger(__name__)

TID_RE = re.compile(r"^t(\d{4})(?:\.(\d{3}))?$", re.IGNORECASE)


def normalize_technique_id(raw: str) -> str | None:
    """attack.t1059.001 -> T1059.001"""
    raw = raw.strip().lower().removeprefix("attack.")
    m = TID_RE.match(raw)
    if not m:
        return None
    base, sub = m.groups()
    return f"T{base}" + (f".{sub}" if sub else "")


# ---------------------------------------------------------------- Sigma

def parse_sigma_file(path: Path) -> dict | None:
    try:
        rule = yaml.safe_load(path.read_text())
    except Exception as e:
        log.warning("Failed to parse %s: %s", path, e)
        return None
    if not isinstance(rule, dict):
        return None

    tags = rule.get("tags", []) or []
    technique_ids = sorted({
        nid for t in tags
        if (nid := normalize_technique_id(t)) is not None
    })
    if not technique_ids:
        return None

    return {
        "name": rule.get("title", path.stem),
        "description": (rule.get("description", "") or "").strip()[:500],
        "source": "Sigma",
        "severity": rule.get("level", "medium"),
        "technique_ids": technique_ids,
        "rule_type": "sigma",
        "raw_content": path.read_text(),
    }


def import_sigma_directory(path: str | Path, store: RuleStore) -> dict:
    base = Path(path)
    if not base.exists():
        raise FileNotFoundError(f"{base} does not exist")

    files = list(base.rglob("*.yml")) + list(base.rglob("*.yaml"))
    imported = 0
    skipped = 0
    errors = []

    for f in files:
        parsed = parse_sigma_file(f)
        if not parsed:
            skipped += 1
            continue
        try:
            store.add_rule(**parsed)
            imported += 1
        except Exception as e:
            errors.append(f"{f.name}: {e}")

    return {
        "scanned": len(files),
        "imported": imported,
        "skipped": skipped,
        "errors": errors,
    }


# ---------------------------------------------------------------- JSON

def import_json_rules(path: str | Path, store: RuleStore) -> dict:
    """JSON: list of {name, description, source, severity, technique_ids}."""
    rules = json.loads(Path(path).read_text())
    if not isinstance(rules, list):
        raise ValueError("JSON file must contain a list of rule objects")

    imported = 0
    errors = []
    for r in rules:
        try:
            store.add_rule(
                name=r["name"],
                description=r.get("description", ""),
                source=r.get("source", "json-import"),
                severity=r.get("severity", "medium"),
                technique_ids=r.get("technique_ids", []),
                rule_type=r.get("rule_type", "json"),
                raw_content=json.dumps(r),
            )
            imported += 1
        except Exception as e:
            errors.append(f"{r.get('name', '<unnamed>')}: {e}")
    return {"imported": imported, "errors": errors}


# ---------------------------------------------------------------- Wazuh XML

def import_wazuh_xml(path: str | Path, store: RuleStore) -> dict:
    """Best-effort Wazuh local_rules.xml parser. Extracts rule id, level,
    description, and any mitre/id child elements."""
    xml = Path(path).read_text()
    # Wrap in a root element since Wazuh files often have multiple top-level groups
    wrapped = f"<root>{xml}</root>"
    try:
        root = ET.fromstring(wrapped)
    except ET.ParseError as e:
        return {"imported": 0, "errors": [str(e)]}

    imported = 0
    errors = []
    for rule in root.iter("rule"):
        try:
            rid = rule.get("id", "?")
            level = rule.get("level", "medium")
            desc_el = rule.find("description")
            description = desc_el.text if desc_el is not None else ""
            mitre_ids = [
                el.text for el in rule.findall(".//mitre/id")
                if el.text
            ]
            normalized = sorted({
                nid for m in mitre_ids
                if (nid := normalize_technique_id(m)) is not None
            })
            if not normalized:
                continue
            store.add_rule(
                name=f"Wazuh rule {rid}",
                description=description or "",
                source="Wazuh",
                severity=str(level),
                technique_ids=normalized,
                rule_type="wazuh",
                raw_content=ET.tostring(rule, encoding="unicode"),
            )
            imported += 1
        except Exception as e:
            errors.append(str(e))
    return {"imported": imported, "errors": errors}
