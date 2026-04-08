"""
app/db.py
SQLite persistence for detection rules and rule-to-technique mappings.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime
from pathlib import Path

import pandas as pd

log = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS rules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    source TEXT NOT NULL,
    severity TEXT,
    rule_type TEXT,
    raw_content TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rule_techniques (
    rule_id TEXT NOT NULL,
    technique_id TEXT NOT NULL,
    PRIMARY KEY (rule_id, technique_id),
    FOREIGN KEY (rule_id) REFERENCES rules(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS rule_data_sources (
    rule_id TEXT NOT NULL,
    data_source TEXT NOT NULL,
    PRIMARY KEY (rule_id, data_source),
    FOREIGN KEY (rule_id) REFERENCES rules(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS available_data_sources (
    name TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 1,
    quality REAL NOT NULL DEFAULT 1.0,
    notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_rule_tech_tid
    ON rule_techniques(technique_id);
CREATE INDEX IF NOT EXISTS idx_rules_source
    ON rules(source);
"""


class RuleStore:
    def __init__(self, db_path: str):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.db_path = db_path
        self._lock = threading.Lock()
        with self._conn() as c:
            c.executescript(SCHEMA)
        log.info("RuleStore ready at %s", db_path)

    def _conn(self):
        c = sqlite3.connect(self.db_path, check_same_thread=False)
        c.execute("PRAGMA foreign_keys = ON")
        c.row_factory = sqlite3.Row
        return c

    # ------------------------------------------------------------ rules

    def add_rule(
        self,
        name: str,
        description: str,
        source: str,
        severity: str,
        technique_ids: list[str],
        rule_type: str = "custom",
        raw_content: str | None = None,
        data_sources: list[str] | None = None,
    ) -> str:
        rule_id = str(uuid.uuid4())
        now = datetime.utcnow().isoformat()
        with self._lock, self._conn() as c:
            c.execute(
                """INSERT INTO rules
                   (id, name, description, source, severity,
                    rule_type, raw_content, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (rule_id, name, description, source, severity,
                 rule_type, raw_content, now, now),
            )
            for tid in set(technique_ids):
                c.execute(
                    """INSERT OR IGNORE INTO rule_techniques
                       (rule_id, technique_id) VALUES (?, ?)""",
                    (rule_id, tid),
                )
            for ds in set(data_sources or []):
                c.execute(
                    """INSERT OR IGNORE INTO rule_data_sources
                       (rule_id, data_source) VALUES (?, ?)""",
                    (rule_id, ds),
                )
        return rule_id

    def delete_rule(self, rule_id: str) -> bool:
        with self._lock, self._conn() as c:
            cur = c.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
            return cur.rowcount > 0

    def all_rules(self) -> pd.DataFrame:
        with self._conn() as c:
            rules = pd.read_sql("SELECT * FROM rules ORDER BY created_at DESC", c)
            mapping = pd.read_sql(
                "SELECT rule_id, technique_id FROM rule_techniques", c)
        if rules.empty:
            rules["technique_ids"] = pd.Series(dtype=object)
            return rules
        tech_by_rule = (mapping.groupby("rule_id")["technique_id"]
                        .apply(list).to_dict())
        rules["technique_ids"] = rules["id"].map(
            lambda r: tech_by_rule.get(r, []))
        rules["technique_count"] = rules["technique_ids"].apply(len)
        return rules

    def covered_techniques(self) -> set[str]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT DISTINCT technique_id FROM rule_techniques"
            ).fetchall()
        return {r[0] for r in rows}

    def rules_for_technique(self, tid: str) -> pd.DataFrame:
        with self._conn() as c:
            return pd.read_sql(
                """SELECT r.* FROM rules r
                   JOIN rule_techniques rt ON r.id = rt.rule_id
                   WHERE rt.technique_id = ?""",
                c, params=(tid,))

    def stats(self) -> dict:
        with self._conn() as c:
            n_rules = c.execute("SELECT COUNT(*) FROM rules").fetchone()[0]
            n_tech = c.execute(
                "SELECT COUNT(DISTINCT technique_id) FROM rule_techniques"
            ).fetchone()[0]
            by_source = dict(c.execute(
                "SELECT source, COUNT(*) FROM rules GROUP BY source"
            ).fetchall())
            by_severity = dict(c.execute(
                "SELECT severity, COUNT(*) FROM rules GROUP BY severity"
            ).fetchall())
        return {
            "rule_count": n_rules,
            "covered_techniques": n_tech,
            "by_source": by_source,
            "by_severity": by_severity,
        }

    # ------------------------------------------------------------ data sources

    def set_data_source(self, name: str, enabled: bool = True,
                        quality: float = 1.0, notes: str = ""):
        with self._lock, self._conn() as c:
            c.execute(
                """INSERT INTO available_data_sources
                   (name, enabled, quality, notes) VALUES (?, ?, ?, ?)
                   ON CONFLICT(name) DO UPDATE SET
                     enabled=excluded.enabled,
                     quality=excluded.quality,
                     notes=excluded.notes""",
                (name, int(enabled), quality, notes),
            )

    def available_data_sources(self) -> pd.DataFrame:
        with self._conn() as c:
            return pd.read_sql(
                "SELECT * FROM available_data_sources ORDER BY name", c)

    def bulk_seed_data_sources(self, names: list[str]):
        for name in names:
            self.set_data_source(name, enabled=True, quality=1.0)
