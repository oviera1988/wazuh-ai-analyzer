"""
Capa de datos con SQLite + aiosqlite (async)
"""

import aiosqlite
import json
import logging
from datetime import datetime
from typing import Optional
from models import AlertFilter, SyncStatus

logger = logging.getLogger(__name__)
DB_PATH = "/app/data/wazuh_alerts.db"


class Database:
    def __init__(self):
        self.db_path = DB_PATH

    async def init(self):
        """Crea tablas si no existen"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.executescript("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    wazuh_id TEXT UNIQUE NOT NULL,
                    timestamp TEXT,
                    rule_id TEXT,
                    rule_level INTEGER,
                    rule_description TEXT,
                    rule_groups TEXT,        -- JSON array
                    mitre_id TEXT,           -- JSON array
                    mitre_tactic TEXT,
                    mitre_technique TEXT,
                    agent_id TEXT,
                    agent_name TEXT,
                    agent_ip TEXT,
                    manager_name TEXT,
                    raw_data TEXT,           -- JSON object
                    full_log TEXT,
                    ai_priority INTEGER DEFAULT 0,
                    ai_severity TEXT,
                    ai_analysis TEXT,        -- JSON object con el análisis completo
                    processed_at TEXT,
                    created_at TEXT DEFAULT (datetime('now'))
                );

                CREATE INDEX IF NOT EXISTS idx_ai_priority ON alerts(ai_priority DESC);
                CREATE INDEX IF NOT EXISTS idx_agent_name ON alerts(agent_name);
                CREATE INDEX IF NOT EXISTS idx_ai_severity ON alerts(ai_severity);
                CREATE INDEX IF NOT EXISTS idx_timestamp ON alerts(timestamp DESC);

                CREATE TABLE IF NOT EXISTS sync_status (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    status TEXT DEFAULT 'idle',
                    message TEXT,
                    last_sync TEXT,
                    total_processed INTEGER DEFAULT 0
                );

                INSERT OR IGNORE INTO sync_status (id, status, message) VALUES (1, 'idle', 'Sin sincronizar');
            """)
            await db.commit()

    async def filter_unprocessed(self, alerts: list[dict]) -> list[dict]:
        """Retorna solo alertas que no están en la BD todavía"""
        ids = [a["wazuh_id"] for a in alerts]
        async with aiosqlite.connect(self.db_path) as db:
            placeholders = ",".join("?" * len(ids))
            cursor = await db.execute(
                f"SELECT wazuh_id FROM alerts WHERE wazuh_id IN ({placeholders})", ids
            )
            existing = {row[0] for row in await cursor.fetchall()}
        return [a for a in alerts if a["wazuh_id"] not in existing]

    async def save_alerts(self, alerts: list[dict]):
        """Guarda alertas procesadas en batch"""
        async with aiosqlite.connect(self.db_path) as db:
            for alert in alerts:
                analysis = alert.get("ai_analysis", {})
                await db.execute("""
                    INSERT OR REPLACE INTO alerts (
                        wazuh_id, timestamp, rule_id, rule_level, rule_description,
                        rule_groups, mitre_id, mitre_tactic, mitre_technique,
                        agent_id, agent_name, agent_ip, manager_name,
                        raw_data, full_log,
                        ai_priority, ai_severity, ai_analysis, processed_at
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    alert.get("wazuh_id"),
                    alert.get("timestamp"),
                    alert.get("rule_id"),
                    alert.get("rule_level"),
                    alert.get("rule_description"),
                    json.dumps(alert.get("rule_groups", [])),
                    json.dumps(alert.get("mitre_id", [])),
                    json.dumps(alert.get("mitre_tactic", [])),
                    json.dumps(alert.get("mitre_technique", [])),
                    alert.get("agent_id"),
                    alert.get("agent_name"),
                    alert.get("agent_ip"),
                    alert.get("manager_name"),
                    json.dumps(alert.get("raw_data", {})),
                    alert.get("full_log"),
                    analysis.get("ai_priority", 0),
                    analysis.get("ai_severity", ""),
                    json.dumps(analysis),
                    datetime.utcnow().isoformat(),
                ))
            await db.commit()

    async def get_alerts(self, filters: AlertFilter) -> list[dict]:
        sort_col = {
            "ai_priority": "ai_priority DESC",
            "timestamp": "timestamp DESC",
            "rule_level": "rule_level DESC",
        }.get(filters.sort_by, "ai_priority DESC")

        conditions = []
        params = []
        if filters.severity:
            conditions.append("ai_severity = ?")
            params.append(filters.severity)
        if filters.agent:
            conditions.append("agent_name LIKE ?")
            params.append(f"%{filters.agent}%")
        if filters.rule_group:
            conditions.append("rule_groups LIKE ?")
            params.append(f"%{filters.rule_group}%")

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        params.extend([filters.limit, filters.offset])

        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                f"SELECT * FROM alerts {where} ORDER BY {sort_col} LIMIT ? OFFSET ?",
                params,
            )
            rows = await cursor.fetchall()
            return [self._row_to_dict(row) for row in rows]

    async def get_alert_by_id(self, alert_id: str) -> Optional[dict]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM alerts WHERE id = ? OR wazuh_id = ?",
                (alert_id, alert_id),
            )
            row = await cursor.fetchone()
            return self._row_to_dict(row) if row else None

    async def count_alerts(self, filters: AlertFilter) -> int:
        conditions = []
        params = []
        if filters.severity:
            conditions.append("ai_severity = ?")
            params.append(filters.severity)
        if filters.agent:
            conditions.append("agent_name LIKE ?")
            params.append(f"%{filters.agent}%")
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(f"SELECT COUNT(*) FROM alerts {where}", params)
            return (await cursor.fetchone())[0]

    async def get_dashboard_stats(self) -> dict:
        async with aiosqlite.connect(self.db_path) as db:
            stats = {}
            cursor = await db.execute("SELECT COUNT(*) FROM alerts")
            stats["total"] = (await cursor.fetchone())[0]

            cursor = await db.execute(
                "SELECT ai_severity, COUNT(*) FROM alerts GROUP BY ai_severity"
            )
            stats["by_severity"] = {row[0]: row[1] for row in await cursor.fetchall()}

            cursor = await db.execute(
                "SELECT agent_name, COUNT(*) as cnt FROM alerts GROUP BY agent_name ORDER BY cnt DESC LIMIT 10"
            )
            stats["top_agents"] = [{"agent": row[0], "count": row[1]} for row in await cursor.fetchall()]

            cursor = await db.execute(
                "SELECT * FROM alerts ORDER BY ai_priority DESC LIMIT 5"
            )
            db.row_factory = aiosqlite.Row
            rows = await cursor.fetchall()
            stats["top_priority"] = []

        return stats

    async def update_alert_analysis(self, alert_id: int, analysis: dict):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "UPDATE alerts SET ai_analysis=?, ai_priority=?, ai_severity=?, processed_at=? WHERE id=?",
                (
                    json.dumps(analysis),
                    analysis.get("ai_priority", 0),
                    analysis.get("ai_severity", ""),
                    datetime.utcnow().isoformat(),
                    alert_id,
                ),
            )
            await db.commit()

    async def get_sync_status(self) -> SyncStatus:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM sync_status WHERE id=1")
            row = await cursor.fetchone()
            return SyncStatus(**dict(row)) if row else SyncStatus()

    async def update_sync_status(self, status: str, message: str, total: int = 0):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "UPDATE sync_status SET status=?, message=?, last_sync=?, total_processed=total_processed+? WHERE id=1",
                (status, message, datetime.utcnow().isoformat(), total),
            )
            await db.commit()

    async def get_unique_agents(self) -> list[str]:
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute("SELECT DISTINCT agent_name FROM alerts ORDER BY agent_name")
            return [row[0] for row in await cursor.fetchall()]

    async def get_unique_rule_groups(self) -> list[str]:
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute("SELECT DISTINCT rule_groups FROM alerts")
            groups = set()
            for row in await cursor.fetchall():
                try:
                    groups.update(json.loads(row[0]))
                except Exception:
                    pass
            return sorted(groups)

    def _row_to_dict(self, row) -> dict:
        if row is None:
            return None
        d = dict(row)
        for json_field in ["rule_groups", "mitre_id", "mitre_tactic", "mitre_technique", "raw_data", "ai_analysis"]:
            if d.get(json_field):
                try:
                    d[json_field] = json.loads(d[json_field])
                except Exception:
                    pass
        return d
