"""Audit logger — stores every permission decision in SQLite."""

from __future__ import annotations

import logging
import sqlite3
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    user_arn TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    aws_action TEXT NOT NULL,
    resource TEXT NOT NULL,
    decision TEXT NOT NULL,
    reason TEXT NOT NULL
)
"""


class AuditLogger:
    """Writes permission decisions to a SQLite database.

    Each call to log_decision() inserts one row. The database and table
    are created automatically on first use.
    """

    def __init__(self, db_path: str = "audit.db") -> None:
        self._db_path = db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(CREATE_TABLE_SQL)
        self._conn.commit()

    def log_decision(
        self,
        user_arn: str,
        agent_id: str,
        tool_name: str,
        aws_action: str,
        resource: str,
        decision: str,
        reason: str,
    ) -> None:
        """Record a single permission decision."""
        timestamp = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            """INSERT INTO audit_log (timestamp, user_arn, agent_id, tool_name, aws_action, resource, decision, reason)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (timestamp, user_arn, agent_id, tool_name, aws_action, resource, decision, reason),
        )
        self._conn.commit()
        logger.info(
            "Audit: %s %s %s on %s → %s",
            user_arn,
            tool_name,
            aws_action,
            resource,
            decision,
        )

    def get_recent(self, limit: int = 50) -> list[dict[str, Any]]:
        """Retrieve the most recent audit log entries."""
        cursor = self._conn.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        return [dict(row) for row in cursor.fetchall()]

    def get_by_user(self, user_arn: str, limit: int = 50) -> list[dict[str, Any]]:
        """Retrieve audit entries for a specific user."""
        cursor = self._conn.execute(
            "SELECT * FROM audit_log WHERE user_arn = ? ORDER BY id DESC LIMIT ?",
            (user_arn, limit),
        )
        return [dict(row) for row in cursor.fetchall()]

    def close(self) -> None:
        """Close the database connection."""
        self._conn.close()
