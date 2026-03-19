from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


class LocalStorage:
    """Small local-only SQLite store used for bounded logs, event history, and baselines.

    The app deliberately keeps this on the local machine only. Nothing in this class
    talks to any network service.
    """

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=20, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        return connection

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                PRAGMA journal_mode=WAL;
                PRAGMA synchronous=NORMAL;

                CREATE TABLE IF NOT EXISTS entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    category TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    fingerprint TEXT,
                    payload_json TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_entries_category_id
                ON entries(category, id DESC);

                CREATE TABLE IF NOT EXISTS snapshots (
                    category TEXT PRIMARY KEY,
                    updated_at REAL NOT NULL,
                    payload_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS baselines (
                    name TEXT PRIMARY KEY,
                    updated_at REAL NOT NULL,
                    payload_json TEXT NOT NULL
                );
                """
            )

    def append_entry(self, category: str, payload: Dict[str, Any], retention: int, fingerprint: str = '') -> None:
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        now = time.time()
        with self._lock, self._connect() as conn:
            conn.execute(
                'INSERT INTO entries(category, created_at, fingerprint, payload_json) VALUES (?, ?, ?, ?)',
                (category, now, fingerprint or None, encoded),
            )
            conn.execute(
                """
                DELETE FROM entries
                WHERE category = ?
                  AND id NOT IN (
                    SELECT id FROM entries
                    WHERE category = ?
                    ORDER BY id DESC
                    LIMIT ?
                  )
                """,
                (category, category, max(1, int(retention))),
            )

    def list_entries(self, category: str, limit: int) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                'SELECT payload_json FROM entries WHERE category = ? ORDER BY id DESC LIMIT ?',
                (category, max(1, int(limit))),
            ).fetchall()
        payloads = [json.loads(row['payload_json']) for row in rows]
        payloads.reverse()
        return payloads

    def clear_entries(self, category: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute('DELETE FROM entries WHERE category = ?', (category,))

    def set_snapshot(self, category: str, payload: Any) -> None:
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        now = time.time()
        with self._lock, self._connect() as conn:
            conn.execute(
                'INSERT INTO snapshots(category, updated_at, payload_json) VALUES (?, ?, ?) '
                'ON CONFLICT(category) DO UPDATE SET updated_at = excluded.updated_at, payload_json = excluded.payload_json',
                (category, now, encoded),
            )

    def get_snapshot(self, category: str, default: Any = None) -> Any:
        with self._lock, self._connect() as conn:
            row = conn.execute('SELECT payload_json FROM snapshots WHERE category = ?', (category,)).fetchone()
        if not row:
            return default
        return json.loads(row['payload_json'])

    def set_baseline(self, name: str, payload: Any) -> None:
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        now = time.time()
        with self._lock, self._connect() as conn:
            conn.execute(
                'INSERT INTO baselines(name, updated_at, payload_json) VALUES (?, ?, ?) '
                'ON CONFLICT(name) DO UPDATE SET updated_at = excluded.updated_at, payload_json = excluded.payload_json',
                (name, now, encoded),
            )

    def get_baseline(self, name: str, default: Any = None) -> Any:
        with self._lock, self._connect() as conn:
            row = conn.execute('SELECT payload_json FROM baselines WHERE name = ?', (name,)).fetchone()
        if not row:
            return default
        return json.loads(row['payload_json'])
