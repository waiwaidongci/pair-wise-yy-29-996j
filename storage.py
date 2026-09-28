"""SQLite 存储层：只管建表、连接与行级数据访问，不含业务规则。"""
from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Any

from core import iso

DB_PATH = Path(__file__).with_name("data.db")


class Store:
    def __init__(self, path: str | os.PathLike[str] = DB_PATH):
        self.path = str(path)
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.init_schema()

    # ---- schema ----
    def init_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS key_versions (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              issuer TEXT NOT NULL,
              version INTEGER NOT NULL,
              secret_hex TEXT NOT NULL,
              status TEXT NOT NULL CHECK(status IN ('active','retired')),
              created_at TEXT NOT NULL,
              retired_at TEXT,
              UNIQUE(issuer, version)
            );
            CREATE TABLE IF NOT EXISTS templates (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              issuer TEXT NOT NULL,
              code TEXT NOT NULL,
              name TEXT NOT NULL,
              current_version INTEGER NOT NULL DEFAULT 1,
              status TEXT NOT NULL CHECK(status IN ('active','disabled')),
              created_at TEXT NOT NULL,
              UNIQUE(issuer, code)
            );
            CREATE TABLE IF NOT EXISTS template_versions (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              template_id INTEGER NOT NULL REFERENCES templates(id),
              version INTEGER NOT NULL,
              fields_json TEXT NOT NULL,
              validity_days INTEGER NOT NULL CHECK(validity_days BETWEEN 1 AND 3650),
              created_at TEXT NOT NULL,
              UNIQUE(template_id, version)
            );
            CREATE TABLE IF NOT EXISTS credentials (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              template_id INTEGER NOT NULL REFERENCES templates(id),
              template_version INTEGER NOT NULL DEFAULT 1,
              issuer TEXT NOT NULL,
              holder_id TEXT NOT NULL,
              claims_json TEXT NOT NULL,
              issued_at TEXT NOT NULL,
              valid_until TEXT NOT NULL,
              status TEXT NOT NULL CHECK(status IN ('active','revoked','disputed')),
              key_version INTEGER NOT NULL,
              idempotency_key TEXT NOT NULL,
              revocation_reason TEXT,
              revocation_effective_at TEXT,
              UNIQUE(template_id, holder_id, idempotency_key)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS one_live_credential
              ON credentials(template_id, holder_id)
              WHERE status IN ('active','disputed');
            CREATE TABLE IF NOT EXISTS disputes (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              credential_id INTEGER NOT NULL REFERENCES credentials(id),
              raised_by TEXT NOT NULL,
              reason TEXT NOT NULL,
              status TEXT NOT NULL CHECK(status IN ('open','upheld','rejected')),
              resolution TEXT,
              created_at TEXT NOT NULL,
              resolved_at TEXT
            );
            CREATE TABLE IF NOT EXISTS audit_log (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              at TEXT NOT NULL,
              actor TEXT NOT NULL,
              action TEXT NOT NULL,
              entity_type TEXT NOT NULL,
              entity_id TEXT NOT NULL,
              details_json TEXT NOT NULL
            );
            """
        )
        self._migrate_legacy_schema()
        self.conn.commit()

    def _migrate_legacy_schema(self) -> None:
        """把单表模板结构（字段直接挂在 templates 上）升级为模板族+版本表。"""
        cols = {row["name"] for row in self.conn.execute("PRAGMA table_info(templates)")}
        if not cols:
            return
        added = []
        if "current_version" not in cols:
            self.conn.execute("ALTER TABLE templates ADD COLUMN current_version INTEGER NOT NULL DEFAULT 1")
            added.append("current_version")
        cred_cols = {row["name"] for row in self.conn.execute("PRAGMA table_info(credentials)")}
        if cred_cols and "template_version" not in cred_cols:
            self.conn.execute("ALTER TABLE credentials ADD COLUMN template_version INTEGER NOT NULL DEFAULT 1")
        # 旧库中字段和有效期在 templates 行上：为每个模板族回填 version=1。
        if {"fields_json", "validity_days"} <= cols:
            for row in self.conn.execute("SELECT id,fields_json,validity_days,created_at FROM templates").fetchall():
                exists = self.conn.execute(
                    "SELECT 1 FROM template_versions WHERE template_id=? AND version=1", (row["id"],)
                ).fetchone()
                if not exists:
                    self.conn.execute(
                        "INSERT INTO template_versions(template_id,version,fields_json,validity_days,created_at) VALUES(?,1,?,?,?)",
                        (row["id"], row["fields_json"], row["validity_days"], row["created_at"]),
                    )
        if added:
            self.conn.commit()

    # ---- 通用 ----
    def audit(self, actor: str, action: str, entity_type: str, entity_id: object, details: dict) -> None:
        self.conn.execute(
            "INSERT INTO audit_log(at,actor,action,entity_type,entity_id,details_json) VALUES(?,?,?,?,?,?)",
            (iso(), actor, action, entity_type, str(entity_id), json.dumps(details, ensure_ascii=False)),
        )

    def insert(self, table: str, data: dict[str, Any]) -> int:
        cols = ", ".join(data)
        marks = ", ".join("?" for _ in data)
        cur = self.conn.execute(f"INSERT INTO {table}({cols}) VALUES({marks})", tuple(data.values()))
        return int(cur.lastrowid)

    def get(self, table: str, identity: int) -> sqlite3.Row | None:
        return self.conn.execute(f"SELECT * FROM {table} WHERE id=?", (identity,)).fetchone()

    def close(self) -> None:
        self.conn.close()
