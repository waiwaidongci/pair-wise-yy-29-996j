"""模板存储：模板族（templates）与版本（template_versions）的行级读写。

存储层不做规则判断，只承担持久化和行到字典的装配。
"""
from __future__ import annotations

import json
import sqlite3

from storage import Store


class TemplateStore:
    def __init__(self, store: Store):
        self.store = store
        self.conn = store.conn

    # ---- 模板族 ----
    def create_family(self, issuer: str, code: str, name: str, created_at: str) -> int:
        return self.store.insert(
            "templates",
            {"issuer": issuer, "code": code, "name": name, "current_version": 1,
             "status": "active", "created_at": created_at},
        )

    def get_family(self, template_id: int) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM templates WHERE id=?", (template_id,)).fetchone()

    def find_family(self, issuer: str, code: str) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM templates WHERE issuer=? AND code=?", (issuer, code)).fetchone()

    def list_families(self, issuer: str | None = None) -> list[sqlite3.Row]:
        if issuer is not None:
            return self.conn.execute(
                "SELECT * FROM templates WHERE issuer=? ORDER BY id DESC", (issuer,)
            ).fetchall()
        return self.conn.execute("SELECT * FROM templates ORDER BY id DESC").fetchall()

    def bump_current_version(self, template_id: int, version: int) -> None:
        self.conn.execute("UPDATE templates SET current_version=? WHERE id=?", (version, template_id))

    # ---- 模板版本 ----
    def insert_version(self, template_id: int, version: int, fields: list[dict],
                       validity_days: int, created_at: str) -> int:
        return self.store.insert(
            "template_versions",
            {"template_id": template_id, "version": version,
             "fields_json": json.dumps(fields, ensure_ascii=False),
             "validity_days": validity_days, "created_at": created_at},
        )

    def get_version(self, template_id: int, version: int) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM template_versions WHERE template_id=? AND version=?", (template_id, version)
        ).fetchone()

    def list_versions(self, template_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM template_versions WHERE template_id=? ORDER BY version ASC", (template_id,)
        ).fetchall()

    # ---- 装配 ----
    @staticmethod
    def version_dict(row: sqlite3.Row) -> dict:
        return {"id": row["id"], "template_id": row["template_id"], "version": row["version"],
                "fields": json.loads(row["fields_json"]), "validity_days": row["validity_days"],
                "created_at": row["created_at"]}

    def family_dict(self, row: sqlite3.Row, include_versions: bool = True) -> dict:
        data = {"id": row["id"], "issuer": row["issuer"], "code": row["code"], "name": row["name"],
                "current_version": row["current_version"], "status": row["status"],
                "created_at": row["created_at"]}
        versions = self.list_versions(row["id"])
        if versions:
            current = next((v for v in versions if v["version"] == row["current_version"]), versions[-1])
            data["current"] = self.version_dict(current)
        if include_versions:
            data["versions"] = [self.version_dict(v) for v in versions]
        return data
