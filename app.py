#!/usr/bin/env python3
"""Minimal standards-library digital credential service for local evaluation."""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import sys
import uuid
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

DB_PATH = Path(__file__).with_name("data.db")

SCHEMA_SQL = """
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
CREATE TABLE IF NOT EXISTS template_series (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  issuer TEXT NOT NULL,
  code TEXT NOT NULL,
  name TEXT NOT NULL,
  current_version INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(issuer, code)
);
CREATE TABLE IF NOT EXISTS templates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  series_id INTEGER NOT NULL REFERENCES template_series(id),
  issuer TEXT NOT NULL,
  code TEXT NOT NULL,
  version INTEGER NOT NULL,
  name TEXT NOT NULL,
  fields_json TEXT NOT NULL,
  validity_days INTEGER NOT NULL CHECK(validity_days BETWEEN 1 AND 3650),
  status TEXT NOT NULL CHECK(status IN ('active','disabled')),
  created_at TEXT NOT NULL,
  UNIQUE(series_id, version),
  UNIQUE(issuer, code, version)
);
CREATE TABLE IF NOT EXISTS credentials (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  template_id INTEGER NOT NULL REFERENCES templates(id),
  template_version INTEGER NOT NULL,
  template_code TEXT NOT NULL,
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
  UNIQUE(issuer, template_code, holder_id, idempotency_key)
);
CREATE UNIQUE INDEX IF NOT EXISTS one_live_credential
  ON credentials(issuer, template_code, holder_id)
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


def now() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime | None = None) -> str:
    return (value or now()).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_time(value: str | None) -> datetime:
    if not value:
        return now()
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


class Store:
    def __init__(self, path: str | os.PathLike[str] = DB_PATH):
        self.path = str(path)
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.init_schema()

    def init_schema(self) -> None:
        self._migrate_legacy()
        self.conn.executescript(SCHEMA_SQL)
        self.conn.commit()

    def _migrate_legacy(self) -> None:
        """Upgrade a pre-versioning database: one templates row -> series + version 1."""
        cols = {row["name"] for row in self.conn.execute("PRAGMA table_info(templates)")}
        if not cols or "series_id" in cols:
            return
        with self.conn:
            self.conn.executescript(
                """
                CREATE TABLE template_series (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  issuer TEXT NOT NULL,
                  code TEXT NOT NULL,
                  name TEXT NOT NULL,
                  current_version INTEGER NOT NULL DEFAULT 1,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL,
                  UNIQUE(issuer, code)
                );
                CREATE TABLE templates_new (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  series_id INTEGER NOT NULL REFERENCES template_series(id),
                  issuer TEXT NOT NULL,
                  code TEXT NOT NULL,
                  version INTEGER NOT NULL,
                  name TEXT NOT NULL,
                  fields_json TEXT NOT NULL,
                  validity_days INTEGER NOT NULL CHECK(validity_days BETWEEN 1 AND 3650),
                  status TEXT NOT NULL CHECK(status IN ('active','disabled')),
                  created_at TEXT NOT NULL,
                  UNIQUE(series_id, version),
                  UNIQUE(issuer, code, version)
                );
                CREATE TABLE credentials_new (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  template_id INTEGER NOT NULL REFERENCES templates_new(id),
                  template_version INTEGER NOT NULL,
                  template_code TEXT NOT NULL,
                  issuer TEXT NOT NULL,
                  holder_id TEXT NOT NULL,
                  claims_json TEXT NOT NULL,
                  issued_at TEXT NOT NULL,
                  valid_until TEXT NOT NULL,
                  status TEXT NOT NULL CHECK(status IN ('active','revoked','disputed')),
                  key_version INTEGER NOT NULL,
                  idempotency_key TEXT NOT NULL,
                  revocation_reason TEXT,
                  revocation_effective_at TEXT
                );
                CREATE TABLE disputes_new (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  credential_id INTEGER NOT NULL REFERENCES credentials_new(id),
                  raised_by TEXT NOT NULL,
                  reason TEXT NOT NULL,
                  status TEXT NOT NULL CHECK(status IN ('open','upheld','rejected')),
                  resolution TEXT,
                  created_at TEXT NOT NULL,
                  resolved_at TEXT
                );
                """
            )
            stamp = iso()
            self.conn.execute(
                "INSERT INTO template_series(id,issuer,code,name,current_version,created_at,updated_at) "
                "SELECT id, issuer, code, name, 1, created_at, ? FROM templates",
                (stamp,),
            )
            self.conn.execute(
                "INSERT INTO templates_new(id,series_id,issuer,code,version,name,fields_json,validity_days,status,created_at) "
                "SELECT id, id, issuer, code, 1, name, fields_json, validity_days, status, created_at FROM templates"
            )
            self.conn.execute(
                "INSERT INTO credentials_new(id,template_id,template_version,template_code,issuer,holder_id,claims_json,"
                "issued_at,valid_until,status,key_version,idempotency_key,revocation_reason,revocation_effective_at) "
                "SELECT c.id, c.template_id, 1, t.code, c.issuer, c.holder_id, c.claims_json, c.issued_at, c.valid_until,"
                "c.status, c.key_version, c.idempotency_key, c.revocation_reason, c.revocation_effective_at "
                "FROM credentials c JOIN templates t ON t.id = c.template_id"
            )
            self.conn.execute(
                "INSERT INTO disputes_new(id,credential_id,raised_by,reason,status,resolution,created_at,resolved_at) "
                "SELECT id, credential_id, raised_by, reason, status, resolution, created_at, resolved_at FROM disputes"
            )
            self.conn.execute("DROP TABLE disputes")
            self.conn.execute("DROP INDEX IF EXISTS one_live_credential")
            self.conn.execute("DROP TABLE credentials")
            self.conn.execute("DROP TABLE templates")
            self.conn.execute("ALTER TABLE templates_new RENAME TO templates")
            self.conn.execute("ALTER TABLE credentials_new RENAME TO credentials")
            self.conn.execute("ALTER TABLE disputes_new RENAME TO disputes")
            self.conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS one_live_credential "
                "ON credentials(issuer, template_code, holder_id) WHERE status IN ('active','disputed')"
            )

    # ---- template series / versions (storage only, rules live in TemplateService) ----

    def get_template_series(self, issuer: str, code: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM template_series WHERE issuer=? AND code=?", (issuer, code)
        ).fetchone()

    def insert_template_series(self, issuer: str, code: str, name: str, at: str) -> int:
        cur = self.conn.execute(
            "INSERT INTO template_series(issuer,code,name,current_version,created_at,updated_at) VALUES(?,?,?,1,?,?)",
            (issuer, code, name, at, at),
        )
        return int(cur.lastrowid)

    def bump_template_series(self, series_id: int, name: str, version: int, at: str) -> None:
        self.conn.execute(
            "UPDATE template_series SET name=?, current_version=?, updated_at=? WHERE id=?",
            (name, version, at, series_id),
        )

    def insert_template_version(
        self, series_id: int, issuer: str, code: str, version: int, name: str,
        fields: list[dict], validity_days: int, at: str,
    ) -> int:
        cur = self.conn.execute(
            "INSERT INTO templates(series_id,issuer,code,version,name,fields_json,validity_days,status,created_at) "
            "VALUES(?,?,?,?,?,?,?,'active',?)",
            (series_id, issuer, code, version, name, json.dumps(fields, ensure_ascii=False), validity_days, at),
        )
        return int(cur.lastrowid)

    def get_template_version(self, series_id: int, version: int) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM templates WHERE series_id=? AND version=?", (series_id, version)
        ).fetchone()

    def list_template_versions(self, issuer: str | None = None) -> list[sqlite3.Row]:
        if issuer is None:
            sql = "SELECT * FROM templates ORDER BY issuer, code, version"
            return list(self.conn.execute(sql))
        return list(self.conn.execute(
            "SELECT * FROM templates WHERE issuer=? ORDER BY code, version", (issuer,)
        ))

    def list_series(self, issuer: str | None = None) -> list[sqlite3.Row]:
        sql = "SELECT * FROM template_series"
        args: tuple = ()
        if issuer is not None:
            sql += " WHERE issuer=?"
            args = (issuer,)
        return list(self.conn.execute(sql + " ORDER BY issuer, code", args))

    def audit(self, actor: str, action: str, entity_type: str, entity_id: object, details: dict) -> None:
        self.conn.execute(
            "INSERT INTO audit_log(at,actor,action,entity_type,entity_id,details_json) VALUES(?,?,?,?,?,?)",
            (iso(), actor, action, entity_type, str(entity_id), json.dumps(details, ensure_ascii=False)),
        )

    def close(self) -> None:
        self.conn.close()


def require_actor(actor: str | None, role: str | None, expected: str) -> str:
    if not actor:
        raise ApiError(401, "缺少身份")
    if role != expected:
        raise ApiError(403, f"需要角色 {expected}")
    return actor


def normalize_fields(fields: list[dict]) -> list[dict]:
    """Template field rules: non-empty, unique names, at least one field."""
    field_names: set[str] = set()
    normalized: list[dict] = []
    for field in fields:
        field_name = str(field.get("name", "")).strip()
        if not field_name or field_name in field_names:
            raise ApiError(400, "模板字段为空或重复")
        field_names.add(field_name)
        normalized.append({"name": field_name, "required": bool(field.get("required", False))})
    if not normalized:
        raise ApiError(400, "模板至少需要一个字段")
    return normalized


def validate_validity_days(validity_days: int) -> int:
    try:
        days = int(validity_days)
    except (TypeError, ValueError) as exc:
        raise ApiError(400, "有效期天数必须是整数") from exc
    if not 1 <= days <= 3650:
        raise ApiError(400, "有效期天数必须在 1 到 3650 之间")
    return days


def field_changes(before: list[dict], after: list[dict], before_days: int, after_days: int) -> dict:
    """Diff two field lists by name, required flag, order, and validity window."""
    before_by_name = {f["name"]: f for f in before}
    after_by_name = {f["name"]: f for f in after}
    before_names = [f["name"] for f in before]
    after_names = [f["name"] for f in after]
    added = [name for name in after_names if name not in before_by_name]
    removed = [name for name in before_names if name not in after_by_name]
    became_required = [
        name for name in after_names
        if name in before_by_name and not before_by_name[name]["required"] and after_by_name[name]["required"]
    ]
    became_optional = [
        name for name in after_names
        if name in before_by_name and before_by_name[name]["required"] and not after_by_name[name]["required"]
    ]
    shared_before = [name for name in before_names if name in after_by_name]
    shared_after = [name for name in after_names if name in before_by_name]
    reordered = shared_before != shared_after
    validity_changed = before_days != after_days
    changed = bool(added or removed or became_required or became_optional or reordered or validity_changed)
    return {
        "changed": changed,
        "added": added,
        "removed": removed,
        "became_required": became_required,
        "became_optional": became_optional,
        "reordered": reordered,
        "validity_days_before": before_days if validity_changed else None,
        "validity_days_after": after_days if validity_changed else None,
    }


class TemplateService:
    """Template rules: revision-based versioning on top of the dumb Store."""

    def __init__(self, store: Store):
        self.store = store
        self.conn = store.conn

    def create(self, actor: str | None, role: str | None, code: str, name: str, fields: list[dict], validity_days: int) -> dict:
        actor = require_actor(actor, role, "issuer")
        code, name = str(code).strip(), str(name).strip()
        if not code or not name:
            raise ApiError(400, "模板代号和名称不能为空")
        normalized = normalize_fields(fields)
        days = validate_validity_days(validity_days)
        at = iso()
        try:
            with self.conn:
                series_id = self.store.insert_template_series(actor, code, name, at)
                template_id = self.store.insert_template_version(
                    series_id, actor, code, 1, name, normalized, days, at
                )
                self.store.audit(
                    actor, "template.create", "template", template_id,
                    {"code": code, "version": 1, "fields": normalized, "validity_days": days},
                )
        except sqlite3.IntegrityError as exc:
            raise ApiError(409, "同一签发方不能重复使用模板代号") from exc
        return self._version_dict(self._row(template_id), None)

    def revise(
        self, actor: str | None, role: str | None, code: str, fields: list[dict],
        validity_days: int, name: str | None = None,
    ) -> dict:
        """Create a new version for an existing code, based on its current version."""
        actor = require_actor(actor, role, "issuer")
        code = str(code).strip()
        if not code:
            raise ApiError(400, "模板代号不能为空")
        normalized = normalize_fields(fields)
        days = validate_validity_days(validity_days)
        series = self.store.get_template_series(actor, code)
        if not series:
            raise ApiError(404, "模板代号不存在，请先创建模板")
        current = self.store.get_template_version(int(series["id"]), int(series["current_version"]))
        if not current:
            raise ApiError(409, "模板当前版本缺失，无法修订")
        current_fields = json.loads(current["fields_json"])
        required_names = {f["name"] for f in current_fields if f["required"]}
        dropped_required = sorted(required_names - {f["name"] for f in normalized})
        if dropped_required:
            raise ApiError(400, f"新版本缺少必填字段={dropped_required}，必填字段不能在修订中删除")
        changes = field_changes(current_fields, normalized, int(current["validity_days"]), days)
        if not changes["changed"]:
            raise ApiError(409, "字段和有效期均未变化，不生成新版本")
        new_name = str(name).strip() if name is not None else series["name"]
        if not new_name:
            raise ApiError(400, "模板名称不能为空")
        new_version = int(current["version"]) + 1
        at = iso()
        with self.conn:
            template_id = self.store.insert_template_version(
                int(series["id"]), actor, code, new_version, new_name, normalized, days, at
            )
            self.store.bump_template_series(int(series["id"]), new_name, new_version, at)
            self.store.audit(
                actor, "template.revise", "template", template_id,
                {"code": code, "version": new_version, "based_on": current["version"],
                 "fields": normalized, "validity_days": days, "changes": changes},
            )
        return self._version_dict(self._row(template_id), changes)

    def resolve_for_issue(self, actor: str, ref: str) -> sqlite3.Row:
        """Resolve a code or a (possibly stale) template row id to the current version."""
        ref = str(ref).strip()
        if not ref:
            raise ApiError(400, "缺少模板代号或模板版本 ID")
        if ref.isdigit():
            row = self.conn.execute("SELECT * FROM templates WHERE id=?", (int(ref),)).fetchone()
            if not row:
                raise ApiError(404, "模板版本不存在")
            if row["issuer"] != actor:
                raise ApiError(403, "不能使用其他签发方的模板")
            series = self.store.get_template_series(row["issuer"], row["code"])
            current = self.store.get_template_version(int(series["id"]), int(series["current_version"]))
            if row["id"] != current["id"]:
                raise ApiError(
                    409,
                    f"该代号当前为 v{current['version']}，不能用旧版本 v{row['version']} 签发；"
                    "请改用模板代号或当前版本 ID",
                )
            return current
        series = self.store.get_template_series(actor, ref)
        if not series:
            raise ApiError(404, "模板代号不存在")
        current = self.store.get_template_version(int(series["id"]), int(series["current_version"]))
        if not current or current["status"] != "active":
            raise ApiError(409, "模板已停用")
        return current

    def list_versions(self, issuer: str | None = None) -> list[dict]:
        return [self._version_dict(row, None) for row in self.store.list_template_versions(issuer)]

    def get_series_detail(self, actor: str | None, role: str | None, code: str) -> dict:
        code = str(code).strip()
        rows = self.conn.execute(
            "SELECT * FROM templates WHERE code=? ORDER BY issuer, version", (code,)
        ).fetchall()
        if not rows:
            raise ApiError(404, "模板代号不存在")
        issuers = {row["issuer"] for row in rows}
        if actor is None or (actor not in issuers and role != "regulator"):
            raise ApiError(403, "不能查看其他签发方的模板")
        versions: list[dict] = []
        for index, row in enumerate(rows):
            changes = None
            if index > 0 and row["issuer"] == rows[index - 1]["issuer"]:
                prev = rows[index - 1]
                changes = field_changes(
                    json.loads(prev["fields_json"]), json.loads(row["fields_json"]),
                    int(prev["validity_days"]), int(row["validity_days"]),
                )
            versions.append(self._version_dict(row, changes))
        return {"code": code, "versions": versions}

    def _row(self, template_id: int) -> sqlite3.Row:
        row = self.conn.execute("SELECT * FROM templates WHERE id=?", (template_id,)).fetchone()
        if not row:
            raise ApiError(404, "模板版本不存在")
        return row

    @staticmethod
    def _version_dict(row: sqlite3.Row, changes: dict | None) -> dict:
        result = {
            "id": row["id"],
            "series_id": row["series_id"],
            "issuer": row["issuer"],
            "code": row["code"],
            "version": row["version"],
            "name": row["name"],
            "fields": json.loads(row["fields_json"]),
            "validity_days": row["validity_days"],
            "status": row["status"],
            "created_at": row["created_at"],
        }
        if changes is not None:
            result["changes"] = changes
        return result


class CredentialService:
    """Credential issuance and verification with small, explicit trust boundaries."""

    def __init__(self, store: Store):
        self.store = store
        self.conn = store.conn
        self.templates = TemplateService(store)

    @staticmethod
    def _required_actor(actor: str | None, role: str | None, expected: str) -> str:
        return require_actor(actor, role, expected)

    def _row(self, table: str, identity: int) -> sqlite3.Row:
        row = self.conn.execute(f"SELECT * FROM {table} WHERE id=?", (identity,)).fetchone()
        if not row:
            raise ApiError(404, "对象不存在")
        return row

    def _active_key(self, issuer: str) -> sqlite3.Row:
        row = self.conn.execute(
            "SELECT * FROM key_versions WHERE issuer=? AND status='active' ORDER BY version DESC LIMIT 1", (issuer,)
        ).fetchone()
        if not row:
            raise ApiError(409, "签发方尚未初始化密钥")
        return row

    def rotate_key(self, actor: str | None, role: str | None, issuer: str) -> dict:
        actor = self._required_actor(actor, role, "issuer")
        if actor != issuer:
            raise ApiError(403, "只能轮换自己的密钥")
        with self.conn:
            old = self.conn.execute("SELECT * FROM key_versions WHERE issuer=? AND status='active'", (issuer,)).fetchone()
            version = 1
            if old:
                version = int(old["version"]) + 1
                self.conn.execute("UPDATE key_versions SET status='retired', retired_at=? WHERE id=?", (iso(), old["id"]))
            secret_hex = secrets.token_hex(32)
            cur = self.conn.execute(
                "INSERT INTO key_versions(issuer,version,secret_hex,status,created_at) VALUES(?,?,?,'active',?)",
                (issuer, version, secret_hex, iso()),
            )
            self.store.audit(actor, "key.rotate", "key_version", cur.lastrowid, {"version": version, "retired_previous": bool(old)})
        return {"issuer": issuer, "version": version, "status": "active", "public_fingerprint": hashlib.sha256(secret_hex.encode()).hexdigest()[:20]}

    def create_template(self, actor: str | None, role: str | None, code: str, name: str, fields: list[dict], validity_days: int) -> dict:
        return self.templates.create(actor, role, code, name, fields, validity_days)

    def revise_template(self, actor: str | None, role: str | None, code: str, fields: list[dict], validity_days: int, name: str | None = None) -> dict:
        return self.templates.revise(actor, role, code, fields, validity_days, name)

    def issue(self, actor: str | None, role: str | None, template_ref: str, holder_id: str, claims: dict, idempotency_key: str, valid_until: str | None = None) -> dict:
        actor = self._required_actor(actor, role, "issuer")
        if not holder_id.strip() or not idempotency_key.strip():
            raise ApiError(400, "持有人和幂等键不能为空")
        # New issuance always resolves to the current version of the code;
        # credentials already issued stay pinned to the version at issuance time.
        template = self.templates.resolve_for_issue(actor, template_ref)
        existing = self.conn.execute(
            "SELECT * FROM credentials WHERE issuer=? AND template_code=? AND holder_id=? AND idempotency_key=?",
            (actor, template["code"], holder_id, idempotency_key),
        ).fetchone()
        if existing:
            return self._credential_dict(existing)
        fields = json.loads(template["fields_json"])
        missing = [f["name"] for f in fields if f["required"] and not str(claims.get(f["name"], "")).strip()]
        unknown = sorted(set(claims) - {f["name"] for f in fields})
        if missing or unknown:
            raise ApiError(400, f"声明不完整，缺少={missing}，未知字段={unknown}")
        live = self.conn.execute(
            "SELECT id FROM credentials WHERE issuer=? AND template_code=? AND holder_id=? AND status IN ('active','disputed')",
            (actor, template["code"], holder_id),
        ).fetchone()
        if live:
            raise ApiError(409, "该持有人已有有效的同代号凭证；重复提交应使用相同幂等键")
        issued = now()
        expiration = parse_time(valid_until) if valid_until else issued + timedelta(days=int(template["validity_days"]))
        if expiration <= issued:
            raise ApiError(400, "有效期必须晚于签发时间")
        key = self._active_key(actor)
        try:
            with self.conn:
                cur = self.conn.execute(
                    """INSERT INTO credentials(template_id,template_version,template_code,issuer,holder_id,claims_json,
                       issued_at,valid_until,status,key_version,idempotency_key)
                       VALUES(?,?,?,?,?,?,?,?, 'active',?,?)""",
                    (template["id"], template["version"], template["code"], actor, holder_id,
                     json.dumps(claims, ensure_ascii=False), iso(issued), iso(expiration),
                     key["version"], idempotency_key),
                )
                self.store.audit(
                    actor, "credential.issue", "credential", cur.lastrowid,
                    {"holder_id": holder_id, "template_id": template["id"], "template_code": template["code"],
                     "template_version": template["version"], "key_version": key["version"]},
                )
        except sqlite3.IntegrityError as exc:
            raise ApiError(409, "并发签发冲突，请用相同幂等键重试") from exc
        return self._credential_dict(self._row("credentials", cur.lastrowid))

    def revoke(self, actor: str | None, role: str | None, credential_id: int, reason: str, effective_at: str | None = None) -> dict:
        actor = self._required_actor(actor, role, "issuer")
        credential = self._row("credentials", credential_id)
        if credential["issuer"] != actor:
            raise ApiError(403, "只能撤销本机构签发的凭证")
        if credential["status"] == "revoked":
            if credential["revocation_reason"] == reason:
                return self._credential_dict(credential)
            raise ApiError(409, "凭证已经撤销")
        effective = parse_time(effective_at) if effective_at else now()
        with self.conn:
            self.conn.execute(
                "UPDATE credentials SET status='revoked',revocation_reason=?,revocation_effective_at=? WHERE id=?",
                (reason, iso(effective), credential_id),
            )
            self.store.audit(actor, "credential.revoke", "credential", credential_id, {"reason": reason, "effective_at": iso(effective)})
        return self._credential_dict(self._row("credentials", credential_id))

    def dispute(self, actor: str | None, role: str | None, credential_id: int, reason: str) -> dict:
        actor = self._required_actor(actor, role, "holder")
        credential = self._row("credentials", credential_id)
        if credential["holder_id"] != actor:
            raise ApiError(403, "只能对自己的凭证提出争议")
        if credential["status"] != "revoked":
            raise ApiError(409, "只有已撤销凭证可以提出争议")
        open_dispute = self.conn.execute("SELECT id FROM disputes WHERE credential_id=? AND status='open'", (credential_id,)).fetchone()
        if open_dispute:
            raise ApiError(409, "已有待处理争议")
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO disputes(credential_id,raised_by,reason,status,created_at) VALUES(?,?,?,'open',?)",
                (credential_id, actor, reason, iso()),
            )
            self.conn.execute("UPDATE credentials SET status='disputed' WHERE id=?", (credential_id,))
            self.store.audit(actor, "dispute.open", "credential", credential_id, {"dispute_id": cur.lastrowid, "reason": reason})
        return {"id": cur.lastrowid, "credential_id": credential_id, "status": "open"}

    def resolve_dispute(self, actor: str | None, role: str | None, dispute_id: int, decision: str, resolution: str) -> dict:
        actor = self._required_actor(actor, role, "regulator")
        if decision not in {"uphold", "reject"}:
            raise ApiError(400, "决定只能是 uphold 或 reject")
        dispute = self._row("disputes", dispute_id)
        if dispute["status"] != "open":
            raise ApiError(409, "争议已经处理")
        credential = self._row("credentials", dispute["credential_id"])
        if credential["status"] != "disputed":
            raise ApiError(409, "凭证状态与争议不一致")
        new_status = "revoked" if decision == "uphold" else "active"
        dispute_status = "upheld" if decision == "uphold" else "rejected"
        with self.conn:
            self.conn.execute("UPDATE disputes SET status=?,resolution=?,resolved_at=? WHERE id=?", (dispute_status, resolution, iso(), dispute_id))
            self.conn.execute("UPDATE credentials SET status=? WHERE id=?", (new_status, credential["id"]))
            self.store.audit(actor, "dispute.resolve", "dispute", dispute_id, {"decision": decision, "credential_status": new_status})
        return {"id": dispute_id, "status": decision, "credential_status": new_status, "resolution": resolution}

    def present(self, actor: str | None, role: str | None, credential_id: int, disclosed_fields: list[str] | None) -> dict:
        actor = self._required_actor(actor, role, "holder")
        credential = self._row("credentials", credential_id)
        if credential["holder_id"] != actor:
            raise ApiError(403, "不能出示他人的凭证")
        # The credential is pinned to the exact version it was issued against;
        # later revisions never change what an existing credential discloses.
        template = self.conn.execute(
            "SELECT * FROM templates WHERE id=? AND version=?",
            (credential["template_id"], credential["template_version"]),
        ).fetchone()
        if not template:
            raise ApiError(409, "凭证所属模板版本缺失，无法出示")
        allowed = [field["name"] for field in json.loads(template["fields_json"])]
        disclosed = disclosed_fields if disclosed_fields is not None else allowed
        if len(disclosed) != len(set(disclosed)) or any(name not in allowed for name in disclosed):
            raise ApiError(400, "披露字段不在模板中或重复")
        claims = json.loads(credential["claims_json"])
        visible = {name: claims[name] for name in disclosed}
        payload = {
            "credential_id": credential["id"],
            "template_id": credential["template_id"],
            "template_code": credential["template_code"],
            "template_version": credential["template_version"],
            "issuer": credential["issuer"],
            "holder_id": credential["holder_id"],
            "claims": visible,
            "valid_until": credential["valid_until"],
            "key_version": credential["key_version"],
        }
        key = self.conn.execute(
            "SELECT secret_hex FROM key_versions WHERE issuer=? AND version=?", (credential["issuer"], credential["key_version"])
        ).fetchone()
        signature = hmac.new(bytes.fromhex(key["secret_hex"]), canonical(payload), hashlib.sha256).hexdigest()
        token = base64.urlsafe_b64encode(canonical({"payload": payload, "signature": signature})).decode().rstrip("=")
        self.store.audit(actor, "credential.present", "credential", credential_id, {"disclosed_fields": disclosed, "template_version": credential["template_version"]})
        self.conn.commit()
        return {"token": token, "payload": payload, "signature": signature, "disclosed_fields": disclosed}

    def verify(self, token: str, at: str | None = None, online: bool = True) -> dict:
        if not token:
            raise ApiError(400, "缺少凭证令牌")
        try:
            padded = token + "=" * (-len(token) % 4)
            envelope = json.loads(base64.urlsafe_b64decode(padded.encode()))
            payload = envelope["payload"]
            supplied_signature = envelope["signature"]
        except (ValueError, KeyError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ApiError(400, "凭证令牌格式错误") from exc
        credential = self._row("credentials", int(payload.get("credential_id", 0)))
        # Template version is part of the signed payload; verify against the
        # issuance-time version and reject a tampered version claim.
        if "template_version" in payload and int(payload["template_version"]) != int(credential["template_version"]):
            raise ApiError(400, "令牌模板版本与凭证记录不一致")
        if "template_code" in payload and str(payload["template_code"]) != str(credential["template_code"]):
            raise ApiError(400, "令牌模板代号与凭证记录不一致")
        key = self.conn.execute(
            "SELECT * FROM key_versions WHERE issuer=? AND version=?", (credential["issuer"], credential["key_version"])
        ).fetchone()
        if not key:
            raise ApiError(409, "无法找到签发密钥版本")
        expected = hmac.new(bytes.fromhex(key["secret_hex"]), canonical(payload), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, str(supplied_signature)):
            raise ApiError(400, "凭证签名无效")
        check_at = parse_time(at)
        expiration = parse_time(credential["valid_until"])
        series = self.conn.execute(
            "SELECT current_version FROM template_series WHERE issuer=? AND code=?",
            (credential["issuer"], credential["template_code"]),
        ).fetchone()
        current_version = int(series["current_version"]) if series else int(credential["template_version"])
        result = {
            "valid": True,
            "status": "valid",
            "key_retired": key["status"] == "retired",
            "claims": payload.get("claims", {}),
            "template_code": credential["template_code"],
            "template_version": credential["template_version"],
            "current_template_version": current_version,
            "template_is_current": current_version == int(credential["template_version"]),
        }
        if check_at >= expiration:
            result.update(valid=False, status="expired", reason="凭证已过期")
        elif credential["status"] == "disputed":
            result.update(valid=False, status="disputed", reason="撤销决定正在争议复核")
        elif credential["status"] == "revoked":
            effective = parse_time(credential["revocation_effective_at"])
            if check_at >= effective:
                result.update(valid=False, status="revoked", reason=credential["revocation_reason"])
            else:
                result.update(status="valid_until_revocation", revocation_starts_at=credential["revocation_effective_at"])
        if not online:
            result["offline"] = True
            result["revocation_freshness"] = "needs_online_check"
            if result["valid"]:
                result["status"] = "valid_offline"
        self.conn.commit()
        return result

    def _credential_dict(self, row: sqlite3.Row) -> dict:
        return {
            "id": row["id"], "template_id": row["template_id"],
            "template_code": row["template_code"], "template_version": row["template_version"],
            "issuer": row["issuer"], "holder_id": row["holder_id"],
            "claims": json.loads(row["claims_json"]), "issued_at": row["issued_at"], "valid_until": row["valid_until"],
            "status": row["status"], "key_version": row["key_version"], "revocation_reason": row["revocation_reason"],
            "revocation_effective_at": row["revocation_effective_at"],
        }

    def state(self) -> dict:
        credentials = [self._credential_dict(row) for row in self.conn.execute("SELECT * FROM credentials ORDER BY id DESC")]
        current_versions = {
            (row["issuer"], row["code"]): int(row["current_version"])
            for row in self.conn.execute("SELECT issuer,code,current_version FROM template_series")
        }
        templates = []
        for row in self.conn.execute("SELECT * FROM templates ORDER BY issuer, code, version"):
            version = self.templates._version_dict(row, None)
            current = current_versions.get((row["issuer"], row["code"]))
            version["is_current"] = current == int(row["version"])
            templates.append(version)
        audits = [dict(row) for row in self.conn.execute("SELECT at,actor,action,entity_type,entity_id,details_json FROM audit_log ORDER BY id DESC LIMIT 30")]
        return {"templates": templates, "credentials": credentials, "audits": audits}

    def seed(self) -> None:
        if not self.conn.execute("SELECT id FROM key_versions LIMIT 1").fetchone():
            self.rotate_key("issuer-demo", "issuer", "issuer-demo")
        if not self.conn.execute("SELECT id FROM template_series LIMIT 1").fetchone():
            self.create_template("issuer-demo", "issuer", "student", "学生身份", [{"name": "name", "required": True}, {"name": "program", "required": True}, {"name": "degree", "required": False}], 365)


class Handler(BaseHTTPRequestHandler):
    service: CredentialService

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _json(self, status: int, body: dict) -> None:
        data = json.dumps(body, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length))
        except json.JSONDecodeError as exc:
            raise ApiError(400, "JSON 请求体无效") from exc

    def _parts(self) -> list[str]:
        return [part for part in urlparse(self.path).path.strip("/").split("/") if part]

    def do_GET(self) -> None:
        try:
            parts = self._parts()
            query = urlparse(self.path).query
            if parts == ["health"] or parts == ["api", "health"]:
                return self._json(200, {"status": "ok"})
            if parts == ["api", "state"]:
                return self._json(200, self.service.state())
            if parts == ["api", "templates"]:
                issuer = None
                for pair in query.split("&"):
                    if pair.startswith("issuer="):
                        from urllib.parse import unquote
                        issuer = unquote(pair.split("=", 1)[1])
                return self._json(200, {"templates": self.service.templates.list_versions(issuer)})
            if len(parts) == 3 and parts[:2] == ["api", "templates"]:
                from urllib.parse import unquote
                return self._json(200, self.service.templates.get_series_detail(
                    self.headers.get("X-Actor"), self.headers.get("X-Role"), unquote(parts[2])
                ))
            if not parts:
                page = (Path(__file__).parent / "static" / "index.html").read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(page)))
                self.end_headers()
                self.wfile.write(page)
                return
            raise ApiError(404, "接口不存在")
        except ApiError as exc:
            self._json(exc.status, {"error": exc.message})
        except Exception as exc:
            self._json(500, {"error": str(exc)})

    def do_POST(self) -> None:
        try:
            parts = self._parts()
            body = self._body()
            actor, role = self.headers.get("X-Actor"), self.headers.get("X-Role")
            if parts == ["api", "keys", "rotate"]:
                result = self.service.rotate_key(actor, role, body.get("issuer", actor or ""))
            elif parts == ["api", "templates"]:
                result = self.service.create_template(actor, role, body.get("code", ""), body.get("name", ""), body.get("fields", []), body.get("validity_days", 1))
            elif parts == ["api", "templates", "revise"]:
                result = self.service.revise_template(
                    actor, role, body.get("code", ""), body.get("fields", []),
                    body.get("validity_days", 1), body.get("name"),
                )
            elif parts == ["api", "credentials"]:
                template_ref = body.get("template", body.get("template_code", body.get("template_id", "")))
                result = self.service.issue(actor, role, str(template_ref), body.get("holder_id", ""), body.get("claims", {}), body.get("idempotency_key", ""), body.get("valid_until"))
            elif len(parts) == 4 and parts[:2] == ["api", "credentials"] and parts[3] == "revoke":
                result = self.service.revoke(actor, role, int(parts[2]), body.get("reason", ""), body.get("effective_at"))
            elif len(parts) == 4 and parts[:2] == ["api", "credentials"] and parts[3] == "dispute":
                result = self.service.dispute(actor, role, int(parts[2]), body.get("reason", ""))
            elif len(parts) == 4 and parts[:2] == ["api", "credentials"] and parts[3] == "present":
                result = self.service.present(actor, role, int(parts[2]), body.get("disclosed_fields"))
            elif len(parts) == 4 and parts[:2] == ["api", "disputes"] and parts[3] == "resolve":
                result = self.service.resolve_dispute(actor, role, int(parts[2]), body.get("decision", ""), body.get("resolution", ""))
            elif parts == ["api", "verify"]:
                result = self.service.verify(body.get("token", ""), body.get("at"), bool(body.get("online", True)))
            else:
                raise ApiError(404, "接口不存在")
            self._json(200, result)
        except ApiError as exc:
            self._json(exc.status, {"error": exc.message})
        except (ValueError, TypeError, sqlite3.IntegrityError) as exc:
            self._json(400, {"error": str(exc)})
        except Exception as exc:
            self._json(500, {"error": str(exc)})


def run(port: int, db_path: str, seed: bool) -> None:
    store = Store(db_path)
    service = CredentialService(store)
    if seed:
        service.seed()
    Handler.service = service
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"digital credentials listening on http://127.0.0.1:{port}")
    server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8211)
    parser.add_argument("--db", default=str(DB_PATH))
    parser.add_argument("--init", action="store_true")
    parser.add_argument("--seed", action="store_true")
    args = parser.parse_args()
    if args.init:
        Store(args.db).close()
    if not any((args.seed, not args.init)):
        return
    run(args.port, args.db, args.seed)


if __name__ == "__main__":
    main()
