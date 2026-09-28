"""模板服务：编排模板规则与模板存储，负责创建、修订和版本展示。

凭证服务只依赖这里的查询结果，不自行解释模板结构。
"""
from __future__ import annotations

import json
import sqlite3

from core import ApiError, iso
from storage import Store
from template_rules import (
    diff_versions,
    has_content_change,
    normalize_fields,
    parse_validity_days,
)
from template_store import TemplateStore


class TemplateService:
    def __init__(self, store: Store, templates: TemplateStore | None = None):
        self.store = store
        self.conn = store.conn
        self.templates = templates or TemplateStore(store)

    @staticmethod
    def require_issuer(actor: str | None, role: str | None, issuer: str | None = None) -> str:
        if not actor:
            raise ApiError(401, "缺少身份")
        if role != "issuer":
            raise ApiError(403, "需要角色 issuer")
        if issuer is not None and actor != issuer:
            raise ApiError(403, "只能维护本签发方的模板")
        return actor

    def create_template(self, actor: str | None, role: str | None,
                        code: str, name: str, fields: list[dict], validity_days: int) -> dict:
        actor = self.require_issuer(actor, role)
        code = str(code or "").strip()
        name = str(name or "").strip()
        if not code or not name:
            raise ApiError(400, "模板代号和名称不能为空")
        normalized = normalize_fields(fields)
        days = parse_validity_days(validity_days)
        try:
            with self.conn:
                family_id = self.templates.create_family(actor, code, name, iso())
                self.templates.insert_version(family_id, 1, normalized, days, iso())
                self.store.audit(actor, "template.create", "template", family_id,
                                 {"code": code, "version": 1, "fields": normalized, "validity_days": days})
        except sqlite3.IntegrityError as exc:
            raise ApiError(409, "同一签发方不能重复使用模板代号") from exc
        family = self.templates.get_family(family_id)
        return self.detail(self.templates.family_dict(family, include_versions=False))

    def revise_template(self, actor: str | None, role: str | None,
                        template_id: int, fields: list[dict], validity_days: int,
                        name: str | None = None) -> dict:
        """基于同一代号的当前版本创建新版本；无实质变化或字段非法时拒绝。"""
        actor = self.require_issuer(actor, role)
        family = self.templates.get_family(int(template_id))
        if not family:
            raise ApiError(404, "模板不存在")
        actor = self.require_issuer(actor, role, family["issuer"])
        if family["status"] != "active":
            raise ApiError(409, "模板已停用，不能修订")
        normalized = normalize_fields(fields)
        days = parse_validity_days(validity_days)
        current_row = self.templates.get_version(family["id"], family["current_version"])
        previous_fields = json.loads(current_row["fields_json"])
        previous_days = int(current_row["validity_days"])
        if not has_content_change(normalized, days, previous_fields, previous_days):
            raise ApiError(409, "字段或有效期与当前版本一致，没有变化，不生成新版本")
        changes = diff_versions(normalized, days, previous_fields, previous_days)
        new_version = family["current_version"] + 1
        if str(name or "").strip():
            self.conn.execute("UPDATE templates SET name=? WHERE id=?", (str(name).strip(), family["id"]))
        try:
            with self.conn:
                self.templates.insert_version(family["id"], new_version, normalized, days, iso())
                self.templates.bump_current_version(family["id"], new_version)
                self.store.audit(actor, "template.revise", "template", family["id"],
                                 {"code": family["code"], "version": new_version,
                                  "fields": normalized, "validity_days": days, "changes": changes})
        except sqlite3.IntegrityError as exc:
            raise ApiError(409, "并发修订冲突，请重试") from exc
        result = self.detail(self.templates.family_dict(self.templates.get_family(family["id"])))
        result["changes"] = changes
        return result

    def resolve(self, template_id: int, version: int | None = None) -> tuple[object, object]:
        """取模板族与指定版本行；version 为空时取当前版本（新签发路径）。"""
        family = self.templates.get_family(int(template_id))
        if not family:
            raise ApiError(404, "模板不存在")
        wanted = int(version) if version is not None else family["current_version"]
        version_row = self.templates.get_version(family["id"], wanted)
        if not version_row:
            raise ApiError(404, f"模板版本 v{wanted} 不存在")
        return family, version_row

    def list_templates(self) -> list[dict]:
        return [self.detail(self.templates.family_dict(row, include_versions=False))
                for row in self.templates.list_families()]

    def get_template(self, template_id: int) -> dict:
        family = self.templates.get_family(int(template_id))
        if not family:
            raise ApiError(404, "模板不存在")
        return self.detail(self.templates.family_dict(family))

    def detail(self, family: dict) -> dict:
        """为模板族附加每版相对上一版的字段变化，供列表与详情展示。"""
        versions = family.get("versions")
        if versions is None:
            rows = self.templates.list_versions(family["id"])
            versions = [self.templates.version_dict(row) for row in rows]
        previous_fields = None
        previous_days = None
        for item in versions:
            item["changes"] = diff_versions(item["fields"], item["validity_days"],
                                            previous_fields, previous_days)
            previous_fields = item["fields"]
            previous_days = item["validity_days"]
        family["versions"] = versions
        return family
