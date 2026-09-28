"""凭证服务：密钥轮换、签发、出示/验证、撤销与争议。

模板版本边界：
- 新签发总是解析模板当前版本，并把版本号固化在凭证行上；
- 出示与验证按凭证固化的版本读取字段，模板后续修订不影响旧凭证。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import sqlite3

from core import (
    ApiError,
    canonical,
    days_later,
    iso,
    now,
    parse_time,
)
from storage import Store
from template_rules import validate_claims
from template_service import TemplateService
from template_store import TemplateStore

CREDENTIAL_SELECT = """
SELECT c.*, t.code AS template_code
FROM credentials c JOIN templates t ON t.id = c.template_id
"""


class CredentialService:
    """Credential issuance and verification with small, explicit trust boundaries."""

    def __init__(self, store: Store, template_service: TemplateService | None = None):
        self.store = store
        self.conn = store.conn
        self.templates = TemplateStore(store)
        self.template_service = template_service or TemplateService(store, self.templates)

    @staticmethod
    def _required_actor(actor: str | None, role: str | None, expected: str) -> str:
        if not actor:
            raise ApiError(401, "缺少身份")
        if role != expected:
            raise ApiError(403, f"需要角色 {expected}")
        return actor

    def _credential_row(self, identity: int) -> sqlite3.Row:
        row = self.conn.execute(CREDENTIAL_SELECT + " WHERE c.id=?", (identity,)).fetchone()
        if not row:
            raise ApiError(404, "对象不存在")
        return row

    def _active_key(self, issuer: str) -> sqlite3.Row:
        row = self.conn.execute(
            "SELECT * FROM key_versions WHERE issuer=? AND status='active' ORDER BY version DESC LIMIT 1",
            (issuer,),
        ).fetchone()
        if not row:
            raise ApiError(409, "签发方尚未初始化密钥")
        return row

    # ---- 密钥轮换（与模板版本相互独立，照常工作） ----
    def rotate_key(self, actor: str | None, role: str | None, issuer: str) -> dict:
        actor = self._required_actor(actor, role, "issuer")
        if actor != issuer:
            raise ApiError(403, "只能轮换自己的密钥")
        with self.conn:
            old = self.conn.execute(
                "SELECT * FROM key_versions WHERE issuer=? AND status='active'", (issuer,)
            ).fetchone()
            version = 1
            if old:
                version = int(old["version"]) + 1
                self.conn.execute(
                    "UPDATE key_versions SET status='retired', retired_at=? WHERE id=?", (iso(), old["id"])
                )
            secret_hex = secrets.token_hex(32)
            cur = self.conn.execute(
                "INSERT INTO key_versions(issuer,version,secret_hex,status,created_at) VALUES(?,?,?,'active',?)",
                (issuer, version, secret_hex, iso()),
            )
            self.store.audit(actor, "key.rotate", "key_version", cur.lastrowid,
                             {"version": version, "retired_previous": bool(old)})
        return {"issuer": issuer, "version": version, "status": "active",
                "public_fingerprint": hashlib.sha256(secret_hex.encode()).hexdigest()[:20]}

    # ---- 签发：使用模板当前版本并固化 ----
    def issue(self, actor: str | None, role: str | None, template_id: int, holder_id: str,
              claims: dict, idempotency_key: str, valid_until: str | None = None) -> dict:
        actor = self._required_actor(actor, role, "issuer")
        holder_id = str(holder_id or "").strip()
        idempotency_key = str(idempotency_key or "").strip()
        if not holder_id or not idempotency_key:
            raise ApiError(400, "持有人和幂等键不能为空")
        family, version_row = self.template_service.resolve(int(template_id))
        if family["issuer"] != actor:
            raise ApiError(403, "不能使用其他签发方的模板")
        if family["status"] != "active":
            raise ApiError(409, "模板已停用")
        existing = self.conn.execute(
            "SELECT * FROM credentials WHERE template_id=? AND holder_id=? AND idempotency_key=?",
            (family["id"], holder_id, idempotency_key),
        ).fetchone()
        if existing:
            return self._credential_dict(self._credential_row(existing["id"]))
        fields = json.loads(version_row["fields_json"])
        validate_claims(fields, claims)
        live = self.conn.execute(
            "SELECT id FROM credentials WHERE template_id=? AND holder_id=? AND status IN ('active','disputed')",
            (family["id"], holder_id),
        ).fetchone()
        if live:
            raise ApiError(409, "该持有人已有有效的同模板凭证；重复提交应使用相同幂等键")
        issued = now()
        expiration = parse_time(valid_until) if valid_until else days_later(issued, version_row["validity_days"])
        if expiration <= issued:
            raise ApiError(400, "有效期必须晚于签发时间")
        key = self._active_key(actor)
        try:
            with self.conn:
                cur = self.conn.execute(
                    """INSERT INTO credentials(template_id,template_version,issuer,holder_id,claims_json,
                         issued_at,valid_until,status,key_version,idempotency_key)
                       VALUES(?,?,?,?,?,?,?, 'active',?,?)""",
                    (family["id"], version_row["version"], actor, holder_id,
                     json.dumps(claims, ensure_ascii=False), iso(issued), iso(expiration),
                     key["version"], idempotency_key),
                )
                self.store.audit(actor, "credential.issue", "credential", cur.lastrowid,
                                 {"holder_id": holder_id, "template_id": family["id"],
                                  "template_code": family["code"],
                                  "template_version": version_row["version"],
                                  "key_version": key["version"]})
        except sqlite3.IntegrityError as exc:
            raise ApiError(409, "并发签发冲突，请用相同幂等键重试") from exc
        return self._credential_dict(self._credential_row(cur.lastrowid))

    # ---- 撤销 ----
    def revoke(self, actor: str | None, role: str | None, credential_id: int,
               reason: str, effective_at: str | None = None) -> dict:
        actor = self._required_actor(actor, role, "issuer")
        credential = self._credential_row(credential_id)
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
            self.store.audit(actor, "credential.revoke", "credential", credential_id,
                             {"reason": reason, "effective_at": iso(effective)})
        return self._credential_dict(self._credential_row(credential_id))

    # ---- 争议 ----
    def dispute(self, actor: str | None, role: str | None, credential_id: int, reason: str) -> dict:
        actor = self._required_actor(actor, role, "holder")
        credential = self._credential_row(credential_id)
        if credential["holder_id"] != actor:
            raise ApiError(403, "只能对自己的凭证提出争议")
        if credential["status"] != "revoked":
            raise ApiError(409, "只有已撤销凭证可以提出争议")
        open_dispute = self.conn.execute(
            "SELECT id FROM disputes WHERE credential_id=? AND status='open'", (credential_id,)
        ).fetchone()
        if open_dispute:
            raise ApiError(409, "已有待处理争议")
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO disputes(credential_id,raised_by,reason,status,created_at) VALUES(?,?,?,'open',?)",
                (credential_id, actor, reason, iso()),
            )
            self.conn.execute("UPDATE credentials SET status='disputed' WHERE id=?", (credential_id,))
            self.store.audit(actor, "dispute.open", "credential", credential_id,
                             {"dispute_id": cur.lastrowid, "reason": reason})
        return {"id": cur.lastrowid, "credential_id": credential_id, "status": "open"}

    def resolve_dispute(self, actor: str | None, role: str | None, dispute_id: int,
                        decision: str, resolution: str) -> dict:
        actor = self._required_actor(actor, role, "regulator")
        if decision not in {"uphold", "reject"}:
            raise ApiError(400, "决定只能是 uphold 或 reject")
        dispute_row = self.conn.execute("SELECT * FROM disputes WHERE id=?", (dispute_id,)).fetchone()
        if not dispute_row:
            raise ApiError(404, "对象不存在")
        if dispute_row["status"] != "open":
            raise ApiError(409, "争议已经处理")
        credential = self._credential_row(dispute_row["credential_id"])
        if credential["status"] != "disputed":
            raise ApiError(409, "凭证状态与争议不一致")
        new_status = "revoked" if decision == "uphold" else "active"
        dispute_status = "upheld" if decision == "uphold" else "rejected"
        with self.conn:
            self.conn.execute(
                "UPDATE disputes SET status=?,resolution=?,resolved_at=? WHERE id=?",
                (dispute_status, resolution, iso(), dispute_id),
            )
            self.conn.execute("UPDATE credentials SET status=? WHERE id=?", (new_status, credential["id"]))
            self.store.audit(actor, "dispute.resolve", "dispute", dispute_id,
                             {"decision": decision, "credential_status": new_status})
        return {"id": dispute_id, "status": decision, "credential_status": new_status, "resolution": resolution}

    # ---- 出示：按凭证签发时的模板版本读取字段 ----
    def present(self, actor: str | None, role: str | None, credential_id: int,
                disclosed_fields: list[str] | None) -> dict:
        actor = self._required_actor(actor, role, "holder")
        credential = self._credential_row(credential_id)
        if credential["holder_id"] != actor:
            raise ApiError(403, "不能出示他人的凭证")
        _, version_row = self.template_service.resolve(credential["template_id"],
                                                       credential["template_version"])
        allowed = [field["name"] for field in json.loads(version_row["fields_json"])]
        claims = json.loads(credential["claims_json"])
        # 按签发时版本解释字段；凭证里没有值的可选字段默认不披露。
        disclosed = disclosed_fields if disclosed_fields is not None else [n for n in allowed if n in claims]
        if len(disclosed) != len(set(disclosed)) or any(name not in allowed for name in disclosed):
            raise ApiError(400, "披露字段不在签发时的模板版本中或重复")
        missing_value = [name for name in disclosed if name not in claims]
        if missing_value:
            raise ApiError(400, f"凭证中没有这些字段的声明：{missing_value}")
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
            "SELECT secret_hex FROM key_versions WHERE issuer=? AND version=?",
            (credential["issuer"], credential["key_version"]),
        ).fetchone()
        signature = hmac.new(bytes.fromhex(key["secret_hex"]), canonical(payload), hashlib.sha256).hexdigest()
        token = base64.urlsafe_b64encode(
            canonical({"payload": payload, "signature": signature})
        ).decode().rstrip("=")
        with self.conn:
            self.store.audit(actor, "credential.present", "credential", credential_id,
                             {"disclosed_fields": disclosed, "template_version": credential["template_version"]})
        return {"token": token, "payload": payload, "signature": signature, "disclosed_fields": disclosed}

    # ---- 验证：按令牌中固化的凭证版本出示结果 ----
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
        credential = self._credential_row(int(payload.get("credential_id", 0)))
        key = self.conn.execute(
            "SELECT * FROM key_versions WHERE issuer=? AND version=?",
            (credential["issuer"], credential["key_version"]),
        ).fetchone()
        if not key:
            raise ApiError(409, "无法找到签发密钥版本")
        expected = hmac.new(bytes.fromhex(key["secret_hex"]), canonical(payload), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, str(supplied_signature)):
            raise ApiError(400, "凭证签名无效")
        check_at = parse_time(at)
        expiration = parse_time(credential["valid_until"])
        result = {
            "valid": True,
            "status": "valid",
            "key_retired": key["status"] == "retired",
            "template_code": credential["template_code"],
            "template_version": credential["template_version"],
            "claims": payload.get("claims", {}),
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
                result.update(status="valid_until_revocation",
                              revocation_starts_at=credential["revocation_effective_at"])
        if not online:
            result["offline"] = True
            result["revocation_freshness"] = "needs_online_check"
            if result["valid"]:
                result["status"] = "valid_offline"
        self.conn.commit()
        return result

    def _credential_dict(self, row: sqlite3.Row) -> dict:
        return {
            "id": row["id"],
            "template_id": row["template_id"],
            "template_code": row["template_code"],
            "template_version": row["template_version"],
            "issuer": row["issuer"],
            "holder_id": row["holder_id"],
            "claims": json.loads(row["claims_json"]),
            "issued_at": row["issued_at"],
            "valid_until": row["valid_until"],
            "status": row["status"],
            "key_version": row["key_version"],
            "revocation_reason": row["revocation_reason"],
            "revocation_effective_at": row["revocation_effective_at"],
        }

    # ---- 总览 ----
    def state(self) -> dict:
        credentials = [
            self._credential_dict(row)
            for row in self.conn.execute(CREDENTIAL_SELECT + " ORDER BY c.id DESC").fetchall()
        ]
        templates = self.template_service.list_templates()
        audits = [dict(row) for row in self.conn.execute(
            "SELECT at,actor,action,entity_type,entity_id,details_json FROM audit_log ORDER BY id DESC LIMIT 30"
        )]
        return {"templates": templates, "credentials": credentials, "audits": audits}

    def seed(self) -> None:
        if not self.conn.execute("SELECT id FROM key_versions LIMIT 1").fetchone():
            self.rotate_key("issuer-demo", "issuer", "issuer-demo")
        if not self.conn.execute("SELECT id FROM templates LIMIT 1").fetchone():
            self.template_service.create_template(
                "issuer-demo", "issuer", "student", "学生身份",
                [{"name": "name", "required": True}, {"name": "program", "required": True},
                 {"name": "degree", "required": False}],
                365,
            )
