"""HTTP 入口：只做路由、请求解析与响应序列化，业务规则全部在服务层。"""
from __future__ import annotations

import json
import sqlite3
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from core import ApiError
from credential_service import CredentialService
from storage import Store
from template_service import TemplateService


class Handler(BaseHTTPRequestHandler):
    service: CredentialService
    templates: TemplateService

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
            if parts == ["health"] or parts == ["api", "health"]:
                return self._json(200, {"status": "ok"})
            if parts == ["api", "state"]:
                return self._json(200, self.service.state())
            if parts == ["api", "templates"]:
                return self._json(200, {"templates": self.templates.list_templates()})
            if len(parts) == 3 and parts[:2] == ["api", "templates"]:
                return self._json(200, self.templates.get_template(int(parts[2])))
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
        except Exception as exc:  # noqa: BLE001 - 本地原型统一兜底
            self._json(500, {"error": str(exc)})

    def do_POST(self) -> None:
        try:
            parts = self._parts()
            body = self._body()
            actor, role = self.headers.get("X-Actor"), self.headers.get("X-Role")
            if parts == ["api", "keys", "rotate"]:
                result = self.service.rotate_key(actor, role, body.get("issuer", actor or ""))
            elif parts == ["api", "templates"]:
                result = self.templates.create_template(
                    actor, role, body.get("code", ""), body.get("name", ""),
                    body.get("fields", []), body.get("validity_days"),
                )
            elif len(parts) == 4 and parts[:2] == ["api", "templates"] and parts[3] == "revisions":
                result = self.templates.revise_template(
                    actor, role, int(parts[2]), body.get("fields", []),
                    body.get("validity_days"), body.get("name"),
                )
            elif parts == ["api", "credentials"]:
                result = self.service.issue(
                    actor, role, int(body.get("template_id", 0)), body.get("holder_id", ""),
                    body.get("claims", {}), body.get("idempotency_key", ""), body.get("valid_until"),
                )
            elif len(parts) == 4 and parts[:2] == ["api", "credentials"] and parts[3] == "revoke":
                result = self.service.revoke(actor, role, int(parts[2]), body.get("reason", ""),
                                             body.get("effective_at"))
            elif len(parts) == 4 and parts[:2] == ["api", "credentials"] and parts[3] == "dispute":
                result = self.service.dispute(actor, role, int(parts[2]), body.get("reason", ""))
            elif len(parts) == 4 and parts[:2] == ["api", "credentials"] and parts[3] == "present":
                result = self.service.present(actor, role, int(parts[2]), body.get("disclosed_fields"))
            elif len(parts) == 4 and parts[:2] == ["api", "disputes"] and parts[3] == "resolve":
                result = self.service.resolve_dispute(actor, role, int(parts[2]),
                                                      body.get("decision", ""), body.get("resolution", ""))
            elif parts == ["api", "verify"]:
                result = self.service.verify(body.get("token", ""), body.get("at"), bool(body.get("online", True)))
            else:
                raise ApiError(404, "接口不存在")
            self._json(200, result)
        except ApiError as exc:
            self._json(exc.status, {"error": exc.message})
        except (ValueError, TypeError, sqlite3.IntegrityError) as exc:
            self._json(400, {"error": str(exc)})
        except Exception as exc:  # noqa: BLE001 - 本地原型统一兜底
            self._json(500, {"error": str(exc)})


def build_services(db_path: str) -> tuple[Store, CredentialService, TemplateService]:
    store = Store(db_path)
    template_service = TemplateService(store)
    credential_service = CredentialService(store, template_service)
    return store, credential_service, template_service


def run(port: int, db_path: str, seed: bool) -> None:
    store, service, template_service = build_services(db_path)
    if seed:
        service.seed()
    Handler.service = service
    Handler.templates = template_service
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"digital credentials listening on http://127.0.0.1:{port}")
    try:
        server.serve_forever()
    finally:
        store.close()
