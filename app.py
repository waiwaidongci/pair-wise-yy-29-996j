#!/usr/bin/env python3
"""命令行入口。

代码按职责拆分为：
- template_rules.py    模板领域规则（字段校验、版本递增判定、差异计算）
- template_store.py    模板族与模板版本的存储访问
- storage.py           通用 SQLite 存储（密钥、凭证、争议、审计）
- template_service.py  模板用例编排（创建、修订、详情）
- credential_service.py 凭证用例（密钥轮换、签发、出示/验证、撤销、争议）
- api.py               HTTP 路由入口

本文件仅保留参数解析与向后兼容的再导出。
"""
from __future__ import annotations

import argparse
from pathlib import Path

from api import run
from core import ApiError, canonical, iso, now, parse_time
from credential_service import CredentialService
from storage import DB_PATH, Store
from template_rules import diff_versions, normalize_fields, validate_claims
from template_service import TemplateService

__all__ = [
    "ApiError", "Store", "CredentialService", "TemplateService",
    "canonical", "iso", "now", "parse_time", "normalize_fields",
    "validate_claims", "diff_versions",
]


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
