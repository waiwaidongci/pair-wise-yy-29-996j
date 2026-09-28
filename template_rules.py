"""模板领域规则：字段校验、版本递增判定、版本差异计算。

本模块不碰数据库，纯函数便于复用与测试。
"""
from __future__ import annotations

from typing import Any

from core import ApiError

MIN_VALIDITY_DAYS = 1
MAX_VALIDITY_DAYS = 3650


def normalize_fields(raw_fields: Any) -> list[dict]:
    """校验并归一化字段定义；字段为空、重名一律拒绝。"""
    if not isinstance(raw_fields, list):
        raise ApiError(400, "模板字段必须是列表")
    names: set[str] = set()
    normalized: list[dict] = []
    for field in raw_fields:
        if not isinstance(field, dict):
            raise ApiError(400, "模板字段定义格式错误")
        name = str(field.get("name", "")).strip()
        if not name:
            raise ApiError(400, "模板字段名不能为空")
        if name in names:
            raise ApiError(400, f"模板字段名重复：{name}")
        names.add(name)
        normalized.append({"name": name, "required": bool(field.get("required", False))})
    if not normalized:
        raise ApiError(400, "模板至少需要一个字段")
    return normalized


def parse_validity_days(value: Any) -> int:
    """有效期为修订必填字段，缺失或越界都拒绝。"""
    if value is None:
        raise ApiError(400, "有效期 validity_days 不能为空")
    try:
        days = int(value)
    except (TypeError, ValueError) as exc:
        raise ApiError(400, "有效期 validity_days 必须是整数") from exc
    if not MIN_VALIDITY_DAYS <= days <= MAX_VALIDITY_DAYS:
        raise ApiError(400, f"有效期必须在 {MIN_VALIDITY_DAYS} 到 {MAX_VALIDITY_DAYS} 天之间")
    return days


def validate_claims(fields: list[dict], claims: Any) -> None:
    """签发时按当版模板校验声明：必填字段缺失或出现未知字段即拒绝。"""
    if not isinstance(claims, dict):
        raise ApiError(400, "声明 claims 必须是对象")
    missing = [f["name"] for f in fields if f["required"] and not str(claims.get(f["name"], "")).strip()]
    unknown = sorted(set(claims) - {f["name"] for f in fields})
    if missing or unknown:
        raise ApiError(400, f"声明不完整，缺少={missing}，未知字段={unknown}")


def has_content_change(fields: list[dict], validity_days: int,
                       previous_fields: list[dict], previous_validity_days: int) -> bool:
    """只有字段（名称/必填）或有效期发生变化才允许产生新版本。"""
    return fields != previous_fields or int(validity_days) != int(previous_validity_days)


def diff_versions(fields: list[dict], validity_days: int,
                  previous_fields: list[dict] | None, previous_validity_days: int | None) -> dict:
    """相对上一版计算字段增删、必填变化与有效期变化；首版返回空变化。"""
    current = {f["name"]: f["required"] for f in fields}
    if previous_fields is None:
        return {"fields_added": [], "fields_removed": [], "required_added": [],
                "required_removed": [], "validity_days_changed": False,
                "validity_days_from": previous_validity_days, "validity_days_to": validity_days}
    previous = {f["name"]: f["required"] for f in previous_fields}
    added = [name for name in current if name not in previous]
    removed = [name for name in previous if name not in current]
    required_added = [name for name in current if name in previous and current[name] and not previous[name]]
    required_removed = [name for name in current if name in previous and not current[name] and previous[name]]
    return {
        "fields_added": added,
        "fields_removed": removed,
        "required_added": required_added,
        "required_removed": required_removed,
        "validity_days_changed": int(validity_days) != int(previous_validity_days),
        "validity_days_from": previous_validity_days,
        "validity_days_to": validity_days,
    }
