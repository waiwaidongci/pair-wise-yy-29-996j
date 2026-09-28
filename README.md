# 数字凭证签发、验证和撤销服务

标准库 Python 3.11+ 实现，使用 SQLite 保存密钥版本、模板、凭证、争议和审计记录。服务支持最少字段披露、离线签名的在线撤销复核、密钥轮换和证件状态争议。

## 初始化与启动

```bash
python3 app.py --init --seed
python3 app.py
```

默认地址 `http://127.0.0.1:8211`，也可使用 `--port` 与 `--db` 覆盖端口和数据库路径。身份使用 `X-Actor`、`X-Role` 请求头，角色为 `issuer`、`holder` 或 `regulator`。

## 主要接口

- `POST /api/keys/rotate`：签发方轮换密钥。
- `POST /api/templates`：创建模板（同代号首版，版本号 v1）。
- `POST /api/templates/revise`：基于同代号当前版本创建新版本；仅当字段或有效期变化才递增版本，字段名重复或缺少当前版本的必填字段会被拒绝，无变化返回 409。
- `GET /api/templates`、`GET /api/templates/{code}`：模板版本列表与代号详情（详情含每版相对上一版的字段变化）。
- `POST /api/credentials`：按模板代号（`template`/`template_code`）或当前版本 ID 签发，始终使用当前版本；旧版本 ID 会被拒绝。支持幂等键。
- `POST /api/credentials/{id}/present`：凭证按签发时钉住的模板版本出示并选择披露字段，令牌内含模板代号与版本。
- `POST /api/verify`：按签发时版本验证令牌，返回 `template_version`、`current_template_version` 与 `template_is_current`；可指定验证时间与在线/离线模式。
- `POST /api/credentials/{id}/revoke`：签发方撤销凭证。
- `POST /api/credentials/{id}/dispute`、`POST /api/disputes/{id}/resolve`：提出和处理撤销争议。
- `GET /api/state`、`GET /api/health`：查看状态（模板带版本、当前版本标记，凭证带所属模板版本）和健康检查。

## 模板版本化规则

- 同一签发方同一代号是一个模板系列（`template_series`），每次修订在 `templates` 中新增一行，版本号单调递增，系列上记录 `current_version`。
- 字段变化包括：新增字段、删除字段、必填/可选调整、字段顺序变化、有效期天数变化；只改名称不升版。
- 修订不能删除当前版本的必填字段（向后兼容），字段名重复或字段列表为空一律 400。
- 凭证行保存 `template_code` 与 `template_version`，出示时按该版本读取字段集合，签名覆盖版本信息；后续修订不影响旧凭证的披露与验证。
- 同一持有人在同一代号下只能有一张有效（active/disputed）凭证；幂等键按代号+持有人去重。

## 分层

- `Store`：仅负责 SQLite schema、旧库自动迁移与模板版本存取。
- `TemplateService`：模板规则（字段规范化、必填校验、版本递增、字段变化 diff、签发时当前版本解析）。
- `CredentialService`：签发、出示、验证、撤销与争议；`Handler` 只做 HTTP 入口与路由。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

这是本地原型：私钥保存在 SQLite 中，离线验证只能依赖令牌内的到期时间，真实撤销仍需在线检查；也未实现可验证凭证联盟标准或硬件密钥保护。
