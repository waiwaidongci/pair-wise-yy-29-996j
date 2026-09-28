# 数字凭证签发、验证和撤销服务

标准库 Python 3.11+ 实现，使用 SQLite 保存密钥版本、模板及模板版本、凭证、争议和审计记录。服务支持可修订模板、最少字段披露、离线签名的在线撤销复核、密钥轮换和证件状态争议。

代码按职责分离：

- `template_rules.py`：模板领域规则（字段/有效期校验、版本递增判定、版本差异计算），纯函数无存储依赖。
- `template_store.py` / `storage.py`：模板族、模板版本及密钥、凭证、争议、审计的 SQLite 存储。
- `template_service.py` / `credential_service.py`：业务编排（模板创建与修订；密钥轮换、签发、出示/验证、撤销、争议）。
- `api.py`：HTTP 路由入口，只做请求解析与响应。
- `app.py`：命令行入口，并再导出兼容 `from app import ...` 的旧用法。

## 模板版本

模板以「代号（code）」为一个模板族，代号下有从 1 递增的多个版本：

- `POST /api/templates` 创建模板族与 v1；同一签发方代号唯一，字段名重复、缺少字段或缺少/非法有效期一律拒绝（400/409）。
- `POST /api/templates/{id}/revisions` 基于当前版本建新版本：**只有字段（名称或必填）或有效期变化才递增版本**；与当前版本无差异返回 409，不产生新版本。字段名重复或缺少必填的请求体字段返回 400。
- 新签发始终使用模板**当前版本**，并把版本号固化在凭证上；旧凭证继续按**签发时那版**出示和验证，模板修订不影响已发凭证。
- 列表 `GET /api/templates` 与详情 `GET /api/templates/{id}` 显示当前版本、全部版本及每版相对上一版的字段变化（新增/移除字段、必填增减、有效期变化）；凭证记录与出示令牌中带 `template_code`、`template_version`。
- 旧版单表模板数据库在首次启动时自动迁移为模板族 + v1 版本，旧凭证默认属于 v1。

## 初始化与启动

```bash
python3 app.py --init --seed
python3 app.py
```

默认地址 `http://127.0.0.1:8211`，也可使用 `--port` 与 `--db` 覆盖端口和数据库路径。身份使用 `X-Actor`、`X-Role` 请求头，角色为 `issuer`、`holder` 或 `regulator`。

## 主要接口

- `POST /api/keys/rotate`：签发方轮换密钥（与模板版本相互独立）。
- `POST /api/templates`：创建凭证模板（模板族 v1）。
- `POST /api/templates/{id}/revisions`：修订模板，字段或有效期变化时生成新版本。
- `GET /api/templates`、`GET /api/templates/{id}`：模板列表与版本详情（含字段变化）。
- `POST /api/credentials`：按模板当前版本签发凭证，支持幂等键。
- `POST /api/credentials/{id}/present`：按凭证签发时的模板版本选择披露字段并生成令牌。
- `POST /api/verify`：验证令牌（结果带模板代号与版本），可指定验证时间与在线/离线模式。
- `POST /api/credentials/{id}/revoke`：签发方撤销凭证。
- `POST /api/credentials/{id}/dispute`、`POST /api/disputes/{id}/resolve`：提出和处理撤销争议。
- `GET /api/state`、`GET /api/health`：查看状态和健康检查。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

这是本地原型：私钥保存在 SQLite 中，离线验证只能依赖令牌内的到期时间，真实撤销仍需在线检查；也未实现可验证凭证联盟标准或硬件密钥保护。
