# EnvVault · Agent 凭证保险箱

AES-256-GCM 加密的密钥管理服务。与 OpenAI MCP 协议兼容，Agent 可以安全地请求和取用凭证——全程审计、Agent 不碰明文密钥。
![License](https://img.shields.io/badge/license-MIT-green) ![Python](https://img.shields.io/badge/python-3.10%2B-blue) ![GitHub stars](https://img.shields.io/github/stars/wholegale39/envvault)
## 为什么做这个？

Agent 需要调用各种 API（GitHub、Gmail、Notion、DeepSeek…），密钥放哪？环境变量？不安全。硬编码？更不安全。

- ❌ 密钥混在代码里，git 泄露就完了
- ❌ 多个 Agent 共享密钥，谁用了不知道
- ❌ 换密钥要重新部署

EnvVault 让密钥存在加密保险箱，Agent 通过 MCP 协议取用。每次取用都记录在审计日志里。

## 快速开始

```bash
git clone https://github.com/wholegale39/envvault.git
cd envvault

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 设置主密码（AES 密钥从此派生）
export MASTER_PASSWORD="your-strong-password-here"

# 启动
python3 -m uvicorn server:app --host 0.0.0.0 --port 8766
```

打开 `http://localhost:8766` 即可通过 Web UI 管理密钥。

## 特性

| 特性 | 说明 |
|------|------|
| **AES-256-GCM + scrypt** | 军用级加密，主密码经 scrypt 派生密钥 |
| **MCP 协议支持** | Agent 通过标准 MCP 工具请求凭证 |
| **审计日志** | 每次取用记录：谁、什么密钥、什么时间 |
| **访问控制** | 按密钥+Agent 限制使用次数 |
| **Web UI** | 内嵌前端，CRUD + 查看 + 复制 |
| **bashrc 导出** | 一键导出为环境变量（base64 编码防泄露） |
| **自托管** | Docker 部署，数据全在本地 |

## MCP 集成

启动 MCP 服务器（两种模式）：

```bash
# HTTP 模式（端口 8769）
python3 mcp_server.py http 8769

# stdio 模式（用于 Hermes MCP transport）
python3 mcp_server.py stdio
```

### MCP 工具

| 工具 | 说明 |
|------|------|
| `get_credential(name, agent?)` | 按名称获取密钥值（自动记录审计） |
| `list_credentials()` | 列出所有密钥名称（不返回值） |

### 集成到 Hermes Agent

```yaml
# hermes config.yaml
hermes:
  mcp_servers:
    envvault:
      command: python3 /opt/data/envvault/mcp_server.py stdio
```

### 从 Agent 调用

Agent 通过 MCP 协议调用：
```
工具: get_credential
参数: {"name": "GITHUB_TOKEN", "agent": "market-summary"}
返回: {"name": "GITHUB_TOKEN", "value": "ghp_xxxxx"}
```

每次调用都会记入审计日志：
```
2026-07-28 → GITHUB_TOKEN → market-summary → granted
```

## API

| Method | Path | 说明 |
|--------|------|------|
| `GET` | `/api/secrets` | 列出密钥（不含值） |
| `POST` | `/api/secrets` | 新增密钥 |
| `PUT` | `/api/secrets/{id}` | 更新密钥 |
| `DELETE` | `/api/secrets/{id}` | 删除密钥 |
| `GET` | `/api/reveal/{id}?agent=xxx` | 查看密钥值（带审计） |
| `GET` | `/api/audit?limit=50` | 审计日志 |
| `GET/POST/DELETE` | `/api/access-rules` | 访问控制规则 |
| `GET` | `/api/export/bashrc` | 导出为 bash 环境变量 |

## 架构

```
┌─ Web UI (HTML/JS) ──┐
│    ↓ CRUD API         │
├─ FastAPI (8766) ────┤
│    ↓ AES-256-GCM      │
├─ SQLite ────────────┤
│   secrets             │
│   audit_log           │
│   access_rules        │
└──────────────────────┘

┌─ MCP Server (8769 / stdio) ───┐
│  JSON-RPC 2.0                  │
│  get_credential → vault API    │
│  list_credentials → vault API  │
└────────────────────────────────┘
```

## 许可证

MIT
