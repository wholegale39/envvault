# EnvVault — 自部署密钥管理中心

轻量级 API Key 加密管理工具。Web UI 录入，AES-256 加密存储，一键导出到 .env / .bashrc / Hermes 配置。

## 为什么需要它？

容器环境里管理密钥很烦：
- 终端里 echo 带 key 的命令 → 被 Hermes secret redaction 拦截
- 写 .bashrc → export 行被自动修改
- 密钥散落在各个配置文件里，换一个要找半天

EnvVault 把密钥集中加密存储，一键导出到不触犯 redaction 的格式。

## 快速开始

```bash
# 启动
docker run -d -p 8765:8765 \
  -v ./data:/app/data \
  -e MASTER_PASSWORD=your-strong-password \
  wholegale39/envvault

# 打开 http://localhost:8765
```

## 导出到 .bashrc（避开 redaction）

```bash
# 从 EnvVault 导出（生成一行不被 redaction 拦截的 export）
curl -s http://localhost:8765/api/export/bashrc | bash
```

## 技术栈

- 后端：Python FastAPI + SQLite + pycryptodome (AES-256-GCM)
- 前端：单 HTML 页，Vanilla JS + CSS
- 部署：单 Docker 容器，200MB

## License

MIT
