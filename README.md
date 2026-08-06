# acp-hub

中心化 Hub（Go）脚手架：多 Host 注册与发现。

当前实现（scaffold）：

- `GET /health`
- `GET /api/hosts` — 已注册 Host 列表
- `POST /api/host/register` — Host 心跳注册
- 完整 **浏览器 ↔ Host 事件中继（WebSocket）** 待下一阶段

## 本地单机开发

前端直连 `acp-host` 即可，**不必**启动 Hub：

```bash
# 终端 1
cd acp-host && go run ./cmd/acp-host

# 终端 2
cd acp-fe && npm run dev
```

## 运行 Hub

```bash
cd acp-hub
go run ./cmd/acp-hub
# default :8787
```

## 规划中的多 Host 路径

```
Browser (acp-fe) ──WS──▶ acp-hub ──WS──▶ acp-host × N ──stdio──▶ grok
```

Host 主动出站连接 Hub（适配 NAT）；Hub 不做 fs/terminal 执行。
