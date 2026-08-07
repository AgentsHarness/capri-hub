# acp-hub

中心化中转服务器（relay）：多 Host 配对、注册与发现、事件聚合、请求中转。

```
Browser (acp-fe) ──HTTP/SSE──▶ acp-hub (:8787) ──SSE+HTTP──▶ acp-host × N ──stdio──▶ grok
```

Host 主动**出站**连接 Hub（适配 NAT，无需 Hub 能访问 Host）；Hub 不做
fs/terminal 执行，只做转发。

## 运行

```bash
cd acp-hub
go run ./cmd/acp-hub        # 默认 :8787（PORT 可改）
```

启动日志会打印**配对码**（6 位，15 分钟有效）：

```
[acp-hub] pairing code: DDVZRR (expires 03:55:17)
```

也可以随时查看 / 轮换：

- `GET /api/pairing` — 查看当前配对码与过期时间
- `POST /api/pairing/rotate` — 轮换配对码（旧的立即失效）

配对状态（token → host）持久化在 `~/.acp-hub/hub.json`，Hub 重启后已配对的
Host 无需重新配对。

## 配对流程

1. Hub 启动，打印配对码。
2. 每个 Host 启动时带着配对码调用 `POST /api/pair`
   （`{ code, hostId, hostName }`），换取 `token`；Host 端持久化 token，
   重启免配对。
3. Host 用 token（`Authorization: Bearer`）维持连接，Hub 据此识别 Host。

## API

### 浏览器侧（acp-fe）

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/events` | 聚合 SSE：所有 Host 事件带 `hostId`/`hostName` 标签；hub 级事件（`hello`、`hosts_changed`）不带 hostId |
| GET | `/api/hosts` | 注册表：`{ hosts: [...], defaultHostId }` |
| GET | `/api/status` | 中转到默认 Host |
| GET/POST | `/api/*`（其余） | 中转：`?host=<hostId>` 选择目标 Host，缺省用默认 Host（最近在线的） |

### Host 侧

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/pair` | 配对码换 token（Bearer 鉴权） |
| GET | `/api/hub/stream?host=<id>` | Host 出站 SSE 长连接；Hub 推送 `{type:"request", reqId, method, path, body}` |
| POST | `/api/hub/events` | Host 批量上报事件（兼作心跳）；`host_status` 事件更新注册表 ready 状态 |
| POST | `/api/hub/respond` | 中转请求应答 `{reqId, status, body}` |

### 其他

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/health` | 存活检查 |
| GET | `/api/info` | 服务信息 |

## 行为细节

- Host 在线状态 = stream 连接状态：断连立即离线并广播 `hosts_changed`，
  中转中的请求立即失败（503）——不会挂死浏览器。
- 中转请求等待上限 45 分钟（对齐 Host 侧 30 分钟 prompt 超时）。
- 事件扇出为尽力而为（慢消费者丢弃），浏览器通过 `/api/status` 与
  `/api/session-updates` 重新水合，与 acp-host 本地模式一致。

## 本地单机开发

前端直连 `acp-host` 即可，**不必**启动 Hub：

```bash
# 终端 1
cd acp-host && go run ./cmd/acp-host

# 终端 2
cd acp-fe && npm run dev
```

多 Host / 跨机器时：

```bash
# 终端 1（Hub）
cd acp-hub && go run ./cmd/acp-hub

# 终端 2..N（每台机器一个 Host，配对码填 Hub 日志里的）
cd acp-host && HUB_URL=http://<hub>:8787 HUB_PAIR_CODE=<code> go run ./cmd/acp-host

# 终端 M（前端指向 Hub）
cd acp-fe && VITE_PROXY_TARGET=http://localhost:8787 npm run dev
```
