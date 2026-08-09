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

### 环境变量

| 变量 | 默认 | 说明 |
|------|------|------|
| `PORT` | `8787` | HTTP 端口 |
| `FE_TOKEN` | — | **前端访问 token**（也认 `ACCESS_TOKEN`）。设置后，浏览器侧接口必须携带该 token，否则 `401`。未设置时浏览器路由开放（仅适合本机开发） |

生产部署示例：

```bash
FE_TOKEN=your-long-random-secret go run ./cmd/acp-hub
# 或
FE_TOKEN=your-long-random-secret ./acp-hub
```

前端**不要**把密钥打进静态构建；用户打开页面后在门禁框输入同一密钥（存本机 `localStorage`）。请求时带上：

- `Authorization: Bearer <FE_TOKEN>`（推荐，所有 `fetch`）
- 或 `X-Access-Token: <FE_TOKEN>`
- 或 `?token=<FE_TOKEN>`（`EventSource` 无法设 header，SSE 用 query）

**不**校验 FE_TOKEN 的路径（Host 仍用自己的配对 Bearer）：

- `GET /health`、`GET /api/info`
- `POST /api/pair`、`GET /api/hub/stream`、`POST /api/hub/events`、`POST /api/hub/respond`

## 配对流程

1. Hub 启动，打印配对码。
2. 每个 Host 启动时带着配对码调用 `POST /api/pair`
   （`{ code, hostId, hostName }`），换取 `token`；Host 端持久化 token，
   重启免配对。
3. Host 用 token（`Authorization: Bearer`）维持连接，Hub 据此识别 Host。

## API

### 浏览器侧（acp-fe）

设置了 `FE_TOKEN` 时，下列接口均需携带访问 token（见上）。

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
| GET | `/api/hub/stream?host=<id>` | Host 出站 SSE 长连接；Hub 推送 `hello`（含 `subscribers`）、`{type:"subscribers",count}`（浏览器订阅数变化）、`{type:"request", reqId, method, path, body}` |
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
- **空闲省流量**：Hub 跟踪浏览器 `/events` 订阅数，经 Host stream 推送
  `{type:"subscribers",count:N}`（stream 的 `hello` 也带 `subscribers`）。
  Host 在 `count==0` 时暂停 bridge 事件上报，仅保留约 15s 一次的
  `host_status` 心跳；有浏览器连上后再恢复。错过的事件靠前端水合补齐。

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
# 终端 1（Hub）— 生产务必设置 FE_TOKEN
cd acp-hub && FE_TOKEN=dev-secret go run ./cmd/acp-hub

# 终端 2..N（每台机器一个 Host，配对码填 Hub 日志里的）
cd acp-host && HUB_URL=http://<hub>:8787 HUB_PAIR_CODE=<code> go run ./cmd/acp-host

# 终端 M（前端指向 Hub；密钥在页面上输入，勿写进构建）
cd acp-fe && VITE_PROXY_TARGET=http://localhost:8787 npm run dev
```
