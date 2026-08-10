# acp-hub

中心化中转服务器（relay）：多 Host 配对、注册与发现、事件聚合、请求中转。

```
Browser (acp-fe) ──WS /ws/fe + HTTP /api/*──▶ acp-hub (:8787) ──QUIC(udp:8788) / WS /ws/host──▶ acp-host × N ──stdio──▶ grok
```

Host 主动**出站**连接 Hub（适配 NAT，无需 Hub 能访问 Host）；优先 QUIC（UDP 8788，
抗丢包、连接迁移），失败自动回退 WebSocket。Hub 不做 fs/terminal 执行，只做转发。
业务 API 仍走 HTTP 中转。

**可靠性**：host 给每个事件分配单调 `seq`；hub 缓冲每 host 最近 4000 条事件，
浏览器可经 `GET /api/events?host=X&after=SEQ` 补拉缺口，断线/丢帧最终收敛。

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

- `GET /api/pairing` — 查看当前配对码与过期时间（若已过期会**自动轮换**后再返回）
- `POST /api/pairing/rotate` — 立即轮换配对码（旧的立刻失效）
- 后台每 30s 检查过期并自动轮换，避免挂着失效码

配对状态（token → host）持久化在 `~/.acp-hub/hub.json`（目录 `0700`、文件 `0600`），
Hub 重启后已配对的 Host 无需重新配对。注册表最多 `MaxHosts`（256）台；可用
`DELETE /api/hosts/{hostId}` 解绑。

### 环境变量

| 变量 | 默认 | 说明 |
|------|------|------|
| `PORT` | `8787` | HTTP 端口 |
| `QUIC_PORT` | `8788` | Host 传输 QUIC UDP 端口（UDP 需在云安全组放行；不放行时 host 自动回退 WS） |
| `FE_TOKEN` | — | **前端访问 token**（也认 `ACCESS_TOKEN`）。设置后浏览器侧接口必须鉴权。未设置时路由开放（仅本机开发） |
| `REQUIRE_FE_TOKEN` | — | 设为 `1`/`true` 时，未配置 `FE_TOKEN` 则**拒绝启动**（生产推荐） |
| `CORS_ORIGINS` | `*` | 逗号分隔允许的 Origin；空或 `*` 为放行全部。生产请写成前端真实源 |
| `QUIC_CERT` / `QUIC_KEY` | — | QUIC TLS 证书。**设置了 `FE_TOKEN` 时默认必须提供**（禁止自签）；否则开发可用内存自签 |
| `QUIC_ALLOW_SELF_SIGNED` | — | 设为 `1` 时即使有 `FE_TOKEN` 也允许 QUIC 自签（仅实验室） |

生产部署示例：

```bash
REQUIRE_FE_TOKEN=1 \
FE_TOKEN=your-long-random-secret \
CORS_ORIGINS=https://your-fe.example \
QUIC_CERT=/etc/acp/fullchain.pem QUIC_KEY=/etc/acp/privkey.pem \
  go run ./cmd/acp-hub
```

前端**不要**把密钥打进静态构建；用户打开页面后在门禁框输入同一密钥（存本机 `localStorage`）。请求时带上：

- `Authorization: Bearer <FE_TOKEN>`（推荐，所有 `fetch`）
- 或 `X-Access-Token: <FE_TOKEN>`
- WebSocket：`POST /api/ws-ticket`（带 Bearer）换短期 `ticket`，再连 `/ws/fe?ticket=…`（**推荐**，避免长期密钥进 access log）
- 兼容：`/ws/fe?token=<FE_TOKEN>`（不推荐）

**不**校验 FE_TOKEN 的路径（Host 仍用自己的配对 Bearer）：

- `GET /health`、`GET /api/info`
- `POST /api/pair`、`GET /ws/host`

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
| GET | `/ws/fe` | 聚合 live WebSocket：帧 `{v:1,type:"hello"|"events"|"ping",…}`；事件带 `hostId`/`hostName`/`seq`；`?c=1` 时 events 帧为 flate 压缩二进制；鉴权优先 `?ticket=` |
| POST | `/api/ws-ticket` | 兑换单次短期 ticket（约 2 分钟）供 `/ws/fe` 使用 |
| GET | `/api/events` | 缺口补拉：`?host=X&after=SEQ` → 该 host 缓冲中 seq>after 的事件（升序） |
| GET | `/api/hosts` | 注册表：`{ hosts: [...], defaultHostId }` |
| DELETE | `/api/hosts/{hostId}` | 解绑 host：吊销 token、清 pending、从注册表移除（需 FE_TOKEN） |
| GET | `/api/status` | 中转到默认 Host |
| GET/POST | `/api/*`（其余） | 中转：`?host=<hostId>` 选择目标 Host，缺省用默认 Host（最近在线的） |

### Host 侧

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/pair` | 配对码换 token（Bearer 鉴权） |
| GET | `/ws/host` | Host 出站 WebSocket 回退通道（`Authorization: Bearer <token>`） |
| UDP | `:8788` | Host 主通道 QUIC：单双向流 + 4 字节长度前缀 JSON 帧；首帧 `{type:"auth",token}` 鉴权，之后同 WS 帧协议 |

### 其他

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/health` | 存活检查 |
| GET | `/api/info` | 服务信息 |

## 行为细节

- Host 在线状态 = 传输连接状态：断连立即离线并广播 `hosts_changed`，
  中转中的请求立即失败（503）——不会挂死浏览器。重连会取代旧连接并立刻 fail pending。
- Host 断连后 **约 60s** 内仍保留事件缓冲，便于短断线时 `GET /api/events` 补拉；超时后丢弃。
- 中转请求等待上限 45 分钟（对齐 Host 侧 30 分钟 prompt 超时）。
- 事件扇出为尽力而为（慢消费者丢弃，订阅 buffer 512），浏览器通过 `/api/events` 与
  `/api/session-updates` 重新水合，与 acp-host 本地模式一致。
- **空闲省流量**：Hub 跟踪浏览器 `/ws/fe` 订阅数，经 Host WS 推送
  `{v:1,type:"subscribers",count:N}`（`hello` 也带 `subscribers`）。
  Host 在 `count==0` 时暂停 bridge 事件上报，仅保留约 15s 一次的
  `host_status` 心跳；有浏览器连上后再恢复。错过的事件靠前端水合补齐。
- Host 侧对 live 事件做异步发送队列 + chunk/thought 合并 + `seq` 编号 + 断线重放（最近 5000 条）后上行，降低丢包与帧数；重连后按 `hello.seq` 补发缺口。

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
