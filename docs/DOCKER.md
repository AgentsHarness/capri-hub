# Docker 部署

hub 是纯 Go、无 cgo、不内嵌前端，所以镜像就是一个静态二进制加两个数据
文件（约 20 MB）。多架构镜像由 GitHub Actions 构建并推到 GHCR。

```
ghcr.io/agentsharness/capri-hub:latest     # 跟随最新 tag
ghcr.io/agentsharness/capri-hub:v1.2.3     # 具体版本
ghcr.io/agentsharness/capri-hub:sha-abc1234
```

支持 `linux/amd64` 和 `linux/arm64`。

## 快速开始

服务器上只需要 `docker-compose.yml` 和 `.env` 两个文件，不必 clone 仓库。

```bash
cp .env.example .env
# 至少填 FE_TOKEN：openssl rand -hex 24
$EDITOR .env

# 状态目录。容器以 uid 10001 运行，所以宿主机上要把目录给它。
mkdir -p data && sudo chown -R 10001:10001 data

docker compose up -d
docker compose logs -f            # 看启动日志
```

起来之后第一件事就是拿配对码。

## 配对码在哪儿看

配对码只活在 hub 进程的内存里，**每 15 分钟自动轮换一次**，重启也会换新。
所以没有一个文件可以 `cat`，"启动时打印的那一行" 也只在头 15 分钟里有效。
三条路，按推荐顺序：

### 1. `paircode` 子命令（推荐）

```bash
docker compose exec capri-hub capri-hub paircode
```

```
配对码  44KJHC
有效期  16:42:31（剩余 12 分 08 秒）
```

在容器里跑的好处是不用碰任何密钥：它连的是 `127.0.0.1`，用的是 hub 进程
自己那份 `FE_TOKEN`。所以不需要参数。

需要一个立刻生效的新码（比如上一个快过期了，或者你怀疑泄露了）：

```bash
docker compose exec capri-hub capri-hub paircode -rotate
```

`-rotate` 会让旧码**立即失效**。给脚本用加 `-json`：

```bash
docker compose exec capri-hub capri-hub paircode -json | jq -r .code
```

在容器外也能用，自己给地址，token 走 `FE_TOKEN` 环境变量：

```bash
FE_TOKEN="$FE_TOKEN" capri-hub paircode -url https://hub.example.com
```

不要用 `-token` 参数把密钥写在命令行上 —— 命令行参数会留在进程 argv 里，
同机的其他用户 `ps` 就能看到。`-token` 依然可用（`FE_TOKEN` /
`ACCESS_TOKEN` 环境变量都没设时的兜底），但只该在密钥已经公开的场合用。

### 2. 日志

```bash
docker compose logs capri-hub | grep -i "pairing code" | tail -1
```

轮换时也会打一行，所以 `tail -1` 拿到的就是当前有效的那个：

```
[capri-hub] pairing code: 44KJHC (expires 16:42:31)
[capri-hub] pairing code auto-rotated (expired): 7QM2XB (expires 16:57:31)
```

这条路不需要 exec 进容器，缺点是看不到还剩多久，而且日志轮转后早期的行
会被丢掉（这没关系，你要的本来就是最后一行）。

### 3. HTTP API

```bash
curl -H "Authorization: Bearer $FE_TOKEN" https://hub.example.com/api/pairing
```

```json
{"code":"44KJHC","expiresAt":"2026-08-26T16:42:31+08:00","ttl":15}
```

前端（capri-fe）用的就是这个接口。注意**设了 `FE_TOKEN` 之后这个接口需要
带 token**，没设的话它是公开的 —— 这也是为什么生产必须设 `FE_TOKEN`：
否则任何人都能读走配对码，然后把自己的 host 挂到你的 hub 上。

换新码是 `POST /api/pairing/rotate`，同样要 token。

### 然后在 host 上输入

拿到码之后，在装了 [capri-host](https://github.com/AgentsHarness/capri-host)
的机器上：托盘 →「配对 hub」→ 填 hub 地址 → 填这 6 位码。或者首次启动前
设 `HUB_URL` + `HUB_PAIR_CODE` 环境变量。

配对成功后 token 记在那台机器的 `~/.capri-host/hub.json`，之后重启不再
需要配对码。

## 反向代理

hub **自己不会说 TLS**（代码里没有 `ListenAndServeTLS`），只监听明文
HTTP 8787 和 QUIC UDP 8788。所以 443 上必须有反代。

compose 默认把 HTTP 绑在 `127.0.0.1:8787`，正是给宿主机上的 nginx/caddy
用的。

### nginx

```nginx
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen 443 ssl;
    http2 on;
    server_name hub.example.com;

    ssl_certificate     /etc/letsencrypt/live/hub.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/hub.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8787;

        # WebSocket 必需：/ws/fe 是浏览器事件流，/ws/host 是 QUIC 不通时
        # host 的回退通道。漏了这四行，host 在 QUIC 也不通的情况下就彻底
        # 连不上了。
        proxy_http_version 1.1;
        proxy_set_header Upgrade    $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host       $host;

        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # 长连接不要缓冲，也不要 60s 就掐断。
        proxy_buffering off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
```

### 反代也在 Docker 里

那 `127.0.0.1:8787` 从反代容器里是不通的。删掉 compose 里那条 HTTP 端口
映射，让两个容器共享一个 network，反代直接 `proxy_pass http://capri-hub:8787`。
QUIC 那条 UDP 映射要保留。

### QUIC 不走反代

host 的主通道是 QUIC，它直接拨 `<hub 地址>:8788/udp`，**绕过反代**。
所以：

- 防火墙/安全组要放行 **UDP 8788**（华为云、阿里云默认只开 TCP）。
- compose 里那条 `"8788:8788/udp"` 必须公开绑定。

漏了任何一条都不会报错。host 会静默退回 WebSocket，功能照常，只是延迟
更高 —— 这是本项目最难发现的一类配置问题。想确认走的是哪条通道，看
host 侧托盘的「连接信息」，或者 hub 日志里的 `host connected (quic)` /
`(ws)`。

### 限流桶在反代后面是共享的

`POST /api/pair` 有每 IP 每分钟 10 次的滑动窗口限流，而 hub **故意不信任
`X-Forwarded-For`**（源码注释写明了）。所以在反代后面，所有请求看起来都
来自反代那一个 IP，10 次/分钟变成了全局共享。

正常用没影响（配对是偶发操作），但如果你连着输错码超过 10 次，会收到
`429 尝试过于频繁`，等一分钟就好。要按真实 IP 限流的话在反代那层做。

## 迁移已有的配对

`hub.json` 里存着所有已配对 host 的 token。**不搬过来的话，所有 host 都要
重新配对一次。**

先找到你现在的状态目录。三种常见情况：

- 裸跑二进制 → `~/.capri-hub/`
- 容器里用 `HOME` 重定向（`HOME=/root` + 挂载到 `/root/.capri-hub`）→
  宿主机上那个挂载源，例如 `/opt/capri-hub/data`
- 已经用了 `HUB_DATA_DIR` → 你自己指定的目录

```bash
docker compose down                    # 或 docker stop <旧容器>

mkdir -p data
cp /opt/capri-hub/data/hub.json   data/     # ← 换成你的实际路径
cp /opt/capri-hub/data/prefs.json data/ 2>/dev/null || true

# 这一步不能省。
sudo chown -R 10001:10001 data

docker compose up -d
curl -H "Authorization: Bearer $FE_TOKEN" http://127.0.0.1:8787/api/hosts
```

最后一行应该列出你原来那些 hostId。

### 为什么 chown 不能省

旧部署以 **root** 跑，`hub.json` 通常是 `-rw------- root root`（600）。新镜像
以 **uid 10001** 跑，对这个文件**连读权限都没有**。而 hub 读不到状态文件时
不会报错退出 —— 它当成"第一次启动"，用一份空状态继续跑。结果就是：容器
healthy、日志干净、`/api/hosts` 空的，你所有 host 都掉线且要重新配对，
而没有任何一行日志告诉你原因。

搬完确认一下属主：

```bash
ls -l data/hub.json     # 期望 10001 10001
```

写入失败的情况反而好认，日志里会有
`persist: rename ... permission denied`。

### 从"挂载二进制"的部署切过来

如果你现在的 compose 是把 release 二进制 bind-mount 进一个空镜像
（`- /opt/capri-hub/capri-hub-linux-amd64:/capri-hub:ro`），换成这个镜像时
要一起删掉三样东西：

- 那条二进制的 `volumes` 挂载 —— 二进制现在在镜像里
- `environment` 里的 `HOME` —— 改由 `HUB_DATA_DIR` 指定状态目录
- 状态挂载的容器侧路径 `/root/.capri-hub` → 改成 `/data`

证书挂载（`- /key:/certs:ro`）保留，并把 `QUIC_CERT` / `QUIC_KEY` 留在
`.env` 里 —— 有真证书就不需要 `QUIC_ALLOW_SELF_SIGNED`。

### 两个 compose 文件会互相顶掉

Compose 用 `name:` 认项目，而这个文件里写的是 `name: capri-hub`。如果你把
它放在新目录、而旧的 `docker-compose.yml` 还在别处，两者是**同一个项目**：
在新目录 `up -d` 会按新定义重建那个容器。要么直接替换旧文件，要么给其中
一个换 `-p <别的名字>`。

## 升级 / 备份 / 卸载

```bash
# 升级
docker compose pull && docker compose up -d

# 备份（就是这一个目录）
tar czf capri-hub-$(date +%F).tar.gz data/

# 停掉但保留状态
docker compose down

# 连状态一起删（所有配对失效）
docker compose down && rm -rf data
```

## 排查

| 现象 | 原因 |
| --- | --- |
| 容器起来就退，日志 `FE_TOKEN is required` | `.env` 里 `FE_TOKEN` 空着，而 `REQUIRE_FE_TOKEN=1`。这是有意的 fail-closed。 |
| 日志 `QUIC TLS 初始化失败` | 设了 `FE_TOKEN` 但没给证书、也没设 `QUIC_ALLOW_SELF_SIGNED=1`。QUIC 被关掉，host 退回 WS。 |
| host 连上了但延迟高 | 走了 WS 回退。查 UDP 8788 是否放行。 |
| 日志 `persist: rename ... permission denied` | `data/` 的属主不是 10001。`sudo chown -R 10001:10001 data`。 |
| 容器 healthy、日志干净，但 `/api/hosts` 是空的 | 迁移过来的 `hub.json` 还是 root:600，容器读不到，于是当成首次启动。见「为什么 chown 不能省」。 |
| 重启后所有配对丢失 | `HUB_DATA_DIR` 没生效或没挂卷，状态写进了容器可写层。确认 `docker compose exec capri-hub test -f /data/hub.json`。 |
| `go mod download` i/o timeout | 只在本地构建时会遇到，国内机器要加 `--build-arg GOPROXY=https://goproxy.cn,direct`。 |
| `/api/pairing` 返回 401 | 没带 `FE_TOKEN`。容器内直接用 `capri-hub paircode`。 |
| `429 尝试过于频繁` | 见上面「限流桶在反代后面是共享的」。 |
| 浏览器打开 hub 是 404 | 正常：hub 不提供网页，它只做配对/发现/转发。UI 是 capri-fe（capri-host 内嵌了一份）。 |

看实时状态：

```bash
docker compose ps                    # 含 healthcheck 状态
curl -fsS http://127.0.0.1:8787/health
curl -H "Authorization: Bearer $FE_TOKEN" http://127.0.0.1:8787/api/hosts | jq
```

## 环境变量

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `FE_TOKEN` | — | 浏览器门禁。生产必设。 |
| `REQUIRE_FE_TOKEN` | — | `1` 时没有 `FE_TOKEN` 就拒绝启动。 |
| `HUB_DATA_DIR` | `~/.capri-hub` | 状态目录。镜像里设为 `/data`。 |
| `PORT` | `8787` | HTTP 端口。 |
| `QUIC_PORT` | `8788` | host 主通道（UDP）。 |
| `QUIC_ALLOW_SELF_SIGNED` | — | `1` 时允许自签证书跑 QUIC。设了 `FE_TOKEN` 又没有真证书时必须开。 |
| `QUIC_CERT` / `QUIC_KEY` | — | 真证书路径（容器内）。 |
| `CORS_ORIGINS` | `*` | 生产写成前端真实源。 |
| `TZ` | `UTC` | 影响日志时间戳和配对码有效期的显示。 |

`HUB_DATA_DIR` 是为容器部署新增的：容器没有有意义的 home 目录，而
`~/.capri-hub` 会把状态写进可写层，`up --force-recreate` 一次就全丢。

## 本地构建

```bash
docker build -t capri-hub:local .
docker run --rm -p 8787:8787 -p 8788:8788/udp capri-hub:local
```

镜像在 `$BUILDPLATFORM` 上交叉编译到目标架构（CGO 关闭，所以完全等价），
arm64 镜像不需要 QEMU 模拟。

**在国内的机器上构建**要换 Go 模块代理 —— `proxy.golang.org` 不通，
`go mod download` 会卡 90 秒然后 i/o timeout：

```bash
docker build --build-arg GOPROXY=https://goproxy.cn,direct -t capri-hub:local .
```

CI 在 GitHub 的机器上跑，用默认值即可。正常部署路径是 **CI 构建、服务器
`docker compose pull`**，根本不需要在服务器上编译。

## 验证过什么

镜像和 compose 在一台真实服务器上跑过（Debian 12 / x86_64 / Docker 29.7.2
/ Compose v5.4.0），与生产容器隔离（独立项目名、回环 18787/18788）：

- 镜像自带的 HEALTHCHECK 能变 healthy
- 以 uid 10001 非 root 运行
- `/health` 不需要 token；未认证的 `/api/pairing` 返回 401
- `capri-hub paircode` 在容器内**不带任何参数**就能打印当前码
- 该码能真的换到 64 位 token（`POST /api/pair` 全链路）
- `-rotate` 换码后旧码立即失效，新码可用
- `HUB_DATA_DIR` 生效：`hub.json` 落在挂载卷上，重启后配对仍在
- `TZ=Asia/Shanghai` 在容器里解析成 `CST+0800`（tzdata 装对了）
- QUIC 监听正常起来
- `read_only: true` 下依然能配对和持久化

CI 的 workflow 里有同一组断言，每次构建都会重跑。
