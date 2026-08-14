<p align="center">
  <img src="docs/brand/banner.png" alt="Capri" width="920" />
</p>

<p align="center">
  <img src="docs/brand/capri.png" alt="Capri mark" width="88" />
</p>

<h1 align="center">Capri Hub</h1>

<p align="center">
  <strong>把多台机器上的 Agents 收拢到一处</strong><br />
  <em>Capricorn · AgentsHarness 的第一颗星座</em>
</p>

<p align="center">
  <a href="https://github.com/AgentsHarness/capri-hub/releases"><img src="https://img.shields.io/github/v/release/AgentsHarness/capri-hub?style=flat-square&color=002255" alt="release" /></a>
  <a href="https://github.com/AgentsHarness"><img src="https://img.shields.io/badge/AgentsHarness-vision-002255?style=flat-square" alt="AgentsHarness" /></a>
  <img src="https://img.shields.io/badge/for-Grok%20Build-0c0c0e?style=flat-square" alt="Grok Build" />
  <img src="https://img.shields.io/badge/license-MIT-0c0c0e?style=flat-square" alt="MIT" />
</p>

---

[AgentsHarness](https://github.com/AgentsHarness) 想让你在任何时间、任何设备上，掌控任何设备上的 Agents。这件事叫 **slogin**。

**Capri**（Capricorn）是现在的落地。`capri-hub` 是中继：各台机器上的 [capri-host](https://github.com/AgentsHarness/capri-host) 主动连出来，你打开浏览器就能挑选要操作的那一台。

Hub **不执行**任何命令、不碰你的文件。它只做配对、发现和转发。Host 从内网主动出站，家里没有公网 IP 也能用。

```
浏览器  ──▶  capri-hub :8787  ──▶  家里的 host
                           ──▶  办公室的 host
                           ──▶  服务器上的 host
```

只在一台机器上用？不必起 Hub，直接跑 [capri-host](https://github.com/AgentsHarness/capri-host) 即可。

## 部署

需要 Go 1.26+，或从 [Releases](https://github.com/AgentsHarness/capri-hub/releases) 下载二进制。

```bash
# 生产务必设置 FE_TOKEN（浏览器门禁）
FE_TOKEN=$(openssl rand -hex 24) go run ./cmd/acp-hub
```

启动日志会打印 **6 位配对码**（15 分钟有效）。也可以随时查看 / 换新：

```bash
curl http://127.0.0.1:8787/api/pairing
curl -X POST http://127.0.0.1:8787/api/pairing/rotate
```

默认端口：HTTP `8787`，QUIC UDP `8788`（云安全组放行 UDP 更稳；不放行会自动走 WebSocket）。

## 把 Host 接进来

在每台有 grok 的机器上：

```bash
HUB_URL=http://<hub>:8787 HUB_PAIR_CODE=XXXXXX HOST_NAME="办公室 Mac" \
  go run ./cmd/acp-host
```

配对一次即可，token 记在那台机器的 `~/.acp-host/hub.json`。然后用浏览器打开 `http://<hub>:8787`，输入刚才的 `FE_TOKEN`，从左上角切换 Host。

密钥不要写进前端构建，只在页面上输入。

## 常用变量

| 变量 | 默认 | 说明 |
|------|------|------|
| `PORT` | `8787` | HTTP 端口 |
| `QUIC_PORT` | `8788` | Host 主通道（UDP） |
| `FE_TOKEN` | — | 浏览器访问密钥。生产必设 |
| `REQUIRE_FE_TOKEN` | — | 设为 `1` 时，没配 `FE_TOKEN` 会拒绝启动 |
| `CORS_ORIGINS` | `*` | 生产写成前端真实源 |

## 一家子

| | |
|---|---|
| [AgentsHarness](https://github.com/AgentsHarness) | 愿景：远程接入，互相调用 |
| [capri-host](https://github.com/AgentsHarness/capri-host) | 本机节点，真正跑 Agent 的地方 |
| [capri-fe](https://github.com/AgentsHarness/capri-fe) | 浏览器操作台（已嵌在 Host） |

MIT · [Linux.do](https://linux.do)
