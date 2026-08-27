package main

// paircode.go implements `capri-hub paircode` — print (or rotate) the
// hub's current pairing code.
//
// Why a subcommand rather than a doc note telling operators to read the
// log: the pairing code lives only in the running hub's memory and
// rotates every PairingCodeTTL, so there is no file to cat and the
// startup log line goes stale within 15 minutes. In a container nobody
// has a terminal attached to the process, and GET /api/pairing sits
// behind FE_TOKEN in production.
//
// Running this command INSIDE the container solves both halves: it dials
// 127.0.0.1 (so the endpoint need not be exposed publicly) and picks up
// the very FE_TOKEN the hub process was started with (so the operator
// never handles the secret):
//
//	docker compose exec capri-hub capri-hub paircode
//
// It also works from anywhere else with -url and -token.

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// pairCodeResult mirrors the JSON of GET /api/pairing and
// POST /api/pairing/rotate (both return code + expiresAt).
type pairCodeResult struct {
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// errPairCodeUnauthorized is returned for a 401 so the CLI can explain
// the FE_TOKEN mismatch instead of dumping a raw status line.
var errPairCodeUnauthorized = errors.New("unauthorized")

// fetchPairCode reads the live pairing code from a running hub, or
// rotates it first when rotate is true (the old code stops working).
func fetchPairCode(ctx context.Context, client *http.Client, baseURL, token string, rotate bool) (pairCodeResult, error) {
	var out pairCodeResult

	method, path := http.MethodGet, "/api/pairing"
	if rotate {
		method, path = http.MethodPost, "/api/pairing/rotate"
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(baseURL, "/")+path, nil)
	if err != nil {
		return out, err
	}
	// Header auth only: a token in the query string lands in access logs.
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return out, errPairCodeUnauthorized
	}
	if resp.StatusCode != http.StatusOK {
		// Bound the echoed body: this goes to a terminal, and a
		// misrouted request (reverse proxy, wrong port) can answer
		// with a whole HTML error page.
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return out, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&out); err != nil {
		return out, fmt.Errorf("解析响应失败: %w", err)
	}
	if out.Code == "" {
		return out, errors.New("响应里没有配对码")
	}
	return out, nil
}

// defaultPairCodeURL points at the loopback address of a hub in this same
// container / machine, honouring PORT so an overridden port still works.
func defaultPairCodeURL() string {
	port := 8787
	if v := strings.TrimSpace(os.Getenv("PORT")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			port = n
		}
	}
	return fmt.Sprintf("http://127.0.0.1:%d", port)
}

// formatRemaining renders the time left as a short human string. The
// expiry matters as much as the code: a code with 20 seconds left will
// fail for a user typing it into a tray dialog, and the operator should
// see that and rotate instead of blaming the host.
func formatRemaining(d time.Duration) string {
	if d <= 0 {
		return "已过期"
	}
	d = d.Round(time.Second)
	m := int(d / time.Minute)
	s := int((d % time.Minute) / time.Second)
	if m > 0 {
		return fmt.Sprintf("剩余 %d 分 %02d 秒", m, s)
	}
	return fmt.Sprintf("剩余 %d 秒", s)
}

// runPairCode is the CLI entry point. Returns the process exit code:
// 0 ok, 1 request failed, 2 bad usage.
func runPairCode(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("capri-hub paircode", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, `用法: capri-hub paircode [选项]

打印当前配对码（Host 端配对时输入的 6 位码）。

在容器里运行时不需要任何参数 —— 它连 127.0.0.1 并复用 hub 进程自己的
FE_TOKEN:

  docker compose exec capri-hub capri-hub paircode

选项:
`)
		fs.PrintDefaults()
	}
	rotate := fs.Bool("rotate", false, "先换一个新码再打印（旧码立即失效）")
	asJSON := fs.Bool("json", false, "输出 JSON，便于脚本消费")
	url := fs.String("url", defaultPairCodeURL(), "hub 的 HTTP 地址")
	token := fs.String("token", "", "FE_TOKEN（默认取环境变量 FE_TOKEN / ACCESS_TOKEN）")
	timeout := fs.Duration("timeout", 5*time.Second, "请求超时")
	if err := fs.Parse(args); err != nil {
		return 2 // flag package already printed the reason
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "多余的参数: %s\n", strings.Join(fs.Args(), " "))
		fs.Usage()
		return 2
	}

	tok := *token
	if tok == "" {
		tok = strings.TrimSpace(os.Getenv("FE_TOKEN"))
	}
	if tok == "" {
		tok = strings.TrimSpace(os.Getenv("ACCESS_TOKEN"))
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	res, err := fetchPairCode(ctx, &http.Client{Timeout: *timeout}, *url, tok, *rotate)
	if err != nil {
		switch {
		case errors.Is(err, errPairCodeUnauthorized):
			fmt.Fprintf(stderr, "hub 拒绝了请求: FE_TOKEN 不匹配。\n"+
				"容器内请直接运行 `capri-hub paircode`（会复用 hub 自己的 FE_TOKEN）；\n"+
				"容器外请用 -token 或设置环境变量 FE_TOKEN。\n")
		case errors.Is(err, context.DeadlineExceeded):
			fmt.Fprintf(stderr, "连接 %s 超时。hub 起来了吗？端口/反代对吗？\n", *url)
		default:
			fmt.Fprintf(stderr, "读取配对码失败 (%s): %v\n", *url, err)
		}
		return 1
	}

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			fmt.Fprintf(stderr, "输出失败: %v\n", err)
			return 1
		}
		return 0
	}

	fmt.Fprintf(stdout, "配对码  %s\n", res.Code)
	fmt.Fprintf(stdout, "有效期  %s（%s）\n",
		res.ExpiresAt.Local().Format("15:04:05"),
		formatRemaining(time.Until(res.ExpiresAt)))
	return 0
}
