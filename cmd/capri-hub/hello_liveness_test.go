package main

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/AgentsHarness/capri-hub/internal/hub"
)

// hello 必须带上 hub 判活的时间尺度（pingInterval / idleTimeout），host 才能
// 用自己的下行看门狗对齐 hub，而不是两端各自硬编码。
func TestWriteHostHelloCarriesLivenessScale(t *testing.T) {
	h := hub.NewWithDir("")
	code, _ := h.PairingCode()
	if _, err := h.Pair(code, "h1", "H1"); err != nil {
		t.Fatalf("pair: %v", err)
	}

	var raw []byte
	if _, err := writeHostHello(h, "h1", false, true, func(b []byte) error {
		raw = append([]byte(nil), b...)
		return nil
	}); err != nil {
		t.Fatalf("writeHostHello: %v", err)
	}

	var hello map[string]any
	if err := json.Unmarshal(raw, &hello); err != nil {
		t.Fatalf("hello is not JSON: %v (%s)", err, raw)
	}

	// 必须是整型秒：host 按 int 解析，float 会被拒绝。
	ping, ok := hello["pingInterval"].(float64)
	if !ok {
		t.Fatalf("hello has no numeric pingInterval: %s", raw)
	}
	if got, want := int(ping), int(hostPingInterval/time.Second); got != want {
		t.Errorf("pingInterval = %d, want %d", got, want)
	}
	idle, ok := hello["idleTimeout"].(float64)
	if !ok {
		t.Fatalf("hello has no numeric idleTimeout: %s", raw)
	}
	if got, want := int(idle), int(hostIdleTimeout()/time.Second); got != want {
		t.Errorf("idleTimeout = %d, want %d", got, want)
	}

	// 既有字段不能被这两个新增项挤掉。
	for _, key := range []string{"v", "type", "service", "subscribers", "seq", "probe"} {
		if _, ok := hello[key]; !ok {
			t.Errorf("hello lost %q: %s", key, raw)
		}
	}
	if hello["probe"] != true {
		t.Errorf("WS hello probe = %v, want true: %s", hello["probe"], raw)
	}
}

// probe 只在 WS 上成立：QUIC 没有协议级 pong 可刷 LastSeen，所以 QUIC 的
// hello 必须省掉这个字段，host 才会保留自己的心跳节奏。
func TestWriteHostHelloProbeIsTransportScoped(t *testing.T) {
	h := hub.NewWithDir("")
	code, _ := h.PairingCode()
	if _, err := h.Pair(code, "h1", "H1"); err != nil {
		t.Fatalf("pair: %v", err)
	}

	read := func(probe bool) map[string]any {
		t.Helper()
		var raw []byte
		if _, err := writeHostHello(h, "h1", false, probe, func(b []byte) error {
			raw = append([]byte(nil), b...)
			return nil
		}); err != nil {
			t.Fatalf("writeHostHello(probe=%v): %v", probe, err)
		}
		var hello map[string]any
		if err := json.Unmarshal(raw, &hello); err != nil {
			t.Fatalf("hello is not JSON: %v (%s)", err, raw)
		}
		return hello
	}

	if got := read(true)["probe"]; got != true {
		t.Errorf("WS hello probe = %v, want true", got)
	}
	if got, ok := read(false)["probe"]; ok {
		t.Errorf("QUIC hello must omit probe, got %v", got)
	}
}

// idleTimeout 必须跟着 sweep 的旋钮走，且始终比 sweep 本身晚一个 tick：
// host 在 registry 翻牌之前就开始重连，是这条时间线要消除的两端不一致。
func TestWriteHostHelloIdleTimeoutTracksSweep(t *testing.T) {
	prevSilence, prevSweep := hub.HostSilenceTimeout, hub.LivenessCheckInterval
	hub.HostSilenceTimeout = 42 * time.Second
	hub.LivenessCheckInterval = 3 * time.Second
	t.Cleanup(func() {
		hub.HostSilenceTimeout = prevSilence
		hub.LivenessCheckInterval = prevSweep
	})

	h := hub.NewWithDir("")
	code, _ := h.PairingCode()
	if _, err := h.Pair(code, "h1", "H1"); err != nil {
		t.Fatalf("pair: %v", err)
	}

	var raw []byte
	if _, err := writeHostHello(h, "h1", false, false, func(b []byte) error {
		raw = append([]byte(nil), b...)
		return nil
	}); err != nil {
		t.Fatalf("writeHostHello: %v", err)
	}
	var hello struct {
		IdleTimeout *int `json:"idleTimeout"`
	}
	if err := json.Unmarshal(raw, &hello); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// sweep 42s + 两个 tick 3s = 48s：一个 tick 覆盖「刚好在 tick 之后静默」
	// 的 host 被扫掉的最坏时刻，另一个是 host 自己检查粒度的排序余量。
	if hello.IdleTimeout == nil || *hello.IdleTimeout != 48 {
		t.Fatalf("idleTimeout = %v, want 48 (sweep 42s + two 3s ticks)", hello.IdleTimeout)
	}
	// 排序不变式：广播出去的预算必须严格长于 registry 真正翻牌的时刻。
	if got := hostIdleTimeout(); got <= hub.HostSilenceTimeout+hub.LivenessCheckInterval {
		t.Fatalf("advertised %s must exceed the sweep's worst case %s", got, hub.HostSilenceTimeout+hub.LivenessCheckInterval)
	}
}

// 与 host 看门狗的关系：registry 必须先翻牌。广播出去的 idleTimeout 就是
// host 会用的预算，所以它必须严格长于 sweep 真正生效的最坏时刻。这两个数字
// 一旦反转，两边就会互相打断。
func TestHubJudgesDeathBeforeHost(t *testing.T) {
	// 线上值：sweep 30s（最坏 33s 翻牌），host 拿到 36s——hub 先判死。
	if got := hostIdleTimeout(); got%time.Second != 0 {
		t.Fatalf("advertised idleTimeout %s is not whole seconds", got)
	}
	// 排序：只要 host 按广播值走，registry 一定先翻牌。
	if hub.HostSilenceTimeout >= hostIdleTimeout() {
		t.Fatalf("sweep %s must flip before the advertised host budget %s", hub.HostSilenceTimeout, hostIdleTimeout())
	}
	// But the sweep still has to sit above one probe cycle, or a single slow
	// probe reads as application silence.
	probeInterval := time.Duration(hostProbeInterval.Load())
	probeTimeout := time.Duration(hostProbeTimeout.Load())
	idleAfter := time.Duration(hostProbeIdleAfter.Load())
	// The probe only starts after the link has been idle, then needs two
	// failed rounds. The sweep must still be later than that.
	worst := idleAfter + time.Duration(hostProbeFailures)*(probeInterval+probeTimeout)
	if hub.HostSilenceTimeout <= worst {
		t.Fatalf("HostSilenceTimeout = %s must exceed the probe's %s worst case", hub.HostSilenceTimeout, worst)
	}
	// The transport read timeout stays the slowest backstop.
	if hostReadTimeout <= hub.HostSilenceTimeout {
		t.Fatalf("hostReadTimeout = %s must be the slowest backstop, sweep is %s", hostReadTimeout, hub.HostSilenceTimeout)
	}
}
