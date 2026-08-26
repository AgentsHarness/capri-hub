package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// pairCodeStub serves the two pairing endpoints the way the real hub
// does, recording what it received so the tests can assert on the wire
// contract rather than on the client's internals.
type pairCodeStub struct {
	token    string
	code     string
	gotAuth  string
	gotPath  string
	gotVerb  string
	status   int
	body     string
	rotated  bool
	expires  time.Time
	reqCount int
}

func (s *pairCodeStub) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.reqCount++
		s.gotAuth = r.Header.Get("Authorization")
		s.gotPath = r.URL.Path
		s.gotVerb = r.Method

		if s.status != 0 {
			w.WriteHeader(s.status)
			_, _ = w.Write([]byte(s.body))
			return
		}
		if s.token != "" && r.Header.Get("Authorization") != "Bearer "+s.token {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"ok":false,"error":"需要有效的访问 token"}`))
			return
		}
		if r.URL.Path == "/api/pairing/rotate" {
			s.rotated = true
			s.code = "ROT8ED"
		}
		exp := s.expires
		if exp.IsZero() {
			exp = time.Now().Add(15 * time.Minute)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code":      s.code,
			"expiresAt": exp,
			"ttl":       15,
		})
	})
}

func TestFetchPairCodeReadsCurrentCode(t *testing.T) {
	stub := &pairCodeStub{token: "sekret", code: "44KJHC"}
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()

	res, err := fetchPairCode(context.Background(), srv.Client(), srv.URL, "sekret", false)
	if err != nil {
		t.Fatalf("fetchPairCode: %v", err)
	}
	if res.Code != "44KJHC" {
		t.Errorf("code = %q, want 44KJHC", res.Code)
	}
	if stub.gotVerb != http.MethodGet || stub.gotPath != "/api/pairing" {
		t.Errorf("called %s %s, want GET /api/pairing", stub.gotVerb, stub.gotPath)
	}
	// Header auth, never ?token= — a query token would be written to the
	// reverse proxy's access log.
	if stub.gotAuth != "Bearer sekret" {
		t.Errorf("Authorization = %q, want Bearer sekret", stub.gotAuth)
	}
}

func TestFetchPairCodeRotateUsesPost(t *testing.T) {
	stub := &pairCodeStub{token: "sekret", code: "OLDONE"}
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()

	res, err := fetchPairCode(context.Background(), srv.Client(), srv.URL, "sekret", true)
	if err != nil {
		t.Fatalf("fetchPairCode(rotate): %v", err)
	}
	if !stub.rotated || stub.gotVerb != http.MethodPost || stub.gotPath != "/api/pairing/rotate" {
		t.Errorf("called %s %s (rotated=%v), want POST /api/pairing/rotate", stub.gotVerb, stub.gotPath, stub.rotated)
	}
	if res.Code != "ROT8ED" {
		t.Errorf("code = %q, want the rotated code", res.Code)
	}
}

// A 401 must be distinguishable, because it is the one failure with a
// specific fix (wrong/absent FE_TOKEN) rather than "hub unreachable".
func TestFetchPairCodeUnauthorizedIsTyped(t *testing.T) {
	stub := &pairCodeStub{token: "right", code: "44KJHC"}
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()

	_, err := fetchPairCode(context.Background(), srv.Client(), srv.URL, "wrong", false)
	if !errors.Is(err, errPairCodeUnauthorized) {
		t.Fatalf("err = %v, want errPairCodeUnauthorized", err)
	}
}

func TestFetchPairCodeNoTokenSendsNoAuthHeader(t *testing.T) {
	// FE_TOKEN unset (dev): the endpoint is open and we must not invent
	// an empty Bearer header, which some proxies reject outright.
	stub := &pairCodeStub{code: "OPEN01"}
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()

	if _, err := fetchPairCode(context.Background(), srv.Client(), srv.URL, "", false); err != nil {
		t.Fatalf("fetchPairCode: %v", err)
	}
	if stub.gotAuth != "" {
		t.Errorf("Authorization = %q, want empty", stub.gotAuth)
	}
}

func TestFetchPairCodeBoundsErrorBody(t *testing.T) {
	// A misrouted request (wrong port, reverse proxy error page) answers
	// with HTML; the message must stay terminal-sized.
	stub := &pairCodeStub{status: 502, body: strings.Repeat("x", 5000)}
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()

	_, err := fetchPairCode(context.Background(), srv.Client(), srv.URL, "", false)
	if err == nil {
		t.Fatal("want an error for HTTP 502")
	}
	if !strings.Contains(err.Error(), "502") {
		t.Errorf("error should name the status: %v", err)
	}
	if len(err.Error()) > 400 {
		t.Errorf("error body not bounded: %d chars", len(err.Error()))
	}
}

func TestFetchPairCodeRejectsResponseWithoutCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ttl":15}`))
	}))
	defer srv.Close()

	if _, err := fetchPairCode(context.Background(), srv.Client(), srv.URL, "", false); err == nil {
		t.Fatal("want an error when the response carries no code")
	}
}

func TestFetchPairCodeTrimsTrailingSlash(t *testing.T) {
	stub := &pairCodeStub{code: "44KJHC"}
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()

	if _, err := fetchPairCode(context.Background(), srv.Client(), srv.URL+"/", "", false); err != nil {
		t.Fatalf("fetchPairCode with trailing slash: %v", err)
	}
	if stub.gotPath != "/api/pairing" {
		t.Errorf("path = %q, want /api/pairing (no double slash)", stub.gotPath)
	}
}

func TestRunPairCodePrintsCodeAndExpiry(t *testing.T) {
	stub := &pairCodeStub{token: "sekret", code: "44KJHC", expires: time.Now().Add(12*time.Minute + 8*time.Second)}
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()

	var out, errOut bytes.Buffer
	rc := runPairCode([]string{"-url", srv.URL, "-token", "sekret"}, &out, &errOut)
	if rc != 0 {
		t.Fatalf("exit = %d, stderr = %s", rc, errOut.String())
	}
	if !strings.Contains(out.String(), "44KJHC") {
		t.Errorf("stdout missing the code: %q", out.String())
	}
	if !strings.Contains(out.String(), "剩余 12 分") {
		t.Errorf("stdout missing remaining time: %q", out.String())
	}
}

func TestRunPairCodeReadsTokenFromEnv(t *testing.T) {
	// This is the container path: `capri-hub paircode` with no flags
	// inherits the hub's own FE_TOKEN from the process environment.
	stub := &pairCodeStub{token: "from-env", code: "ENVOK1"}
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()
	t.Setenv("FE_TOKEN", "from-env")

	var out, errOut bytes.Buffer
	if rc := runPairCode([]string{"-url", srv.URL}, &out, &errOut); rc != 0 {
		t.Fatalf("exit = %d, stderr = %s", rc, errOut.String())
	}
	if !strings.Contains(out.String(), "ENVOK1") {
		t.Errorf("stdout = %q", out.String())
	}
}

func TestRunPairCodeFallsBackToAccessToken(t *testing.T) {
	stub := &pairCodeStub{token: "legacy", code: "LEGCY1"}
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()
	t.Setenv("FE_TOKEN", "")
	t.Setenv("ACCESS_TOKEN", "legacy")

	var out, errOut bytes.Buffer
	if rc := runPairCode([]string{"-url", srv.URL}, &out, &errOut); rc != 0 {
		t.Fatalf("exit = %d, stderr = %s", rc, errOut.String())
	}
	if !strings.Contains(out.String(), "LEGCY1") {
		t.Errorf("stdout = %q", out.String())
	}
}

func TestRunPairCodeJSONIsMachineReadable(t *testing.T) {
	stub := &pairCodeStub{code: "44KJHC"}
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()

	var out, errOut bytes.Buffer
	if rc := runPairCode([]string{"-url", srv.URL, "-json"}, &out, &errOut); rc != 0 {
		t.Fatalf("exit = %d, stderr = %s", rc, errOut.String())
	}
	var got pairCodeResult
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("stdout is not valid JSON (%v): %q", err, out.String())
	}
	if got.Code != "44KJHC" {
		t.Errorf("code = %q", got.Code)
	}
}

func TestRunPairCodeUnauthorizedExplainsFEToken(t *testing.T) {
	stub := &pairCodeStub{token: "right", code: "44KJHC"}
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()

	var out, errOut bytes.Buffer
	rc := runPairCode([]string{"-url", srv.URL, "-token", "wrong"}, &out, &errOut)
	if rc != 1 {
		t.Fatalf("exit = %d, want 1", rc)
	}
	if !strings.Contains(errOut.String(), "FE_TOKEN") {
		t.Errorf("stderr should name FE_TOKEN: %q", errOut.String())
	}
	if out.Len() != 0 {
		t.Errorf("nothing should reach stdout on failure: %q", out.String())
	}
}

func TestRunPairCodeUnreachableHubFails(t *testing.T) {
	// Closed port: the operator's most likely mistake is a hub that is
	// not running, and it must not look like success.
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()

	var out, errOut bytes.Buffer
	if rc := runPairCode([]string{"-url", url, "-timeout", "2s"}, &out, &errOut); rc != 1 {
		t.Fatalf("exit = %d, want 1 (stderr: %s)", rc, errOut.String())
	}
	if errOut.Len() == 0 {
		t.Error("want an explanation on stderr")
	}
}

func TestRunPairCodeRejectsStrayArgs(t *testing.T) {
	var out, errOut bytes.Buffer
	if rc := runPairCode([]string{"rotate"}, &out, &errOut); rc != 2 {
		t.Fatalf("exit = %d, want 2 for usage error", rc)
	}
	// `paircode rotate` is a plausible typo for `paircode -rotate`; it
	// must not silently read the code instead of rotating it.
	if !strings.Contains(errOut.String(), "rotate") {
		t.Errorf("stderr should echo the stray arg: %q", errOut.String())
	}
}

func TestDefaultPairCodeURLHonoursPort(t *testing.T) {
	t.Setenv("PORT", "9999")
	if got, want := defaultPairCodeURL(), "http://127.0.0.1:9999"; got != want {
		t.Errorf("defaultPairCodeURL() = %q, want %q", got, want)
	}

	t.Setenv("PORT", "")
	if got, want := defaultPairCodeURL(), "http://127.0.0.1:8787"; got != want {
		t.Errorf("defaultPairCodeURL() = %q, want %q", got, want)
	}

	// Garbage must not produce an unparseable URL.
	t.Setenv("PORT", "not-a-port")
	if got, want := defaultPairCodeURL(), "http://127.0.0.1:8787"; got != want {
		t.Errorf("defaultPairCodeURL() = %q, want %q", got, want)
	}
}

func TestFormatRemaining(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want string
	}{
		{-time.Second, "已过期"},
		{0, "已过期"},
		{45 * time.Second, "剩余 45 秒"},
		{12*time.Minute + 8*time.Second, "剩余 12 分 08 秒"},
		{time.Minute, "剩余 1 分 00 秒"},
	}
	for _, tc := range cases {
		if got := formatRemaining(tc.in); got != tc.want {
			t.Errorf("formatRemaining(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
