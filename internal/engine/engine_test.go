package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"pocworkbench/internal/model"
)

func httpSpec(path, exprStr string) *model.Spec {
	return &model.Spec{
		Transport: "http",
		Rules: map[string]model.Rule{
			"r0": {
				Request:    model.Request{Method: "GET", Path: path},
				Expression: exprStr,
			},
		},
		Expression: "r0()",
	}
}

func TestRunHTTPHit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/vuln" {
			w.WriteHeader(200)
			fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash wiki content")
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	e := New(Options{})
	res := e.Run(context.Background(), httpSpec("/vuln", `response.status == 200 && response.body.bcontains(b'root:')`), srv.URL)
	if res.Result != "hit" {
		t.Fatalf("应命中 got=%s log=%s", res.Result, res.Log)
	}

	res = e.Run(context.Background(), httpSpec("/nope", `response.status == 200 && response.body.bcontains(b'root:')`), srv.URL)
	if res.Result != "miss" {
		t.Fatalf("应未命中 got=%s", res.Result)
	}
}

// 回归：时间盲注需要 response.elapsed_ms。慢端点应命中阈值表达式，快端点同表达式应未命中。
func TestRunTimeBlindElapsedMs(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(150 * time.Millisecond)
		w.WriteHeader(200)
	}))
	defer slow.Close()

	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer fast.Close()

	e := New(Options{})
	exprStr := `response.status == 200 && response.elapsed_ms >= 100`
	if res := e.Run(context.Background(), httpSpec("/", exprStr), slow.URL); res.Result != "hit" {
		t.Fatalf("延迟端点应命中 got=%s log=%s", res.Result, res.Log)
	}
	if res := e.Run(context.Background(), httpSpec("/", exprStr), fast.URL); res.Result != "miss" {
		t.Fatalf("快速端点不应命中 got=%s log=%s", res.Result, res.Log)
	}
}

func TestRunHTTPRegexAndShortCircuit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "hello")
	}))
	defer srv.Close()

	// 短路：r0 为 false 时，AND 下 r1 不应被请求
	spec := &model.Spec{
		Transport: "http",
		Rules: map[string]model.Rule{
			"r0": {Request: model.Request{Method: "GET", Path: "/a"}, Expression: `response.body.bmatches('^world$')`},
			"r1": {Request: model.Request{Method: "GET", Path: "/b"}, Expression: `response.status == 200`},
		},
		Expression: "r0() && r1()",
	}
	e := New(Options{})
	res := e.Run(context.Background(), spec, srv.URL)
	if res.Result != "miss" {
		t.Fatalf("应未命中 got=%s log=%s", res.Result, res.Log)
	}
	if strings.Contains(res.Log, "[r1]") {
		t.Fatal("短路失败：r0=false 时不应请求 r1")
	}
}

func TestRunTCP(t *testing.T) {
	// 迷你 rsync 协议模拟
	ln := listenTCP(t, func(in string) string {
		if strings.Contains(in, "@RSYNCD: 31.0") {
			return "@RSYNCD: EXIT"
		}
		return ""
	})
	defer ln.Close()

	spec := &model.Spec{
		Transport: "tcp",
		Rules: map[string]model.Rule{
			"req": {
				Request: model.Request{
					Inputs:      []model.TCPInput{{Data: "@RSYNCD: 31.0\n\n"}},
					ReadTimeout: 2,
				},
				Expression: `response.raw.bcontains(b'@RSYNCD: ') && response.raw.bcontains(b'@RSYNCD: EXIT')`,
			},
		},
		Expression: "req()",
	}
	e := New(Options{})
	res := e.Run(context.Background(), spec, "127.0.0.1:"+portOf(ln.Addr().String()))
	if res.Result != "hit" {
		t.Fatalf("tcp 应命中 got=%s log=%s", res.Result, res.Log)
	}
}

func TestRunTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Second)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	e := New(Options{RunTimeout: 500 * time.Millisecond})
	res := e.Run(context.Background(), httpSpec("/slow", `response.status == 200`), srv.URL)
	if res.Result != "timeout" {
		t.Fatalf("应超时 got=%s log=%s", res.Result, res.Log)
	}
}

func TestRunRejectsBadTarget(t *testing.T) {
	e := New(Options{})
	res := e.Run(context.Background(), httpSpec("/", `response.status == 200`), "ftp://x")
	if res.Result != "error" {
		t.Fatal("非法 scheme 应报错")
	}
	res = e.Run(context.Background(), httpSpec("/", `response.status == 200`), "-flag-inject")
	if res.Result != "error" {
		t.Fatal("无 scheme 目标应报错（防 flag 注入）")
	}
}
