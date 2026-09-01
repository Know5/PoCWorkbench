package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"pocworkbench/internal/model"
)

// 逐规则日志必须实时推给 sink，而不是只在收尾推一行 [final]。
// 否则前端日志面板在整轮运行期间空白，长跑（默认硬超时 60s）看不到任何进展。
func TestSinkStreamsPerRuleLogs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "hello")
	}))
	defer srv.Close()

	spec := &model.Spec{
		Transport: "http",
		Rules: map[string]model.Rule{
			"r0": {Request: model.Request{Method: "GET", Path: "/a"}, Expression: `response.status == 200`},
			"r1": {Request: model.Request{Method: "GET", Path: "/b"}, Expression: `response.body.bcontains(b'hello')`},
		},
		Expression: "r0() && r1()",
	}

	var mu sync.Mutex
	var got []string
	e := New(Options{})
	res := e.RunSink(context.Background(), spec, srv.URL, "", func(line string) {
		mu.Lock()
		got = append(got, line)
		mu.Unlock()
	})
	if res.Result != "hit" {
		t.Fatalf("应命中: %s\n%s", res.Result, res.Log)
	}

	streamed := strings.Join(got, "\n")
	for _, needle := range []string{"[r0]", "[r1]", "[final]"} {
		if !strings.Contains(streamed, needle) {
			t.Errorf("sink 应收到 %s，实际收到 %d 行:\n%s", needle, len(got), streamed)
		}
	}
	// sink 内容应与落库日志一致（都是逐行同源）
	for _, line := range got {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !strings.Contains(res.Log, strings.TrimSpace(line)) {
			t.Errorf("sink 行未出现在落库日志中: %q", line)
		}
	}
	// sink 的契约是单行
	for _, line := range got {
		if strings.Contains(line, "\n") {
			t.Errorf("sink 收到多行内容: %q", line)
		}
	}
}

// 规则日志应在该规则完成时即刻推送，而非全部跑完再一起推。
func TestSinkStreamsIncrementally(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			<-release // 卡住第二条规则，直到测试确认第一条日志已到
		}
		w.WriteHeader(200)
		fmt.Fprint(w, "hello")
	}))
	defer srv.Close()

	spec := &model.Spec{
		Transport: "http",
		Rules: map[string]model.Rule{
			"r0": {Request: model.Request{Method: "GET", Path: "/fast"}, Expression: `response.status == 200`},
			"r1": {Request: model.Request{Method: "GET", Path: "/slow"}, Expression: `response.status == 200`},
		},
		Expression: "r0() && r1()",
	}

	firstSeen := make(chan string, 8)
	done := make(chan RunResult, 1)
	e := New(Options{RunTimeout: 10 * time.Second})
	go func() {
		done <- e.RunSink(context.Background(), spec, srv.URL, "", func(line string) {
			select {
			case firstSeen <- line:
			default:
			}
		})
	}()

	// r1 仍被卡住时，r0 的日志就应该已经到了
	deadline := time.After(3 * time.Second)
	sawR0 := false
	for !sawR0 {
		select {
		case line := <-firstSeen:
			if strings.Contains(line, "[r0]") {
				sawR0 = true
			}
		case <-deadline:
			close(release)
			<-done
			t.Fatal("r1 阻塞期间未收到 r0 的日志——日志仍是收尾时一次性推送")
		}
	}
	close(release)
	if res := <-done; res.Result != "hit" {
		t.Errorf("应命中: %s", res.Result)
	}
}
