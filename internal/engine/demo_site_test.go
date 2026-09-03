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

// demoSite 起"故意带洞"的演示站，覆盖引擎全部验证类型，每洞配反例：
//
//	/sqli-time  SQL 时间盲注（注入 sleep 才延迟；正常请求内容相同、无延迟）
//	/api/list + /api/exec  串联提取（GET 提取 reportId → POST 用它命中）
//	/leak      敏感信息泄露（内容匹配）
//	/users     手机号形态（正则匹配）
func demoSite(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/sqli-time", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(strings.ToLower(r.URL.RawQuery), "sleep") {
			time.Sleep(1200 * time.Millisecond)
		}
		fmt.Fprint(w, "query ok") // 正常/延迟响应内容一致：只有时间差可判
	})

	mux.HandleFunc("/api/list", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"code":0,"data":{"reportId":"R9X7"},"msg":"ok"}`)
	})
	mux.HandleFunc("/api/exec", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("rid") == "R9X7" {
			fmt.Fprint(w, "render: uid=0(root) mode=privileged")
			return
		}
		fmt.Fprintf(w, "report %s not found", r.URL.Query().Get("rid"))
	})

	mux.HandleFunc("/leak", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"admin_password":"P@ssw0rd2026","hint":"internal use only"}`)
	})

	mux.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"contacts":[{"phone":"13812345678"},{"phone":"13987654321"}]}`)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "welcome to demo corp portal")
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, srv.URL
}

func httpRule(method, path, expr string) model.Rule {
	return model.Rule{Request: model.Request{Method: method, Path: path}, Expression: expr}
}

// 演示 1：时间盲注——基线对照 + 延迟阈值，双规则。
func TestDemoTimeBlind(t *testing.T) {
	_, target := demoSite(t)
	e := New(Options{RunTimeout: 10 * time.Second})

	spec := &model.Spec{
		Transport: "http",
		Rules: map[string]model.Rule{
			"base":  httpRule("GET", "/sqli-time?id=1", `response.status == 200 && response.elapsed_ms < 800`),
			"delay": httpRule("GET", "/sqli-time?id=1%20AND%20SLEEP(1)", `response.status == 200 && response.elapsed_ms >= 1000`),
		},
		Expression: "base() && delay()",
	}
	if res := e.Run(context.Background(), spec, target); res.Result != "hit" {
		t.Fatalf("时间盲注应命中 got=%s log=%s", res.Result, res.Log)
	}

	// 反例：无洞页面同模板必 miss（正常页不延迟）
	spec2 := &model.Spec{
		Transport: "http",
		Rules: map[string]model.Rule{
			"base":  httpRule("GET", "/?t=1", `response.status == 200 && response.elapsed_ms < 800`),
			"delay": httpRule("GET", "/?t=1%20AND%20SLEEP(1)", `response.status == 200 && response.elapsed_ms >= 1000`),
		},
		Expression: "base() && delay()",
	}
	if res := e.Run(context.Background(), spec2, target); res.Result != "miss" {
		t.Fatalf("无洞页面不应命中 got=%s log=%s", res.Result, res.Log)
	}
}

// 演示 2：串联提取——GET 提取 reportId → POST 注入 {{rid}}。
func TestDemoChained(t *testing.T) {
	_, target := demoSite(t)
	e := New(Options{RunTimeout: 10 * time.Second})

	spec := &model.Spec{
		Transport: "http",
		Rules: map[string]model.Rule{
			"getid": {
				Request:    model.Request{Method: "GET", Path: "/api/list"},
				Extract:    map[string]string{"rid": `"reportId":"([A-Z0-9]+)"`},
				Expression: "response.status == 200",
			},
			"exec": {
				Request:    model.Request{Method: "POST", Path: "/api/exec?rid={{rid}}"},
				Expression: `response.body.bcontains(b'uid=0')`,
			},
		},
		Expression: "getid() && exec()",
	}
	if res := e.Run(context.Background(), spec, target); res.Result != "hit" {
		t.Fatalf("串联提取应命中 got=%s log=%s", res.Result, res.Log)
	}

	// 反例：rid 写死错误值必 miss——证明命中确实来自提取替换
	spec2 := &model.Spec{
		Transport: "http",
		Rules: map[string]model.Rule{
			"exec": httpRule("POST", "/api/exec?rid=WRONG", `response.body.bcontains(b'uid=0')`),
		},
		Expression: "exec()",
	}
	if res := e.Run(context.Background(), spec2, target); res.Result != "miss" {
		t.Fatalf("错误 rid 不应命中 got=%s log=%s", res.Result, res.Log)
	}
}

// 演示 3：内容匹配——敏感信息泄露。
func TestDemoWordMatch(t *testing.T) {
	_, target := demoSite(t)
	e := New(Options{RunTimeout: 10 * time.Second})

	spec := &model.Spec{
		Transport: "http",
		Rules: map[string]model.Rule{
			"r0": httpRule("GET", "/leak", `response.status == 200 && response.body.bcontains(b'admin_password')`),
		},
		Expression: "r0()",
	}
	if res := e.Run(context.Background(), spec, target); res.Result != "hit" {
		t.Fatalf("泄露页应命中 got=%s", res.Result)
	}

	// 反例：正常页无此关键字
	spec2 := &model.Spec{
		Transport: "http",
		Rules: map[string]model.Rule{
			"r0": httpRule("GET", "/", `response.status == 200 && response.body.bcontains(b'admin_password')`),
		},
		Expression: "r0()",
	}
	if res := e.Run(context.Background(), spec2, target); res.Result != "miss" {
		t.Fatalf("正常页不应命中 got=%s", res.Result)
	}
}

// 演示 4：正则匹配——手机号形态。
func TestDemoRegexMatch(t *testing.T) {
	_, target := demoSite(t)
	e := New(Options{RunTimeout: 10 * time.Second})

	spec := &model.Spec{
		Transport: "http",
		Rules: map[string]model.Rule{
			"r0": httpRule("GET", "/users", `response.body.bmatches('1[3-9][0-9]{9}')`),
		},
		Expression: "r0()",
	}
	if res := e.Run(context.Background(), spec, target); res.Result != "hit" {
		t.Fatalf("手机号页应命中 got=%s log=%s", res.Result, res.Log)
	}

	spec2 := &model.Spec{
		Transport: "http",
		Rules: map[string]model.Rule{
			"r0": httpRule("GET", "/leak", `response.body.bmatches('1[3-9][0-9]{9}')`),
		},
		Expression: "r0()",
	}
	if res := e.Run(context.Background(), spec2, target); res.Result != "miss" {
		t.Fatalf("无手机号页不应命中 got=%s", res.Result)
	}
}
