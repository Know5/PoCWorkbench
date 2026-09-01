package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"pocworkbench/internal/pwf"
)

// 编译通过 ≠ 运行可用。每个声明可用的函数都必须在真实响应上跑出正确布尔值，
// 而不是「三关校验放行、UI 显示 ✓、实测报 invalid operation」。
func TestDeclaredFuncsWorkAtRuntime(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.24.0")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte("welcome home"))
	}))
	defer srv.Close()

	// want=true 的表达式必须 hit，want=false 的必须 miss；任何 error 都是失败
	cases := []struct {
		expr string
		want bool
	}{
		{`response.status == 200`, true},
		{`response.body.bcontains(b'welcome')`, true},
		{`response.body.bcontains(b'absent')`, false},
		{`response.body.bmatches('wel.*me')`, true},
		{`response.body.bstartswith(b'welcome')`, true},
		{`response.body.bendswith(b'home')`, true},
		// 字符串面：contains/matches 经别名落到 b* 实现
		{`response.content_type.contains('application/json')`, true},
		{`response.content_type.contains('text/html')`, false},
		{`response.content_type.matches('json|xml')`, true},
		{`response.body.contains('welcome')`, true},
		{`response.body.matches('^welcome')`, true},
		{`response.content_type.startswith('application')`, true},
		{`response.content_type.endswith('json')`, true},
		{`tolower(response.content_type) == 'application/json'`, true},
		{`toupper(response.content_type) == 'APPLICATION/JSON'`, true},
		// 下标接收者（header 匹配）
		{`response.headers['server'].contains('nginx')`, true},
		{`response.headers['server'].contains('apache')`, false},
		{`response.headers['server'].matches('nginx/1\\.\\d+')`, true},
		{`response.headers['server'] == 'nginx/1.24.0'`, true},
		// 组合
		{`response.status == 200 && response.body.contains('welcome')`, true},
		{`response.status == 404 || response.headers['server'].contains('nginx')`, true},
		{`response.elapsed_ms >= 0`, true},
	}

	e := New(Options{})
	for _, c := range cases {
		if err := pwf.CheckRuleExpr(c.expr); err != nil {
			t.Errorf("校验失败: %s\n   → %s", c.expr, firstLine(err.Error()))
			continue
		}
		res := e.Run(context.Background(), httpSpec("/", c.expr), srv.URL)
		want := "miss"
		if c.want {
			want = "hit"
		}
		if res.Result != want {
			t.Errorf("运行结果不符: %s\n   want=%s got=%s\n   日志: %s",
				c.expr, want, res.Result, strings.TrimSpace(res.Log))
		}
	}
}

// needle 里含 `.contains(` 之类的内容不得被改写破坏。
func TestNeedleWithFuncTextIntact(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("if (response.body.contains('x')) { alert(1) }"))
	}))
	defer srv.Close()

	e := New(Options{})
	ex := `response.body.bcontains(b'response.body.contains(')`
	if err := pwf.CheckRuleExpr(ex); err != nil {
		t.Fatalf("应可编译: %v", err)
	}
	if res := e.Run(context.Background(), httpSpec("/", ex), srv.URL); res.Result != "hit" {
		t.Errorf("字面量内容应原样匹配, got=%s log=%s", res.Result, res.Log)
	}
}

// 非字面量正则在运行期编译失败时必须报 error，不能静默 false。
func TestRuntimeRegexErrorNotSilent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("([unclosed"))
	}))
	defer srv.Close()

	// 拼接表达式：AST 上是 BinaryNode 而非 StringNode，静态检查覆盖不到，
	// 运行期才拼出非法正则 "([unclosed" —— 正是 reMatch 必须兜住的路径
	e := New(Options{})
	res := e.Run(context.Background(), httpSpec("/", `response.body.bmatches('([' + 'unclosed')`), srv.URL)
	if res.Result != "error" {
		t.Errorf("运行期非法正则应报 error 而非静默 miss, got=%s log=%s", res.Result, res.Log)
	}
	if !strings.Contains(res.Log, "正则") {
		t.Errorf("错误信息应点明正则: %s", res.Log)
	}
}

func firstLine(s string) string {
	if i := strings.Index(s, "\n"); i >= 0 {
		return s[:i]
	}
	return s
}
