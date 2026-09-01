package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"pocworkbench/internal/pwf"
)

// 复跑最初那张「校验 vs 运行」对照表：不允许再出现
// 「校验放行但运行报错」或「静默误判」两类结果。
func TestVerifyNoCompileRuntimeMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte("welcome home"))
	}))
	defer srv.Close()

	// 全部构造为「应命中」
	cases := []string{
		"response.status == 200",
		"response.body.bcontains(b'welcome')",
		"response.body.bmatches('wel.*me')",
		"response.content_type.contains('application/json')",
		"response.headers['server'].contains('nginx')",
		"response.body.contains('welcome')",
		"response.content_type contains 'json'",
		"response.content_type.startswith('application')",
		"response.content_type.endswith('json')",
		"response.content_type.tolower() == 'application/json'",
		"response.body.bstartswith(b'welcome')",
		"response.body.bendswith(b'home')",
		"response.content_type.toupper() == 'APPLICATION/JSON'",
		"response.body.matches('^welcome')",
		"response.headers['server'].matches('ngin.')",
	}

	e := New(Options{})
	for _, c := range cases {
		compileErr := pwf.CheckRuleExpr(c)
		res := e.Run(context.Background(), httpSpec("/", c), srv.URL)
		switch {
		case compileErr != nil:
			t.Errorf("校验失败: %-52s → %s", c, firstLine(compileErr.Error()))
		case res.Result == "error":
			t.Errorf("校验放行但运行报错: %-52s → %s", c, firstLine(strings.TrimSpace(res.Log)))
		case res.Result != "hit":
			t.Errorf("应命中却得到 %s: %s", res.Result, c)
		}
	}
}
