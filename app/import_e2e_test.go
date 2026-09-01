package app

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pocworkbench/internal/engine"
	"pocworkbench/internal/store"
)

// 端到端：粘贴模板 → 转换 → 保存 → 实测。
// 用户真正走的是这条链路，单测各段都过但链路断掉的情况已经发生过
// （root 路径模板转换成功却在保存时报「缺少 path」）。
func newApp(t *testing.T) *App {
	t.Helper()
	a := NewApp()
	s, err := store.Open(filepath.Join(t.TempDir(), "e2e.db"))
	if err != nil {
		t.Fatal(err)
	}
	a.store = s
	a.engine = engine.New(engine.Options{RunTimeout: 10 * time.Second, MaxConc: 1})
	t.Cleanup(func() { s.Close() })
	return a
}

func importAndRun(t *testing.T, a *App, tmpl, target string) string {
	t.Helper()
	d, err := a.ConvertTemplate(tmpl)
	if err != nil {
		t.Fatalf("转换失败: %v", err)
	}
	uid, err := a.CreatePoc(d)
	if err != nil {
		t.Fatalf("保存失败: %v\nspec:\n%s", err, d.SpecYAML)
	}
	p, err := a.store.GetPoc(uid)
	if err != nil {
		t.Fatal(err)
	}
	return a.engine.Run(context.Background(), &p.Spec, target).Result
}

// 裸 {{BaseURL}} 根路径模板：转换、保存、实测三段都要通。
func TestImportRootPathTemplateEndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			w.WriteHeader(404)
			return
		}
		w.WriteHeader(200)
		fmt.Fprint(w, "Welcome to the admin console")
	}))
	defer srv.Close()

	tmpl := `id: root-probe
info:
  name: 根路径探测
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["admin console"]
`
	if got := importAndRun(t, newApp(t), tmpl, srv.URL); got != "hit" {
		t.Errorf("根路径模板应命中, got %s", got)
	}
}

// and 语义模板不得对「仅状态码相符」的目标误报。
func TestImportAndSemanticsNoFalsePositive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "ordinary page, no marker here")
	}))
	defer srv.Close()

	tmpl := `id: and-probe
info:
  name: and 语义
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/x"
    matchers-condition: and
    matchers:
      - type: status
        status: [200, 302]
      - type: word
        words: ["VULN_MARKER"]
`
	if got := importAndRun(t, newApp(t), tmpl, srv.URL); got != "miss" {
		t.Errorf("状态码相符但无关键字应 miss（and 语义），got %s", got)
	}
}

// xray 模板里的 contains/matches（字符串面）经改写后必须真能跑。
func TestImportXrayStringFuncsEndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		fmt.Fprint(w, `{"user":"admin"}`)
	}))
	defer srv.Close()

	tmpl := `name: xray-string-funcs
transport: http
rules:
  r0:
    request:
      method: GET
      path: /api/me
    expression: response.status == 200 && response.content_type.contains('application/json') && response.body.contains('admin')
expression: r0()
detail:
  fingerprint:
    company: TestCo
    product: TestApp
`
	if got := importAndRun(t, newApp(t), tmpl, srv.URL); got != "hit" {
		t.Errorf("xray 字符串函数模板应命中, got %s", got)
	}
}

// negative matcher 端到端：命中反向关键字的目标不得报命中。
func TestImportNegativeMatcherEndToEnd(t *testing.T) {
	tmpl := `id: neg-probe
info:
  name: negative 语义
http:
  - method: GET
    path:
      - "{{BaseURL}}/api"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        negative: true
        words: ["Access Denied"]
`
	denied := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "Access Denied")
	}))
	defer denied.Close()
	open := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "here is the data")
	}))
	defer open.Close()

	if got := importAndRun(t, newApp(t), tmpl, denied.URL); got != "miss" {
		t.Errorf("含 negative 关键字应 miss, got %s", got)
	}
	if got := importAndRun(t, newApp(t), tmpl, open.URL); got != "hit" {
		t.Errorf("不含 negative 关键字应 hit, got %s", got)
	}
}

// 非法正则的模板在保存阶段就该被挡下，而不是入库后永久静默不命中。
func TestImportInvalidRegexRejectedOnSave(t *testing.T) {
	a := newApp(t)
	tmpl := `name: bad-regex
transport: http
rules:
  r0:
    request:
      method: GET
      path: /x
    expression: response.body.bmatches('([unclosed')
expression: r0()
`
	d, err := a.ConvertTemplate(tmpl)
	if err != nil {
		t.Fatalf("转换阶段不应失败: %v", err)
	}
	if _, err := a.CreatePoc(d); err == nil {
		t.Error("含非法正则的模板应在保存时被拒绝")
	} else if !strings.Contains(err.Error(), "正则") {
		t.Errorf("错误应点明正则问题: %v", err)
	}
}
