package convert

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"pocworkbench/internal/engine"
	"pocworkbench/internal/model"
	"pocworkbench/internal/pwf"
)

// specOf 转换并解析出 spec（同时确认过三关校验）。
func specOf(t *testing.T, src string) (*model.Spec, *model.Draft) {
	t.Helper()
	d, err := NucleiToDraft(src)
	if err != nil {
		t.Fatalf("转换失败: %v", err)
	}
	canonical, err := pwf.ValidateSpec(d.SpecYAML)
	if err != nil {
		t.Fatalf("产物未通过三关校验: %v\nspec:\n%s", err, d.SpecYAML)
	}
	var spec model.Spec
	if err := yaml.Unmarshal([]byte(canonical), &spec); err != nil {
		t.Fatal(err)
	}
	return &spec, d
}

// 修复 1：matchers-condition: and 下，多值 status 的 or 组必须加括号，
// 否则 `a || b && c` 按 `a || (b && c)` 求值 —— 只要状态码命中就假命中。
// 这里用真实 HTTP 服务端到端验证：返回 200 但 body 无关键字，必须 miss。
func TestNucleiAndPrecedenceNoFalsePositive(t *testing.T) {
	src := `id: prec
info:
  name: precedence
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
        part: body
        words: ["SECRET_TOKEN"]
`
	spec, _ := specOf(t, src)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "nothing interesting here")
	}))
	defer srv.Close()

	e := engine.New(engine.Options{})
	res := e.Run(context.Background(), spec, srv.URL)
	if res.Result != "miss" {
		t.Errorf("200 但无关键字必须 miss（and 语义），got=%s\n表达式: %s\n日志:\n%s",
			res.Result, spec.Rules["r0"].Expression, res.Log)
	}

	// 反向：同时满足才命中
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "here is SECRET_TOKEN")
	}))
	defer srv2.Close()
	if res := e.Run(context.Background(), spec, srv2.URL); res.Result != "hit" {
		t.Errorf("状态码与关键字都命中时应 hit, got=%s log=%s", res.Result, res.Log)
	}
}

// 修复 1b：单个 matcher 内部 condition: and 与组间 or 混用时同样需要括号。
func TestNucleiInnerOuterPrecedence(t *testing.T) {
	src := `id: prec2
info:
  name: inner outer
http:
  - method: GET
    path:
      - "{{BaseURL}}/x"
    matchers-condition: or
    matchers:
      - type: word
        words: ["AAA", "BBB"]
        condition: and
      - type: status
        status: [500]
`
	spec, _ := specOf(t, src)

	// body 只含 AAA、状态 200：word 组为 false（要求 AAA&&BBB），status 组 false → 应 miss
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "only AAA present")
	}))
	defer srv.Close()

	e := engine.New(engine.Options{})
	if res := e.Run(context.Background(), spec, srv.URL); res.Result != "miss" {
		t.Errorf("word(and) 未全中且状态不符应 miss, got=%s\n表达式: %s", res.Result, spec.Rules["r0"].Expression)
	}
}

// 修复 2：negative: true 必须取反，且不得静默。
func TestNucleiNegativeMatcher(t *testing.T) {
	src := `id: neg
info:
  name: negative
http:
  - method: GET
    path:
      - "{{BaseURL}}/y"
    matchers-condition: and
    matchers:
      - type: word
        negative: true
        words: ["Not Found"]
      - type: status
        status: [200]
`
	spec, _ := specOf(t, src)
	expr := spec.Rules["r0"].Expression
	if !strings.Contains(expr, "!") {
		t.Errorf("negative 应产生取反表达式: %s", expr)
	}

	// 200 且 body 不含 "Not Found" → hit
	hitSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "welcome admin")
	}))
	defer hitSrv.Close()
	// 200 但 body 含 "Not Found" → miss（negative 生效）
	missSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "404 Not Found")
	}))
	defer missSrv.Close()

	e := engine.New(engine.Options{})
	if res := e.Run(context.Background(), spec, hitSrv.URL); res.Result != "hit" {
		t.Errorf("不含 negative 关键字应 hit, got=%s expr=%s", res.Result, expr)
	}
	if res := e.Run(context.Background(), spec, missSrv.URL); res.Result != "miss" {
		t.Errorf("含 negative 关键字应 miss, got=%s expr=%s", res.Result, expr)
	}
}

// 修复 4：裸 {{BaseURL}}（根路径）必须转成 "/" 并通过三关校验。
func TestNucleiRootPathSavable(t *testing.T) {
	for _, p := range []string{`"{{BaseURL}}"`, `"{{RootURL}}"`, `"{{Hostname}}"`} {
		src := fmt.Sprintf(`id: root
info:
  name: root path
http:
  - method: GET
    path:
      - %s
    matchers:
      - type: status
        status: [200]
`, p)
		spec, _ := specOf(t, src) // specOf 内含 ValidateSpec，失败即 Fatal
		if got := spec.Rules["r0"].Request.Path; got != "/" {
			t.Errorf("path=%s 应转为 \"/\", got %q", p, got)
		}
	}
}

// 修复 6：part=response/all/header 不得静默降级为 body。
func TestNucleiPartNotSilentlyDowngraded(t *testing.T) {
	for _, part := range []string{"response", "all", "raw"} {
		src := fmt.Sprintf(`id: part
info:
  name: part %s
http:
  - method: GET
    path:
      - "{{BaseURL}}/z"
    matchers:
      - type: word
        part: %s
        words: ["Server: Apache"]
      - type: status
        status: [200]
`, part, part)
		_, d := specOf(t, src)
		if warned := strings.Join(d.Warnings, "\n"); !strings.Contains(warned, "part") {
			t.Errorf("http part=%s 必须有降级警告，实际警告:\n%s", part, warned)
		}
	}

	// part=header 无法映射，应跳过该 matcher（此处 status 仍可用，故不整体失败）
	headerSrc := `id: parth
info:
  name: part header
http:
  - method: GET
    path:
      - "{{BaseURL}}/z"
    matchers:
      - type: word
        part: header
        words: ["Apache"]
      - type: status
        status: [200]
`
	spec, d := specOf(t, headerSrc)
	if strings.Contains(spec.Rules["r0"].Expression, "Apache") {
		t.Errorf("part=header 的 matcher 不应被映射进表达式: %s", spec.Rules["r0"].Expression)
	}
	if !strings.Contains(strings.Join(d.Warnings, "\n"), "已跳过") {
		t.Errorf("part=header 应有跳过警告: %v", d.Warnings)
	}

	// tcp 下 response.raw 是全量字节流，part=raw 不构成降级，不该报警告
	tcpSrc := `id: parttcp
info:
  name: tcp raw
tcp:
  - inputs:
      - data: "PING\r\n"
    read-timeout: 2
    matchers:
      - type: word
        part: raw
        words: ["+PONG"]
`
	_, dt := specOf(t, tcpSrc)
	if strings.Contains(strings.Join(dt.Warnings, "\n"), "降级") {
		t.Errorf("tcp part=raw 不应报降级警告: %v", dt.Warnings)
	}
}

// 修复 8：一个 http 块内多个 path 是彼此独立的请求，nuclei 语义为任一命中即命中；
// matchers-condition 只作用于单请求内部，不得外溢到规则间。
func TestNucleiMultiPathJoinsWithOr(t *testing.T) {
	src := `id: multi
info:
  name: multi path
http:
  - method: GET
    path:
      - "{{BaseURL}}/a"
      - "{{BaseURL}}/b"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["FLAG"]
`
	spec, d := specOf(t, src)
	if len(spec.Rules) != 2 {
		t.Fatalf("应生成两条规则, got %d", len(spec.Rules))
	}
	if spec.Expression != "r0() || r1()" {
		t.Errorf("多请求应以 || 合并（任一命中即命中）, got %q", spec.Expression)
	}
	// 每条规则内部仍须是 and
	for _, n := range []string{"r0", "r1"} {
		if !strings.Contains(spec.Rules[n].Expression, "&&") {
			t.Errorf("%s 内部应保留 matchers-condition: and: %s", n, spec.Rules[n].Expression)
		}
	}

	// 端到端：/a 返回 200 无 FLAG，/b 返回 200 带 FLAG → 整体应命中
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		if r.URL.Path == "/b" {
			fmt.Fprint(w, "FLAG here")
			return
		}
		fmt.Fprint(w, "boring")
	}))
	defer srv.Close()
	e := engine.New(engine.Options{})
	if res := e.Run(context.Background(), spec, srv.URL); res.Result != "hit" {
		t.Errorf("任一路径命中即应 hit, got=%s log=%s", res.Result, res.Log)
	}
	_ = d
}
