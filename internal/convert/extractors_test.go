package convert

import (
	"strings"
	"testing"

	"pocworkbench/internal/pwf"
)

// ---- v1.2 E3：xray search / Nuclei extractors → PWF extract 映射 ----

func TestXraySearchToExtract(t *testing.T) {
	src := `id: test-search
name: 搜索提取串联
transport: http
rules:
  step1:
    request:
      method: GET
      path: /list
    search: '"id":"([0-9]+)"'
    expression: response.status == 200
  step2:
    request:
      method: GET
      path: /detail?id={{search}}
    expression: response.status == 200
expression: step1() && step2()
`
	d, err := XrayToDraft(src)
	if err != nil {
		t.Fatalf("转换失败: %v", err)
	}
	// search 不再进丢弃警告
	for _, w := range d.Warnings {
		if strings.Contains(w, "search") && strings.Contains(w, "丢弃") {
			t.Fatalf("search 不应再被丢弃: %s", w)
		}
	}
	if _, err := pwf.ValidateSpec(d.SpecYAML); err != nil {
		t.Fatalf("串联产物应通过三关校验: %v\nspec:\n%s", err, d.SpecYAML)
	}
	if !strings.Contains(d.SpecYAML, "extract:") || !strings.Contains(d.SpecYAML, "search") {
		t.Fatalf("产物应含 extract 声明:\n%s", d.SpecYAML)
	}
}

// xray search 多捕获组 → 降级警告（不静默错配），无捕获组 → 提示改写。
func TestXraySearchDegradations(t *testing.T) {
	multi := `id: t
name: 多捕获组
transport: http
rules:
  r:
    request: {method: GET, path: /a}
    search: "(a)(b)"
    expression: response.status == 200
expression: r()
`
	d, err := XrayToDraft(multi)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, w := range d.Warnings {
		if strings.Contains(w, "捕获组") {
			found = true
		}
	}
	if !found {
		t.Fatalf("多捕获组应产生降级警告: %v", d.Warnings)
	}

	nogroup := `id: t2
name: 无捕获组
transport: http
rules:
  r:
    request: {method: GET, path: /a}
    search: "plain"
    expression: response.status == 200
expression: r()
`
	d2, err := XrayToDraft(nogroup)
	if err != nil {
		t.Fatal(err)
	}
	found = false
	for _, w := range d2.Warnings {
		if strings.Contains(w, "无捕获组") {
			found = true
		}
	}
	if !found {
		t.Fatalf("无捕获组应有提示: %v", d2.Warnings)
	}
}

// nuclei 请求级 regex extractor（name + 1 组）→ extract 变量；
// 引用该变量的第二个请求被放行（此前 path 残留 {{var}} 直接整体报错）。
func TestNucleiExtractorsToExtract(t *testing.T) {
	src := `id: nuclei-chained
info:
  name: 提取器串联
  severity: high
http:
  - raw:
      - "GET /api/list HTTP/1.1\r\nHost: {{BaseURL}}\r\n\r\n"
    extractors:
      - type: regex
        name: rid
        regex:
          - '"id":"([0-9]+)"'
    matchers:
      - type: status
        status: [200]
  - raw:
      - "POST /api/exec?rid={{rid}} HTTP/1.1\r\nHost: {{BaseURL}}\r\n\r\n"
    matchers:
      - type: word
        words: ["ok"]
`
	d, err := NucleiToDraft(src)
	if err != nil {
		t.Fatalf("转换失败: %v", err)
	}
	if !strings.Contains(d.SpecYAML, "rid") {
		t.Fatalf("产物应含 rid 变量:\n%s", d.SpecYAML)
	}
	if _, err := pwf.ValidateSpec(d.SpecYAML); err != nil {
		t.Fatalf("串联产物应通过三关校验: %v\nspec:\n%s", err, d.SpecYAML)
	}
}

// nuclei 非 regex 提取器与 group>1：降级警告，绝不静默错配；
// 未声明变量的 path 残留仍整体报错（payload/变量类特性）。
func TestNucleiExtractorDegradations(t *testing.T) {
	kval := `id: t
info:
  name: kval
  severity: info
http:
  - path: ["{{BaseURL}}/a"]
    extractors:
      - type: kval
        kval: ["server"]
    matchers:
      - type: status
        status: [200]
`
	d, err := NucleiToDraft(kval)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, w := range d.Warnings {
		if strings.Contains(w, "kval") && strings.Contains(w, "跳过") {
			found = true
		}
	}
	if !found {
		t.Fatalf("kval 提取器应有降级警告: %v", d.Warnings)
	}

	undeclared := `id: t2
info:
  name: 未声明变量
  severity: info
http:
  - path: ["{{BaseURL}}/exec?id={{ghost}}"]
    matchers:
      - type: status
        status: [200]
`
	if _, err := NucleiToDraft(undeclared); err == nil {
		t.Fatal("未声明的 {{ghost}} path 残留应整体报错")
	}
}
