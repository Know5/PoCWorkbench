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
	// v1.2.2 起 kval 映射为等价正则：应产出变量，不再是降级警告
	if !strings.Contains(d.SpecYAML, "server") {
		t.Fatalf("kval 应物化为 server 变量:\n%s", d.SpecYAML)
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

// xray set 两种形态（简写字符串 / regex+group 对象）都映射为 extract 变量，
// 后续规则 {{Var}} 引用被放行且过三关校验；group>1 / 多捕获组降级跳过。
func TestXraySetToExtract(t *testing.T) {
	shorthand := `id: set-shorthand
name: set简写形态
transport: http
rules:
  s1:
    request: {method: GET, path: /token}
    set:
      tk: '"token":"([0-9a-f]+)"'
    expression: response.status == 200
  s2:
    request: {method: POST, path: /exec, body: "tk={{tk}}"}
    expression: response.status == 200
expression: s1() && s2()
`
	d, err := XrayToDraft(shorthand)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pwf.ValidateSpec(d.SpecYAML); err != nil {
		t.Fatalf("简写 set 产物应过三关: %v\n%s", err, d.SpecYAML)
	}
	if !strings.Contains(d.SpecYAML, "tk:") {
		t.Fatalf("产物应含 tk 变量:\n%s", d.SpecYAML)
	}

	objForm := `id: set-obj
name: set对象形态
transport: http
rules:
  o1:
    request: {method: GET, path: /t}
    set:
      sid: {regex: "sid=([a-z]+)", group: 1}
    expression: response.status == 200
  o2:
    request: {method: GET, path: "/use?sid={{sid}}"}
    expression: response.status == 200
expression: o1() && o2()
`
	d2, err := XrayToDraft(objForm)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pwf.ValidateSpec(d2.SpecYAML); err != nil {
		t.Fatalf("对象 set 产物应过三关: %v\n%s", err, d2.SpecYAML)
	}

	badGroup := `id: set-bad
name: set非法组
transport: http
rules:
  b1:
    request: {method: GET, path: /t}
    set:
      v: {regex: "(a)(b)", group: 2}
    expression: response.status == 200
expression: b1()
`
	d3, err := XrayToDraft(badGroup)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, w := range d3.Warnings {
		if strings.Contains(w, "跳过") {
			found = true
		}
	}
	if !found {
		t.Fatalf("非法 set 应降级警告: %v", d3.Warnings)
	}
}

// 回归：PWF 原生 extract 字段必须透传（曾因只映射 search/set 而丢失，
// 导致"导出件再导入"的串联模板在保存时报未声明变量）。
func TestXrayNativeExtractPassthrough(t *testing.T) {
	src := `id: pwf-native
name: 原生extract透传
transport: http
rules:
  getid:
    request: {method: GET, path: /list}
    extract:
      rid: '"id":"([0-9]+)"'
    expression: response.status == 200
  use:
    request: {method: POST, path: "/exec?rid={{rid}}"}
    expression: response.status == 200
expression: getid() && use()
`
	d, err := XrayToDraft(src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pwf.ValidateSpec(d.SpecYAML); err != nil {
		t.Fatalf("原生 extract 透传后应过三关: %v\n%s", err, d.SpecYAML)
	}
	if !strings.Contains(d.SpecYAML, "rid:") {
		t.Fatalf("产物应含 rid 声明:\n%s", d.SpecYAML)
	}
}

// kval 提取器 → 静态物化为 k=([^\s&"']+) 等价正则，串联引用过三关。
func TestNucleiKvalExtractor(t *testing.T) {
	src := `id: kval-chained
info:
  name: kval提取串联
  severity: high
http:
  - path: ["{{BaseURL}}/session"]
    extractors:
      - type: kval
        name: sid
        kval:
          - JSESSIONID
    matchers:
      - type: status
        status: [200]
  - path: ["{{BaseURL}}/admin?sid={{sid}}"]
    matchers:
      - type: word
        words: ["admin"]
`
	d, err := NucleiToDraft(src)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d.SpecYAML, "sid:") {
		t.Fatalf("产物应含 sid 变量:\n%s", d.SpecYAML)
	}
	if _, err := pwf.ValidateSpec(d.SpecYAML); err != nil {
		t.Fatalf("kval 物化应过三关: %v\n%s", err, d.SpecYAML)
	}
}

// json 纯键路径 → 键序列正则；含数组下标的复杂路径降级警告。
func TestNucleiJsonExtractor(t *testing.T) {
	simple := `id: json-chained
info:
  name: json提取串联
  severity: high
http:
  - path: ["{{BaseURL}}/api/token"]
    extractors:
      - type: json
        name: tok
        json:
          - .data.token
    matchers:
      - type: status
        status: [200]
  - path: ["{{BaseURL}}/use?tok={{tok}}"]
    matchers:
      - type: status
        status: [200]
`
	d, err := NucleiToDraft(simple)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pwf.ValidateSpec(d.SpecYAML); err != nil {
		t.Fatalf("json 物化应过三关: %v\n%s", err, d.SpecYAML)
	}

	complexPath := `id: json-complex
info:
  name: 复杂路径
  severity: info
http:
  - path: ["{{BaseURL}}/x"]
    extractors:
      - type: json
        name: v
        json:
          - .items[0].id
    matchers:
      - type: status
        status: [200]
`
	d2, err := NucleiToDraft(complexPath)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, w := range d2.Warnings {
		if strings.Contains(w, "数组下标") {
			found = true
		}
	}
	if !found {
		t.Fatalf("复杂路径应降级警告: %v", d2.Warnings)
	}
}

// xpath 提取器：整体报错拒绝（静默丢变量会打断串联链）。
func TestNucleiXpathRejected(t *testing.T) {
	src := `id: x
info:
  name: xpath
  severity: info
http:
  - path: ["{{BaseURL}}/"]
    extractors:
      - type: xpath
        xpath: /html/head/title
    matchers:
      - type: status
        status: [200]
`
	if _, err := NucleiToDraft(src); err == nil {
		t.Fatal("xpath 提取器应整体报错")
	}
}
