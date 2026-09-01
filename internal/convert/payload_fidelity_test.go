package convert

import (
	"testing"

	"gopkg.in/yaml.v3"

	"pocworkbench/internal/model"
)

// 载荷字段（TCP inputs.data / HTTP body）的空白是协议字节，转换不得裁剪。
// 回归：xray 侧曾统一走 str()（含 TrimSpace），把 rsync 握手串末尾的两个换行吃掉，
// 对端因此不回话——转换出来的 PoC 静默打不响，实测只看到 miss，排查不到原因。
// nuclei 侧走另一条路径（直接取 data），作为对照一并锁定。
func TestPayloadWhitespacePreserved(t *testing.T) {
	xraySrc := `name: rsync-unauth
transport: tcp
rules:
  req:
    request:
      inputs:
        - data: "@RSYNCD: 31.0\n\n"
      read_timeout: 3
    expression: "response.raw.bcontains(b'@RSYNCD: ')"
expression: req()
`
	d, err := XrayToDraft(xraySrc)
	if err != nil {
		t.Fatal(err)
	}
	var spec model.Spec
	if err := yaml.Unmarshal([]byte(d.SpecYAML), &spec); err != nil {
		t.Fatal(err)
	}
	got := spec.Rules["req"].Request.Inputs[0].Data
	const want = "@RSYNCD: 31.0\n\n"
	if got != want {
		t.Errorf("xray TCP input 被裁剪:\n got %q\nwant %q", got, want)
	}

	// HTTP body 同源问题：str() 会 TrimSpace
	xrayHTTP := `name: body-trim
transport: http
rules:
  r0:
    request:
      method: POST
      path: /x
      body: "a=1&b=2\n"
    expression: "response.status == 200"
expression: r0()
`
	dh, err := XrayToDraft(xrayHTTP)
	if err != nil {
		t.Fatal(err)
	}
	var specH model.Spec
	_ = yaml.Unmarshal([]byte(dh.SpecYAML), &specH)
	if gotBody := specH.Rules["r0"].Request.Body; gotBody != "a=1&b=2\n" {
		t.Errorf("xray HTTP body 被裁剪:\n got %q\nwant %q", gotBody, "a=1&b=2\n")
	}

	// 对照：nuclei 的 tcp inputs 走的是另一条路径
	nucleiSrc := `id: redis
info:
  name: redis unauth
tcp:
  - inputs:
      - data: "PING\r\n"
    read-timeout: 2
    matchers:
      - type: word
        words: ["+PONG"]
`
	dn, err := NucleiToDraft(nucleiSrc)
	if err != nil {
		t.Fatal(err)
	}
	var specN model.Spec
	_ = yaml.Unmarshal([]byte(dn.SpecYAML), &specN)
	if gotN := specN.Rules["r0"].Request.Inputs[0].Data; gotN != "PING\r\n" {
		t.Errorf("nuclei TCP input 被裁剪:\n got %q\nwant %q", gotN, "PING\r\n")
	} else {
		t.Logf("nuclei 侧完好: %q", gotN)
	}
}
