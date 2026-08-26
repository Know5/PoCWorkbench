package pwf

import "testing"

const validHTTPSpec = `transport: http
rules:
  r0:
    request:
      method: GET
      path: /bin/get/Main/SolrSearch?media=rss&text=xxx
    expression: response.status == 200 && response.body.bmatches('root:.*:0:0') && response.body.bcontains(b'wiki')
expression: r0()
`

const validTCPSpec = "transport: tcp\n" +
	"rules:\n" +
	"  req:\n" +
	"    request:\n" +
	"      inputs:\n" +
	"        - data: \"@RSYNCD: 31.0\\n\\n\"\n" +
	"      read_timeout: 3\n" +
	"    expression: \"response.raw.bcontains(b'@RSYNCD: ') && response.raw.bcontains(b'@RSYNCD: EXIT')\"\n" +
	"expression: req()\n"

func TestValidateSpec_HTTP(t *testing.T) {
	canonical, err := ValidateSpec(validHTTPSpec)
	if err != nil {
		t.Fatalf("合法 http spec 校验失败: %v", err)
	}
	if canonical == "" {
		t.Fatal("规范化输出为空")
	}
}

func TestValidateSpec_TCP(t *testing.T) {
	if _, err := ValidateSpec(validTCPSpec); err != nil {
		t.Fatalf("合法 tcp spec 校验失败: %v", err)
	}
}

func TestValidateSpec_RejectsUnknownField(t *testing.T) {
	bad := validHTTPSpec + "unknown_top: 1\n"
	if _, err := ValidateSpec(bad); err == nil {
		t.Fatal("未知字段应被拒绝（KnownFields）")
	}
}

func TestValidateSpec_RejectsUndeclaredRuleRef(t *testing.T) {
	bad := `transport: http
rules:
  r0:
    request:
      method: GET
      path: /a
    expression: response.status == 200
expression: r0() || r9()
`
	if _, err := ValidateSpec(bad); err == nil {
		t.Fatal("引用未声明 rule 应被拒绝")
	}
}

func TestValidateSpec_RejectsNonBoolFinal(t *testing.T) {
	bad := `transport: http
rules:
  r0:
    request:
      method: GET
      path: /a
    expression: response.status == 200
expression: r0() && 'x'
`
	if _, err := ValidateSpec(bad); err == nil {
		t.Fatal("总表达式含字面量应被拒绝")
	}
}

func TestValidateSpec_RejectsBadRuleName(t *testing.T) {
	bad := `transport: http
rules:
  "bad name!":
    request:
      method: GET
      path: /a
    expression: response.status == 200
expression: badname()
`
	if _, err := ValidateSpec(bad); err == nil {
		t.Fatal("非法 rule 名应被拒绝")
	}
}

func TestTransformExpression(t *testing.T) {
	got := TransformExpression(`response.body.bcontains(b'root') && response.status == 200`)
	// b'...' 是 expr-lang 原生字节字面量，必须原样保留（\xff 等高字节转义依赖其原始字节语义）
	want := `bcontains(response.body, b'root') && response.status == 200`
	if got != want {
		t.Fatalf("改写结果不符:\n got=%s\nwant=%s", got, want)
	}
}

func TestCanonicalHashStable(t *testing.T) {
	c1, _ := ValidateSpec(validHTTPSpec)
	c2, _ := ValidateSpec(validHTTPSpec)
	if CanonicalHash(c1) != CanonicalHash(c2) {
		t.Fatal("同内容哈希应一致")
	}
}
