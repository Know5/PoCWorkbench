package pwf

import (
	"strings"
	"testing"
)

// FuncNames 里声明可用的每个函数，都必须能在 response 字段上以方法形态编译。
// contains / matches 是 expr-lang 的保留中缀运算符，不能出现在函数调用位置——
// 改写必须把它们映射到等价的 b* 实现，而不是产出 `contains(x, y)` 这种解析不了的形态。
func TestAllDeclaredFuncsCompile(t *testing.T) {
	cases := []string{
		// 字节面（xray 主流写法）
		`response.body.bcontains(b'root:')`,
		`response.raw.bcontains(b'@RSYNCD: ')`,
		`response.body.bmatches('root:.*:0:0')`,
		`response.body.bstartswith(b'HTTP')`,
		`response.body.bendswith(b'</html>')`,
		// 字符串面
		`response.content_type.contains('application/json')`,
		`response.content_type.matches('json|xml')`,
		`response.content_type.startswith('text')`,
		`response.content_type.endswith('utf-8')`,
		`response.body.contains('welcome')`,
		`response.body.matches('wel.*me')`,
		`tolower(response.content_type) == 'application/json'`,
		`toupper(response.content_type) == 'APPLICATION/JSON'`,
		// 下标接收者（header 匹配的唯一实用形态）
		`response.headers['server'].contains('nginx')`,
		// 正则里的反斜杠须按 expr-lang 字符串转义写成 \\（'\.' 是非法字符转义）
		`response.headers['server'].matches('nginx/1\\.\\d+')`,
		`response.headers["x-powered-by"].contains('PHP')`,
		// 组合
		`response.status == 200 && response.body.contains('admin')`,
		`response.elapsed_ms >= 4000`,
	}
	for _, c := range cases {
		if err := CheckRuleExpr(c); err != nil {
			t.Errorf("应可编译但失败: %s\n   → %s", c, firstLineOf(err.Error()))
		}
	}
}

// 改写后的源码形态：contains/matches 必须落到 b* 实现上。
func TestTransformMapsOperatorNames(t *testing.T) {
	cases := map[string]string{
		`response.body.contains('x')`:               `bcontains(response.body, 'x')`,
		`response.body.matches('x')`:                `bmatches(response.body, 'x')`,
		`response.content_type.contains('json')`:    `bcontains(response.content_type, 'json')`,
		`response.headers['server'].contains('ng')`: `bcontains(response.headers['server'], 'ng')`,
		`response.headers["a"].matches('b')`:        `bmatches(response.headers["a"], 'b')`,
		`response.body.bcontains(b'x')`:             `bcontains(response.body, b'x')`,
		`response.content_type.startswith('text')`:  `startswith(response.content_type, 'text')`,
	}
	for in, want := range cases {
		if got := TransformExpression(in); got != want {
			t.Errorf("TransformExpression(%q)\n got %q\nwant %q", in, got, want)
		}
	}
}

// 字符串字面量里的 .contains( 不得被误改写。
func TestTransformLeavesLiteralsAlone(t *testing.T) {
	in := `response.body.bcontains(b'response.body.contains(')`
	if got := TransformExpression(in); strings.Count(got, "bcontains(") != 1 {
		t.Errorf("字面量内的函数名被误改写: %q", got)
	}
}

// 非法正则必须在校验阶段就被拦下，绝不能放行后在运行期静默返回 false。
func TestInvalidRegexRejectedAtValidation(t *testing.T) {
	bad := []string{
		`response.body.bmatches('([unclosed')`,
		`response.body.matches('([unclosed')`,
		`response.content_type.matches('*bad')`,
		`response.body.bmatches('(?P<')`,
	}
	for _, c := range bad {
		if err := CheckRuleExpr(c); err == nil {
			t.Errorf("非法正则应被拦截: %s", c)
		} else if !strings.Contains(err.Error(), "正则") {
			t.Errorf("错误信息应点明正则问题: %s → %v", c, firstLineOf(err.Error()))
		}
	}

	// 合法正则不受影响
	for _, c := range []string{
		`response.body.bmatches('root:.*:0:0')`,
		`response.body.bmatches('(?i)admin')`,
		`response.content_type.matches('json|xml')`,
	} {
		if err := CheckRuleExpr(c); err != nil {
			t.Errorf("合法正则被误拦: %s → %v", c, firstLineOf(err.Error()))
		}
	}
}

// ValidateSpec 同样要拦下非法正则（保存路径）。
func TestValidateSpecRejectsInvalidRegex(t *testing.T) {
	spec := `transport: http
rules:
  r0:
    request:
      method: GET
      path: /x
    expression: response.body.bmatches('([unclosed')
expression: r0()
`
	if _, err := ValidateSpec(spec); err == nil {
		t.Error("含非法正则的 spec 应被 ValidateSpec 拒绝")
	}
}

func firstLineOf(s string) string {
	if i := strings.Index(s, "\n"); i >= 0 {
		return s[:i]
	}
	return s
}
