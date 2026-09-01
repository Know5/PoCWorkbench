// Package exprfn 提供 xray 风格表达式函数注册表，供 pwf 校验与 engine 求值共用。
package exprfn

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/expr-lang/expr"
)

// newlineNormalizer 与 expr-lang 词法器对字符串/字节字面量的 \r\n → \n 归一化保持对称：
// 字面量在编译期被归一化，运行期 haystack 必须同样处理，否则 CRLF 敏感匹配恒不命中。
var newlineNormalizer = strings.NewReplacer("\r\n", "\n", "\r", "\n")

func normalizeBytes(b []byte) []byte {
	return []byte(newlineNormalizer.Replace(string(b)))
}

func Options() []expr.Option {
	return []expr.Option{
		expr.Env(EnvShape()),
		expr.Function("bcontains", func(p ...any) (any, error) {
			a, b := arg2(p)
			return strings.Contains(string(normalizeBytes(a)), string(normalizeBytes(b))), nil
		}),
		expr.Function("bmatches", func(p ...any) (any, error) {
			return reMatch(normalizeBytes(toBytes(p[0])), toStr(p[1]))
		}),
		expr.Function("bstartswith", func(p ...any) (any, error) {
			return strings.HasPrefix(string(normalizeBytes(toBytes(p[0]))), toStr(p[1])), nil
		}),
		expr.Function("bendswith", func(p ...any) (any, error) {
			return strings.HasSuffix(string(normalizeBytes(toBytes(p[0]))), toStr(p[1])), nil
		}),
		expr.Function("startswith", func(p ...any) (any, error) {
			return strings.HasPrefix(toStr(p[0]), toStr(p[1])), nil
		}),
		expr.Function("endswith", func(p ...any) (any, error) {
			return strings.HasSuffix(toStr(p[0]), toStr(p[1])), nil
		}),
		expr.Function("tolower", func(p ...any) (any, error) {
			return strings.ToLower(toStr(p[0])), nil
		}),
		expr.Function("toupper", func(p ...any) (any, error) {
			return strings.ToUpper(toStr(p[0])), nil
		}),
	}
}

// EnvShape 编译期环境样本——与引擎运行时构造的 map 完全同构。
func EnvShape() map[string]any {
	return map[string]any{
		"response": map[string]any{
			"status":       0,
			"headers":      map[string]string{},
			"body":         []byte(nil),
			"content_type": "",
			"raw":          []byte(nil),
			"elapsed_ms":   int64(0),
		},
	}
}

func arg2(p []any) ([]byte, []byte) { return toBytes(p[0]), toBytes(p[1]) }

func toBytes(v any) []byte {
	switch t := v.(type) {
	case []byte:
		return t
	case string:
		return []byte(t)
	default:
		return []byte(fmt.Sprint(v))
	}
}

func toStr(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []byte:
		return string(t)
	default:
		return fmt.Sprint(v)
	}
}

// reMatch 编译并匹配。编译失败必须报错而非返回 false：
// 静默 false 会让写错的正则表现为「永远未命中」，实测结果看不出任何异常。
// pwf.CompileResponseExpr 已在保存期静态拦截字面量正则，这里兜住非字面量路径。
func reMatch(b []byte, pattern string) (bool, error) {
	r, err := regexp.Compile(pattern)
	if err != nil {
		return false, fmt.Errorf("正则 %q 无法编译: %w", pattern, err)
	}
	return r.Match(b), nil
}
