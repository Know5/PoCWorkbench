// Package pwf 提供 PWF spec 的三关校验、表达式变换与规范化哈希。
//
// 三关：
//  1. 严格 schema 校验（yaml KnownFields）
//  2. 表达式编译校验（expr-lang，含函数注册表与 xray 方法调用改写）
//  3. 总 expression 只允许引用已声明 rule 名 + 布尔运算
package pwf

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/ast"
	"github.com/expr-lang/expr/parser"
	"github.com/expr-lang/expr/vm"
	"gopkg.in/yaml.v3"

	"pocworkbench/internal/exprfn"
	"pocworkbench/internal/model"
)

var SeveritySet = map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "info": true}
var StatusSet = map[string]bool{"tested": true, "untested": true, "failed": true, "faked": true, "archived": true}
var CategorySet = map[string]bool{
	"rce": true, "sqli": true, "fileread": true, "fileupload": true, "unauth": true,
	"weakpass": true, "infoleak": true, "ssrf": true, "xxe": true, "other": true,
}

// ---- 表达式函数注册表（引擎与校验共用）----

// FuncNames 是 response 对象上可用的方法名（xray 风格），用于方法调用改写。
var FuncNames = []string{
	"bcontains", "bmatches", "contains", "matches",
	"startswith", "endswith", "bstartswith", "bendswith",
	"tolower", "toupper",
}

// methodCallRe 匹配 `response.xxx.fn(` 形式，改写为 `fn(response.xxx, `。
// 括号天然平衡：只把接收者挪进参数列表第一位。
var methodCallRe = func() *regexp.Regexp {
	names := strings.Join(FuncNames, "|")
	return regexp.MustCompile(`\b(response(?:\.[A-Za-z_][A-Za-z0-9_]*)+)\.(` + names + `)\(`)
}()

// TransformExpression 将 xray 风格表达式改写为 expr-lang 可编译源码：
// 方法调用 response.x.fn(a) → fn(response.x, a)。
// 注：expr-lang 原生支持 b'...' 字节字面量（lexer unescapeBytes，原始字节语义），
// 不得改写为 '...'——那会把 \xff 当 Unicode 码点 UTF-8 编码成两个字节，静默污染 needle。
func TransformExpression(e string) string {
	return methodCallRe.ReplaceAllString(e, `$2($1, `)
}

// CompileResponseExpr 编译作用于 response 对象的 rule 表达式。
func CompileResponseExpr(raw string) (*vm.Program, error) {
	src := TransformExpression(raw)
	return expr.Compile(src, exprfn.Options()...)
}

// CheckRuleExpr 单条规则表达式的即时编译校验（前端逐字段反馈用）。
func CheckRuleExpr(raw string) error {
	_, err := CompileResponseExpr(raw)
	return err
}

func toNameSet(ns []string) map[string]bool {
	m := make(map[string]bool, len(ns))
	for _, n := range ns {
		m[n] = true
	}
	return m
}

// ValidateSpec 对 spec 执行三关校验，返回规范化 YAML（用于哈希与存储）。
func ValidateSpec(specYAML string) (canonicalYAML string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("解析 panic: %v", r)
		}
	}()

	// 关一：严格 schema
	dec := yaml.NewDecoder(strings.NewReader(specYAML))
	dec.KnownFields(true)
	var spec model.Spec
	if e := dec.Decode(&spec); e != nil {
		return "", fmt.Errorf("schema 校验失败: %w", e)
	}
	if e := validateStructure(&spec); e != nil {
		return "", e
	}

	// 关二：rule 表达式编译
	for name, rule := range spec.Rules {
		if _, e := CompileResponseExpr(rule.Expression); e != nil {
			return "", fmt.Errorf("rule %s: %w", name, e)
		}
	}

	// 关三：总 expression 引用检查 + 布尔结构检查
	ruleNames := make([]string, 0, len(spec.Rules))
	for k := range spec.Rules {
		ruleNames = append(ruleNames, k)
	}
	if e := checkFinal(spec.Expression, toNameSet(ruleNames)); e != nil {
		return "", e
	}

	// 规范化序列化（键序稳定）→ 哈希基底
	canonical, e := MarshalCanonical(&spec)
	if e != nil {
		return "", fmt.Errorf("规范化序列化失败: %w", e)
	}
	return canonical, nil
}

func validateStructure(spec *model.Spec) error {
	switch spec.Transport {
	case "http":
	case "tcp":
	default:
		return fmt.Errorf("transport 必须为 http 或 tcp，当前 %q", spec.Transport)
	}
	if len(spec.Rules) == 0 {
		return fmt.Errorf("至少需要一个 rule")
	}
	if strings.TrimSpace(spec.Expression) == "" {
		return fmt.Errorf("总 expression 不能为空")
	}
	ruleNameRe := regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*$`)
	for name, rule := range spec.Rules {
		if !ruleNameRe.MatchString(name) {
			return fmt.Errorf("rule 名 %q 不合法", name)
		}
		if strings.TrimSpace(rule.Expression) == "" {
			return fmt.Errorf("rule %s 缺少 expression", name)
		}
		req := rule.Request
		if spec.Transport == "http" {
			if req.Path == "" {
				return fmt.Errorf("rule %s 缺少 path", name)
			}
			if len(req.Inputs) > 0 {
				return fmt.Errorf("rule %s: http transport 不允许 inputs", name)
			}
		} else { // tcp
			if len(req.Inputs) == 0 {
				return fmt.Errorf("rule %s: tcp transport 至少需要一个 input", name)
			}
			if req.ReadTimeout <= 0 {
				return fmt.Errorf("rule %s: read_timeout 必须为正整数秒", name)
			}
		}
	}
	return nil
}

// finalExprChecker AST 白名单：Identifier/Call(规则名)/&&/||/!/括号。
type finalExprChecker struct {
	ruleNames map[string]bool
	err       error
}

func (c *finalExprChecker) Visit(n *ast.Node) {
	switch node := (*n).(type) {
	case *ast.IdentifierNode:
		if !c.ruleNames[node.String()] {
			c.err = fmt.Errorf("总 expression 引用了未声明的标识符 %q", node.String())
		}
	case *ast.CallNode:
		id, ok := node.Callee.(*ast.IdentifierNode)
		if !ok || !c.ruleNames[id.String()] {
			c.err = fmt.Errorf("总 expression 只能调用已声明的 rule")
		}
		if len(node.Arguments) != 0 {
			c.err = fmt.Errorf("rule 调用不接受参数")
		}
	case *ast.BinaryNode:
		op := node.Operator
		if op != "&&" && op != "||" {
			c.err = fmt.Errorf("总 expression 仅允许 && 与 ||，发现 %q", op)
		}
	case *ast.UnaryNode:
		if node.Operator != "!" {
			c.err = fmt.Errorf("总 expression 仅允许 ! 运算")
		}
	case *ast.BoolNode, *ast.NilNode:
		c.err = fmt.Errorf("总 expression 不允许字面量")
	default:
		c.err = fmt.Errorf("总 expression 含不允许的语法节点 %T", node)
	}
}

func CheckFinalExpr(final string, ruleNames []string) error {
	return checkFinal(final, toNameSet(ruleNames))
}

func checkFinal(final string, names map[string]bool) error {
	tree, err := parser.Parse(TransformExpression(final))
	if err != nil {
		return fmt.Errorf("总 expression 解析失败: %w", err)
	}
	checker := &finalExprChecker{ruleNames: names}
	ast.Walk(&tree.Node, checker)
	if checker.err != nil {
		return checker.err
	}
	return nil
}

// CanonicalHash 计算规范化 YAML 的 sha256。
func CanonicalHash(canonicalYAML string) string {
	sum := sha256.Sum256([]byte(canonicalYAML))
	return hex.EncodeToString(sum[:])
}

// ParseSpec 把 spec YAML 解析为结构体（假定已通过 ValidateSpec）。
func ParseSpec(specYAML string) (*model.Spec, error) {
	var spec model.Spec
	if err := yaml.Unmarshal([]byte(specYAML), &spec); err != nil {
		return nil, err
	}
	return &spec, nil
}

// MarshalCanonical 输出规范化 YAML（键序稳定，存储格式）。
func MarshalCanonical(spec *model.Spec) (string, error) {
	out, err := yaml.Marshal(spec)
	if err != nil {
		return "", err
	}
	return string(out), nil
}
