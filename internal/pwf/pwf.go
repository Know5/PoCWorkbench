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
// contains / matches 无对应注册函数——它们是 expr-lang 保留运算符，
// 经 operatorFuncAlias 改写到 bcontains / bmatches。改写表与本清单必须同步维护。
var FuncNames = []string{
	"bcontains", "bmatches", "contains", "matches",
	"startswith", "endswith", "bstartswith", "bendswith",
	"tolower", "toupper",
}

// methodCallRe 匹配 `response.xxx.fn(` 与 `response.headers['k'].fn(` 形式，
// 改写为 `fn(response.xxx, `。括号天然平衡：只把接收者挪进参数列表第一位。
// 接收者允许下标段（header 匹配的唯一实用形态），否则该形态走不到改写、
// 会以「编译通过但运行期 invalid operation」的方式炸在用户脸上。
var methodCallRe = func() *regexp.Regexp {
	names := strings.Join(FuncNames, "|")
	receiver := `response(?:\.[A-Za-z_][A-Za-z0-9_]*|\[[^\[\]]*\])+`
	return regexp.MustCompile(`\b(` + receiver + `)\.(` + names + `)\(`)
}()

// operatorFuncAlias 把与 expr-lang 保留中缀运算符同名的函数映射到等价的字节实现。
// contains / matches 在 expr-lang 里是运算符，出现在调用位置一律解析失败
// （`unexpected token Operator`），因此不能注册也不能改写成同名函数调用。
// b* 实现经 toBytes 归一化入参，对字符串操作数语义等价。
var operatorFuncAlias = map[string]string{
	"contains": "bcontains",
	"matches":  "bmatches",
}

// TransformExpression 将 xray 风格表达式改写为 expr-lang 可编译源码：
// 方法调用 response.x.fn(a) → fn(response.x, a)；与运算符同名的 fn 走别名表。
// 改写只作用于字符串字面量之外的片段，避免把 needle 内容里的 `.contains(` 改坏。
// 注：expr-lang 原生支持 b'...' 字节字面量（lexer unescapeBytes，原始字节语义），
// 不得改写为 '...'——那会把 \xff 当 Unicode 码点 UTF-8 编码成两个字节，静默污染 needle。
func TransformExpression(e string) string {
	spans := literalSpans(e)
	matches := methodCallRe.FindAllStringSubmatchIndex(e, -1)
	if len(matches) == 0 {
		return e
	}
	var out strings.Builder
	last := 0
	for _, m := range matches {
		// 起点落在字面量内说明这是 needle 的内容（如 b'...contains('），不是代码
		if insideAny(spans, m[0]) {
			continue
		}
		recv := e[m[2]:m[3]]
		fn := e[m[4]:m[5]]
		if alias, ok := operatorFuncAlias[fn]; ok {
			fn = alias
		}
		out.WriteString(e[last:m[0]])
		out.WriteString(fn + "(" + recv + ", ")
		last = m[1]
	}
	out.WriteString(e[last:])
	return out.String()
}

type span struct{ lo, hi int }

func insideAny(spans []span, pos int) bool {
	for _, s := range spans {
		if pos > s.lo && pos < s.hi {
			return true
		}
	}
	return false
}

// literalSpans 标出 '...' / "..." 字面量的字节区间（含反斜杠转义）。
// 用于判定「某个匹配是否位于字面量内部」——下标键 ['k'] 本身也是字面量，
// 因此不能按字面量切段后再匹配，只能按匹配起点是否落在区间内来筛。
func literalSpans(s string) []span {
	var out []span
	for i := 0; i < len(s); {
		c := s[i]
		if c != '\'' && c != '"' {
			i++
			continue
		}
		j := i + 1
		for j < len(s) {
			if s[j] == '\\' {
				j += 2
				continue
			}
			if s[j] == c {
				j++
				break
			}
			j++
		}
		if j > len(s) {
			j = len(s)
		}
		out = append(out, span{i, j - 1})
		i = j
	}
	return out
}

// CompileResponseExpr 编译作用于 response 对象的 rule 表达式。
// 除语法/类型外还静态校验字面量正则：运行期 reMatch 对编译失败的模式返回 error，
// 但那要等到实测才暴露；写错一个字符的正则应当在保存时就被挡下。
func CompileResponseExpr(raw string) (*vm.Program, error) {
	src := TransformExpression(raw)
	p, err := expr.Compile(src, exprfn.Options()...)
	if err != nil {
		return nil, err
	}
	if err := checkLiteralRegexps(src); err != nil {
		return nil, err
	}
	return p, nil
}

// regexFuncArity 需要校验正则字面量的函数 → 模式所在参数位。
var regexFuncArity = map[string]int{"bmatches": 1, "matches": 1}

// checkLiteralRegexps 遍历 AST，编译所有以字面量形式传入 bmatches/matches 的模式。
// 非字面量（拼接/变量）无从静态判断，跳过。
func checkLiteralRegexps(src string) error {
	tree, err := parser.Parse(src)
	if err != nil {
		return nil // 语法错误已由 expr.Compile 报出，此处不重复
	}
	v := &regexLiteralChecker{}
	ast.Walk(&tree.Node, v)
	return v.err
}

type regexLiteralChecker struct{ err error }

func (c *regexLiteralChecker) Visit(n *ast.Node) {
	if c.err != nil {
		return
	}
	call, ok := (*n).(*ast.CallNode)
	if !ok {
		return
	}
	id, ok := call.Callee.(*ast.IdentifierNode)
	if !ok {
		return
	}
	pos, ok := regexFuncArity[id.Value]
	if !ok || len(call.Arguments) <= pos {
		return
	}
	lit, ok := call.Arguments[pos].(*ast.StringNode)
	if !ok {
		return
	}
	if _, err := regexp.Compile(lit.Value); err != nil {
		c.err = fmt.Errorf("正则 %q 无法编译: %w（RE2 语法；运行期无法匹配任何内容）", lit.Value, err)
	}
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

	// 关四（v1.2 串联）：extract 正则合法 + 变量引用闭环 + 依赖无环
	if e := validateExtracts(&spec); e != nil {
		return "", e
	}

	// 规范化序列化（键序稳定）→ 哈希基底
	canonical, e := MarshalCanonical(&spec)
	if e != nil {
		return "", fmt.Errorf("规范化序列化失败: %w", e)
	}
	return canonical, nil
}

// ---- 变量提取与串联（v1.2）----

// VarRefRe 揜取规则请求文本（path/headers/body/inputs）中的 {{变量名}} 引用。
// 变量名字符集与 rule 名一致；不允许 {{}} 空引用（那是字面量歧义，直接拒绝更安全）。
var VarRefRe = regexp.MustCompile(`\{\{\s*([A-Za-z_][A-Za-z0-9_-]*)\s*\}\}`)

// ExtractFrom 依声明的变量名集合，返回文本中实际引用的变量名（不去重、保序）。
// 引擎运行期与保存期校验共用同一实现，保证"保存时认得的引用，运行时一定认得"。
func ExtractFrom(text string, declared map[string]bool) []string {
	var out []string
	for _, m := range VarRefRe.FindAllStringSubmatch(text, -1) {
		if declared[m[1]] {
			out = append(out, m[1])
		}
	}
	return out
}

// HasVarRef 请求的任一字段是否引用了 {{var}}（不含声明白名单——任何花括号形态都算）。
// 引擎据此判断是否需要走替换路径。
func HasVarRef(req model.Request) bool {
	texts := []string{req.Path, req.Body, req.Method}
	for _, v := range req.Headers {
		texts = append(texts, v)
	}
	for _, in := range req.Inputs {
		texts = append(texts, in.Data)
	}
	for _, t := range texts {
		if VarRefRe.MatchString(t) {
			return true
		}
	}
	return false
}

// RequestTexts 规则请求中允许出现 {{var}} 的全部字段（method/path/headers 值/body/inputs）。
// 保存期校验与引擎运行期共用同一清单，保证两端看到的引用面一致。
func RequestTexts(spec *model.Spec, name string) []string {
	r := spec.Rules[name]
	texts := []string{r.Request.Path, r.Request.Body, r.Request.Method}
	for _, v := range r.Request.Headers {
		texts = append(texts, v)
	}
	for _, in := range r.Request.Inputs {
		texts = append(texts, in.Data)
	}
	return texts
}

// validateExtracts 串联特性的保存期校验：
//  1. 每个 extract 正则可编译且恰好 1 个捕获组（0 组无处取值，多组取哪个有歧义）
//  2. 请求文本中出现的每个 {{var}} 必须已声明（含"零声明但写了 {{var}}"的旧模板误用：
//     不检查会被静默当字面量发出，违反绝不静默原则）
//  3. 声明未被任何规则引用 → 报错（笔误）
//  4. 依赖不得成环（A 引 B 的变量、B 又引 A 的变量）
//
// 无 extract 声明且无 {{var}} 引用的 spec（全部旧模板）直接通过，零影响。
func validateExtracts(spec *model.Spec) error {
	declaredBy := map[string]string{} // 变量名 → 声明它的 rule
	for name, rule := range spec.Rules {
		for varName, pattern := range rule.Extract {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return fmt.Errorf("rule %s 变量 %s 的正则无法编译: %w（RE2 语法）", name, varName, err)
			}
			if n := re.NumSubexp(); n != 1 {
				return fmt.Errorf("rule %s 变量 %s 的正则须恰好 1 个捕获组，当前 %d 个", name, varName, n)
			}
			if _, dup := declaredBy[varName]; dup {
				return fmt.Errorf("变量 %s 在多个 rule 中重复声明", varName)
			}
			declaredBy[varName] = name
		}
	}

	// 先扫全部请求文本：{{var}} 引用必须全部已声明，且至少一处真实引用
	refs := map[string][]string{} // 规则 → 引用的变量
	anyRef := false
	for name := range spec.Rules {
		for _, text := range RequestTexts(spec, name) {
			for _, m := range VarRefRe.FindAllStringSubmatch(text, -1) {
				owner, ok := declaredBy[m[1]]
				if !ok {
					return fmt.Errorf("rule %s 引用了未声明的变量 {{%s}}（先在某个规则里 extract 声明它）", name, m[1])
				}
				if owner == name {
					return fmt.Errorf("rule %s 引用了自己声明的变量 {{%s}}（此时值尚不存在，须由其他规则引用）", name, m[1])
				}
				refs[name] = append(refs[name], m[1])
				anyRef = true
			}
		}
	}
	if len(declaredBy) == 0 && !anyRef {
		return nil // 旧模板：无声明也无引用，全部跳过
	}
	if len(declaredBy) > 0 && !anyRef {
		return fmt.Errorf("声明了 extract 变量但没有任何规则引用它们（删除 extract 或补上 {{变量名}} 引用）")
	}

	// 依赖环检测：规则级依赖 = 我引用了它声明的变量；DFS 三色标记
	deps := map[string]map[string]bool{}
	for name, vs := range refs {
		m := map[string]bool{}
		for _, v := range vs {
			m[declaredBy[v]] = true
		}
		deps[name] = m
	}
	const (
		white = 0
		gray  = 1
		black = 2
	)
	color := map[string]int{}
	var visit func(n string, path []string) error
	visit = func(n string, path []string) error {
		color[n] = gray
		for d := range deps[n] {
			switch color[d] {
			case gray:
				return fmt.Errorf("规则依赖成环: %s → %s", strings.Join(append(path, d), " → "), d)
			case white:
				if err := visit(d, append(path, d)); err != nil {
					return err
				}
			}
		}
		color[n] = black
		return nil
	}
	for name := range deps {
		if color[name] == white {
			if err := visit(name, []string{name}); err != nil {
				return err
			}
		}
	}
	return nil
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
