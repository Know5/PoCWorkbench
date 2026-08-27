// Package convert 实现 Xray / Nuclei YAML → PWF 草稿的转换。
//
// Nuclei 方向（v1.1.0 起）：
//   - http：raw 报文与 path 型请求（{{BaseURL}} 等变量剥离为相对路径）
//   - tcp / network：inputs 按序收发
//   - matchers：status / word / regex / binary → 表达式；dsl、interactsh 等
//     无法布尔化的类型逐条进警告列表，绝不静默丢弃；全部不可用时才报错
//   - 变量模板、payload、attack、extractors 不支持：path 残留 {{var}} 直接报错，
//     body 中残留按字面发送并警告
package convert

import (
	"encoding/hex"
	"fmt"
	"math"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"pocworkbench/internal/model"
)

// ---- 格式识别 ----

const (
	FormatXray    = "xray"
	FormatNuclei  = "nuclei"
	FormatUnknown = "unknown"
)

// DetectFormat 依据顶层结构区分 Xray 与 Nuclei 模板。
func DetectFormat(src string) string {
	if d := yamlDepthHint(src); d > maxScanNesting {
		return FormatUnknown // 过深结构交由各转换器入口报错，这里不猜格式
	}
	var root map[string]any
	if err := yaml.Unmarshal([]byte(src), &root); err != nil {
		return FormatUnknown
	}
	if _, ok := root["rules"].(map[string]any); ok {
		return FormatXray
	}
	if hasNucleiProtocolBlock(root) {
		return FormatNuclei
	}
	if _, ok := root["info"]; ok && root["id"] != nil {
		return FormatNuclei // 仅剩元数据的空壳也算 nuclei 形态，交给其转换器报具体错误
	}
	return FormatUnknown
}

func hasNucleiProtocolBlock(root map[string]any) bool {
	for _, key := range []string{"http", "tcp", "network"} {
		if l, ok := root[key].([]any); ok && len(l) > 0 {
			return true
		}
	}
	return false
}

// ---- 编号模式与严重度 ----

var severityMap = map[string]string{
	"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info",
}

var nucleiIDPatterns = []*regexp.Regexp{
	cveRe,
	regexp.MustCompile(`(?i)(CNVD-\d{4}-\d+)`),
	regexp.MustCompile(`(?i)(XVE-\d{4}-\d+)`),
	regexp.MustCompile(`(?i)(GHSA(?:-[23456789cfghjmpqrvwx]{4}){3})`),
}

var pathVarRe = regexp.MustCompile(`\{\{\s*(BaseURL|RootURL|Hostname)\s*\}\}(:\{\{\s*Port\s*\}\})?`)
var leftoverVarRe = regexp.MustCompile(`\{\{[^{}]*\}\}`)

// NucleiToDraft 把 Nuclei 模板转换为 PWF 草稿。尽力转换，失败细节进 Warnings。
func NucleiToDraft(src string) (*model.Draft, error) {
	if d := yamlDepthHint(src); d > maxScanNesting {
		return nil, fmt.Errorf("YAML 嵌套过深（约 %d 层 > %d 上限），疑似恶意模板，已拒绝", d, maxScanNesting)
	}
	var root map[string]any
	if err := yaml.Unmarshal([]byte(src), &root); err != nil {
		return nil, fmt.Errorf("Nuclei YAML 解析失败: %w", err)
	}

	draft := &model.Draft{
		Severity: "info", Category: "other", Status: "untested",
		Source: FormatNuclei, Kind: "template",
		Vendor: "UNKNOWN", Product: "UNKNOWN",
	}
	draft.Warnings = append(draft.Warnings, "Nuclei 无厂商指纹信息，vendor/product 置为 UNKNOWN 待治理")

	info, _ := root["info"].(map[string]any)
	classification, _ := info["classification"].(map[string]any)

	// ---- 标识 / 名称 / 别名 / CVE ----
	id := str(root["id"])
	name := orDefault(str(info["name"]), id)
	draft.Name = name

	haystack := id + "\n" + name + "\n" + str(info["description"]) + "\n" + classificationText(classification)
	draft.CVE = upperFirstMatch(haystack, cveRe)
	aliasSet := map[string]bool{}
	if id != "" {
		aliasSet[id] = true
	}
	for _, re := range nucleiIDPatterns {
		for _, m := range re.FindAllString(haystack, -1) {
			aliasSet[strings.ToUpper(m)] = true
		}
	}
	for a := range aliasSet {
		draft.Aliases = append(draft.Aliases, a)
	}

	// ---- 严重度 / 标签 / 分类推断 / 描述 ----
	sev := strings.ToLower(str(info["severity"]))
	switch {
	case sev == "":
		draft.Warnings = append(draft.Warnings, "severity 缺失，按 info 处理")
	case severityMap[sev] != "":
		draft.Severity = severityMap[sev]
	default:
		draft.Warnings = append(draft.Warnings, fmt.Sprintf("未知 severity %q，按 info 处理", sev))
	}

	tags := parseTags(info["tags"])
	text := name + "\n" + str(info["description"]) + "\n" + strings.Join(tags, " ")
	draft.Tags = tags
	for _, cr := range categoryRules {
		if cr.re.MatchString(text) {
			draft.Category = cr.category
			break
		}
	}

	desc := str(info["description"])
	if refs, ok := info["reference"].([]any); ok && len(refs) > 0 {
		var lines []string
		for _, r := range refs {
			if s := str(r); s != "" {
				lines = append(lines, s)
			}
		}
		if len(lines) > 0 {
			desc += "\n参考:\n" + strings.Join(lines, "\n")
		}
	}
	draft.Desc = desc

	// ---- 协议块 → 规则 ----
	spec := model.Spec{Rules: map[string]model.Rule{}}
	var order []string          // 规则名顺序（map 无序，最终表达式拼接必须稳定）
	matchersCond := ""          // 首个显式 matchers-condition 生效
	hostHeaderDropped := false

	addRule := func(rule model.Rule, expr, cond, label string) {
		expr = strings.TrimSpace(expr)
		if expr == "" {
			draft.Warnings = append(draft.Warnings, fmt.Sprintf("%s 无可用 matcher 组合，该请求未纳入", label))
			return
		}
		rname := fmt.Sprintf("r%d", len(order))
		rule.Expression = expr
		spec.Rules[rname] = rule
		order = append(order, rname)
		if cond == "" {
			return
		}
		c := normalizeCond(cond)
		if matchersCond == "" {
			matchersCond = c
		} else if matchersCond != c {
			draft.Warnings = append(draft.Warnings,
				fmt.Sprintf("%s 的 matchers-condition(%s) 与先前(%s)不一致，按 %s 合并", label, c, matchersCond, matchersCond))
		}
	}

	convertReqMatchers := func(reqMap map[string]any, subject, label string) (string, error) {
		expr, notes, err := buildMatcherExpr(reqMap, subject)
		for _, n := range notes {
			draft.Warnings = append(draft.Warnings, label+"："+n)
		}
		if err != nil {
			return "", fmt.Errorf("%s: %w", label, err)
		}
		return expr, nil
	}

	httpList, _ := root["http"].([]any)
	for i, item := range httpList {
		reqMap, ok := item.(map[string]any)
		if !ok {
			draft.Warnings = append(draft.Warnings, fmt.Sprintf("http[%d] 结构异常，已跳过", i))
			continue
		}
		label := fmt.Sprintf("http[%d]", i)
		mc := strings.ToLower(str(reqMap["matchers-condition"]))

		raws, _ := reqMap["raw"].([]any)
		for j, rv := range raws {
			sub := fmt.Sprintf("%s raw[%d]", label, j)
			method, path, headers, body, perr := parseRawHTTP(str(rv), &hostHeaderDropped)
			if perr != nil {
				draft.Warnings = append(draft.Warnings, sub+" 解析失败: "+perr.Error())
				continue
			}
			path = stripPathVars(path, draft)
			if leftover := leftoverVarRe.FindAllString(path, -1); len(leftover) > 0 {
				return nil, fmt.Errorf("%s 路径含不受支持的模板变量 %v（payload/变量类特性无法静态执行）", sub, leftover)
			}
			bodyVars := leftoverVarRe.FindAllString(body, -1)
			if len(bodyVars) > 0 {
				draft.Warnings = append(draft.Warnings, fmt.Sprintf("%s body 含模板变量 %v，将按字面发送", sub, bodyVars))
			}
			expr, err := convertReqMatchers(reqMap, "body", sub)
			if err != nil {
				return nil, err
			}
			addRule(model.Rule{
				Request: model.Request{Method: method, Path: ensureAbsPath(path), Headers: headers, Body: body},
			}, expr, mc, sub)
		}

		paths, _ := reqMap["path"].([]any)
		for j, pv := range paths {
			sub := fmt.Sprintf("%s path[%d]", label, j)
			p := stripPathVars(str(pv), draft)
			if p == "" && str(pv) == "" {
				continue
			}
			if leftover := leftoverVarRe.FindAllString(p, -1); len(leftover) > 0 {
				return nil, fmt.Errorf("%s 路径含不受支持的模板变量 %v（payload/变量类特性无法静态执行）", sub, leftover)
			}
			method := strings.ToUpper(orDefault(str(reqMap["method"]), "GET"))
			hs := headerMap(reqMap["headers"])
			body := str(reqMap["body"])
			expr, err := convertReqMatchers(reqMap, "body", sub)
			if err != nil {
				return nil, err
			}
			addRule(model.Rule{
				Request: model.Request{Method: method, Path: ensureAbsPath(p), Headers: hs, Body: body},
			}, expr, mc, sub)
		}
	}

	tcpList, _ := root["tcp"].([]any)
	netList, _ := root["network"].([]any)
	for _, block := range []struct {
		key  string
		list []any
	}{{"tcp", tcpList}, {"network", netList}} {
		for i, item := range block.list {
			reqMap, ok := item.(map[string]any)
			if !ok {
				continue
			}
			label := fmt.Sprintf("%s[%d]", block.key, i)
			rule := model.Rule{}
			if inputs, ok := reqMap["inputs"].([]any); ok {
				for _, iv := range inputs {
					switch im := iv.(type) {
					case string:
						rule.Request.Inputs = append(rule.Request.Inputs, model.TCPInput{Data: im})
					case map[string]any:
						data, _ := im["data"].(string)
						rule.Request.Inputs = append(rule.Request.Inputs, model.TCPInput{Data: data})
					}
				}
			}
			if rt := intOf(reqMap["read-timeout"]); rt > 0 {
				rule.Request.ReadTimeout = rt
			}
			expr, err := convertReqMatchers(reqMap, "raw", label)
			if err != nil {
				return nil, err
			}
			addRule(rule, expr, strings.ToLower(str(reqMap["matchers-condition"])), label)
		}
	}
	if len(tcpList)+len(netList) > 0 {
		draft.Warnings = append(draft.Warnings, "TCP 型模板：模板内 host/port 不带入，验证时目标须填 host:port")
	}

	var dropped []string
	for _, k := range []string{"dns", "file", "code", "ssl", "websocket", "javascript", "lua"} {
		if v, ok := root[k]; ok && hasContent(v) {
			dropped = append(dropped, k)
		}
	}
	if len(dropped) > 0 {
		draft.Warnings = append(draft.Warnings, fmt.Sprintf("不支持且已丢弃的协议块: %s", strings.Join(dropped, ", ")))
	}
	checkNucleiUnsupported(root, draft)

	if hostHeaderDropped {
		draft.Warnings = append(draft.Warnings, "已移除 raw 报文中的 Host 头，运行时使用真实目标 host")
	}
	if len(order) == 0 {
		return nil, fmt.Errorf("没有可转换的请求规则（需 http raw/path 或 tcp/network inputs）")
	}

	spec.Transport = "http"
	hasHTTPBlock := false
	if l, ok := root["http"].([]any); ok {
		hasHTTPBlock = len(l) > 0
	}
	if len(tcpList)+len(netList) > 0 && !hasHTTPBlock {
		spec.Transport = "tcp"
	} else if len(tcpList)+len(netList) > 0 {
		draft.Warnings = append(draft.Warnings, "同时存在 http 与 tcp/network 块，PWF 单模板仅支持一种 transport，仅保留 http 部分")
	}

	if len(order) == 1 {
		spec.Expression = order[0] + "()"
	} else {
		op := "||"
		if normalizeCond(orDefault(matchersCond, "or")) == "and" {
			op = "&&"
		}
		var calls []string
		for _, n := range order {
			calls = append(calls, n+"()")
		}
		spec.Expression = strings.Join(calls, " "+op+" ")
		if len(order) > 2 {
			draft.Warnings = append(draft.Warnings, fmt.Sprintf("多请求模板按 %s 条件合并为总表达式", strings.ToUpper(orDefault(matchersCond, "or"))))
		}
	}

	specBytes, err := yaml.Marshal(&spec)
	if err != nil {
		return nil, fmt.Errorf("spec 序列化失败: %w", err)
	}
	draft.SpecYAML = string(specBytes)
	return draft, nil
}

// ---- matcher → 表达式 ----

// buildMatcherExpr 把一个请求对象的 matchers 编译成单条布尔表达式。
// subject："body"（http）或 "raw"（tcp）。
// notes 收集"安全跳过"的说明（如 part 指向 header/all）；err 仅在全部 matcher
// 都无法转换或数据损坏时返回。
func buildMatcherExpr(reqMap map[string]any, subject string) (expr string, notes []string, err error) {
	ms, _ := reqMap["matchers"].([]any)
	if len(ms) == 0 {
		return "", nil, fmt.Errorf("缺少 matchers 定义")
	}
	cond := normalizeCond(orDefault(strings.ToLower(str(reqMap["matchers-condition"])), "or"))
	op := "||"
	if cond == "and" {
		op = "&&"
	}

	var groups []string
	for mi, mv := range ms {
		mmap, ok := mv.(map[string]any)
		if !ok {
			return "", notes, fmt.Errorf("matcher[%d] 结构异常", mi)
		}
		g, note := matcherGroup(mmap, subject)
		if g == "" {
			if note != "" {
				notes = append(notes, fmt.Sprintf("matcher[%d](%s): %s", mi, str(mmap["type"]), note))
			}
			continue
		}
		groups = append(groups, g)
	}
	if len(groups) == 0 {
		return "", notes, fmt.Errorf("全部 matchers 均无法转换为表达式，需人工改写")
	}
	out := groups[0]
	if len(groups) > 1 {
		out = strings.Join(groups, " "+op+" ")
	}
	return out, notes, nil
}

// matcherGroup 返回单个 matcher 的子表达式；空串 + note 表示安全跳过并说明原因。
func matcherGroup(m map[string]any, subject string) (expr, note string) {
	mtype := strings.ToLower(str(m["type"]))
	part := strings.ToLower(str(m["part"]))
	target := subject
	if part == "header" || part == "all" || part == "interactsh_protocol" {
		return "", fmt.Sprintf("part=%q 无法映射到 PWF 的匹配面，已跳过", part)
	}

	scalarOf := func(v any) string {
		switch t := v.(type) {
		case string:
			return strings.TrimSpace(t)
		case int, int64:
			return fmt.Sprint(t)
		case float64:
			if t == math.Trunc(t) && !math.IsInf(t, 0) {
				return fmt.Sprintf("%d", int64(t)) // 2.0 → "2"
			}
			return fmt.Sprint(t)
		default:
			return ""
		}
	}
	itemsOf := func(key string) []string {
		l, _ := m[key].([]any)
		var out []string
		for _, v := range l {
			if s := scalarOf(v); s != "" {
				out = append(out, s)
			}
		}
		if len(out) == 0 {
			if s := scalarOf(m[key]); s != "" {
				out = []string{s}
			}
		}
		return out
	}
	ci := isTruthy(m["case-insensitive"])
	innerOp := "||"
	if normalizeCond(strings.ToLower(str(m["condition"]))) == "and" {
		innerOp = "&&"
	}

	subj := responseSubject(target)
	switch mtype {
	case "status":
		if subject != "body" { // tcp 模式下没有状态码概念
			return "", "tcp 传输无 status 匹配面，已跳过"
		}
		var terms []string
		for _, s := range itemsOf("status") {
			n := intOf(s)
			if n <= 0 {
				continue
			}
			terms = append(terms, fmt.Sprintf("response.status == %d", n))
		}
		if len(terms) == 0 {
			return "", "status 列表为空"
		}
		return strings.Join(terms, " || "), ""

	case "word":
		words := itemsOf("words")
		if len(words) == 0 {
			return "", "words 为空"
		}
		var terms []string
		for _, w := range words {
			terms = append(terms, wordTerm(subj, w, ci))
		}
		return strings.Join(terms, " "+innerOp+" "), ""

	case "regex":
		pats := itemsOf("regex")
		if len(pats) == 0 {
			return "", "regex 为空"
		}
		var terms []string
		for _, p := range pats {
			flags := ""
			if ci {
				flags = "(?i)"
			}
			terms = append(terms, fmt.Sprintf("%s.bmatches('%s')", subj, exprEscape(flags+p)))
		}
		return strings.Join(terms, " "+innerOp+" "), ""

	case "binary":
		bins := itemsOf("binary")
		if len(bins) == 0 {
			return "", "binary 为空"
		}
		var terms []string
		for _, b := range bins {
			hexBytes, err := decodeHexBlob(b)
			if err != nil {
				return "", "hex 解析失败: " + err.Error()
			}
			terms = append(terms, fmt.Sprintf("%s.bcontains(b'%s')", subj, bytesLiteral(string(hexBytes))))
		}
		return strings.Join(terms, " "+innerOp+" "), ""

	default:
		return "", "类型暂不支持自动转换，请改写为等价 word/status/regex/binary 组合后重新粘贴"
	}
}

func responseSubject(part string) string {
	if part == "raw" {
		return "response.raw"
	}
	return "response.body"
}

func wordTerm(subj, word string, ci bool) string {
	if ci {
		// 忽略大小写：转为 (?i) 字面正则（QuoteMeta 保证语义仍为子串匹配）
		return fmt.Sprintf("%s.bmatches('(?i)%s')", subj, exprEscape(regexp.QuoteMeta(word)))
	}
	return fmt.Sprintf("%s.bcontains(b'%s')", subj, bytesLiteral(word))
}

// ---- 字面量转义（expr-lang 支持 Go 风格转义 + \xNN，源码 parser/lexer/utils.go）----

func bytesLiteral(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\\':
			b.WriteString(`\\`)
		case '\'':
			b.WriteString(`\'`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if c < 0x20 || c == 0x7f {
				fmt.Fprintf(&b, `\x%02x`, c)
			} else {
				b.WriteByte(c)
			}
		}
	}
	return b.String()
}

func exprEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	s = strings.ReplaceAll(s, "\r\n", `\n`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\t", `\t`)
	return s
}

var hexTokenPrefixRe = regexp.MustCompile(`(?i)^(\\x|x|0x)`)

// decodeHexBlob 容忍 "50 4B 03 04"、"504b0304"、"\x50\x4b" 三种常见写法。
func decodeHexBlob(s string) ([]byte, error) {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == ',' || r == '\n' || r == '\t' || r == '\r'
	})
	var hexStr strings.Builder
	for _, tok := range fields {
		for {
			loc := hexTokenPrefixRe.FindStringIndex(tok)
			if loc == nil {
				break
			}
			tok = tok[loc[1]:]
		}
		hexStr.WriteString(tok)
	}
	h := hexStr.String()
	if h == "" || len(h)%2 != 0 {
		return nil, fmt.Errorf("无效十六进制串 %q", s)
	}
	out, err := hex.DecodeString(h)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ---- 工具函数 ----

func normalizeCond(c string) string {
	if strings.TrimSpace(strings.ToLower(c)) == "and" {
		return "and"
	}
	return "or"
}

func isTruthy(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(strings.TrimSpace(t), "true")
	default:
		return false
	}
}

func parseTags(v any) []string {
	var raw []string
	switch t := v.(type) {
	case string:
		raw = strings.FieldsFunc(t, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' })
	case []any:
		for _, x := range t {
			if s := str(x); s != "" {
				raw = append(raw, strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' })...)
			}
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, s := range raw {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func upperFirstMatch(s string, re *regexp.Regexp) string {
	m := re.FindString(s)
	if m == "" {
		return ""
	}
	return strings.ToUpper(m)
}

func classificationText(c map[string]any) string {
	if len(c) == 0 {
		return ""
	}
	var b strings.Builder
	for k, v := range c {
		b.WriteString(k)
		b.WriteString(": ")
		b.WriteString(str(v))
		b.WriteString("\n")
	}
	return b.String()
}

func headerMap(v any) map[string]string {
	hm, _ := v.(map[string]any)
	out := map[string]string{}
	for k, val := range hm {
		out[k] = str(val)
	}
	return out
}

// stripPathVars 把 {{BaseURL}}/{{RootURL}}/{{Hostname}}(:{{Port}})? 剥离为相对路径。
func stripPathVars(p string, draft *model.Draft) string {
	if pathVarRe.MatchString(p) {
		draft.Warnings = append(draft.Warnings, "已剥离路径中的 BaseURL/Hostname 变量，转为相对路径")
		p = pathVarRe.ReplaceAllString(p, "")
	}
	return strings.TrimSpace(p)
}

func ensureAbsPath(p string) string {
	if p == "" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

// parseRawHTTP 解析裸 HTTP 报文 → method/path/headers/body。
// Host 头剥离（引擎以真实目标为准），重复头合并为分号拼接。
func parseRawHTTP(raw string, hostDropped *bool) (method, path string, headers map[string]string, body string, err error) {
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return "", "", nil, "", fmt.Errorf("空报文")
	}
	first := strings.Fields(strings.TrimSpace(lines[0]))
	if len(first) < 2 {
		return "", "", nil, "", fmt.Errorf("首行不是 \"METHOD PATH [HTTP/x]\" 形式: %q", lines[0])
	}
	method = strings.ToUpper(first[0])
	path = first[1]

	headers = map[string]string{}
	i := 1
	for ; i < len(lines); i++ {
		line := strings.TrimRight(lines[i], " \t")
		if line == "" {
			i++
			break
		}
		ci := strings.Index(line, ":")
		if ci <= 0 {
			continue // 容忍残缺行
		}
		k := strings.TrimSpace(line[:ci])
		v := strings.TrimSpace(line[ci+1:])
		if strings.EqualFold(k, "Host") {
			*hostDropped = true
			continue
		}
		if exist, ok := headers[k]; ok {
			headers[k] = exist + "; " + v
		} else {
			headers[k] = v
		}
	}
	if i <= len(lines) {
		body = strings.Trim(strings.Join(lines[i:], "\n"), "\n")
	}
	return method, path, headers, body, nil
}

// checkNucleiUnsupported 明示 Nuclei 特有且被丢弃的顶层特性。
func checkNucleiUnsupported(root map[string]any, draft *model.Draft) {
	var dropped []string
	for _, k := range []string{"variables", "payloads", "attack", "stop-at-first-match", "req-condition", "extractors"} {
		if v, ok := root[k]; ok && hasContent(v) {
			dropped = append(dropped, k)
		}
	}
	if len(dropped) > 0 {
		draft.Warnings = append(draft.Warnings, fmt.Sprintf("不支持且已丢弃的 Nuclei 特性: %s", strings.Join(dropped, ", ")))
	}
}
