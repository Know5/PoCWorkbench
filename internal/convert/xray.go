// Package convert 实现 Xray YAML → PWF 草稿的唯一转换方向。
// 转换边界明确：表达式语法同源近乎无损；Xray 冷门特性（set/output 等）
// 不支持，命中即在警告列表中列出，绝不静默丢弃。
package convert

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"pocworkbench/internal/model"
)

var cveRe = regexp.MustCompile(`(?i)(CVE-\d{4}-\d{4,})`)
var cnvdRe = regexp.MustCompile(`(?i)(CNVD-\d{4}-\d+)`)

// namePrefixRe 清洗 `yingyongruanjian-rsync_unauthorized` 这类小写前缀。
// 仅当前缀为纯小写字母数字且长度≥4、剩余部分非空时剥离，避免误伤 CVE-xxx。
var namePrefixRe = regexp.MustCompile(`^[a-z][a-z0-9]{3,}[-_](.+)$`)

type categoryRule struct {
	re       *regexp.Regexp
	category string
}

var categoryRules = []categoryRule{
	{regexp.MustCompile(`(?i)rce|远程命令执行|命令执行|代码执行`), "rce"},
	{regexp.MustCompile(`(?i)sqli|sql.?注入|注入`), "sqli"},
	{regexp.MustCompile(`(?i)文件读取|任意文件|fileread|file.?read|路径遍历|目录遍历`), "fileread"},
	{regexp.MustCompile(`(?i)文件上传|fileupload|file.?upload`), "fileupload"},
	{regexp.MustCompile(`(?i)未授权|unauth|越权|bypass.?login|绕过`), "unauth"},
	{regexp.MustCompile(`(?i)弱口令|弱密码|默认密码|weakpass|default.?pass`), "weakpass"},
	{regexp.MustCompile(`(?i)信息泄露|信息泄漏|infoleak|敏感信息`), "infoleak"},
	{regexp.MustCompile(`(?i)ssrf`), "ssrf"},
	{regexp.MustCompile(`(?i)xxe`), "xxe"},
}

// maxScanNesting 深度预扫阈值：真实 xray 模板嵌套不超过十几层，
// 超过即判定为恶意构造，在 yaml.Unmarshal 递归解码耗尽栈之前拒绝。
const maxScanNesting = 128

// XrayToDraft 把 Xray 模板 YAML 转换为 PWF 草稿。
// 尽力转换；失败细节进 Warnings，不中断（CreatePoc 阶段做最终校验）。
func XrayToDraft(xrayYAML string) (*model.Draft, error) {
	if d := yamlDepthHint(xrayYAML); d > maxScanNesting {
		return nil, fmt.Errorf("YAML 嵌套过深（约 %d 层 > %d 上限），疑似恶意模板，已拒绝", d, maxScanNesting)
	}
	var root map[string]any
	if err := yaml.Unmarshal([]byte(xrayYAML), &root); err != nil {
		return nil, fmt.Errorf("Xray YAML 解析失败: %w", err)
	}

	draft := &model.Draft{
		Severity: "info",
		Category: "other",
		Status:   "untested",
		Source:   "xray",
		Kind:     "template",
	}

	// ---- 标识与名称 ----
	id := str(root["id"])
	name := str(root["name"])
	if m := namePrefixRe.FindStringSubmatch(name); m != nil {
		draft.Warnings = append(draft.Warnings, fmt.Sprintf("已清洗 name 前缀: %q → %q", name, m[1]))
		name = m[1]
	}
	if name == "" {
		name = id
	}
	draft.Name = name

	// ---- aliases / cve 抽取 ----
	aliasSet := map[string]bool{}
	if id != "" {
		aliasSet[id] = true
	}
	haystack := name + "\n" + proofInfo(root)
	for _, re := range []*regexp.Regexp{cveRe, cnvdRe} {
		for _, m := range re.FindAllString(haystack, -1) {
			aliasSet[strings.ToUpper(m)] = true
		}
	}
	for a := range aliasSet {
		if strings.HasPrefix(strings.ToUpper(a), "CVE-") && draft.CVE == "" {
			draft.CVE = strings.ToUpper(a)
		}
		draft.Aliases = append(draft.Aliases, a)
	}

	// ---- 分类推断 ----
	text := proofInfo(root)
	for _, cr := range categoryRules {
		if cr.re.MatchString(text) || cr.re.MatchString(name) {
			draft.Category = cr.category
			break
		}
	}

	// ---- fingerprint → vendor/product ----
	if detail, ok := root["detail"].(map[string]any); ok {
		if fp, ok := detail["fingerprint"].(map[string]any); ok {
			draft.Vendor = str(fp["company"])
			draft.Product = str(fp["product"])
		}
	}
	if draft.Vendor == "" {
		draft.Vendor = "UNKNOWN"
		draft.Warnings = append(draft.Warnings, "fingerprint.company 缺失，vendor 置为 UNKNOWN 待治理")
	}
	if draft.Product == "" {
		draft.Product = "UNKNOWN"
	}
	if tags, ok := root["tags"].([]any); ok {
		for _, t := range tags {
			if s := str(t); s != "" {
				draft.Tags = append(draft.Tags, s)
			}
		}
	}
	draft.Desc = proofInfo(root)

	// ---- transport ----
	transport := str(root["transport"])
	if transport == "" {
		transport = "http"
		draft.Warnings = append(draft.Warnings, "transport 字段缺失，按 http 处理")
	}

	// ---- rules ----
	spec := model.Spec{Transport: transport, Rules: map[string]model.Rule{}}
	rulesMap, _ := root["rules"].(map[string]any)
	if len(rulesMap) == 0 {
		return nil, fmt.Errorf("缺少 rules 定义")
	}
	for rname, rv := range rulesMap {
		rmap, ok := rv.(map[string]any)
		if !ok {
			draft.Warnings = append(draft.Warnings, fmt.Sprintf("rule %s 结构异常，已跳过", rname))
			continue
		}
		rule := model.Rule{}
		if req, ok := rmap["request"].(map[string]any); ok {
			rule.Request.Method = strings.ToUpper(orDefault(str(req["method"]), "GET"))
			rule.Request.Path = str(req["path"])
			rule.Request.Body = str(req["body"])
			if hs, ok := req["headers"].(map[string]any); ok {
				hh := map[string]string{}
				for k, v := range hs {
					hh[k] = str(v)
				}
				rule.Request.Headers = hh
			}
			if inputs, ok := req["inputs"].([]any); ok {
				for _, iv := range inputs {
					if im, ok := iv.(map[string]any); ok {
						rule.Request.Inputs = append(rule.Request.Inputs, model.TCPInput{Data: str(im["data"])})
					}
				}
			}
			rt := intOf(req["read_timeout"])
			if rt > 0 {
				rule.Request.ReadTimeout = rt
			}
		}
		rule.Expression = str(rmap["expression"])
		spec.Rules[rname] = rule
	}
	finalExpr := str(root["expression"])
	if finalExpr == "" {
		// 单规则时自动生成
		if len(spec.Rules) == 1 {
			for n := range spec.Rules {
				finalExpr = n + "()"
			}
			draft.Warnings = append(draft.Warnings, "顶层 expression 缺失，单规则已自动生成")
		} else {
			return nil, fmt.Errorf("多规则但顶层 expression 缺失")
		}
	}
	spec.Expression = finalExpr

	// ---- 不支持特性检测（明示，不静默）----
	checkUnsupported(root, "", draft)

	// 序列化 spec 为 YAML 文本
	specBytes, err := yaml.Marshal(&spec)
	if err != nil {
		return nil, fmt.Errorf("spec 序列化失败: %w", err)
	}
	draft.SpecYAML = string(specBytes)
	return draft, nil
}

func str(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

func intOf(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case float64:
		return int(n)
	case string:
		var out int
		fmt.Sscanf(n, "%d", &out)
		return out
	default:
		return 0
	}
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func proofInfo(root map[string]any) string {
	detail, _ := root["detail"].(map[string]any)
	vuln, _ := detail["vulnerability"].(map[string]any)
	proof, _ := vuln["proof"].(map[string]any)
	return str(proof["info"])
}

// maxNestingDepth 限制 YAML 解析结构的递归深度，防御超深嵌套模板打爆栈。
const maxNestingDepth = 64

// checkUnsupported 递归检测 Xray 特有且 PWF 不支持的键。
func checkUnsupported(node any, path string, draft *model.Draft) {
	checkUnsupportedDepth(node, path, draft, 0)
}

func checkUnsupportedDepth(node any, path string, draft *model.Draft, depth int) {
	if depth > maxNestingDepth {
		draft.Warnings = append(draft.Warnings,
			fmt.Sprintf("结构嵌套超过 %d 层已截断检测: %s", maxNestingDepth, path))
		return
	}
	unsupportedKeys := map[string]bool{
		"set": true, "output": true, "needreverse": true, "search": true,
		"cache": true, "follow_redirects": true, "script": true,
	}
	switch v := node.(type) {
	case map[string]any:
		for k, child := range v {
			p := k
			if path != "" {
				p = path + "." + k
			}
			if unsupportedKeys[k] {
				// set/output 在 rule 层与根层都可能出现
				if hasContent(child) {
					draft.Warnings = append(draft.Warnings,
						fmt.Sprintf("不支持的字段 %s 已丢弃（PWF 暂不实现该特性）", p))
				}
			}
			checkUnsupportedDepth(child, p, draft, depth+1)
		}
	case []any:
		for _, item := range v {
			checkUnsupportedDepth(item, path, draft, depth+1)
		}
	}
}

func hasContent(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case string:
		return strings.TrimSpace(t) != ""
	case map[string]any:
		return len(t) > 0
	case []any:
		return len(t) > 0
	default:
		return true
	}
}

// yamlDepthHint 粗估 YAML 最大嵌套深度：缩进/2 + 行首连续 "- " 序列数，取各行最大值。
// 仅作防御性预扫（配合 maxScanNesting），不要求精确。
func yamlDepthHint(src string) int {
	max := 0
	for _, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimLeft(line, " \t")
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		d := (len(line) - len(trimmed)) / 2
		for trimmed == "-" || strings.HasPrefix(trimmed, "- ") {
			d++
			trimmed = strings.TrimLeft(strings.TrimPrefix(trimmed, "-"), " ")
		}
		if d > max {
			max = d
		}
	}
	return max
}
