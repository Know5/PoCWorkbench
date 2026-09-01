package pwf

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// UI 的一键示例必须都能编译。清单直接从 PocForm.tsx 里抓取，
// 避免两处各改一份、日久失配——曾出现过 3 条示例插入即报错/实测即炸。
func TestUICheatsheetExamplesCompile(t *testing.T) {
	const formPath = "../../frontend/src/pages/PocForm.tsx"
	src, err := os.ReadFile(formPath)
	if err != nil {
		t.Skipf("读不到前端源码（%v），跳过", err)
	}

	examples := extractExampleArrays(string(src))
	if len(examples) == 0 {
		t.Fatalf("未能从 %s 抓到示例清单，正则或常量名可能已变更", formPath)
	}
	t.Logf("抓到 %d 条 UI 示例", len(examples))

	for _, ex := range examples {
		if err := CheckRuleExpr(ex); err != nil {
			t.Errorf("UI 一键示例无法编译: %s\n   → %s", ex, firstLineOf(err.Error()))
		}
	}
}

// 收尾锚定行首的 "];"：示例里含 response.headers['server'] 这类下标，
// 非贪婪匹配到第一个 ] 会把清单截断（曾因此只抓到 6/9 条）。
var exampleArrayRe = regexp.MustCompile(`(?sm)const (?:HTTP|TCP)_EXAMPLES = \[(.*?)^\];`)
var exampleItemRe = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"`)

// extractExampleArrays 取出 HTTP_EXAMPLES / TCP_EXAMPLES 里的字符串字面量，
// 并还原 TS 源码中的 \\ 与 \" 转义。
func extractExampleArrays(src string) []string {
	var out []string
	for _, block := range exampleArrayRe.FindAllStringSubmatch(src, -1) {
		for _, item := range exampleItemRe.FindAllStringSubmatch(block[1], -1) {
			s := item[1]
			s = strings.ReplaceAll(s, `\\`, `\`)
			s = strings.ReplaceAll(s, `\"`, `"`)
			out = append(out, s)
		}
	}
	return out
}
