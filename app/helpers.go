package app

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/oklog/ulid/v2"

	"pocworkbench/internal/convert"
	"pocworkbench/internal/engine"
	"pocworkbench/internal/model"
)

func convertXraySafe(yamlText string) (d *model.Draft, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("解析 panic: %v", r)
		}
	}()
	return convert.XrayToDraft(yamlText)
}

func strings_Blank(s string) bool { return strings.TrimSpace(s) == "" }

func orDefaultStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func genUID() string {
	return "poc_" + ulid.Make().String()
}

func nowRFC() string { return time.Now().UTC().Format(time.RFC3339) }

func ptrNowRFC() *string {
	s := nowRFC()
	return &s
}

func hostOf(target string) string {
	t := target
	if i := strings.Index(t, "://"); i >= 0 {
		t = t[i+3:]
	}
	if i := strings.IndexAny(t, "/"); i >= 0 {
		t = t[:i]
	}
	if u, err := url.Parse("http://" + t); err == nil {
		return u.Host
	}
	return t
}

var secretRe = regexp.MustCompile(`(?i)(password|passwd|token|secret|api[_-]?key)["']?\s*[:=]\s*\S+`)

// sanitizeLog 落库前脱敏（方案 §六）。
// 截断回退到 UTF-8 rune 边界，中文日志不在边界处产出乱码尾巴。
func sanitizeLog(log string) string {
	log = secretRe.ReplaceAllString(log, `$1=***`)
	const maxLog = 5 << 20
	if len(log) > maxLog {
		cut := maxLog
		for cut > 0 && !utf8.RuneStart(log[cut]) {
			cut--
		}
		return log[:cut] + "\n...(truncated)"
	}
	return log
}

func lower(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func containsFold(name, needle string) bool {
	return strings.Contains(strings.ToLower(name), needle)
}

func containsAny(list []string, needle string) bool {
	for _, x := range list {
		if strings.Contains(strings.ToLower(x), needle) {
			return true
		}
	}
	return false
}

// checkTargetFormat 批量目标预筛。直接复用引擎运行时校验（engine.ValidateTarget），
// 两端规则天然一致。
func checkTargetFormat(transport, target string) bool {
	return engine.ValidateTarget(transport, target) == nil
}
