package app

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"

	"pocworkbench/internal/convert"
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
func sanitizeLog(log string) string {
	log = secretRe.ReplaceAllString(log, `$1=***`)
	const maxLog = 5 << 20
	if len(log) > maxLog {
		return log[:maxLog] + "\n...(truncated)"
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

// checkTargetFormat 与引擎运行时校验规则一致，用于批量预筛。
func checkTargetFormat(transport, target string) bool {
	if transport == "http" {
		u, err := url.Parse(target)
		return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
	}
	t := target
	if i := strings.Index(t, "://"); i >= 0 {
		t = t[i+3:]
	}
	host, _, err := net.SplitHostPort(t)
	return err == nil && host != ""
}
