package app

import (
	"strings"
	"testing"
	"unicode/utf8"

	"pocworkbench/internal/engine"
)

func TestSanitizeLogMasksSecrets(t *testing.T) {
	in := "POST /login\npassword=hunter2\ntoken: abc123\nX-Api-Key: xyz\nsecret=\"v3ry\""
	out := sanitizeLog(in)
	for _, secret := range []string{"hunter2", "abc123", "xyz", "v3ry"} {
		if strings.Contains(out, secret) {
			t.Fatalf("敏感值 %q 未脱敏:\n%s", secret, out)
		}
	}
	for _, want := range []string{"password=***", "token=***", "X-Api-Key=***"} {
		if !strings.Contains(out, want) {
			t.Fatalf("缺少脱敏标记 %q:\n%s", want, out)
		}
	}
}

func TestSanitizeLogSizeCapRuneSafe(t *testing.T) {
	// 多字节 rune 填充到超过 5MB 上限，截断边界必须落在合法 UTF-8 上
	big := strings.Repeat("响应内容λ", 1<<20)
	out := sanitizeLog(big)
	if !strings.HasSuffix(out, "(truncated)") {
		t.Fatal("超限日志应带截断标记")
	}
	body := strings.TrimSuffix(out, "\n...(truncated)")
	if !utf8.ValidString(body) {
		t.Fatalf("截断不应切断 UTF-8 rune（len=%d）", len(body))
	}
	if sanitizeLog("short log") != "short log" {
		t.Fatal("未超限日志应原样保留")
	}
}

func TestHostOf(t *testing.T) {
	cases := map[string]string{
		"http://a.com/path?q=1": "a.com",
		"http://a.com:8080/x":   "a.com:8080",
		"https://[::1]:9/x":     "[::1]:9",
		"a.com:8080":            "a.com:8080",
		"[::1]:9":               "[::1]:9",
		"http://A.com/x":        "A.com", // 保持原文不做大小写改写
	}
	for in, want := range cases {
		if got := hostOf(in); got != want {
			t.Errorf("hostOf(%q) = %q, want %q", in, got, want)
		}
	}
}

// 批量目标预筛与引擎共用同一校验源（engine.ValidateTarget），此处锁定两端判定口径。
func TestCheckTargetFormat(t *testing.T) {
	httpOK := []string{"http://a.com", "https://a.com:8443/p", "HTTP://A.COM"}
	httpBad := []string{"ftp://x", "-flag-inject", "http://", "a.com"}
	for _, tc := range httpOK {
		if !checkTargetFormat("http", tc) || engine.ValidateTarget("http", tc) != nil {
			t.Errorf("http 目标 %q 应为合法", tc)
		}
	}
	for _, tc := range httpBad {
		if checkTargetFormat("http", tc) || engine.ValidateTarget("http", tc) == nil {
			t.Errorf("http 目标 %q 应为非法", tc)
		}
	}

	tcpOK := []string{"1.2.3.4:80", "rsync.local:873", "[::1]:9", "http://h:8080"}
	tcpBad := []string{":80", "noport", "http://h"}
	for _, tc := range tcpOK {
		if !checkTargetFormat("tcp", tc) || engine.ValidateTarget("tcp", tc) != nil {
			t.Errorf("tcp 目标 %q 应为合法", tc)
		}
	}
	for _, tc := range tcpBad {
		if checkTargetFormat("tcp", tc) || engine.ValidateTarget("tcp", tc) == nil {
			t.Errorf("tcp 目标 %q 应为非法", tc)
		}
	}
}

func TestContainsFoldAndAny(t *testing.T) {
	if !containsFold("OpenSSH", "opens") || containsFold("nginx", "apache") {
		t.Fatal("containsFold 行为异常")
	}
	if !containsAny([]string{"CVE-2025-1234", "内部编号"}, "cve") {
		t.Fatal("containsAny 应命中别名子串")
	}
}
