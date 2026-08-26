package convert

import (
	"strings"
	"testing"
)

// 用户真实样例：XWiki CVE-2025-24893（http）
const xrayXwiki = `id: VUL-2025-32520
name: CVE-2025-24893
tags:
  - cve
  - cve2025
  - xwiki
  - rce
transport: http
rules:
  r0:
    request:
      path: /bin/get/Main/SolrSearch?media=rss&text=payload
      method: GET
    expression: response.status == 200 && 'root:.*:0:0'.bmatches(response.body) && response.body.bcontains(b"wiki")
  r1:
    request:
      path: /xwiki/bin/get/Main/SolrSearch?media=rss&text=payload
      method: GET
    expression: response.status == 200 && 'root:.*:0:0'.bmatches(response.body)
expression: r0() || r1()
detail:
  fingerprint:
    softhard: ""
    product: xwiki
    company: xwiki
    category: ""
    parent_category: ""
  vulnerability:
    proof:
      info: 存在(CVE-2025-24893)XWiki SolrSearch接口远程命令执行漏洞
`

// 用户真实样例：rsync 未授权（tcp，含 set/output/needreverse 特性）
const xrayRsync = `id: VUL-2023-02063
name: yingyongruanjian-rsync_unauthorized
tags:
    - rsync
transport: tcp
set: null
rules:
    req:
        request:
            inputs:
               - data: "@RSYNCD: 31.0\n\n"
            read_timeout: 3
        expression: 'response.raw.bcontains(b"@RSYNCD: ") && response.raw.bcontains(b"@RSYNCD: EXIT")'
        output:
             matches: response.raw
expression: req()
detail:
    fingerprint:
        softhard: ""
        product: ""
        company: ""
        category: ""
        parent_category: ""
    vulnerability:
        proof:
            info: 存在rsync未授权访问漏洞
needreverse: false
`

func TestConvertXwiki(t *testing.T) {
	d, err := XrayToDraft(xrayXwiki)
	if err != nil {
		t.Fatalf("转换失败: %v", err)
	}
	if d.Name != "CVE-2025-24893" {
		t.Errorf("name = %q", d.Name)
	}
	if d.Vendor != "xwiki" || d.Product != "xwiki" {
		t.Errorf("vendor/product = %q/%q", d.Vendor, d.Product)
	}
	if d.CVE != "CVE-2025-24893" {
		t.Errorf("cve 抽取失败: %q", d.CVE)
	}
	if d.Category != "rce" {
		t.Errorf("category 推断失败: %q", d.Category)
	}
	if len(d.Aliases) < 2 { // id + CVE
		t.Errorf("aliases 数量不足: %v", d.Aliases)
	}
	if !strings.Contains(d.SpecYAML, "transport: http") {
		t.Error("spec 缺少 transport")
	}
}

func TestConvertRsync(t *testing.T) {
	d, err := XrayToDraft(xrayRsync)
	if err != nil {
		t.Fatalf("转换失败: %v", err)
	}
	if d.Name != "rsync_unauthorized" {
		t.Errorf("前缀清洗失败: %q", d.Name)
	}
	if d.Vendor != "UNKNOWN" || d.Product != "UNKNOWN" {
		t.Errorf("空 fingerprint 应回退 UNKNOWN: %q/%q", d.Vendor, d.Product)
	}
	if d.Category != "unauth" {
		t.Errorf("category 推断失败: %q", d.Category)
	}
	foundSetWarn := false
	for _, w := range d.Warnings {
		if strings.Contains(w, "set") || strings.Contains(w, "output") || strings.Contains(w, "needreverse") {
			foundSetWarn = true
		}
	}
	if !foundSetWarn {
		t.Errorf("不支持特性应有警告: %v", d.Warnings)
	}
	if !strings.Contains(d.SpecYAML, "read_timeout: 3") {
		t.Error("read_timeout 未映射")
	}
}

func TestConvertRejectsEmpty(t *testing.T) {
	if _, err := XrayToDraft(""); err == nil {
		t.Fatal("空输入应报错")
	}
	noRules := "id: x\nname: x\ntransport: http\n"
	if _, err := XrayToDraft(noRules); err == nil {
		t.Fatal("缺 rules 应报错")
	}
}
