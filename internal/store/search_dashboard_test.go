package store

import (
	"fmt"
	"path/filepath"
	"testing"

	"pocworkbench/internal/model"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func addPoc(t *testing.T, s *Store, uid, name, vendor, product string) {
	t.Helper()
	d := &model.Draft{
		Name: name, Severity: "high", Category: "rce",
		Vendor: vendor, Product: product,
		Status: "untested", Source: "manual", Kind: "template",
		Tags: []string{"t"}, Desc: "desc",
	}
	spec := fmt.Sprintf("transport: http\nrules:\n  r0:\n    request:\n      method: GET\n      path: /%s\n    expression: response.status == 200\nexpression: r0()\n", uid)
	ok, err := s.InsertPoc(uid, d, spec)
	if err != nil || !ok {
		t.Fatalf("insert %s: err=%v ok=%v", uid, err, ok)
	}
}

// 短词（<3 字符）走 LIKE 回退分支，其检索字段必须与 FTS 分支一致——
// 都要覆盖 vendor / product。中文两字厂商名（华为、用友）正落在这个区间。
func TestShortWordSearchesVendorProduct(t *testing.T) {
	s := newStore(t)
	addPoc(t, s, "u1", "某系统远程命令执行", "华为", "USG")
	addPoc(t, s, "u2", "另一个漏洞", "用友", "NC")
	addPoc(t, s, "u3", "无关记录", "Oracle", "WebLogic")

	cases := []struct {
		query string
		want  int64
		note  string
	}{
		{"华为", 1, "两字厂商名（短词分支）"},
		{"用友", 1, "两字厂商名（短词分支）"},
		{"USG", 1, "三字产品名（FTS 分支）"},
		{"NC", 1, "两字产品名（短词分支）"},
		{"Oracle", 1, "长厂商名（FTS 分支）"},
		{"某系统 华为", 1, "长词+短词：两者分别命中 name 与 vendor"},
		{"另一个 用友", 1, "长词+短词组合"},
		{"某系统 用友", 0, "长词命中 u1、短词命中 u2，交集应为空"},
	}
	for _, c := range cases {
		_, total, err := s.ListPocs(model.Filter{Query: c.query}, model.Page{Number: 1, Size: 20})
		if err != nil {
			t.Errorf("query %q 出错: %v", c.query, err)
			continue
		}
		if total != c.want {
			t.Errorf("query %q (%s): want total=%d got %d", c.query, c.note, c.want, total)
		}
	}
}

// Dashboard 的口径必须自洽：totalPocs 与 bySeverity / topVendors 同为「不含归档」，
// 归档数另行给出。否则首页头部数字与下方图表对不上。
func TestDashboardArchivedConsistency(t *testing.T) {
	s := newStore(t)
	for i := 0; i < 5; i++ {
		addPoc(t, s, fmt.Sprintf("u%d", i), fmt.Sprintf("poc %d", i), "V", "P")
	}
	for _, u := range []string{"u0", "u1"} {
		if err := s.SetStatus(u, "archived"); err != nil {
			t.Fatal(err)
		}
	}

	d, err := s.Dashboard()
	if err != nil {
		t.Fatal(err)
	}
	var sevSum, vendorSum int64
	for _, n := range d.BySeverity {
		sevSum += n
	}
	for _, vc := range d.TopVendors {
		vendorSum += vc.Count
	}

	if d.TotalPocs != 3 {
		t.Errorf("totalPocs 应为未归档数 3, got %d", d.TotalPocs)
	}
	if sevSum != d.TotalPocs {
		t.Errorf("bySeverity 之和(%d) 应等于 totalPocs(%d)", sevSum, d.TotalPocs)
	}
	if vendorSum != d.TotalPocs {
		t.Errorf("topVendors 之和(%d) 应等于 totalPocs(%d)", vendorSum, d.TotalPocs)
	}
	if d.ArchivedPocs != 2 {
		t.Errorf("archivedPocs 应为 2, got %d", d.ArchivedPocs)
	}
	// byStatus 是状态分布，仍应完整含归档
	if d.ByStatus["archived"] != 2 || d.ByStatus["untested"] != 3 {
		t.Errorf("byStatus 应完整反映各状态: %v", d.ByStatus)
	}
}

// 全部归档时 totalPocs 为 0，但 archivedPocs 非 0——
// 前端据此区分「真空库」与「全部已归档」，不能一律显示「库还是空的」。
func TestDashboardAllArchived(t *testing.T) {
	s := newStore(t)
	addPoc(t, s, "u1", "only one", "V", "P")
	if err := s.SetStatus("u1", "archived"); err != nil {
		t.Fatal(err)
	}
	d, err := s.Dashboard()
	if err != nil {
		t.Fatal(err)
	}
	if d.TotalPocs != 0 || d.ArchivedPocs != 1 {
		t.Errorf("want totalPocs=0 archivedPocs=1, got %d/%d", d.TotalPocs, d.ArchivedPocs)
	}
}
