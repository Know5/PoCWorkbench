package store

import (
	"path/filepath"
	"testing"

	"pocworkbench/internal/model"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("打开失败: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func draft(name, spec string) *model.Draft {
	return &model.Draft{
		Name: name, Aliases: []string{"CVE-2025-24893"}, Severity: "critical",
		Category: "rce", Vendor: "XWiki", Product: "XWiki Platform",
		Tags: []string{"cve", "xwiki"}, Desc: "测试描述", CVE: "CVE-2025-24893",
		Status: "untested", Source: "xray", Kind: "template", SpecYAML: spec,
	}
}

const specA = `transport: http
rules:
  r0:
    request:
      method: GET
      path: /a
    expression: response.status == 200
expression: r0()
`

const specB = `transport: tcp
rules:
  req:
    request:
      inputs:
        - data: "@RSYNCD: 31.0\n\n"
      read_timeout: 3
    expression: response.raw.bcontains(b'@RSYNCD: ')
expression: req()
`

func mustInsert(t *testing.T, s *Store, uid string, d *model.Draft, spec string) {
	t.Helper()
	ok, err := s.InsertPoc(uid, d, spec)
	if err != nil || !ok {
		t.Fatalf("插入 %s 失败 ok=%v err=%v", uid, ok, err)
	}
}

func TestInsertAndList(t *testing.T) {
	s := openTest(t)
	mustInsert(t, s, "uid-1", draft("Poc A", specA), specA)

	ok2, err := s.InsertPoc("uid-2", draft("Poc A2", specA), specA)
	if err != nil {
		t.Fatal(err)
	}
	if ok2 {
		t.Fatal("同 sha256 应判重")
	}

	items, total, err := s.ListPocs(model.Filter{}, model.Page{Number: 1, Size: 10})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(items) != 1 || items[0].Name != "Poc A" {
		t.Fatalf("列表异常: total=%d items=%v", total, items)
	}
	if items[0].Vendor != "XWiki" {
		t.Errorf("vendor 联查失败: %q", items[0].Vendor)
	}
}

func TestSearchFTSAndLike(t *testing.T) {
	s := openTest(t)
	mustInsert(t, s, "uid-1", draft("Poc A", specA), specA)

	d2 := draft("rsync 未授权检测", specB)
	d2.Vendor = "UNKNOWN"
	d2.Severity = "high"
	d2.Category = "unauth"
	d2.CVE = ""
	d2.Aliases = []string{"VUL-2023-02063"}
	mustInsert(t, s, "uid-2", d2, specB)

	// FTS：≥3 字符中文词
	uids, err := s.searchUIDs("未授权")
	if err != nil {
		t.Fatal(err)
	}
	if len(uids) != 1 || uids[0] != "uid-2" {
		t.Errorf("FTS 中文检索失败: %v", uids)
	}
	// LIKE 回退：2 字符词
	uids, err = s.searchUIDs("授权")
	if err != nil {
		t.Fatal(err)
	}
	if len(uids) != 1 || uids[0] != "uid-2" {
		t.Errorf("LIKE 回退失败: %v", uids)
	}
	// 多词 AND
	uids, err = s.searchUIDs("rsync 未授权")
	if err != nil {
		t.Fatal(err)
	}
	if len(uids) != 1 || uids[0] != "uid-2" {
		t.Errorf("多词检索失败: %v", uids)
	}
}

func TestArchiveFilterAndDelete(t *testing.T) {
	s := openTest(t)
	mustInsert(t, s, "uid-1", draft("Poc A", specA), specA)

	if err := s.SetStatus("uid-1", "archived"); err != nil {
		t.Fatal(err)
	}
	_, total, _ := s.ListPocs(model.Filter{}, model.Page{Number: 1, Size: 10})
	if total != 0 {
		t.Fatal("archived 应被默认过滤")
	}
	if err := s.DeletePoc("uid-1"); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(1) FROM poc`).Scan(&n)
	if n != 0 {
		t.Fatal("删除后应无记录")
	}
}

func TestDictMergeRefreshesFts(t *testing.T) {
	s := openTest(t)
	d := draft("Poc A", specA)
	d.Vendor = "xwiki"
	mustInsert(t, s, "uid-1", d, specA)

	if _, err := s.ensureVendor("XWiki"); err != nil {
		t.Fatal(err)
	}
	if err := s.MergeVendorAlias("XWiki", "xwiki"); err != nil {
		t.Fatal(err)
	}
	items, _, _ := s.ListPocs(model.Filter{Query: "XWiki"}, model.Page{Number: 1, Size: 10})
	if len(items) != 1 {
		t.Fatalf("字典归并后 FTS 应可按新规范名命中: %v", items)
	}
}

func TestGetPocRoundTrip(t *testing.T) {
	s := openTest(t)
	mustInsert(t, s, "uid-1", draft("Poc A", specA), specA)

	p, err := s.GetPoc("uid-1")
	if err != nil {
		t.Fatal(err)
	}
	if p.Metadata.Name != "Poc A" || p.Spec.Transport != "http" {
		t.Fatalf("往返不一致: %+v", p.Metadata)
	}
	if len(p.Spec.Rules) != 1 {
		t.Fatalf("rules 解析失败: %v", p.Spec.Rules)
	}
}

func TestBackup(t *testing.T) {
	s := openTest(t)
	mustInsert(t, s, "uid-1", draft("Poc A", specA), specA)

	dest := filepath.Join(t.TempDir(), "backup.db")
	if err := s.BackupDB(dest); err != nil {
		t.Fatalf("备份失败: %v", err)
	}
	s2, err := Open(dest)
	if err != nil {
		t.Fatalf("备份库打不开: %v", err)
	}
	defer s2.Close()
	_, total, _ := s2.ListPocs(model.Filter{}, model.Page{Number: 1, Size: 10})
	if total != 1 {
		t.Fatalf("备份数据不完整: total=%d", total)
	}
}

// 回归：ListPocs 按 vendor/product 筛选时，COUNT 查询此前缺 JOIN 直接报 no such column。
func TestListPocsFilterByVendorProduct(t *testing.T) {
	s := openTest(t)
	mustInsert(t, s, "uid-1", draft("Poc A", specA), specA)

	items, total, err := s.ListPocs(model.Filter{Vendor: "XWiki"}, model.Page{Number: 1, Size: 10})
	if err != nil {
		t.Fatalf("按厂商筛选不应报错: %v", err)
	}
	if total != 1 || len(items) != 1 {
		t.Fatalf("vendor 筛选应命中 1 条: total=%d len=%d", total, len(items))
	}
	items, total, err = s.ListPocs(model.Filter{Product: "XWiki Platform"}, model.Page{Number: 1, Size: 10})
	if err != nil {
		t.Fatalf("按产品筛选不应报错: %v", err)
	}
	if total != 1 {
		t.Fatalf("product 筛选应命中 1 条: total=%d", total)
	}
	_, total, err = s.ListPocs(model.Filter{Vendor: "不存在"}, model.Page{Number: 1, Size: 10})
	if err != nil || total != 0 {
		t.Fatalf("未知厂商应零命中且不报错: err=%v total=%d", err, total)
	}
}

// 回归：未归档记录删除必须被拒，且不得误删 FTS 行。
func TestDeletePocRejectsNonArchived(t *testing.T) {
	s := openTest(t)
	mustInsert(t, s, "uid-1", draft("Poc A", specA), specA)

	if err := s.DeletePoc("uid-1"); err == nil {
		t.Fatal("未归档删除应被拒绝")
	}
	// 主行仍在，FTS 行也必须仍在（此前无条件删 FTS 导致搜索丢条目）
	items, _, _ := s.ListPocs(model.Filter{Query: "Poc A"}, model.Page{Number: 1, Size: 10})
	if len(items) != 1 {
		t.Fatal("被拒删除后 FTS 应仍可检索到该 PoC")
	}
}

// 回归：UpdateMeta 必须在同一事务内同步 poc 与 poc_fts。
func TestUpdateMetaSyncsFts(t *testing.T) {
	s := openTest(t)
	mustInsert(t, s, "uid-1", draft("Poc A", specA), specA)

	d := draft("改名后的PoC", specA)
	d.Vendor = "XWiki"
	d.Product = "XWiki Platform"
	if err := s.UpdateMeta("uid-1", d); err != nil {
		t.Fatal(err)
	}
	if items, _ := searchAll(t, s, "改名后的PoC"); len(items) != 1 {
		t.Fatal("新名称应能被 FTS 命中")
	}
	if items, _ := searchAll(t, s, "Poc A"); len(items) != 0 {
		t.Fatal("旧名称不应再被 FTS 命中")
	}
}

func searchAll(t *testing.T, s *Store, q string) ([]model.Summary, error) {
	t.Helper()
	items, _, err := s.ListPocs(model.Filter{Query: q}, model.Page{Number: 1, Size: 10})
	return items, err
}

// 回归：ensureVendor 的别名解析此前条件反了（ErrNoRows 时跳过别名查询），
// 导致已存在别名时仍重复建厂商；LIKE 模式还曾丢引号退化为子串误匹配。
func TestEnsureVendorAliasResolution(t *testing.T) {
	s := openTest(t)
	mustInsert(t, s, "uid-1", draft("Poc A", specA), specA) // draft 默认 Vendor=XWiki

	// 把 "xwiki" 归并为 XWiki 的别名
	if err := s.MergeVendorAlias("XWiki", "xwiki"); err != nil {
		t.Fatal(err)
	}

	idXWiki, err := s.ensureVendor("XWiki")
	if err != nil {
		t.Fatal(err)
	}
	// 别名精确命中：返回既有厂商，不新建
	idAlias, err := s.ensureVendor("xwiki")
	if err != nil {
		t.Fatal(err)
	}
	if idAlias != idXWiki {
		t.Fatalf("别名 xwiki 应命中 XWiki(id=%d)，got=%d", idXWiki, idAlias)
	}
	// 子串不得误命中："Wiki" 是 "XWiki" 的子串，但不是完整别名 → 应新建
	idSub, err := s.ensureVendor("Wiki")
	if err != nil {
		t.Fatal(err)
	}
	if idSub == idXWiki {
		t.Fatal("子串 Wiki 不应误命中别名 XWiki")
	}
	// 通配符不得透传："_%Wiki" 里的 % 是字面量，不应匹配任何别名 → 新建
	idWild, err := s.ensureVendor("%XWiki")
	if err != nil {
		t.Fatal(err)
	}
	if idWild == idXWiki {
		t.Fatalf("通配符 %%XWiki 不应误命中别名 xwiki")
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(1) FROM vendor`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 3 { // XWiki + Wiki + %XWiki，不得有重复
		t.Fatalf("厂商数量应为 3（无重复），got=%d", n)
	}
}
