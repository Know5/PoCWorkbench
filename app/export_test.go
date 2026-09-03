package app

import (
	"os"
	"path/filepath"
	"pocworkbench/internal/model"
	"strings"
	"testing"
)

const expTmpl = `id: export-test
name: 导出测试
transport: http
rules:
  r:
    request: {method: GET, path: /a}
    expression: response.status == 200
expression: r()
`

// 批量导出：uid 列表合并为 --- 分隔 YAML；坏 uid 跳过不中断。
func TestExportPocs(t *testing.T) {
	a := newApp(t)
	var uids []string
	for i := 0; i < 2; i++ {
		// spec 去重按内容哈希：两条 path 不同才不会被挡
		tmpl := strings.Replace(expTmpl, "path: /a", "path: /a"+string(rune('a'+i)), 1)
		d, err := a.ConvertTemplate(tmpl)
		if err != nil {
			t.Fatal(err)
		}
		uid, err := a.CreatePoc(d)
		if err != nil {
			t.Fatal(err)
		}
		uids = append(uids, uid)
	}
	dest := filepath.Join(t.TempDir(), "export.yaml")
	n, err := a.ExportPocs([]string{uids[0], "ghost-uid", uids[1]}, dest)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("导出数量应为 2（坏 uid 跳过）: %d", n)
	}
	data, rerr := os.ReadFile(dest)
	if rerr != nil {
		t.Fatal(rerr)
	}
	txt := string(data)
	if strings.Count(txt, "---") != 2 {
		t.Fatalf("应有两个文档分隔符:\n%s", txt)
	}
	if !strings.Contains(txt, uids[0]) || !strings.Contains(txt, uids[1]) {
		t.Fatal("两个 uid 都应在导出内容里")
	}
}

// 空列表与空路径应报错；导出的内容可被 ConvertTemplate 再次识别（往返可用）。
func TestExportPocsValidation(t *testing.T) {
	a := newApp(t)
	if _, err := a.ExportPocs(nil, "x.yaml"); err == nil {
		t.Fatal("空 uid 列表应报错")
	}
	d, err := a.ConvertTemplate(expTmpl)
	if err != nil {
		t.Fatal(err)
	}
	uid, err := a.CreatePoc(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.ExportPocs([]string{uid}, ""); err == nil {
		t.Fatal("空保存路径应报错")
	}
}

// dry-run 预览：与正式导入走同一遍历/转换/校验/查重，但不落库。
func TestImportTemplatesPreviewDryRun(t *testing.T) {
	a := newApp(t)
	root := t.TempDir()
	tpl := `id: preview-1
name: 预览测试
transport: http
rules:
  r:
    request: {method: GET, path: /pv}
    expression: response.status == 200
expression: r()
`
	if err := os.WriteFile(filepath.Join(root, "ok.yaml"), []byte(tpl), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bad.yaml"), []byte("id: x\nrules: ["), 0o644); err != nil {
		t.Fatal(err)
	}

	// 预览：1 可导入 + 1 失败，库中零条
	res, err := a.ImportTemplatesPreview(root)
	if err != nil {
		t.Fatal(err)
	}
	if res.Created != 1 || res.Failed != 1 || res.Skipped != 0 {
		t.Fatalf("预览三态不符: %+v", res)
	}
	if n := countPocs(t, a); n != 0 {
		t.Fatalf("dry-run 绝不落库: %d", n)
	}

	// 正式导入后：库里 1 条；再预览 → 该文件变 skipped
	if _, err := a.ImportTemplates(root); err != nil {
		t.Fatal(err)
	}
	if n := countPocs(t, a); n != 1 {
		t.Fatalf("正式导入应有 1 条: %d", n)
	}
	res2, err := a.ImportTemplatesPreview(root)
	if err != nil {
		t.Fatal(err)
	}
	if res2.Skipped != 1 || res2.Created != 0 {
		t.Fatalf("重复导入预览应 skipped: %+v", res2)
	}
}

func countPocs(t *testing.T, a *App) int {
	t.Helper()
	ps, err := a.ListPocs(model.Filter{}, model.Page{Number: 1, Size: 10, Sort: "updated_desc"})
	if err != nil {
		t.Fatal(err)
	}
	return len(ps.Items)
}
