// Package app 是 Wails 绑定层：薄封装，业务在 internal 各包。
package app

import (
	"bytes"
	"context"
	"fmt"
	"github.com/wailsapp/wails/v2/pkg/runtime"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	yml "gopkg.in/yaml.v3"
	"pocworkbench/internal/convert"
	"pocworkbench/internal/engine"
	"pocworkbench/internal/model"
	"pocworkbench/internal/pwf"
	"pocworkbench/internal/store"
	"strings"
)

// Version 由构建注入：-ldflags "-X pocworkbench/app.Version=v1.0.0"，源码跑为 dev。
var Version = "dev"

type App struct {
	store  *store.Store
	engine *engine.Engine

	runSeq       atomic.Int64
	cancelMu     sync.Mutex
	cancels      map[int64]context.CancelFunc
	batchCancels map[string]context.CancelFunc
	runsWG       sync.WaitGroup // 跟踪 RunTest/RunTestBatch 后台 goroutine，Shutdown 时等待落库完成
	eventsMu     sync.Mutex
	emitEvent    func(event string, data ...any) // 由 main 注入 wails runtime
	startupErr   string                          // Startup 失败原因（StartupError 绑定读取）
	ctx          context.Context
}

func NewApp() *App {
	return &App{
		cancels:      map[int64]context.CancelFunc{},
		batchCancels: map[string]context.CancelFunc{},
	}
}

// SetEmitter 注入事件发送函数（wails runtime.EventsEmit）。
func (a *App) SetEmitter(fn func(event string, data ...any)) { a.emitEvent = fn }

func (a *App) emit(event string, data ...any) {
	a.eventsMu.Lock()
	fn := a.emitEvent
	a.eventsMu.Unlock()
	if fn != nil {
		fn(event, data...)
	}
}

// Startup 打开数据库（Wails OnStartup 调用）。
// 失败时错误同时留存于 startupErr 字段：OnStartup 阶段 emit 的事件先于前端监听器注册，
// 前端挂载后须经 StartupError() 绑定主动拉取才能看到。
func (a *App) Startup(ctx context.Context) (err error) {
	defer func() {
		if err != nil {
			a.startupErr = err.Error()
		}
	}()
	a.ctx = ctx
	a.SetEmitter(func(event string, data ...any) {
		runtime.EventsEmit(ctx, event, data...)
	})
	dir := userDBDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	s, err := store.Open(filepath.Join(dir, "pocwb.db"))
	if err != nil {
		return err
	}
	a.store = s
	a.engine = engine.New(engine.Options{RunTimeout: 60 * time.Second, MaxConc: 1})
	return nil
}

// AppVersion 返回构建时注入的版本号（设置页展示）。
func (a *App) AppVersion() string { return Version }

// StartupError 返回启动阶段错误（无错为空串），供前端挂载时拉取。
func (a *App) StartupError() string { return a.startupErr }

func (a *App) Shutdown() {
	a.cancelAllRuns()
	if a.store != nil {
		a.store.Close()
	}
}

// cancelAllRuns 取消全部进行中/排队的测试任务，并有限等待其落库完成。
// Shutdown 与 RestoreBackup（替换数据库前必须停写）共用。
func (a *App) cancelAllRuns() {
	a.cancelMu.Lock()
	for _, c := range a.batchCancels {
		c()
	}
	for _, c := range a.cancels {
		c()
	}
	a.cancelMu.Unlock()
	done := make(chan struct{})
	go func() {
		a.runsWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
	}
}

func (a *App) requireStore() error {
	if a.store == nil {
		return fmt.Errorf("应用尚未初始化完成")
	}
	return nil
}

// ---- 创建/编辑 ----

// ConvertXray 粘贴 Xray YAML → PWF 草稿（不落库）。
func (a *App) ConvertXray(yamlText string) (*model.Draft, error) {
	if len(yamlText) > 256<<10 {
		return nil, fmt.Errorf("输入超过 256KB 上限")
	}
	return convertXraySafe(yamlText)
}

// ConvertTemplate 自动识别 Xray / Nuclei 模板并转换为 PWF 草稿（不落库）。
// source 字段标记实际命中的格式；无法识别时显式报错。
func (a *App) ConvertTemplate(yamlText string) (*model.Draft, error) {
	if len(yamlText) > 256<<10 {
		return nil, fmt.Errorf("输入超过 256KB 上限")
	}
	switch convert.DetectFormat(yamlText) {
	case convert.FormatNuclei:
		return withParseRecover(func() (*model.Draft, error) { return convert.NucleiToDraft(yamlText) })
	case convert.FormatXray:
		return withParseRecover(func() (*model.Draft, error) { return convert.XrayToDraft(yamlText) })
	default:
		return nil, fmt.Errorf("无法识别模板格式（支持 Xray 与 Nuclei，请检查粘贴内容）")
	}
}

// CreatePoc 三关校验后入库，返回 uid。
func (a *App) CreatePoc(d *model.Draft) (string, error) {
	if err := a.requireStore(); err != nil {
		return "", err
	}
	if strings_Blank(d.Name) {
		return "", fmt.Errorf("name 必填")
	}
	switch d.Kind {
	case "script":
		if strings_Blank(d.SpecYAML) {
			return "", fmt.Errorf("脚本内容不能为空")
		}
		if len(d.SpecYAML) > 256<<10 {
			return "", fmt.Errorf("脚本内容超过 256KB 上限")
		}
		d.Source = orDefaultStr(d.Source, "manual")
	default:
		d.Kind = "template"
		canonical, err := pwf.ValidateSpec(d.SpecYAML)
		if err != nil {
			return "", err
		}
		d.SpecYAML = canonical
	}
	if !pwf.SeveritySet[d.Severity] {
		d.Severity = "info"
	}
	if !pwf.StatusSet[d.Status] {
		d.Status = "untested"
	}
	if d.Category == "" || !pwf.CategorySet[d.Category] {
		d.Category = "other"
	}
	uid := genUID()
	ok, err := a.store.InsertPoc(uid, d, d.SpecYAML)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("内容重复：相同 spec 已存在")
	}
	return uid, nil
}

// PickImportDir 弹出系统目录选择框；取消返回空串。
func (a *App) PickImportDir() (string, error) {
	if a.ctx == nil {
		return "", fmt.Errorf("应用尚未初始化完成")
	}
	return runtime.OpenDirectoryDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "选择模板目录（递归导入 .yaml/.yml）",
	})
}

// BatchImportResults 批量导入结果：每文件一行，失败含原因。
type BatchImportResults struct {
	Created int                `json:"created"`
	Skipped int                `json:"skipped"` // spec 重复（已有相同内容）
	Failed  int                `json:"failed"`
	Details []BatchImportEntry `json:"details"`
}

type BatchImportEntry struct {
	File   string `json:"file"`             // 相对导入根的路径
	Status string `json:"status"`           // created|skipped|failed
	Reason string `json:"reason,omitempty"` // skipped/failed 的原因
}

// ImportTemplatesPreview 批量导入 dry-run 预览：走与正式导入完全相同的
// 遍历/转换/三关校验/spec 查重，但不落库。前端确认后才调 ImportTemplates。
func (a *App) ImportTemplatesPreview(dir string) (*BatchImportResults, error) {
	return a.importTemplates(dir, true)
}

// ImportTemplates 批量导入目录下的模板文件（.yaml/.yml，递归）。
// 每文件独立处理：转换失败/校验失败/spec 重复只记录该文件，不中断整批。
// 上限：单文件 256KB（与粘贴一致）、单批 2000 文件（防误选超大目录拖死 UI）。
func (a *App) ImportTemplates(dir string) (*BatchImportResults, error) {
	return a.importTemplates(dir, false)
}

// importTemplates 公共实现：dryRun=true 只转换/校验/查重不落库。
func (a *App) importTemplates(dir string, dryRun bool) (*BatchImportResults, error) {
	if err := a.requireStore(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("未选择目录")
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return nil, fmt.Errorf("目录不可读: %s", dir)
	}
	var files []string
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if ext == ".yaml" || ext == ".yml" {
			files = append(files, path)
			if len(files) >= 2000 {
				return fs.SkipAll
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("遍历目录失败: %w", err)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("目录下没有 .yaml/.yml 模板文件")
	}

	res := &BatchImportResults{Details: []BatchImportEntry{}}
	for _, f := range files {
		rel, _ := filepath.Rel(dir, f)
		entry := BatchImportEntry{File: filepath.ToSlash(rel)}
		data, rerr := os.ReadFile(f)
		switch {
		case rerr != nil:
			entry.Status, entry.Reason = "failed", "读取失败: "+rerr.Error()
		case len(data) > 256<<10:
			entry.Status, entry.Reason = "failed", "超过 256KB 上限"
		default:
			entry.Status, entry.Reason = a.importOne(string(data), dryRun)
		}
		switch entry.Status {
		case "created":
			res.Created++
		case "skipped":
			res.Skipped++
		default:
			res.Failed++
		}
		res.Details = append(res.Details, entry)
	}
	return res, nil
}
// importOne 转换并（可选）入库单个模板；返回 (status, reason)。
// dryRun=true：转换 + 三关校验 + spec 查重，绝不写库。
func (a *App) importOne(yamlText string, dryRun bool) (string, string) {
	var draft *model.Draft
	switch convert.DetectFormat(yamlText) {
	case convert.FormatXray:
		d, err := convert.XrayToDraft(yamlText)
		if err != nil {
			return "failed", "Xray 转换失败: " + err.Error()
		}
		draft = d
	case convert.FormatNuclei:
		d, err := convert.NucleiToDraft(yamlText)
		if err != nil {
			return "failed", "Nuclei 转换失败: " + err.Error()
		}
		draft = d
	default:
		return "failed", "无法识别模板格式（支持 Xray 与 Nuclei）"
	}
	if dryRun {
		canonical, err := pwf.ValidateSpec(draft.SpecYAML)
		if err != nil {
			return "failed", err.Error()
		}
		exists, err := a.store.SpecExists(canonical)
		if err != nil {
			return "failed", "查重失败: " + err.Error()
		}
		if exists {
			return "skipped", "spec 内容重复，已存在"
		}
		return "created", ""
	}
	_, err := a.CreatePoc(draft)
	switch {
	case err == nil:
		return "created", ""
	case strings.Contains(err.Error(), "内容重复"):
		return "skipped", "spec 内容重复，已存在"
	default:
		return "failed", err.Error()
	}
}

// UpdatePocSpec 更新内容体：template 过三关校验；script 仅限空与大小（不做 PWF 校验）。
func (a *App) UpdatePocSpec(uid, specYAML string) error {
	if err := a.requireStore(); err != nil {
		return err
	}
	kind, err := a.store.KindOf(uid)
	if err != nil {
		return err
	}
	var canonical string
	switch kind {
	case "script":
		if strings.TrimSpace(specYAML) == "" {
			return fmt.Errorf("脚本内容不能为空")
		}
		if len(specYAML) > 256<<10 {
			return fmt.Errorf("脚本内容超过 256KB 上限")
		}
		canonical = specYAML
	default:
		canonical, err = pwf.ValidateSpec(specYAML)
		if err != nil {
			return err
		}
	}
	// 复用 Insert 的去重语义不可行（同 uid 更新），直接改列：
	return a.store.UpdateSpec(uid, canonical)
}

// UpdatePocMeta 更新元数据并同步 FTS。
func (a *App) UpdatePocMeta(uid string, d *model.Draft) error {
	if err := a.requireStore(); err != nil {
		return err
	}
	if !pwf.SeveritySet[d.Severity] {
		d.Severity = "info"
	}
	if !pwf.StatusSet[d.Status] {
		d.Status = "untested"
	}
	return a.store.UpdateMeta(uid, d)
}

// ---- 查询 ----

func (a *App) ListPocs(f model.Filter, pg model.Page) (*model.PagedSummary, error) {
	if err := a.requireStore(); err != nil {
		return nil, err
	}
	items, total, err := a.store.ListPocs(f, pg)
	if err != nil {
		return nil, err
	}
	if items == nil {
		items = []model.Summary{}
	}
	return &model.PagedSummary{Items: items, Total: total}, nil
}

func (a *App) GetPoc(uid string) (*model.Pwf, error) {
	if err := a.requireStore(); err != nil {
		return nil, err
	}
	return a.store.GetPoc(uid)
}

func (a *App) ArchivePoc(uid string) error    { return a.statusTo(uid, "archived") }
func (a *App) RestorePoc(uid string) error    { return a.statusTo(uid, "untested") }
func (a *App) SetStatus(uid, st string) error { return a.statusTo(uid, st) }

func (a *App) statusTo(uid, st string) error {
	if err := a.requireStore(); err != nil {
		return err
	}
	if !pwf.StatusSet[st] {
		return fmt.Errorf("非法状态 %q", st)
	}
	return a.store.SetStatus(uid, st)
}

func (a *App) DeletePoc(uid string) error {
	if err := a.requireStore(); err != nil {
		return err
	}
	return a.store.DeletePoc(uid)
}

// ---- 字典 ----

func (a *App) ListVendors() ([]model.Vendor, error) {
	if err := a.requireStore(); err != nil {
		return nil, err
	}
	vs, err := a.store.ListVendors()
	if vs == nil {
		vs = []model.Vendor{}
	}
	return vs, err
}

func (a *App) ListProducts(vendorID int64) ([]model.Product, error) {
	if err := a.requireStore(); err != nil {
		return nil, err
	}
	ps, err := a.store.ListProducts(vendorID)
	if ps == nil {
		ps = []model.Product{}
	}
	return ps, err
}

func (a *App) MergeVendorAlias(canonical, alias string) error {
	if err := a.requireStore(); err != nil {
		return err
	}
	return a.store.MergeVendorAlias(canonical, alias)
}

func (a *App) SetPocVendorProduct(uid, vendor, product string) error {
	if err := a.requireStore(); err != nil {
		return err
	}
	return a.store.SetPocVendorProduct(uid, vendor, product)
}

// SuggestVendorProduct 按文本前缀建议厂商/产品（自动补全数据源）。
func (a *App) SuggestVendorProduct(text string) ([]string, error) {
	if err := a.requireStore(); err != nil {
		return nil, err
	}
	vs, err := a.store.ListVendors()
	if err != nil {
		return nil, err
	}
	var out []string
	t := lower(text)
	for _, v := range vs {
		if t == "" || containsFold(v.CanonicalName, t) || containsAny(v.Aliases, t) {
			out = append(out, v.CanonicalName)
		}
	}
	return out, nil
}

// CompileRuleExpr 单条规则表达式即时校验。
func (a *App) CompileRuleExpr(expr string) error {
	return pwf.CheckRuleExpr(expr)
}

// CompileFinalExpr 总表达式校验（语法 + rule 引用）。
func (a *App) CompileFinalExpr(final string, ruleNames []string) error {
	return pwf.CheckFinalExpr(final, ruleNames)
}

// ---- 验证（自研引擎）----

// RunTest 异步执行：立即返回 runID；日志经 "test:log" 事件推送；结束经 "test:done"。
func (a *App) RunTest(uid, target, proxy string, authorized bool) (int64, error) {
	if err := a.requireStore(); err != nil {
		return 0, err
	}
	if !authorized {
		return 0, fmt.Errorf("未确认测试授权，拒绝执行")
	}
	p, err := a.store.GetPoc(uid)
	if err != nil {
		return 0, fmt.Errorf("PoC 不存在: %w", err)
	}
	if p.Metadata.Kind == "script" {
		return 0, fmt.Errorf("脚本类 PoC 不支持自动执行")
	}

	runID := a.runSeq.Add(1)
	ctx, cancel := context.WithCancel(context.Background())
	a.cancelMu.Lock()
	a.cancels[runID] = cancel
	a.cancelMu.Unlock()

	a.runsWG.Add(1)
	go func() {
		defer a.runsWG.Done()
		defer func() {
			a.cancelMu.Lock()
			delete(a.cancels, runID)
			a.cancelMu.Unlock()
			cancel()
		}()

		sink := func(line string) {
			a.emit("test:log", runID, line)
		}
		if proxy != "" {
			sink("proxy=" + proxy)
		}
		startedRFC := nowRFC() // goroutine 内即刻记录，勿在结束后取时间（否则与 EndedAt 几乎重合）
		res := a.engine.RunSink(ctx, &p.Spec, target, proxy, sink)

		host := hostOf(target)
		tr := &model.TestRun{
			PocUID: uid, Target: target, TargetHost: host,
			Result: res.Result, Log: sanitizeLog(res.Log),
			Authorized: authorized, StartedAt: startedRFC, EndedAt: ptrNowRFC(),
		}
		id, err := a.store.InsertTestRun(tr)
		if err == nil {
			tr.ID = id
			if res.Result == "hit" || res.Result == "miss" {
				_ = a.store.TouchTested(uid)
			}
		}
		a.emit("test:done", runID, tr, err)
	}()
	return runID, nil
}

// CancelTest 取消正在执行的测试。
func (a *App) CancelTest(runID int64) error {
	a.cancelMu.Lock()
	cancel, ok := a.cancels[runID]
	a.cancelMu.Unlock()
	if !ok {
		return fmt.Errorf("运行不存在或已结束")
	}
	cancel()
	return nil
}

func (a *App) ListTestRuns(uid string) ([]model.TestRun, error) {
	if err := a.requireStore(); err != nil {
		return nil, err
	}
	rs, err := a.store.ListTestRuns(uid)
	if rs == nil {
		rs = []model.TestRun{}
	}
	return rs, err
}

func (a *App) GetTestRun(id int64) (*model.TestRun, error) {
	if err := a.requireStore(); err != nil {
		return nil, err
	}
	return a.store.GetTestRun(id)
}

// ExportPoc 导出单个 PoC 的完整 PWF YAML（元数据 + spec；script 类导出原文）。
func (a *App) ExportPoc(uid string) (string, error) {
	if err := a.requireStore(); err != nil {
		return "", err
	}
	p, err := a.store.GetPoc(uid)
	if err != nil {
		return "", err
	}
	if p.Metadata.Kind == "script" {
		out, err := yml.Marshal(struct {
			Metadata *model.Metadata `yaml:"metadata"`
			Script   string          `yaml:"script"`
		}{&p.Metadata, p.SpecRaw})
		if err != nil {
			return "", err
		}
		return string(out), nil
	}
	out, err := yml.Marshal(p)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// PickExportFile 弹出系统保存框选择导出文件；取消返回空串。
func (a *App) PickExportFile(defaultName string) (string, error) {
	if a.ctx == nil {
		return "", fmt.Errorf("应用尚未初始化完成")
	}
	return runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           "导出 PoC（合并 YAML）",
		DefaultFilename: defaultName,
		Filters: []runtime.FileFilter{
			{DisplayName: "PWF YAML (*.yaml)", Pattern: "*.yaml"},
		},
	})
}

// ExportPocs 批量导出：按 uid 列表合并为单个 YAML（--- 分隔）写入 destPath。
// script 与 template 混排也正确：每条独立序列化；单条失败跳过不中断。
func (a *App) ExportPocs(uids []string, destPath string) (int, error) {
	if err := a.requireStore(); err != nil {
		return 0, err
	}
	if len(uids) == 0 {
		return 0, fmt.Errorf("未选择任何 PoC")
	}
	if strings.TrimSpace(destPath) == "" {
		return 0, fmt.Errorf("未选择保存路径")
	}
	ps, err := a.store.GetPocsByUIDs(uids)
	if err != nil {
		return 0, err
	}
	if len(ps) == 0 {
		return 0, fmt.Errorf("所选 PoC 均不存在")
	}
	var b strings.Builder
	for _, p := range ps {
		var out []byte
		var merr error
		if p.Metadata.Kind == "script" {
			out, merr = yml.Marshal(struct {
				Metadata *model.Metadata `yaml:"metadata"`
				Script   string          `yaml:"script"`
			}{&p.Metadata, p.SpecRaw})
		} else {
			out, merr = yml.Marshal(p)
		}
		if merr != nil {
			continue
		}
		b.WriteString("---\n")
		b.Write(out)
	}
	if b.Len() == 0 {
		return 0, fmt.Errorf("序列化全部失败")
	}
	if err := os.WriteFile(destPath, []byte(b.String()), 0o644); err != nil {
		return 0, fmt.Errorf("写文件失败: %w", err)
	}
	return len(ps), nil
}

// ---- 统计与维护 ----

func (a *App) Dashboard() (*model.Dashboard, error) {
	if err := a.requireStore(); err != nil {
		return nil, err
	}
	return a.store.Dashboard()
}

// backupKeep 备份保留份数：超出最新 N 份的旧备份在每次备份后清理。
const backupKeep = 10

func userDBDir() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = "."
	}
	return filepath.Join(dir, "PoCWorkbench")
}

// BackupDB 备份到用户配置目录，返回备份文件路径；随后清理超出保留份数的旧备份。
func (a *App) BackupDB() (string, error) {
	if err := a.requireStore(); err != nil {
		return "", err
	}
	dest := filepath.Join(userDBDir(),
		fmt.Sprintf("pocwb-backup-%s.db", time.Now().Format("20060102-150405")))
	if err := a.store.BackupDB(dest); err != nil {
		return "", err
	}
	pruneBackups(userDBDir())
	return dest, nil
}

// pruneBackups 按 mtime 倒序保留最新 backupKeep 份备份，其余删除（删除失败静默，不影响主流程）。
func pruneBackups(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	type backupFile struct{ path string; mod time.Time }
	var bks []backupFile
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, "pocwb-backup-") || !strings.HasSuffix(name, ".db") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		bks = append(bks, backupFile{filepath.Join(dir, name), info.ModTime()})
	}
	sort.Slice(bks, func(i, j int) bool { return bks[i].mod.After(bks[j].mod) })
	for i := backupKeep; i < len(bks); i++ {
		_ = os.Remove(bks[i].path)
	}
}

// PickRestoreFile 弹出系统文件选择框选取备份文件；取消返回空串。
func (a *App) PickRestoreFile() (string, error) {
	if a.ctx == nil {
		return "", fmt.Errorf("应用尚未初始化完成")
	}
	return runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "选择备份文件",
		Filters: []runtime.FileFilter{
			{DisplayName: "SQLite 数据库 (*.db)", Pattern: "*.db"},
		},
	})
}

// RestoreBackup 用备份文件替换当前数据库并重新打开。进行中的测试将被取消。
// 流程：文件头与可开性校验（在临时副本上）→ 现库改名留档 → 覆盖 → 重开；
// 重开失败自动回退到原库。成功后前端刷新页面加载新数据。
func (a *App) RestoreBackup(path string) error {
	if err := a.requireStore(); err != nil {
		return err
	}
	dbPath := filepath.Join(userDBDir(), "pocwb.db")

	// 文件头校验：拒绝任意非 SQLite 文件顶替
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("无法读取备份文件: %w", err)
	}
	if info.Size() < 100 {
		return fmt.Errorf("备份文件过小，不是有效的 SQLite 库")
	}
	hdr := make([]byte, 16)
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("无法读取备份文件: %w", err)
	}
	n, _ := io.ReadFull(f, hdr)
	_ = f.Close()
	if n != 16 || !bytes.Equal(hdr, []byte("SQLite format 3\x00")) {
		return fmt.Errorf("文件头不符合 SQLite 格式，拒绝恢复")
	}
	// 在临时副本上完整打开验证（迁移只发生在副本上），确认核心表可用
	if err := verifySQLiteCopy(path); err != nil {
		return fmt.Errorf("备份验证失败: %w", err)
	}

	// 停写并等待在跑任务落库，避免覆盖时丢数据或锁冲突
	a.cancelAllRuns()

	pre := dbPath + ".pre-restore"
	_ = os.Remove(pre)
	if err := a.store.Close(); err != nil {
		return fmt.Errorf("关闭当前数据库失败: %w", err)
	}
	renameFailed := false
	if err := os.Rename(dbPath, pre); err != nil {
		if !os.IsNotExist(err) {
			renameFailed = true
		}
	}
	if renameFailed {
		if s2, oe := store.Open(dbPath); oe == nil {
			a.store = s2 // 尽力回到原现场
		} else {
			a.startupErr = "数据库重开失败: " + oe.Error()
		}
		return fmt.Errorf("预留当前数据库失败: %w", err)
	}
	if err := copyFile(path, dbPath); err != nil {
		os.Remove(dbPath)
		_ = os.Rename(pre, dbPath)
		if s2, oe := store.Open(dbPath); oe == nil {
			a.store = s2
		} else {
			a.startupErr = "数据库重开失败: " + oe.Error()
		}
		return fmt.Errorf("写入新数据库失败: %w", err)
	}
	s2, err := store.Open(dbPath)
	if err != nil {
		// 新库打不开：回退原库
		os.Remove(dbPath)
		_ = os.Rename(pre, dbPath)
		if s3, oe := store.Open(dbPath); oe == nil {
			a.store = s3
			return fmt.Errorf("恢复后的数据库无法打开（已回退原库）: %w", err)
		}
		a.startupErr = "数据库重开失败: " + err.Error()
		return fmt.Errorf("恢复后的数据库无法打开且回退失败: %w", err)
	}
	a.store = s2
	_ = os.Remove(pre)
	a.emit("db:restored")
	return nil
}

// verifySQLiteCopy 把候选备份拷贝到临时目录并完整打开+健康检查，验证其确实可用。
func verifySQLiteCopy(src string) error {
	tmp := filepath.Join(os.TempDir(), fmt.Sprintf("pocwb-verify-%d.db", time.Now().UnixNano()))
	defer func() {
		_ = os.Remove(tmp)
		_ = os.Remove(tmp + "-wal")
		_ = os.Remove(tmp + "-shm")
	}()
	if err := copyFile(src, tmp); err != nil {
		return err
	}
	vs, err := store.Open(tmp) // 迁移只在副本上执行，不触碰原备份
	if err != nil {
		return err
	}
	defer vs.Close()
	return vs.HealthCheck()
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// ── 批量测试：单 PoC × 多目标 ─────────────────────────

// BatchTargetResult 单个目标的批量结果行。
type BatchTargetResult struct {
	Target string `json:"target"`
	Result string `json:"result"` // hit|miss|error|timeout|cancelled
}

// BatchStart 批量任务启动返回：batchID 与预检剔除的非法目标。
// Wails 绑定契约只保证「无值/单值/(值,error)」，多返回值行为不受约束，故收拢为结构体。
type BatchStart struct {
	ID      string   `json:"id"`
	Invalid []string `json:"invalid"`
}

// RunTestBatch 对多目标顺序执行同一 PoC；立即返回 batchID 与非法目标列表。
// 事件流："batch:log"(id,line) / "batch:result"(id,row) / "batch:progress"(id,done,total) / "batch:done"(id,total,hits)
func (a *App) RunTestBatch(uid string, targets []string, proxy string, authorized bool) (BatchStart, error) {
	if err := a.requireStore(); err != nil {
		return BatchStart{}, err
	}
	if !authorized {
		return BatchStart{}, fmt.Errorf("未确认测试授权，拒绝执行")
	}
	p, err := a.store.GetPoc(uid)
	if err != nil {
		return BatchStart{}, fmt.Errorf("PoC 不存在: %w", err)
	}
	if p.Metadata.Kind == "script" {
		return BatchStart{}, fmt.Errorf("脚本类 PoC 不支持自动执行")
	}

	valid := make([]string, 0, len(targets))
	invalid := []string{}
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if checkTargetFormat(p.Spec.Transport, t) {
			valid = append(valid, t)
		} else {
			invalid = append(invalid, t)
		}
	}
	if len(valid) == 0 {
		return BatchStart{Invalid: invalid}, fmt.Errorf("没有合法目标（http 目标须为 http/https URL，tcp 须为 host:port）")
	}
	id := fmt.Sprintf("batch-%d", time.Now().UnixNano())
	ctx, cancel := context.WithCancel(context.Background())
	a.cancelMu.Lock()
	a.batchCancels[id] = cancel
	a.cancelMu.Unlock()

	a.runsWG.Add(1)
	go func() {
		defer a.runsWG.Done()
		defer func() {
			a.cancelMu.Lock()
			delete(a.batchCancels, id)
			a.cancelMu.Unlock()
			cancel()
		}()

		hits := 0
		for i, target := range valid {
			select {
			case <-ctx.Done():
				// 契约统一为 (id, total, hits, status)；取消时已完成 i 个
				a.emit("batch:done", id, len(valid), hits, "cancelled")
				return
			default:
			}
			idx := i + 1
			sink := func(line string) {
				a.emit("batch:log", id, "["+strconv.Itoa(idx)+"] "+line)
			}
			startedRFC := nowRFC() // 每个目标在执行前记录开始时刻
			res := a.engine.RunSink(ctx, &p.Spec, target, proxy, sink)

			tr := &model.TestRun{
				PocUID: uid, Target: target, TargetHost: hostOf(target),
				Result: res.Result, Log: sanitizeLog(res.Log),
				Authorized: authorized, StartedAt: startedRFC, EndedAt: ptrNowRFC(),
			}
			if _, err := a.store.InsertTestRun(tr); err == nil {
				if res.Result == "hit" || res.Result == "miss" {
					_ = a.store.TouchTested(uid)
				}
			}
			if res.Result == "hit" {
				hits++
			}
			a.emit("batch:result", id, BatchTargetResult{Target: target, Result: res.Result})
			a.emit("batch:progress", id, idx, len(valid))
		}
		a.emit("batch:done", id, len(valid), hits, "finished")
	}()
	return BatchStart{ID: id, Invalid: invalid}, nil
}

// CancelBatch 取消进行中的批量任务。
func (a *App) CancelBatch(id string) error {
	a.cancelMu.Lock()
	cancel, ok := a.batchCancels[id]
	a.cancelMu.Unlock()
	if !ok {
		return fmt.Errorf("批量任务不存在或已结束")
	}
	cancel()
	return nil
}
