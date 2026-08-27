// Package app 是 Wails 绑定层：薄封装，业务在 internal 各包。
package app

import (
	"context"
	"fmt"
	"github.com/wailsapp/wails/v2/pkg/runtime"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	yml "gopkg.in/yaml.v3"
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
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = "."
	}
	dbDir := filepath.Join(dir, "PoCWorkbench")
	if err := os.MkdirAll(dbDir, 0o755); err != nil {
		return err
	}
	s, err := store.Open(filepath.Join(dbDir, "pocwb.db"))
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
	a.cancelMu.Lock()
	for _, c := range a.batchCancels {
		c()
	}
	for _, c := range a.cancels {
		c()
	}
	a.cancelMu.Unlock()
	// 有界等待在跑任务落库：正常秒级完成；极端卡死时不无限拖住进程退出（最多 10s）
	done := make(chan struct{})
	go func() {
		a.runsWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
	}
	if a.store != nil {
		a.store.Close()
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
		res := a.engine.RunSink(ctx, &p.Spec, target, proxy, sink)

		host := hostOf(target)
		tr := &model.TestRun{
			PocUID: uid, Target: target, TargetHost: host,
			Result: res.Result, Log: sanitizeLog(res.Log),
			Authorized: authorized, StartedAt: nowRFC(), EndedAt: ptrNowRFC(),
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

// ---- 统计与维护 ----

func (a *App) Dashboard() (*model.Dashboard, error) {
	if err := a.requireStore(); err != nil {
		return nil, err
	}
	return a.store.Dashboard()
}

// BackupDB 备份到用户配置目录，返回备份文件路径。
func (a *App) BackupDB() (string, error) {
	if err := a.requireStore(); err != nil {
		return "", err
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = "."
	}
	dest := filepath.Join(dir, "PoCWorkbench",
		fmt.Sprintf("pocwb-backup-%s.db", time.Now().Format("20060102-150405")))
	if err := a.store.BackupDB(dest); err != nil {
		return "", err
	}
	return dest, nil
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
			res := a.engine.RunSink(ctx, &p.Spec, target, proxy, sink)

			tr := &model.TestRun{
				PocUID: uid, Target: target, TargetHost: hostOf(target),
				Result: res.Result, Log: sanitizeLog(res.Log),
				Authorized: authorized, StartedAt: nowRFC(), EndedAt: ptrNowRFC(),
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
