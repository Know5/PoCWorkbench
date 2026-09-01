// Package model 定义 PWF（PoC Workbench Format）结构与前后端 DTO。
package model

// Pwf 完整 PoC 记录（存储与详情返回形态）。
type Pwf struct {
	Metadata Metadata `json:"metadata" yaml:"metadata"`
	Spec     Spec     `json:"spec" yaml:"spec"`
	// SpecRaw 存储原文：script 类为任意脚本内容，template 恒为空（内容走 Spec）。
	SpecRaw string `json:"specRaw,omitempty" yaml:"specRaw,omitempty"`
}

// Metadata PWF 元数据块（存储列的内存形态）。
type Metadata struct {
	UID          string   `json:"uid"`
	Name         string   `json:"name"`
	Aliases      []string `json:"aliases"`
	Severity     string   `json:"severity"`
	Category     string   `json:"category"`
	Vendor       string   `json:"vendor"`
	Product      string   `json:"product"`
	Tags         []string `json:"tags"`
	Description  string   `json:"description"`
	CVE          string   `json:"cve"`
	Status       string   `json:"status"`
	Source       string   `json:"source"`
	Kind         string   `json:"kind"`
	CreatedAt    string   `json:"createdAt"`
	UpdatedAt    string   `json:"updatedAt"`
	LastTestedAt *string  `json:"lastTestedAt"`
}

// Draft 创建/编辑时的草稿形态：元数据 + spec 的 YAML 文本。
// 前端两条入口（粘贴转换 / 手动向导）最终都产出 Draft。
type Draft struct {
	UID      string   `json:"uid,omitempty"`
	Name     string   `json:"name"`
	Aliases  []string `json:"aliases"`
	Severity string   `json:"severity"`
	Category string   `json:"category"`
	Vendor   string   `json:"vendor"`
	Product  string   `json:"product"`
	Tags     []string `json:"tags"`
	Desc     string   `json:"description"`
	CVE      string   `json:"cve"`
	Status   string   `json:"status"`
	Source   string   `json:"source"` // xray|manual|script
	Kind     string   `json:"kind"`   // template|script
	SpecYAML string   `json:"specYaml"`

	Warnings []string `json:"warnings,omitempty"` // 转换/校验警告，仅预览阶段有意义
}

// Summary 列表行 DTO——显式列清单，绝不携带 spec 大字段。
type Summary struct {
	UID          string   `json:"uid"`
	Name         string   `json:"name"`
	Aliases      []string `json:"aliases"`
	Severity     string   `json:"severity"`
	Category     string   `json:"category"`
	Vendor       string   `json:"vendor"`
	Product      string   `json:"product"`
	Tags         []string `json:"tags"`
	CVE          string   `json:"cve"`
	Status       string   `json:"status"`
	Source       string   `json:"source"`
	Kind         string   `json:"kind"`
	CreatedAt    string   `json:"createdAt"`
	UpdatedAt    string   `json:"updatedAt"`
	LastTestedAt *string  `json:"lastTestedAt"`
}

// Filter 列表筛选条件；零值字段忽略。
type Filter struct {
	Query    string `json:"query,omitempty"`
	Vendor   string `json:"vendor,omitempty"`
	Product  string `json:"product,omitempty"`
	Severity string `json:"severity,omitempty"`
	Category string `json:"category,omitempty"`
	Status   string `json:"status,omitempty"`
	Source   string `json:"source,omitempty"`
	CVE      string `json:"cve,omitempty"`
}

// Page 分页参数。
type Page struct {
	Number int    `json:"number"` // 1-based
	Size   int    `json:"size"`   // 默认 50，上限 200
	Sort   string `json:"sort"`   // updated_desc|created_desc|name_asc|severity_desc
}

type PagedSummary struct {
	Items []Summary `json:"items"`
	Total int64     `json:"total"`
}

// ---- PWF spec 结构（严格 schema 校验的对象）----

type Spec struct {
	Transport  string          `yaml:"transport" json:"transport"` // http|tcp
	Rules      map[string]Rule `yaml:"rules" json:"rules"`
	Expression string          `yaml:"expression" json:"expression"`
}

type Rule struct {
	Request    Request `yaml:"request" json:"request"`
	Expression string  `yaml:"expression" json:"expression"`
	// Extract 变量提取（v1.2 串联验证）：变量名 → 含恰好 1 个捕获组的正则，
	// 作用面为本规则响应 body（http）/ raw（tcp）。提取值经 {{变量名}} 供后续规则引用。
	// 旧模板无此字段：omitempty 保证 schema 兼容，引擎按无变量处理，行为不变。
	Extract map[string]string `yaml:"extract,omitempty" json:"extract,omitempty"`
}

type Request struct {
	Method      string            `yaml:"method,omitempty" json:"method,omitempty"`
	Path        string            `yaml:"path,omitempty" json:"path,omitempty"`
	Headers     map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	Body        string            `yaml:"body,omitempty" json:"body,omitempty"`
	Inputs      []TCPInput        `yaml:"inputs,omitempty" json:"inputs,omitempty"`
	ReadTimeout int               `yaml:"read_timeout,omitempty" json:"readTimeout,omitempty"`
}

type TCPInput struct {
	Data string `yaml:"data" json:"data"`
}

// ---- 字典 ----

type Vendor struct {
	ID            int64    `json:"id"`
	CanonicalName string   `json:"canonicalName"`
	Aliases       []string `json:"aliases"`
}

type Product struct {
	ID            int64    `json:"id"`
	VendorID      int64    `json:"vendorId"`
	CanonicalName string   `json:"canonicalName"`
	Aliases       []string `json:"aliases"`
}

// ---- 测试 ----

type TestRun struct {
	ID         int64  `json:"id"`
	PocUID     string `json:"pocUid"`
	Target     string `json:"target"`
	TargetHost string `json:"targetHost"`
	Result     string `json:"result"` // hit|miss|error|timeout|cancelled
	Log        string `json:"log"`    // 列表接口为截断预览（见 LogTruncated），GetTestRun 为全文
	// LogTruncated 标记 Log 仅为预览；完整内容经 GetTestRun 懒加载
	LogTruncated bool    `json:"logTruncated"`
	Authorized   bool    `json:"authorized"`
	StartedAt    string  `json:"startedAt"`
	EndedAt      *string `json:"endedAt"`
}

// Dashboard 总览统计。
// 口径约定：TotalPocs / BySeverity / TopVendors 一律不含归档，三者可互相对账；
// ByStatus 是状态分布，完整含归档；归档数单独由 ArchivedPocs 给出。
type Dashboard struct {
	ByStatus   map[string]int64 `json:"byStatus"`
	BySeverity map[string]int64 `json:"bySeverity"`
	TopVendors []VendorCount    `json:"topVendors"`
	// TotalPocs 未归档 PoC 数（与 BySeverity 之和相等）
	TotalPocs int64 `json:"totalPocs"`
	// ArchivedPocs 已归档数——供前端区分「空库」与「全部已归档」
	ArchivedPocs  int64 `json:"archivedPocs"`
	TotalTestRuns int64 `json:"totalTestRuns"`
}

type VendorCount struct {
	Vendor string `json:"vendor"`
	Count  int64  `json:"count"`
}
