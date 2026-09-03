// Package store 实现 SQLite 持久化：CRUD、FTS 双写、字典、测试记录、迁移与备份。
//
// 工程约定（方案 §2.1）：
//   - 单写连接（MaxOpenConns=1），WAL 模式
//   - FTS 与主表同事务双写；字典变更自动刷新受影响 FTS 行
//   - Summary 查询显式列清单，绝不 SELECT *
//   - 时间戳 RFC3339 UTC 由应用层生成
package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	_ "modernc.org/sqlite"

	"pocworkbench/internal/model"
	"pocworkbench/internal/pwf"
)

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	// foreign_keys 走 DSN 而非 init() 里的一次性 Exec：该 pragma 是连接级的，
	// 若 database/sql 因坏连接丢弃并重建连接，Exec 设的值会静默失效，
	// 之后的 ON DELETE RESTRICT / CASCADE 都不再生效。DSN 对每条新连接都生效。
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // 单写连接，规避 modernc/sqlite 并发写限制
	s := &Store{db: db}
	if err := s.init(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) init() error {
	// journal_mode=WAL 持久化在库文件里，设一次即可；foreign_keys 见 Open 的 DSN
	if _, err := s.db.Exec(`PRAGMA journal_mode = WAL`); err != nil {
		return fmt.Errorf("pragma: %w", err)
	}
	var ver int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&ver); err != nil {
		return err
	}
	// 迁移按版本号顺序执行；新版本一律追加（IF NOT EXISTS 幂等），老库依次升级
	if ver < 1 {
		if err := s.migrateV1(); err != nil {
			return fmt.Errorf("migrate v1: %w", err)
		}
	}
	if ver < 2 {
		if err := s.migrateV2(); err != nil {
			return fmt.Errorf("migrate v2: %w", err)
		}
	}
	if ver < 3 {
		if err := s.migrateV3(); err != nil {
			return fmt.Errorf("migrate v3: %w", err)
		}
	}
	return nil
}

func (s *Store) migrateV1() error {
	ddl := `
CREATE TABLE IF NOT EXISTS vendor (
  id INTEGER PRIMARY KEY,
  canonical_name TEXT NOT NULL UNIQUE,
  aliases TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS product (
  id INTEGER PRIMARY KEY,
  vendor_id INTEGER NOT NULL REFERENCES vendor(id) ON DELETE RESTRICT,
  canonical_name TEXT NOT NULL,
  aliases TEXT NOT NULL DEFAULT '[]',
  UNIQUE(vendor_id, canonical_name)
);
CREATE TABLE IF NOT EXISTS poc (
  uid TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  aliases TEXT NOT NULL DEFAULT '[]',
  severity TEXT NOT NULL DEFAULT 'info'
    CHECK (severity IN ('critical','high','medium','low','info')),
  category TEXT NOT NULL DEFAULT 'other',
  vendor_id INTEGER REFERENCES vendor(id) ON DELETE RESTRICT,
  product_id INTEGER REFERENCES product(id) ON DELETE RESTRICT,
  tags TEXT NOT NULL DEFAULT '[]',
  description TEXT NOT NULL DEFAULT '',
  cve TEXT,
  status TEXT NOT NULL DEFAULT 'untested'
    CHECK (status IN ('tested','untested','failed','faked','archived')),
  source TEXT NOT NULL DEFAULT 'manual' CHECK (source IN ('xray','manual','script')),
  spec_kind TEXT NOT NULL DEFAULT 'template' CHECK (spec_kind IN ('template','script')),
  spec TEXT NOT NULL,
  spec_sha256 TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  last_tested_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_poc_status   ON poc(status);
CREATE INDEX IF NOT EXISTS idx_poc_severity ON poc(severity);
CREATE INDEX IF NOT EXISTS idx_poc_vendor   ON poc(vendor_id);
CREATE INDEX IF NOT EXISTS idx_poc_cve      ON poc(cve) WHERE cve IS NOT NULL;
CREATE TABLE IF NOT EXISTS test_run (
  id INTEGER PRIMARY KEY,
  poc_uid TEXT NOT NULL REFERENCES poc(uid) ON DELETE CASCADE,
  target TEXT NOT NULL,
  target_host TEXT NOT NULL DEFAULT '',
  result TEXT NOT NULL CHECK (result IN ('hit','miss','error','timeout','cancelled')),
  log TEXT NOT NULL DEFAULT '',
  authorized INTEGER NOT NULL,
  started_at TEXT NOT NULL,
  ended_at TEXT
);
CREATE VIRTUAL TABLE IF NOT EXISTS poc_fts USING fts5(
  uid UNINDEXED, name, aliases, tags, description, vendor, product,
  tokenize='trigram'
);
`
	if _, err := s.db.Exec(ddl); err != nil {
		return err
	}
	_, err := s.db.Exec(`PRAGMA user_version = 1`)
	return err
}

// migrateV2 v1.0.1：test_run.poc_uid 无索引，SQLite 不会因 FK 声明自动建索引——
// 测试历史查询与 CASCADE 删除都随记录增长退化为全表扫描。
func (s *Store) migrateV2() error {
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_test_run_poc ON test_run(poc_uid, id)`); err != nil {
		return err
	}
	_, err := s.db.Exec(`PRAGMA user_version = 2`)
	return err
}

// migrateV3 v1.1.0：source 枚举扩展 'nuclei'（Nuclei 模板导入）。
// SQLite 不支持修改 CHECK 约束，按标准流程重建 poc 表：
// 关外键（连接级，事务外）→ 建新表 → 拷贝 → 换名 → 重建索引 → 升版本。
func (s *Store) migrateV3() error {
	if _, err := s.db.Exec(`PRAGMA foreign_keys = OFF`); err != nil {
		return fmt.Errorf("关闭外键失败: %w", err)
	}
	if _, err := s.db.Exec(`PRAGMA legacy_alter_table = ON`); err != nil {
		return fmt.Errorf("设置 legacy_alter_table 失败: %w", err)
	}
	restore := func() {
		_, _ = s.db.Exec(`PRAGMA legacy_alter_table = OFF`)
		_, _ = s.db.Exec(`PRAGMA foreign_keys = ON`)
	}

	tx, err := s.db.Begin()
	if err != nil {
		restore()
		return err
	}
	defer tx.Rollback()

	stmts := []string{
		`CREATE TABLE poc_migrated (
  uid TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  aliases TEXT NOT NULL DEFAULT '[]',
  severity TEXT NOT NULL DEFAULT 'info'
    CHECK (severity IN ('critical','high','medium','low','info')),
  category TEXT NOT NULL DEFAULT 'other',
  vendor_id INTEGER REFERENCES vendor(id) ON DELETE RESTRICT,
  product_id INTEGER REFERENCES product(id) ON DELETE RESTRICT,
  tags TEXT NOT NULL DEFAULT '[]',
  description TEXT NOT NULL DEFAULT '',
  cve TEXT,
  status TEXT NOT NULL DEFAULT 'untested'
    CHECK (status IN ('tested','untested','failed','faked','archived')),
  source TEXT NOT NULL DEFAULT 'manual' CHECK (source IN ('xray','manual','script','nuclei')),
  spec_kind TEXT NOT NULL DEFAULT 'template' CHECK (spec_kind IN ('template','script')),
  spec TEXT NOT NULL,
  spec_sha256 TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  last_tested_at TEXT
)`,
		`INSERT INTO poc_migrated
			(uid,name,aliases,severity,category,vendor_id,product_id,tags,description,cve,status,source,spec_kind,spec,spec_sha256,created_at,updated_at,last_tested_at)
		SELECT uid,name,aliases,severity,category,vendor_id,product_id,tags,description,cve,status,source,spec_kind,spec,spec_sha256,created_at,updated_at,last_tested_at FROM poc`,
		`DROP TABLE poc`,
		`ALTER TABLE poc_migrated RENAME TO poc`,
		`CREATE INDEX idx_poc_status   ON poc(status)`,
		`CREATE INDEX idx_poc_severity ON poc(severity)`,
		`CREATE INDEX idx_poc_vendor   ON poc(vendor_id)`,
		`CREATE INDEX idx_poc_cve      ON poc(cve) WHERE cve IS NOT NULL`,
	}
	for _, q := range stmts {
		if _, err := tx.Exec(q); err != nil {
			restore()
			return fmt.Errorf("poc 表重建: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		restore()
		return err
	}
	if _, err := s.db.Exec(`PRAGMA user_version = 3`); err != nil {
		restore()
		return err
	}
	restore()
	return nil
}

func nowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }

func mustJSON(v any) string {
	b, _ := jsonMarshal(v)
	return string(b)
}

// ---- PoC 写入 ----

// InsertPoc 入库一条已校验的 PoC。canonicalSpec 为规范化 YAML。
// 返回 false 表示 spec_sha256 已存在（重复）。
func (s *Store) InsertPoc(uid string, d *model.Draft, canonicalSpec string) (bool, error) {
	hash := pwf.CanonicalHash(canonicalSpec)
	now := nowRFC3339()

	// 去重预检、字典创建、主行与 FTS 写入同一事务：
	// 此前预检/字典在事务外，并发撞车走不到友好重复路径，PoC 回滚还会残留垃圾字典行
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	var exists int
	if err := tx.QueryRow(`SELECT COUNT(1) FROM poc WHERE spec_sha256 = ?`, hash).Scan(&exists); err != nil {
		return false, err
	}
	if exists > 0 {
		return false, nil
	}

	vendorID, err := ensureVendor(tx, d.Vendor)
	if err != nil {
		return false, err
	}
	productID, err := ensureProduct(tx, vendorID, d.Product)
	if err != nil {
		return false, err
	}

	_, err = tx.Exec(`INSERT INTO poc
		(uid,name,aliases,severity,category,vendor_id,product_id,tags,description,cve,status,source,spec_kind,spec,spec_sha256,created_at,updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		uid, d.Name, mustJSON(d.Aliases), d.Severity, d.Category, vendorID, productID,
		mustJSON(d.Tags), d.Desc, nullIfEmpty(d.CVE), d.Status, d.Source, d.Kind,
		canonicalSpec, hash, now, now)
	if err != nil {
		return false, err
	}
	if err := ftsInsert(tx, uid, d, vendorNameOf(tx, vendorID), productNameOf(tx, productID)); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

func ftsInsert(tx *sql.Tx, uid string, d *model.Draft, vendor, product string) error {
	_, err := tx.Exec(`INSERT INTO poc_fts(uid,name,aliases,tags,description,vendor,product) VALUES (?,?,?,?,?,?,?)`,
		uid, d.Name, mustJSON(d.Aliases), mustJSON(d.Tags), truncate(d.Desc, 8192), vendor, product)
	return err
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

func nullIfEmpty(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}

// dbtx 抽象单连接/事务：确保字典创建等辅助写操作能纳入调用方的事务边界。
type dbtx interface {
	Exec(query string, args ...any) (sql.Result, error)
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
}

func vendorNameOf(q dbtx, id int64) string {
	var name string
	_ = q.QueryRow(`SELECT canonical_name FROM vendor WHERE id=?`, id).Scan(&name)
	return name
}

func productNameOf(q dbtx, id int64) string {
	if id == 0 {
		return ""
	}
	var name string
	_ = q.QueryRow(`SELECT canonical_name FROM product WHERE id=?`, id).Scan(&name)
	return name
}

// ---- 字典 ----

func ensureVendor(q dbtx, name string) (int64, error) {
	if name == "" {
		return 0, nil
	}
	var id int64
	err := q.QueryRow(`SELECT id FROM vendor WHERE canonical_name=?`, name).Scan(&id)
	switch err {
	case nil:
		return id, nil
	case sql.ErrNoRows:
		// canonical 未命中——查别名。aliases 存 JSON 数组文本，
		// 用带引号的完整元素精确匹配（escapeLike 防通配符注入），子串命中不算。
		pat := `%"` + escapeLike(name) + `"%`
		rows, e := q.Query(`SELECT id FROM vendor WHERE aliases LIKE ? ESCAPE '\'`, pat)
		if e == nil {
			defer rows.Close()
			for rows.Next() {
				if e := rows.Scan(&id); e == nil {
					return id, nil
				}
			}
		}
	default:
		return 0, err
	}
	res, err := q.Exec(`INSERT INTO vendor(canonical_name,aliases,created_at) VALUES(?,'[]',?)`, name, nowRFC3339())
	if err != nil {
		existing := int64(0)
		e2 := q.QueryRow(`SELECT id FROM vendor WHERE canonical_name=?`, name).Scan(&existing)
		if e2 == nil {
			return existing, nil
		}
		return 0, err
	}
	return res.LastInsertId()
}

func ensureProduct(q dbtx, vendorID int64, name string) (int64, error) {
	if name == "" || vendorID == 0 {
		return 0, nil
	}
	var id int64
	err := q.QueryRow(`SELECT id FROM product WHERE vendor_id=? AND canonical_name=?`, vendorID, name).Scan(&id)
	if err == nil {
		return id, nil
	}
	res, err := q.Exec(`INSERT INTO product(vendor_id,canonical_name,aliases) VALUES(?,?,'[]')`, vendorID, name)
	if err != nil {
		existing := int64(0)
		e2 := q.QueryRow(`SELECT id FROM product WHERE vendor_id=? AND canonical_name=?`, vendorID, name).Scan(&existing)
		if e2 == nil {
			return existing, nil
		}
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) ListVendors() ([]model.Vendor, error) {
	rows, err := s.db.Query(`SELECT id,canonical_name,aliases FROM vendor ORDER BY canonical_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Vendor
	for rows.Next() {
		var v model.Vendor
		var aliasJSON string
		if err := rows.Scan(&v.ID, &v.CanonicalName, &aliasJSON); err != nil {
			return nil, err
		}
		v.Aliases = unjsonStrings(aliasJSON)
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) ListProducts(vendorID int64) ([]model.Product, error) {
	rows, err := s.db.Query(`SELECT id,vendor_id,canonical_name,aliases FROM product WHERE vendor_id=? ORDER BY canonical_name`, vendorID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Product
	for rows.Next() {
		var p model.Product
		var aliasJSON string
		if err := rows.Scan(&p.ID, &p.VendorID, &p.CanonicalName, &aliasJSON); err != nil {
			return nil, err
		}
		p.Aliases = unjsonStrings(aliasJSON)
		out = append(out, p)
	}
	return out, rows.Err()
}

// MergeVendorAlias 把别名归并到规范厂商；若别名已是其他规范名则合并其 PoC 引用并删除旧行。
func (s *Store) MergeVendorAlias(canonical, alias string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var canonID int64
	if err := tx.QueryRow(`SELECT id FROM vendor WHERE canonical_name=?`, canonical).Scan(&canonID); err != nil {
		return fmt.Errorf("规范厂商不存在: %w", err)
	}
	var oldID int64
	err = tx.QueryRow(`SELECT id FROM vendor WHERE canonical_name=?`, alias).Scan(&oldID)
	if err == nil && oldID != canonID {
		// 先解除 product 引用，再迁移 vendor 引用，最后删除（满足 RESTRICT）
		if _, e := tx.Exec(`UPDATE poc SET product_id=NULL WHERE product_id IN (SELECT id FROM product WHERE vendor_id=?)`, oldID); e != nil {
			return e
		}
		if _, e := tx.Exec(`UPDATE poc SET vendor_id=? WHERE vendor_id=?`, canonID, oldID); e != nil {
			return e
		}
		if _, e := tx.Exec(`DELETE FROM product WHERE vendor_id=?`, oldID); e != nil {
			return e
		}
		if _, e := tx.Exec(`DELETE FROM vendor WHERE id=?`, oldID); e != nil {
			return e
		}
	} else if err != nil && err != sql.ErrNoRows {
		return err
	}
	// 别名追加进 aliases JSON（去重）
	var aliasJSON string
	if err := tx.QueryRow(`SELECT aliases FROM vendor WHERE id=?`, canonID).Scan(&aliasJSON); err != nil {
		return err
	}
	list := unjsonStrings(aliasJSON)
	if !containsStr(list, alias) && alias != canonical {
		list = append(list, alias)
	}
	if _, e := tx.Exec(`UPDATE vendor SET aliases=? WHERE id=?`, mustJSON(list), canonID); e != nil {
		return e
	}

	// 同事务刷新受影响行的 FTS（vendor 迁移后其 poc 的 vendor 列需同步）。
	// 此前提交后独立跑 refreshFtsAll：失败会造成主表与 FTS 永久失配且无补偿
	rows, e := tx.Query(`SELECT p.uid, IFNULL(pr.canonical_name,'') FROM poc p
		LEFT JOIN product pr ON p.product_id=pr.id WHERE p.vendor_id=?`, canonID)
	if e != nil {
		return e
	}
	type uidProduct struct{ uid, product string }
	var affected []uidProduct
	for rows.Next() {
		var r uidProduct
		if err := rows.Scan(&r.uid, &r.product); err != nil {
			rows.Close()
			return err
		}
		affected = append(affected, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, r := range affected {
		if _, e := tx.Exec(`UPDATE poc_fts SET vendor=?, product=? WHERE uid=?`, canonical, r.product, r.uid); e != nil {
			return e
		}
	}
	return tx.Commit()
}

// UpdateSpec 更新内容体（已校验的规范化 YAML 或脚本原文）。
// 去重预检与写入同事务，杜绝并发下预检通过、唯一约束兜底的 TOCTOU 窗口。
func (s *Store) UpdateSpec(uid, canonicalSpec string) error {
	hash := pwf.CanonicalHash(canonicalSpec)
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var n int
	if err := tx.QueryRow(`SELECT COUNT(1) FROM poc WHERE spec_sha256=? AND uid!=?`, hash, uid).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return fmt.Errorf("内容重复：相同 spec 已存在")
	}
	if _, err := tx.Exec(`UPDATE poc SET spec=?, spec_sha256=?, updated_at=? WHERE uid=?`,
		canonicalSpec, hash, nowRFC3339(), uid); err != nil {
		return err
	}
	return tx.Commit()
}

// SetPocVendorProduct 直接指派 PoC 的厂商/产品（UNKNOWN 治理）。
func (s *Store) SetPocVendorProduct(uid string, vendorName, productName string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	vendorID, err := ensureVendor(tx, vendorName)
	if err != nil {
		return err
	}
	productID, err := ensureProduct(tx, vendorID, productName)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE poc SET vendor_id=?, product_id=?, updated_at=? WHERE uid=?`,
		vendorID, productID, nowRFC3339(), uid); err != nil {
		return err
	}
	vendor := vendorNameOf(tx, vendorID)
	product := productNameOf(tx, productID)
	if _, err := tx.Exec(`UPDATE poc_fts SET vendor=?, product=? WHERE uid=?`, vendor, product, uid); err != nil {
		return err
	}
	return tx.Commit()
}

// refreshFtsAll / refreshFtsOne 已删除：FTS 刷新统一内联进各写路径的事务（字典变更见 MergeVendorAlias）。

// ---- 查询 ----

const summaryCols = `p.uid,p.name,p.aliases,p.severity,p.category,
	IFNULL(v.canonical_name,''),IFNULL(pr.canonical_name,''),
	p.tags,p.cve,p.status,p.source,p.spec_kind,p.created_at,p.updated_at,p.last_tested_at`

func scanSummary(rows *sql.Rows) (model.Summary, error) {
	var m model.Summary
	var aliasJSON, tagJSON string
	var cve sql.NullString
	var last sql.NullString
	err := rows.Scan(&m.UID, &m.Name, &aliasJSON, &m.Severity, &m.Category,
		&m.Vendor, &m.Product, &tagJSON, &cve, &m.Status, &m.Source, &m.Kind,
		&m.CreatedAt, &m.UpdatedAt, &last)
	if err != nil {
		return m, err
	}
	m.Aliases = unjsonStrings(aliasJSON)
	m.Tags = unjsonStrings(tagJSON)
	m.CVE = cve.String
	m.LastTestedAt = nil
	if last.Valid {
		s := last.String
		m.LastTestedAt = &s
	}
	return m, nil
}

var sortWhitelist = map[string]string{
	"updated_desc":  "p.updated_at DESC",
	"created_desc":  "p.created_at DESC",
	"name_asc":      "p.name COLLATE NOCASE ASC",
	"severity_desc": `CASE p.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END ASC`,
}

func (s *Store) ListPocs(f model.Filter, pg model.Page) ([]model.Summary, int64, error) {
	where, args, err := s.buildWhere(f)
	if err != nil {
		return nil, 0, err
	}
	order := sortWhitelist[pg.Sort]
	if order == "" {
		order = sortWhitelist["updated_desc"]
	}
	size := pg.Size
	if size <= 0 {
		size = 50
	}
	if size > 200 {
		size = 200
	}
	num := pg.Number
	if num < 1 {
		num = 1
	}

	var total int64
	if err := s.db.QueryRow(`SELECT COUNT(1) FROM poc p
		LEFT JOIN vendor v ON p.vendor_id=v.id
		LEFT JOIN product pr ON p.product_id=pr.id
		WHERE`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	q := `SELECT ` + summaryCols + ` FROM poc p
		LEFT JOIN vendor v ON p.vendor_id=v.id
		LEFT JOIN product pr ON p.product_id=pr.id
		WHERE` + where + ` ORDER BY ` + order + ` LIMIT ? OFFSET ?`
	args = append(args, size, (num-1)*size)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []model.Summary
	for rows.Next() {
		m, err := scanSummary(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, m)
	}
	return out, total, rows.Err()
}

func (s *Store) buildWhere(f model.Filter) (string, []any, error) {
	// 默认过滤软删除；显式筛选「已归档」时不加，否则该视图恒为空、恢复无从谈起
	var conds []string
	if f.Status != "archived" {
		conds = append(conds, ` p.status != 'archived'`)
	}
	var args []any
	add := func(cond string, a ...any) {
		conds = append(conds, cond)
		args = append(args, a...)
	}
	if f.Vendor != "" {
		// UNKNOWN 是 Dashboard 对未指派厂商的合成展示名（IFNULL），不是真实字典项
		if f.Vendor == "UNKNOWN" {
			add(` p.vendor_id IS NULL`)
		} else {
			add(` v.canonical_name = ?`, f.Vendor)
		}
	}
	if f.Product != "" {
		add(` pr.canonical_name = ?`, f.Product)
	}
	if f.Severity != "" {
		add(` p.severity = ?`, f.Severity)
	}
	if f.Category != "" {
		add(` p.category = ?`, f.Category)
	}
	if f.Status != "" {
		add(` p.status = ?`, f.Status)
	}
	if f.Source != "" {
		add(` p.source = ?`, f.Source)
	}
	if f.CVE != "" {
		add(` p.cve = ?`, f.CVE)
	}
	if q := strings.TrimSpace(f.Query); q != "" {
		uids, err := s.searchUIDs(q, f.Status == "archived")
		if err != nil {
			return "", nil, fmt.Errorf("搜索失败: %w", err)
		}
		if len(uids) == 0 {
			add(` 1=0`) // 命中零结果
		} else {
			ph := strings.TrimRight(strings.Repeat("?,", len(uids)), ",")
			add(` p.uid IN (`+ph+`)`, toAny(uids)...)
		}
	}
	return strings.Join(conds, " AND "), args, nil
}

// likeFields 短词 LIKE 分支的检索字段，与 poc_fts 的索引列保持一致。
// 必须含 vendor / product：FTS 索引了它们，而 LIKE 分支曾只查 poc 表自身列，
// 导致「华为」「用友」这类两字厂商名（<3 字符走不到 FTS）根本搜不出来，
// 且长词+短词组合会被短词过滤误杀成 0 结果。占位符顺序与 6 个 pat 参数对应。
const likeFields = `p.name LIKE ? ESCAPE '\' OR p.description LIKE ? ESCAPE '\'
	OR p.aliases LIKE ? ESCAPE '\' OR p.tags LIKE ? ESCAPE '\'
	OR IFNULL(v.canonical_name,'') LIKE ? ESCAPE '\'
	OR IFNULL(pr.canonical_name,'') LIKE ? ESCAPE '\'`

// searchUIDs 混合检索：≥3 字符词走 FTS trigram，<3 字符词 LIKE 回退，取交集。
// includeArchived 控制纯短词 LIKE 分支是否包含已归档行（与列表状态筛选保持一致）。
func (s *Store) searchUIDs(q string, includeArchived bool) ([]string, error) {
	tokens := strings.Fields(q)
	var long, short []string
	for _, t := range tokens {
		if len([]rune(t)) >= 3 {
			long = append(long, t)
		} else {
			short = append(short, t)
		}
	}

	var candidates map[string]bool
	if len(long) > 0 {
		quoted := make([]string, len(long))
		for i, t := range long {
			escaped := strings.ReplaceAll(t, `"`, `""`)
			quoted[i] = `"` + escaped + `"`
		}
		rows, err := s.db.Query(`SELECT uid FROM poc_fts WHERE poc_fts MATCH ?`, strings.Join(quoted, " "))
		if err != nil {
			return nil, err
		}
		candidates = map[string]bool{}
		for rows.Next() {
			var uid string
			if err := rows.Scan(&uid); err == nil {
				candidates[uid] = true
			}
		}
		rows.Close()
	}

	likeFilter := func(uids []string) ([]string, error) {
		if len(uids) == 0 || len(short) == 0 {
			return uids, nil
		}
		// 每个短词一条 SQL（uid IN 限定到候选集），Go 内取交集。
		// 此前对 候选×短词 逐条发 COUNT，宽泛搜索时是语句风暴。
		pool := make(map[string]struct{}, len(uids))
		for _, u := range uids {
			pool[u] = struct{}{}
		}
		for _, st := range short {
			if len(pool) == 0 {
				return nil, nil
			}
			uidsLeft := make([]string, 0, len(pool))
			for u := range pool {
				uidsLeft = append(uidsLeft, u)
			}
			ph := strings.TrimRight(strings.Repeat("?,", len(uidsLeft)), ",")
			pat := likePat(st)
			qargs := append(toAny(uidsLeft), pat, pat, pat, pat, pat, pat)
			rows, err := s.db.Query(`SELECT DISTINCT p.uid FROM poc p
				LEFT JOIN vendor v ON p.vendor_id=v.id
				LEFT JOIN product pr ON p.product_id=pr.id
				WHERE p.uid IN (`+ph+`) AND (`+likeFields+`)`,
				qargs...)
			if err != nil {
				return nil, err
			}
			next := map[string]struct{}{}
			for rows.Next() {
				var uid string
				if err := rows.Scan(&uid); err == nil {
					next[uid] = struct{}{}
				}
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return nil, err
			}
			pool = next
		}
		out := make([]string, 0, len(pool))
		for u := range pool {
			out = append(out, u)
		}
		return out, nil
	}

	switch {
	case len(long) > 0 && len(short) > 0:
		uids := keys(candidates)
		return likeFilter(uids)
	case len(long) > 0:
		return keys(candidates), nil
	default:
		// 纯短词：全表 LIKE 扫描（个人库规模毫秒级）
		statusCond := `p.status!='archived'`
		if includeArchived {
			statusCond = `1=1`
		}
		pat := likePat(short[0])
		rows, err := s.db.Query(`SELECT p.uid FROM poc p
			LEFT JOIN vendor v ON p.vendor_id=v.id
			LEFT JOIN product pr ON p.product_id=pr.id
			WHERE `+statusCond+` AND (`+likeFields+`)`,
			pat, pat, pat, pat, pat, pat)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var uid string
			if err := rows.Scan(&uid); err == nil {
				out = append(out, uid)
			}
		}
		return out, rows.Err()
	}
}

func escapeLike(t string) string {
	t = strings.ReplaceAll(t, `\`, `\\`)
	t = strings.ReplaceAll(t, `%`, `\%`)
	t = strings.ReplaceAll(t, `_`, `\_`)
	return t
}

func likePat(token string) string {
	return `%` + escapeLike(token) + `%`
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func toAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

// GetPoc 取完整记录（元数据 + 解析后的 spec）。
func (s *Store) GetPoc(uid string) (*model.Pwf, error) {
	row := s.db.QueryRow(`SELECT `+summaryCols+`, p.description, p.spec FROM poc p
		LEFT JOIN vendor v ON p.vendor_id=v.id
		LEFT JOIN product pr ON p.product_id=pr.id
		WHERE p.uid=?`, uid)
	var m model.Summary
	var aliasJSON, tagJSON string
	var cve, last, desc sql.NullString
	var specYAML string
	if err := row.Scan(&m.UID, &m.Name, &aliasJSON, &m.Severity, &m.Category,
		&m.Vendor, &m.Product, &tagJSON, &cve, &m.Status, &m.Source, &m.Kind,
		&m.CreatedAt, &m.UpdatedAt, &last, &desc, &specYAML); err != nil {
		return nil, err
	}
	build := func(spec *model.Spec, specRaw string) *model.Pwf {
		aliases := unjsonStrings(aliasJSON)
		tags := unjsonStrings(tagJSON)
		p := &model.Pwf{
			Metadata: model.Metadata{
				UID: m.UID, Name: m.Name, Aliases: aliases, Severity: m.Severity,
				Category: m.Category, Vendor: m.Vendor, Product: m.Product,
				Tags: tags, Description: desc.String, CVE: cve.String,
				Status: m.Status, Source: m.Source, Kind: m.Kind,
				CreatedAt: m.CreatedAt, UpdatedAt: m.UpdatedAt,
			},
			SpecRaw: specRaw,
		}
		if spec != nil {
			p.Spec = *spec
		}
		if last.Valid {
			l := last.String
			p.Metadata.LastTestedAt = &l
		}
		return p
	}
	// script 类内容不是 PWF spec，解析必然失败；原文经 SpecRaw 透传
	if m.Kind == "script" {
		return build(nil, specYAML), nil
	}
	spec, err := pwf.ParseSpec(specYAML)
	if err != nil {
		return nil, fmt.Errorf("spec 解析失败: %w", err)
	}
	return build(spec, ""), nil
}


// SpecExists 按 canonical spec 哈希查重（dry-run 预览用，不落库）。
func (s *Store) SpecExists(canonicalSpec string) (bool, error) {
	var n int
	hash := pwf.CanonicalHash(canonicalSpec)
	err := s.db.QueryRow(`SELECT COUNT(1) FROM poc WHERE spec_sha256=?`, hash).Scan(&n)
	return n > 0, err
}

// 单批上限 2000：与批量导入对称，防误传巨型列表。
func (s *Store) GetPocsByUIDs(uids []string) ([]*model.Pwf, error) {
	if len(uids) == 0 {
		return nil, nil
	}
	if len(uids) > 2000 {
		uids = uids[:2000]
	}
	out := make([]*model.Pwf, 0, len(uids))
	for _, uid := range uids {
		p, err := s.GetPoc(uid)
		if err != nil {
			continue // 单条失败跳过：批量导出不因个别坏记录中断
		}
		out = append(out, p)
	}
	return out, nil
}

// KindOf 返回 PoC 的 spec_kind（template|script），供更新前分流校验。
func (s *Store) KindOf(uid string) (string, error) {
	var k string
	err := s.db.QueryRow(`SELECT spec_kind FROM poc WHERE uid=?`, uid).Scan(&k)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("PoC 不存在")
	}
	return k, err
}

// UpdateMeta 更新元数据字段并同步 FTS。
func (s *Store) UpdateMeta(uid string, d *model.Draft) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	vendorID, err := ensureVendor(tx, d.Vendor)
	if err != nil {
		return err
	}
	productID, err := ensureProduct(tx, vendorID, d.Product)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE poc SET name=?,aliases=?,severity=?,category=?,vendor_id=?,product_id=?,
		tags=?,description=?,cve=?,status=?,updated_at=? WHERE uid=?`,
		d.Name, mustJSON(d.Aliases), d.Severity, d.Category, vendorID, productID,
		mustJSON(d.Tags), d.Desc, nullIfEmpty(d.CVE), d.Status, nowRFC3339(), uid); err != nil {
		return err
	}
	vendor := vendorNameOf(tx, vendorID)
	product := productNameOf(tx, productID)
	if _, err := tx.Exec(`UPDATE poc_fts SET name=?,aliases=?,tags=?,description=?,vendor=?,product=? WHERE uid=?`,
		d.Name, mustJSON(d.Aliases), mustJSON(d.Tags), truncate(d.Desc, 8192), vendor, product, uid); err != nil {
		return err
	}
	return tx.Commit()
}

// DeletePoc 仅允许删除已归档 PoC；FTS 行的删除以主行删除成功为前提。
func (s *Store) DeletePoc(uid string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`DELETE FROM poc WHERE uid=? AND status='archived'`, uid)
	if err != nil {
		return err
	}
	if n, e := res.RowsAffected(); e != nil {
		return e
	} else if n == 0 {
		return fmt.Errorf("PoC 不存在或未归档")
	}
	if _, e := tx.Exec(`DELETE FROM poc_fts WHERE uid=?`, uid); e != nil {
		return e
	}
	return tx.Commit()
}

func (s *Store) SetStatus(uid, status string) error {
	_, err := s.db.Exec(`UPDATE poc SET status=?, updated_at=? WHERE uid=?`, status, nowRFC3339(), uid)
	return err
}

func (s *Store) TouchTested(uid string) error {
	_, err := s.db.Exec(`UPDATE poc SET last_tested_at=? WHERE uid=?`, nowRFC3339(), uid)
	return err
}

// ---- 测试记录 ----

func (s *Store) InsertTestRun(r *model.TestRun) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO test_run(poc_uid,target,target_host,result,log,authorized,started_at,ended_at)
		VALUES(?,?,?,?,?,?,?,?)`,
		r.PocUID, r.Target, r.TargetHost, r.Result, r.Log, boolInt(r.Authorized), r.StartedAt, r.EndedAt)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// logPreviewBytes 列表接口单条日志预览上限（字节）。
// 完整日志单条可达数 MB，列表 100 条直推前端会经 IPC 序列化出数百 MB 载荷卡死 WebView；
// 预览 + GetTestRun 懒加载双段式。
const logPreviewBytes = 4096

func (s *Store) ListTestRuns(pocUID string) ([]model.TestRun, error) {
	rows, err := s.db.Query(`SELECT id,poc_uid,target,target_host,result,substr(log,1,?),authorized,started_at,ended_at
		FROM test_run WHERE poc_uid=? ORDER BY id DESC LIMIT 100`, logPreviewBytes+1, pocUID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRuns(rows, true)
}

func (s *Store) GetTestRun(id int64) (*model.TestRun, error) {
	rows, err := s.db.Query(`SELECT id,poc_uid,target,target_host,result,log,authorized,started_at,ended_at
		FROM test_run WHERE id=?`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	runs, err := scanRuns(rows, false)
	if err != nil {
		return nil, err
	}
	if len(runs) == 0 {
		return nil, sql.ErrNoRows
	}
	return &runs[0], nil
}

func scanRuns(rows *sql.Rows, preview bool) ([]model.TestRun, error) {
	var out []model.TestRun
	for rows.Next() {
		var r model.TestRun
		var ended sql.NullString
		var auth int
		if err := rows.Scan(&r.ID, &r.PocUID, &r.Target, &r.TargetHost, &r.Result, &r.Log, &auth, &r.StartedAt, &ended); err != nil {
			return nil, err
		}
		r.Authorized = auth != 0
		if preview && len(r.Log) > logPreviewBytes {
			r.Log = truncateAtRune(r.Log, logPreviewBytes)
			r.LogTruncated = true
		}
		if ended.Valid {
			e := ended.String
			r.EndedAt = &e
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// truncateAtRune 按字节上限截断并回退到 UTF-8 rune 边界，避免日志预览尾部乱码。
func truncateAtRune(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// ---- 统计与备份 ----

func (s *Store) Dashboard() (*model.Dashboard, error) {
	d := &model.Dashboard{ByStatus: map[string]int64{}, BySeverity: map[string]int64{}}
	rows, err := s.db.Query(`SELECT status, COUNT(1) FROM poc GROUP BY status`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var k string
		var n int64
		if err := rows.Scan(&k, &n); err != nil {
			rows.Close()
			return nil, err
		}
		d.ByStatus[k] = n
		// TotalPocs 与 BySeverity/TopVendors 同口径（不含归档），三者可对账；
		// 此前把归档一并累加，首页头部数字与下方分布图恒不相符
		if k == "archived" {
			d.ArchivedPocs = n
		} else {
			d.TotalPocs += n
		}
	}
	rows.Close()

	rows, err = s.db.Query(`SELECT severity, COUNT(1) FROM poc WHERE status!='archived' GROUP BY severity`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var k string
		var n int64
		if err := rows.Scan(&k, &n); err != nil {
			rows.Close()
			return nil, err
		}
		d.BySeverity[k] = n
	}
	rows.Close()

	rows, err = s.db.Query(`SELECT IFNULL(v.canonical_name,'UNKNOWN') AS vn, COUNT(1) AS n
		FROM poc p LEFT JOIN vendor v ON p.vendor_id=v.id
		WHERE p.status!='archived' GROUP BY vn ORDER BY n DESC LIMIT 10`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var vc model.VendorCount
		if err := rows.Scan(&vc.Vendor, &vc.Count); err != nil {
			rows.Close()
			return nil, err
		}
		d.TopVendors = append(d.TopVendors, vc)
	}
	rows.Close()

	_ = s.db.QueryRow(`SELECT COUNT(1) FROM test_run`).Scan(&d.TotalTestRuns)
	return d, nil
}

func (s *Store) BackupDB(destPath string) error {
	_, err := s.db.Exec(`VACUUM INTO ?`, destPath)
	return err
}

// HealthCheck 验证核心表可查询（恢复前校验备份可用性）。
func (s *Store) HealthCheck() error {
	var n int
	return s.db.QueryRow(`SELECT COUNT(1) FROM poc`).Scan(&n)
}
