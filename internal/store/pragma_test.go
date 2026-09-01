package store

import (
	"path/filepath"
	"testing"
)

// foreign_keys 经 DSN 下发，必须确实生效——否则 ON DELETE RESTRICT/CASCADE 全是空文。
func TestForeignKeysEnforced(t *testing.T) {
	s := newStore(t)

	var on int
	if err := s.db.QueryRow(`PRAGMA foreign_keys`).Scan(&on); err != nil {
		t.Fatal(err)
	}
	if on != 1 {
		t.Fatalf("foreign_keys 应为 1, got %d", on)
	}

	// RESTRICT 生效验证：被 poc 引用的 vendor 不可删除
	addPoc(t, s, "u1", "poc one", "AcmeCorp", "AcmeApp")
	var vid int64
	if err := s.db.QueryRow(`SELECT id FROM vendor WHERE canonical_name='AcmeCorp'`).Scan(&vid); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`DELETE FROM vendor WHERE id=?`, vid); err == nil {
		t.Error("删除被引用的 vendor 应被 RESTRICT 阻止")
	}

	// CASCADE 生效验证：删除已归档 poc 应带走其 test_run
	if _, err := s.db.Exec(`INSERT INTO test_run(poc_uid,target,target_host,result,log,authorized,started_at)
		VALUES('u1','http://x','x','miss','',1,'2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if err := s.SetStatus("u1", "archived"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeletePoc("u1"); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(1) FROM test_run WHERE poc_uid='u1'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("删除 poc 应级联删除其 test_run, 残留 %d 行", n)
	}
}

// 老库（DSN 变更前建立）重新打开后同样要拿到 foreign_keys=ON。
func TestForeignKeysOnReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "reopen.db")

	s1, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	addPoc(t, s1, "u1", "poc one", "AcmeCorp", "AcmeApp")
	s1.Close()

	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	var on int
	if err := s2.db.QueryRow(`PRAGMA foreign_keys`).Scan(&on); err != nil {
		t.Fatal(err)
	}
	if on != 1 {
		t.Errorf("重开后 foreign_keys 应为 1, got %d", on)
	}
}
