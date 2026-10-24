package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func openTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(context.Background(), "sqlite:///"+filepath.Join(t.TempDir(), "manager.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return db
}
func addProject(t *testing.T, db *DB, id string) map[string]any {
	t.Helper()
	row := map[string]any{"id": id, "name": "Test project"}
	if err := db.WithTx(context.Background(), true, func(tx *Tx) error { return tx.Insert(context.Background(), "jm_projects", row) }); err != nil {
		t.Fatal(err)
	}
	return row
}
func addJob(t *testing.T, db *DB, id string) {
	t.Helper()
	addProject(t, db, "project-"+id)
	err := db.WithTx(context.Background(), true, func(tx *Tx) error {
		return tx.Insert(context.Background(), "jm_jobs", map[string]any{
			"id": id, "project_id": "project-" + id, "creator_id": "creator", "name": "Test job",
			"spec_json": map[string]any{}, "spec_hash": strings.Repeat("a", 64), "target_round": 2,
		})
	})
	if err != nil {
		t.Fatal(err)
	}
}
func TestExplicitMigrationAndCompleteSchema(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, "sqlite:///:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.CheckSchema(ctx); err == nil {
		t.Fatal("Open silently initialized schema")
	}
	if revision, err := db.Migrate(ctx); err != nil || revision != CurrentRevision {
		t.Fatalf("migrate %s %v", revision, err)
	}
	if revision, err := db.CheckSchema(ctx); err != nil || revision != CurrentRevision {
		t.Fatalf("check %s %v", revision, err)
	}
	rows, err := db.All(ctx, "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
	if err != nil || len(rows) != 24 {
		t.Fatalf("tables %d %v", len(rows), err)
	}
	for _, name := range []string{"auth_login_attempts", "auth_logout_replays", "jm_auth_sessions"} {
		if row, err := db.One(ctx, "SELECT name FROM sqlite_master WHERE name=?", name); err != nil || row == nil {
			t.Fatalf("missing %s", name)
		}
	}
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatal("idempotent migrate", err)
	}
}
func TestStoreDefaultsForeignKeysAndTransactionRollback(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	row := addProject(t, db, "defaults")
	if row["retained_bytes"] != json.Number("0") || row["version"] != json.Number("1") {
		t.Fatalf("default values %#v", row)
	}
	if _, ok := row["created_at"].(time.Time); !ok {
		t.Fatalf("missing timestamp default %#v", row)
	}
	err := db.WithTx(ctx, true, func(tx *Tx) error {
		if err := tx.Insert(ctx, "jm_projects", map[string]any{"id": "rollback", "name": "Rollback"}); err != nil {
			return err
		}
		return errors.New("controlled abort")
	})
	if err == nil {
		t.Fatal("rollback unexpectedly committed")
	}
	if found, err := db.One(ctx, "SELECT id FROM jm_projects WHERE id=?", "rollback"); err != nil || found != nil {
		t.Fatalf("rollback row %#v %v", found, err)
	}
	err = db.WithTx(ctx, true, func(tx *Tx) error {
		return tx.Insert(ctx, "jm_project_members", map[string]any{"project_id": "absent", "principal_id": "alice"})
	})
	if err == nil {
		t.Fatal("foreign key was not enforced")
	}
}
func TestJSONNumbersTimestampsAndBooleanInteroperability(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	object := map[string]any{"large": json.Number("9007199254740993"), "float": json.Number("1.0"), "unicode": "<A>&\u2028雪"}
	now := time.Date(2026, 10, 23, 12, 5, 3, 123456000, time.FixedZone("source", 3600))
	err := db.WithTx(ctx, true, func(tx *Tx) error {
		if err := tx.Insert(ctx, "jm_projects", map[string]any{"id": "json", "name": "JSON", "quotas_json": object, "created_at": now}); err != nil {
			return err
		}
		return tx.Insert(ctx, "jm_pools", map[string]any{"id": "pool", "name": "CPU", "node_id": "node", "healthy": true, "gpu_uuids": []string{"gpu-1"}})
	})
	if err != nil {
		t.Fatal(err)
	}
	row, err := db.One(ctx, "SELECT * FROM jm_projects WHERE id=?", "json")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(row["quotas_json"], object) {
		t.Fatalf("JSON corrupted %#v", row["quotas_json"])
	}
	got, ok := Time(row["created_at"])
	if !ok || !got.Equal(now) {
		t.Fatalf("timestamp %v %v", got, row["created_at"])
	}
	raw, err := db.One(ctx, "SELECT CAST(created_at AS TEXT) AS stamp FROM jm_projects WHERE id=?", "json")
	if err != nil || raw["stamp"] != "2026-10-23 11:05:03.123456" {
		t.Fatalf("legacy SQLite timestamp %v %v", raw, err)
	}
	pool, err := db.One(ctx, "SELECT * FROM jm_pools WHERE id=?", "pool")
	if err != nil {
		t.Fatal(err)
	}
	if pool["healthy"] != true || pool["quarantined"] != false {
		t.Fatalf("bool decode %#v", pool)
	}
	if !reflect.DeepEqual(pool["gpu_uuids"], []any{"gpu-1"}) {
		t.Fatalf("non-suffixed JSON field %#v", pool)
	}
}
func TestSQLRebindDoesNotAlterQuotedOrCommentedQuestionMarks(t *testing.T) {
	input := "SELECT '?', \"?\", $$?$$, $tag$?$tag$, ? -- ?\n /* ? /* ? */ ? */ ?"
	want := "SELECT '?', \"?\", $$?$$, $tag$?$tag$, $1 -- ?\n /* ? /* ? */ ? */ $2"
	if got := rebind(input, "postgresql"); got != want {
		t.Fatalf("got %s want %s", got, want)
	}
	if got := rebind(input, "sqlite"); got != input {
		t.Fatal(got)
	}
}
func TestUnknownColumnsAndImmutableProvenanceFailClosed(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	addJob(t, db, "job")
	for _, column := range []string{"spec_json", "spec_hash", "creator_id", "project_id", "target_round"} {
		err := db.WithTx(ctx, true, func(tx *Tx) error {
			return tx.Update(ctx, "jm_jobs", map[string]any{"id": "job"}, map[string]any{column: "tamper"})
		})
		if err == nil {
			t.Fatalf("immutable %s changed", column)
		}
	}
	for _, values := range []map[string]any{{"id": "bad", "name": "Bad", "unexpected": "value"}, {"id": "bad"}} {
		err := db.WithTx(ctx, true, func(tx *Tx) error { return tx.Insert(ctx, "jm_projects", values) })
		if err == nil {
			t.Fatalf("invalid row accepted %#v", values)
		}
	}
	err := db.WithTx(ctx, true, func(tx *Tx) error { return tx.Insert(ctx, "jm_projects; DROP TABLE jm_jobs", map[string]any{}) })
	if err == nil {
		t.Fatal("unknown table accepted")
	}
	err = db.WithTx(ctx, true, func(tx *Tx) error {
		return tx.Update(ctx, "jm_projects", map[string]any{}, map[string]any{"name": "Changed"})
	})
	if err == nil {
		t.Fatal("unselected update accepted")
	}
}
func TestArtifactLocatorValidationUsesOwnedStructuredLocations(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	addJob(t, db, "job")
	for _, locator := range []map[string]any{
		{"kind": "local", "resource_id": "resource", "relative_path": "../secret"},
		{"kind": "exchange", "space_id": "space", "record_id": "record", "attachment_id": "attachment", "relative_path": "data"},
		{"kind": "local", "resource_id": "resource", "relative_path": "model", "url": "https://untrusted"},
	} {
		err := db.WithTx(ctx, true, func(tx *Tx) error {
			return tx.Insert(ctx, "jm_artifacts", map[string]any{"job_id": "job", "kind": "checkpoint", "name": "model.safetensors", "size_bytes": 1, "sha256": strings.Repeat("a", 64), "storage_key": "ignored", "locator_json": locator})
		})
		if err == nil {
			t.Fatalf("unsafe locator accepted %#v", locator)
		}
	}
	err := db.WithTx(ctx, true, func(tx *Tx) error {
		return tx.Insert(ctx, "jm_artifacts", map[string]any{"id": "artifact", "job_id": "job", "kind": "checkpoint", "name": "model.safetensors", "size_bytes": 1, "sha256": strings.Repeat("a", 64), "storage_key": "ignored", "locator_json": map[string]any{"kind": "local", "resource_id": "resource", "relative_path": "outputs/model.safetensors"}})
	})
	if err != nil {
		t.Fatal(err)
	}
}
func TestAuditSanitizationAndAppendOnlyPolicy(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	row := map[string]any{"actor_id": "operator", "operation": "project.update", "resource_type": "project", "resource_id": "project", "after_json": map[string]any{"name": "Project", "token": "secret-not-stored", "host_path": "/private/path", "quotas": map[string]any{"memory_bytes": json.Number("9007199254740993"), "token": "secret"}}}
	if err := db.WithTx(ctx, true, func(tx *Tx) error { return tx.Insert(ctx, "jm_admin_audit", row) }); err != nil {
		t.Fatal(err)
	}
	stored, err := db.One(ctx, "SELECT * FROM jm_admin_audit WHERE id=?", row["id"])
	if err != nil {
		t.Fatal(err)
	}
	safe := stored["after_json"].(map[string]any)
	if _, ok := safe["token"]; ok {
		t.Fatal("credential retained")
	}
	if _, ok := safe["host_path"]; ok {
		t.Fatal("host path retained")
	}
	if err := db.WithTx(ctx, true, func(tx *Tx) error {
		return tx.Update(ctx, "jm_admin_audit", map[string]any{"id": row["id"]}, map[string]any{"operation": "changed"})
	}); err == nil {
		t.Fatal("audit updated")
	}
	for _, value := range []any{
		map[string]any{"name": "Bearer credential"}, map[string]any{"healthy": 1},
		map[string]any{"version": 1.0}, map[string]any{"version": json.Number("1.0")},
		map[string]any{"name": "-----BEGIN PRIVATE KEY-----"},
	} {
		if _, err := SanitizeAuditMetadata(value); err == nil {
			t.Fatalf("unsafe metadata accepted %#v", value)
		}
	}
	items := make([]any, 65)
	for i := range items {
		items[i] = "commit"
	}
	safe, err = SanitizeAuditMetadata(map[string]any{"allowed_commits": items})
	if err != nil {
		t.Fatal(err)
	}
	summary := safe["allowed_commits"].(map[string]any)
	if summary["count"] != int64(65) || len(summary["sha256"].(string)) != 64 {
		t.Fatalf("bad summary %#v", summary)
	}
	if _, err := SanitizeAuditMetadata(safe); err != nil {
		t.Fatal("second ORM validation rejected safe summary", err)
	}
}
func TestSQLiteConcurrentTransactionsReserveBeforeRead(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "concurrent.db")
	one, err := Open(ctx, "sqlite:///"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer one.Close()
	two, err := Open(ctx, "sqlite:///"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer two.Close()
	if _, err := one.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	addProject(t, one, "counter")
	var group sync.WaitGroup
	failures := make(chan error, 2)
	for _, db := range []*DB{one, two} {
		group.Add(1)
		go func(db *DB) {
			defer group.Done()
			for i := 0; i < 20; i++ {
				err := db.WithTx(ctx, true, func(tx *Tx) error {
					row, err := tx.One(ctx, "SELECT retained_bytes FROM jm_projects WHERE id=?", "counter")
					if err != nil {
						return err
					}
					return tx.Update(ctx, "jm_projects", map[string]any{"id": "counter"}, map[string]any{"retained_bytes": row["retained_bytes"].(int64) + 1})
				})
				if err != nil {
					failures <- err
					return
				}
			}
		}(db)
	}
	group.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	row, err := one.One(ctx, "SELECT retained_bytes FROM jm_projects WHERE id=?", "counter")
	if err != nil || row["retained_bytes"] != int64(40) {
		t.Fatalf("lost reservation update %#v %v", row, err)
	}
}
func TestRejectsPartialUnknownAndIncompleteSchemas(t *testing.T) {
	ctx := context.Background()
	t.Run("unversioned", func(t *testing.T) {
		db, err := Open(ctx, "sqlite:///:memory:")
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		if _, err := db.Exec(ctx, "CREATE TABLE jm_jobs (id TEXT)"); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Migrate(ctx); err == nil {
			t.Fatal("partial schema repaired")
		}
	})
	t.Run("future revision", func(t *testing.T) {
		db := openTestDB(t)
		if _, err := db.Exec(ctx, "INSERT INTO jm_schema_revisions(revision,applied_at) VALUES (?,?)", "0004_unknown", time.Now()); err != nil {
			t.Fatal(err)
		}
		if _, err := db.CheckSchema(ctx); err == nil {
			t.Fatal("unknown revision accepted")
		}
		if _, err := db.Migrate(ctx); err == nil {
			t.Fatal("unknown revision rewritten")
		}
	})
	t.Run("missing index", func(t *testing.T) {
		db := openTestDB(t)
		if _, err := db.Exec(ctx, "DROP INDEX ix_jm_sessions_expiry"); err != nil {
			t.Fatal(err)
		}
		if _, err := db.CheckSchema(ctx); err == nil {
			t.Fatal("incomplete schema accepted")
		}
		if _, err := db.Migrate(ctx); err == nil {
			t.Fatal("current partial schema repaired")
		}
	})
}
func TestTimeParsesLegacyUTCAndRejectsMalformed(t *testing.T) {
	for _, text := range []string{"2026-10-23 12:00:00.123456", "2026-10-23T12:00:00.123456Z", "2026-10-23 14:00:00.123456+02:00"} {
		got, ok := Time(text)
		if !ok || got.Location() != time.UTC || got.Hour() != 12 {
			t.Fatalf("bad timestamp %s %v", text, got)
		}
	}
	if _, ok := Time("not a timestamp"); ok {
		t.Fatal("invalid timestamp accepted")
	}
}
func TestSQLiteMissingFileParentIsNotCreated(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "missing")
	if _, err := Open(context.Background(), "sqlite:///"+filepath.Join(directory, "db")); err == nil {
		t.Fatal("invalid parent unexpectedly created")
	}
	if _, err := os.Stat(directory); !os.IsNotExist(err) {
		t.Fatalf("missing parent mutated %v", err)
	}
}

func loadLegacyFixture(t *testing.T, revision string) *DB {
	t.Helper()
	ctx := context.Background()
	db, err := Open(ctx, "sqlite:///:memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	source, err := os.ReadFile("testdata/schema_v" + revision + ".sqlite.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range strings.Split(string(source), ";\n") {
		if strings.TrimSpace(statement) == "" {
			continue
		}
		if _, err := db.Exec(ctx, statement); err != nil {
			t.Fatal("legacy fixture", err)
		}
	}
	return db
}
func TestLegacyUpgradesPreserveDataAndFailClosedLocators(t *testing.T) {
	for _, revision := range []string{"1", "2"} {
		t.Run("revision"+revision, func(t *testing.T) {
			db := loadLegacyFixture(t, revision)
			ctx := context.Background()
			addJob(t, db, "legacy")
			err := db.WithTx(ctx, true, func(tx *Tx) error {
				return tx.Insert(ctx, "jm_artifacts", map[string]any{"id": "old", "job_id": "legacy", "kind": "checkpoint", "name": "old.safetensors", "size_bytes": 17, "sha256": strings.Repeat("c", 64), "storage_key": "/legacy/unsafe/path"})
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.CheckSchema(ctx); err == nil {
				t.Fatal("legacy schema accepted before migration")
			}
			if _, err := db.Migrate(ctx); err != nil {
				t.Fatal(err)
			}
			artifact, err := db.One(ctx, "SELECT * FROM jm_artifacts WHERE id=?", "old")
			if err != nil || artifact == nil {
				t.Fatalf("artifact lost %#v %v", artifact, err)
			}
			if artifact["locator_json"] != nil || artifact["storage_key"] != "/legacy/unsafe/path" || artifact["size_bytes"] != int64(17) {
				t.Fatalf("legacy artifact reinterpreted %#v", artifact)
			}
			if _, err := db.CheckSchema(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestMigrationRollsBackAllChangesOnUnversionedAuditTable(t *testing.T) {
	db := loadLegacyFixture(t, "1")
	ctx := context.Background()
	if err := loadSchema(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, schemaTables["jm_admin_audit"].Create["sqlite"]); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Migrate(ctx); err == nil {
		t.Fatal("unversioned audit table silently accepted")
	}
	err := db.WithTx(ctx, false, func(tx *Tx) error {
		revisions, err := tx.All(ctx, "SELECT revision FROM jm_schema_revisions")
		if err != nil {
			return err
		}
		if len(revisions) != 1 {
			t.Fatalf("failed migration committed revision %#v", revisions)
		}
		columns, err := columnsFor(ctx, tx, "jm_artifacts")
		if err != nil {
			return err
		}
		if columns["locator_json"] {
			t.Fatal("failed migration committed added locator column")
		}
		columns, err = columnsFor(ctx, tx, "jm_log_chunks")
		if err != nil {
			return err
		}
		if columns["charged_bytes"] {
			t.Fatal("failed migration committed added accounting column")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
