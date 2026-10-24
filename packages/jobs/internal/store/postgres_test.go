package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
)

func openPostgresTestDB(t *testing.T) *DB {
	t.Helper()
	databaseURL := os.Getenv("JOBS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("JOBS_TEST_DATABASE_URL must point to an isolated PostgreSQL test database")
	}
	ctx := context.Background()
	base, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { base.Close() })
	if base.Dialect != "postgresql" {
		t.Fatal("JOBS_TEST_DATABASE_URL must use PostgreSQL")
	}
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	namespace := "hf2l_store_test_" + hex.EncodeToString(random)
	if _, err := base.Exec(ctx, "CREATE SCHEMA "+quoteID(namespace)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := base.Exec(ctx, "DROP SCHEMA "+quoteID(namespace)+" CASCADE"); err != nil {
			t.Error(err)
		}
	})
	normalized := strings.Replace(databaseURL, "postgresql+psycopg://", "postgresql://", 1)
	parsed, err := url.Parse(normalized)
	if err != nil {
		t.Fatal("invalid test database URL")
	}
	query := parsed.Query()
	query.Set("search_path", namespace)
	parsed.RawQuery = query.Encode()
	db, err := Open(ctx, parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestPostgreSQLSchemaAndConcurrentWriters(t *testing.T) {
	db := openPostgresTestDB(t)
	ctx := context.Background()
	var group sync.WaitGroup
	failures := make(chan error, 2)
	for i := 0; i < 2; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if _, err := db.Migrate(ctx); err != nil {
				failures <- err
			}
		}()
	}
	group.Wait()
	close(failures)
	for err := range failures {
		t.Fatal("concurrent migration", err)
	}
	if _, err := db.CheckSchema(ctx); err != nil {
		t.Fatal(err)
	}
	project := map[string]any{"id": "pg", "name": "PostgreSQL", "quotas_json": map[string]any{"large": json.Number("9007199254740993"), "float": json.Number("1.0")}}
	if err := db.WithTx(ctx, true, func(tx *Tx) error { return tx.Insert(ctx, "jm_projects", project) }); err != nil {
		t.Fatal(err)
	}
	row, err := db.One(ctx, "SELECT * FROM jm_projects WHERE id=?", "pg")
	if err != nil {
		t.Fatal(err)
	}
	values := row["quotas_json"].(map[string]any)
	if values["large"] != json.Number("9007199254740993") {
		t.Fatalf("PostgreSQL JSON precision lost %#v", values)
	}
	failures = make(chan error, 2)
	for i := 0; i < 2; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for n := 0; n < 20; n++ {
				err := db.WithTx(ctx, true, func(tx *Tx) error {
					row, err := tx.One(ctx, "SELECT retained_bytes FROM jm_projects WHERE id=?"+tx.ForUpdate(), "pg")
					if err != nil {
						return err
					}
					return tx.Update(ctx, "jm_projects", map[string]any{"id": "pg"}, map[string]any{"retained_bytes": row["retained_bytes"].(int64) + 1})
				})
				if err != nil {
					failures <- err
					return
				}
			}
		}()
	}
	group.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	row, err = db.One(ctx, "SELECT retained_bytes FROM jm_projects WHERE id=?", "pg")
	if err != nil || row["retained_bytes"] != int64(40) {
		t.Fatalf("PostgreSQL lock accounting %#v %v", row, err)
	}
}

func TestPostgreSQLLegacyMigrationsPreserveArtifacts(t *testing.T) {
	for _, revision := range []string{"1", "2"} {
		t.Run("revision"+revision, func(t *testing.T) {
			db := openPostgresTestDB(t)
			ctx := context.Background()
			source, err := os.ReadFile("testdata/schema_v" + revision + ".postgresql.sql")
			if err != nil {
				t.Fatal(err)
			}
			for _, statement := range strings.Split(string(source), ";\n") {
				if strings.TrimSpace(statement) == "" {
					continue
				}
				if _, err := db.Exec(ctx, statement); err != nil {
					t.Fatal("legacy PostgreSQL fixture", err)
				}
			}
			addJob(t, db, "legacy")
			err = db.WithTx(ctx, true, func(tx *Tx) error {
				return tx.Insert(ctx, "jm_artifacts", map[string]any{"id": "old", "job_id": "legacy", "kind": "checkpoint", "name": "old.safetensors", "size_bytes": 17, "sha256": strings.Repeat("c", 64), "storage_key": "/legacy/unsafe/path"})
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.CheckSchema(ctx); err == nil {
				t.Fatal("legacy PostgreSQL accepted before migration")
			}
			if _, err := db.Migrate(ctx); err != nil {
				t.Fatal(err)
			}
			artifact, err := db.One(ctx, "SELECT * FROM jm_artifacts WHERE id=?", "old")
			if err != nil || artifact == nil {
				t.Fatalf("artifact lost %#v %v", artifact, err)
			}
			if artifact["locator_json"] != nil || artifact["storage_key"] != "/legacy/unsafe/path" || artifact["size_bytes"] != int64(17) {
				t.Fatalf("legacy PostgreSQL artifact changed %#v", artifact)
			}
			if _, err := db.CheckSchema(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}
