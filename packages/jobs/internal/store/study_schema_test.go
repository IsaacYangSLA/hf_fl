package store

import (
	"context"
	"os"
	"strings"
	"testing"
)

// Revision three is reconstructed from the immutable revision-two fixture and
// the unchanged administrative-audit addition. No study metadata participates.
func revisionThreeDB(t *testing.T, postgres bool) *DB {
	t.Helper()
	ctx := context.Background()
	var db *DB
	if postgres {
		db = openPostgresTestDB(t)
		source, err := os.ReadFile("testdata/schema_v2.postgresql.sql")
		if err != nil {
			t.Fatal(err)
		}
		for _, statement := range strings.Split(string(source), ";\n") {
			if strings.TrimSpace(statement) == "" {
				continue
			}
			if _, err := db.Exec(ctx, statement); err != nil {
				t.Fatal(err)
			}
		}
	} else {
		db = loadLegacyFixture(t, "2")
	}
	if err := loadSchema(); err != nil {
		t.Fatal(err)
	}
	audit := schemaTables["jm_admin_audit"]
	if _, err := db.Exec(ctx, audit.Create[db.Dialect]); err != nil {
		t.Fatal(err)
	}
	for _, index := range audit.Indexes {
		if _, err := db.Exec(ctx, index.Create[db.Dialect]); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.WithTx(ctx, true, func(tx *Tx) error {
		return tx.Insert(ctx, "jm_schema_revisions", map[string]any{"revision": "0003_administrative_audit"})
	}); err != nil {
		t.Fatal(err)
	}
	return db
}

func checkStudyUpgrade(t *testing.T, db *DB) {
	t.Helper()
	ctx := context.Background()
	addProject(t, db, "old-project")
	if err := db.WithTx(ctx, true, func(tx *Tx) error {
		return tx.Insert(ctx, "jm_project_members", map[string]any{"project_id": "old-project", "principal_id": "old-admin", "role": "admin"})
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CheckSchema(ctx); err == nil {
		t.Fatal("old revision accepted without explicit migration")
	}
	if revision, err := db.Migrate(ctx); err != nil || revision != CurrentRevision {
		t.Fatalf("migration %s %v", revision, err)
	}
	if _, err := db.CheckSchema(ctx); err != nil {
		t.Fatal(err)
	}
	member, err := db.One(ctx, "SELECT role FROM jm_project_members WHERE project_id=? AND principal_id=?", "old-project", "old-admin")
	if err != nil || member == nil || member["role"] != "admin" {
		t.Fatalf("existing membership changed: %#v %v", member, err)
	}
	for _, name := range []string{"jm_studies", "jm_study_applications"} {
		rows, err := db.All(ctx, "SELECT * FROM "+name)
		if err != nil || len(rows) != 0 {
			t.Fatalf("migration opted old projects into study registration: %s %#v %v", name, rows, err)
		}
	}
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatal("repeat migration", err)
	}
}

func TestRevisionThreeStudyUpgradeIsExplicitAndPreservesExistingMembership(t *testing.T) {
	checkStudyUpgrade(t, revisionThreeDB(t, false))
}

func TestPostgreSQLRevisionThreeStudyUpgrade(t *testing.T) {
	checkStudyUpgrade(t, revisionThreeDB(t, true))
}

func TestStudyApplicationConstraintsDoNotReservePendingAliases(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	addProject(t, db, "study")
	if err := db.WithTx(ctx, true, func(tx *Tx) error {
		return tx.Insert(ctx, "jm_study_applications", map[string]any{"project_id": "study", "principal_id": "unregistered", "participant_id": "alias"})
	}); err == nil {
		t.Fatal("application accepted outside a configured study")
	}
	study := map[string]any{"project_id": "study"}
	if err := db.WithTx(ctx, true, func(tx *Tx) error { return tx.Insert(ctx, "jm_studies", study) }); err != nil {
		t.Fatal(err)
	}
	found, err := db.One(ctx, "SELECT * FROM jm_studies WHERE project_id=?", "study")
	if err != nil || found["enabled"] != false || found["registration_open"] != false {
		t.Fatalf("study was open by default: %#v %v", found, err)
	}
	for _, applicant := range []string{"alice", "bob"} {
		if err := db.WithTx(ctx, true, func(tx *Tx) error {
			return tx.Insert(ctx, "jm_study_applications", map[string]any{"id": applicant, "project_id": "study", "principal_id": applicant, "participant_id": "same-alias"})
		}); err != nil {
			t.Fatalf("pending request reserved an alias: %v", err)
		}
	}
	if err := db.WithTx(ctx, true, func(tx *Tx) error {
		return tx.Update(ctx, "jm_study_applications", map[string]any{"id": "alice"}, map[string]any{"status": "approved"})
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.WithTx(ctx, true, func(tx *Tx) error {
		return tx.Update(ctx, "jm_study_applications", map[string]any{"id": "bob"}, map[string]any{"status": "approved"})
	}); err == nil {
		t.Fatal("two identities approved for the same study alias")
	}
	bob, err := db.One(ctx, "SELECT status FROM jm_study_applications WHERE id=?", "bob")
	if err != nil || bob["status"] != "pending" {
		t.Fatalf("failed approval changed state: %#v %v", bob, err)
	}
	for _, changes := range []map[string]any{{"status": "unknown"}, {"row_version": 0}, {"message": strings.Repeat("x", 2001)}} {
		if err := db.WithTx(ctx, true, func(tx *Tx) error {
			return tx.Update(ctx, "jm_study_applications", map[string]any{"id": "bob"}, changes)
		}); err == nil {
			t.Fatalf("invalid study state accepted: %#v", changes)
		}
	}
	if err := db.WithTx(ctx, true, func(tx *Tx) error {
		return tx.Update(ctx, "jm_studies", map[string]any{"project_id": "study"}, map[string]any{"registration_open": true})
	}); err == nil {
		t.Fatal("disabled study was opened")
	}
}

func TestStudyMigrationRejectsUnversionedTableWithoutPartialUpgrade(t *testing.T) {
	db := revisionThreeDB(t, false)
	ctx := context.Background()
	if _, err := db.Exec(ctx, schemaTables["jm_studies"].Create["sqlite"]); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Migrate(ctx); err == nil {
		t.Fatal("unversioned study table accepted")
	}
	rows, err := db.All(ctx, "SELECT revision FROM jm_schema_revisions")
	if err != nil || len(rows) != 3 {
		t.Fatalf("failed migration advanced revision: %#v %v", rows, err)
	}
	table, err := db.One(ctx, "SELECT name FROM sqlite_master WHERE name='jm_study_applications'")
	if err != nil || table != nil {
		t.Fatalf("failed migration created partial enrollment table: %#v %v", table, err)
	}
}

func TestStudySchemaRejectsMissingApprovalUniquenessIndex(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	if _, err := db.Exec(ctx, "DROP INDEX uq_jm_study_approved_participant"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CheckSchema(ctx); err == nil {
		t.Fatal("missing approval identity guard accepted")
	}
	if _, err := db.Migrate(ctx); err == nil {
		t.Fatal("current incomplete schema silently repaired")
	}
}
