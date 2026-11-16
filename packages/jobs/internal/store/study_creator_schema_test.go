package store

import (
	"context"
	"testing"
)

// Construct the deployed revision-four schema without including the new table.
func revisionFourCreatorDB(t *testing.T, postgres bool) *DB {
	t.Helper()
	db := revisionThreeDB(t, postgres)
	ctx := context.Background()
	if e := db.WithTx(ctx, true, func(tx *Tx) error {
		for _, name := range []string{"jm_studies", "jm_study_applications"} {
			table := schemaTables[name]
			if _, e := tx.Exec(ctx, table.Create[tx.Dialect]); e != nil {
				return e
			}
			for _, index := range table.Indexes {
				if _, e := tx.Exec(ctx, index.Create[tx.Dialect]); e != nil {
					return e
				}
			}
		}
		if e := tx.Insert(ctx, "jm_schema_revisions", map[string]any{"revision": "0004_study_enrollment"}); e != nil {
			return e
		}
		if e := tx.Insert(ctx, "jm_projects", map[string]any{"id": "retained-study", "name": "Retained"}); e != nil {
			return e
		}
		if e := tx.Insert(ctx, "jm_project_members", map[string]any{"project_id": "retained-study", "principal_id": "existing-admin", "role": "admin"}); e != nil {
			return e
		}
		return tx.Insert(ctx, "jm_studies", map[string]any{"project_id": "retained-study", "enabled": true, "registration_open": true})
	}); e != nil {
		t.Fatal(e)
	}
	return db
}
func exerciseStudyCreatorUpgrade(t *testing.T, postgres bool) {
	t.Helper()
	ctx := context.Background()
	db := revisionFourCreatorDB(t, postgres)
	if _, e := db.CheckSchema(ctx); e == nil {
		t.Fatal("old revision accepted without upgrade")
	}
	if revision, e := db.Migrate(ctx); e != nil || revision != CurrentRevision {
		t.Fatal(revision, e)
	}
	if revision, e := db.Migrate(ctx); e != nil || revision != CurrentRevision {
		t.Fatal("repeat migration", revision, e)
	}
	if e := db.WithTx(ctx, false, func(tx *Tx) error {
		rows, e := tx.All(ctx, "SELECT * FROM jm_study_creators")
		if e != nil {
			return e
		}
		if len(rows) != 0 {
			t.Fatal("upgrade silently granted creation")
		}
		member, e := tx.One(ctx, "SELECT role FROM jm_project_members WHERE project_id=? AND principal_id=?", "retained-study", "existing-admin")
		if e != nil {
			return e
		}
		if member["role"] != "admin" {
			t.Fatal("existing administrator changed")
		}
		study, e := tx.One(ctx, "SELECT enabled, registration_open FROM jm_studies WHERE project_id=?", "retained-study")
		if e != nil {
			return e
		}
		if study["enabled"] != true || study["registration_open"] != true {
			t.Fatal("existing policy changed", study)
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}
func TestStudyCreatorSchemaUpgrade(t *testing.T)         { exerciseStudyCreatorUpgrade(t, false) }
func TestStudyCreatorPostgresSchemaUpgrade(t *testing.T) { exerciseStudyCreatorUpgrade(t, true) }
func TestStudyCreatorSchemaRejectsPartialUpgrade(t *testing.T) {
	db := revisionFourCreatorDB(t, false)
	ctx := context.Background()
	if _, e := db.Exec(ctx, "CREATE TABLE jm_study_creators (principal_id TEXT PRIMARY KEY)"); e != nil {
		t.Fatal(e)
	}
	if _, e := db.Migrate(ctx); e == nil {
		t.Fatal("partial unversioned creator table accepted")
	}
}
