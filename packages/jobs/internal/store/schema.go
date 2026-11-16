package store

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// schemaJSON freezes the reviewed persistence contract, including auth-owned
// tables, from the former server implementation. It is not generated at startup.
//
//go:embed schema.json
var schemaJSON []byte

type defaultValue struct {
	Kind  string
	Value any
}
type columnSpec struct {
	Name       string
	Kind       string
	Nullable   bool
	PrimaryKey bool `json:"primary_key"`
	Default    *defaultValue
}
type indexSpec struct {
	Name   string
	Create map[string]string
}
type tableSpec struct {
	Name    string
	Columns []columnSpec
	Create  map[string]string
	Indexes []indexSpec
}
type upgradeSpec struct {
	Column     string
	Definition map[string]string
}
type schemaSpec struct {
	Revisions []string
	Tables    []tableSpec
	Upgrades  map[string]upgradeSpec
}

var schema schemaSpec
var schemaOnce sync.Once
var schemaErr error
var schemaTables map[string]tableSpec
var schemaKinds map[string]string

func loadSchema() error {
	schemaOnce.Do(func() {
		decoder := json.NewDecoder(strings.NewReader(string(schemaJSON)))
		decoder.UseNumber()
		schemaErr = decoder.Decode(&schema)
		if schemaErr != nil {
			return
		}
		schemaTables = map[string]tableSpec{}
		schemaKinds = map[string]string{}
		for _, table := range schema.Tables {
			schemaTables[table.Name] = table
			for _, col := range table.Columns {
				if col.Kind != "value" {
					schemaKinds[col.Name] = col.Kind
				}
			}
		}
		if len(schema.Revisions) != 5 || len(schema.Tables) != 27 {
			schemaErr = errors.New("invalid embedded manager schema")
		}
	})
	return schemaErr
}

// CurrentRevision includes opt-in study registration and explicit participant approval.
const CurrentRevision = "0005_study_creators"

func tableNames(ctx context.Context, tx *Tx) (map[string]bool, error) {
	query := "SELECT name FROM sqlite_master WHERE type='table'"
	if tx.Dialect == "postgresql" {
		query = "SELECT tablename AS name FROM pg_tables WHERE schemaname=current_schema()"
	}
	rows, err := tx.All(ctx, query)
	if err != nil {
		return nil, err
	}
	names := map[string]bool{}
	for _, row := range rows {
		name, _ := row["name"].(string)
		names[name] = true
	}
	return names, nil
}
func columnsFor(ctx context.Context, tx *Tx, table string) (map[string]bool, error) {
	var rows []map[string]any
	var err error
	if tx.Dialect == "postgresql" {
		rows, err = tx.All(ctx, "SELECT column_name AS name FROM information_schema.columns WHERE table_schema=current_schema() AND table_name=?", table)
	} else {
		if _, ok := schemaTables[table]; !ok {
			return nil, errors.New("unknown manager table")
		}
		rows, err = tx.All(ctx, "PRAGMA table_info("+quoteID(table)+")")
	}
	if err != nil {
		return nil, err
	}
	names := map[string]bool{}
	for _, row := range rows {
		name, _ := row["name"].(string)
		names[name] = true
	}
	return names, nil
}
func indexesFor(ctx context.Context, tx *Tx, table string) (map[string]bool, error) {
	var rows []map[string]any
	var err error
	if tx.Dialect == "postgresql" {
		rows, err = tx.All(ctx, "SELECT indexname AS name FROM pg_indexes WHERE schemaname=current_schema() AND tablename=?", table)
	} else {
		if _, ok := schemaTables[table]; !ok {
			return nil, errors.New("unknown manager table")
		}
		rows, err = tx.All(ctx, "PRAGMA index_list("+quoteID(table)+")")
	}
	if err != nil {
		return nil, err
	}
	names := map[string]bool{}
	for _, row := range rows {
		name, _ := row["name"].(string)
		names[name] = true
	}
	return names, nil
}
func revisionCount(ctx context.Context, tx *Tx, tables map[string]bool) (int, error) {
	if !tables["jm_schema_revisions"] {
		return 0, nil
	}
	rows, err := tx.All(ctx, "SELECT revision FROM jm_schema_revisions")
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, errors.New("manager schema revision is unsupported")
	}
	values := map[string]bool{}
	for _, row := range rows {
		v, _ := row["revision"].(string)
		values[v] = true
	}
	if len(values) > len(schema.Revisions) {
		return 0, errors.New("manager schema revision is unsupported")
	}
	for i, revision := range schema.Revisions {
		if (i < len(values)) != values[revision] {
			return 0, errors.New("manager schema revision is unsupported")
		}
	}
	return len(values), nil
}
func tableRevision(table string) int {
	switch table {
	case "jm_study_creators":
		return 5
	case "jm_admin_audit":
		return 3
	case "jm_studies", "jm_study_applications":
		return 4
	default:
		return 1
	}
}

func verifyTables(ctx context.Context, tx *Tx, tables map[string]bool, revision int) error {
	for _, table := range schema.Tables {
		if tableRevision(table.Name) > revision {
			continue
		}
		if !tables[table.Name] {
			return errors.New("manager schema is incomplete; migration required")
		}
		columns, err := columnsFor(ctx, tx, table.Name)
		if err != nil {
			return err
		}
		for _, col := range table.Columns {
			if revision < 2 {
				if upgrade, ok := schema.Upgrades[table.Name]; ok && upgrade.Column == col.Name {
					continue
				}
			}
			if !columns[col.Name] {
				return errors.New("manager schema columns are incomplete; migration required")
			}
		}
	}
	required := map[string][]string{}
	if revision >= 2 {
		required["jm_auth_sessions"] = []string{"ix_jm_sessions_expiry"}
	}
	if revision >= 3 {
		required["jm_admin_audit"] = []string{"ix_jm_admin_audit_resource", "ix_jm_admin_audit_actor"}
	}
	if revision >= 4 {
		required["jm_study_applications"] = []string{"uq_jm_study_approved_participant", "ix_jm_study_applications_review", "ix_jm_study_applications_principal"}
	}
	for table, names := range required {
		indexes, err := indexesFor(ctx, tx, table)
		if err != nil {
			return err
		}
		for _, name := range names {
			if !indexes[name] {
				return errors.New("manager schema indexes are incomplete; migration required")
			}
		}
	}
	return nil
}

// CheckSchema never changes the database or repairs a partial schema.
func (db *DB) CheckSchema(ctx context.Context) (string, error) {
	if err := loadSchema(); err != nil {
		return "", err
	}
	err := db.WithTx(ctx, false, func(tx *Tx) error {
		tables, err := tableNames(ctx, tx)
		if err != nil {
			return err
		}
		count, err := revisionCount(ctx, tx, tables)
		if err != nil {
			return err
		}
		if count == 0 {
			return errors.New("manager schema is absent; initialize it explicitly")
		}
		if count != len(schema.Revisions) {
			return errors.New("manager schema upgrade is required")
		}
		return verifyTables(ctx, tx, tables, len(schema.Revisions))
	})
	if err != nil {
		return "", err
	}
	return CurrentRevision, nil
}

// Migrate applies additive revisions under a transaction-wide migration lock.
// Existing content, ownership, and historical revision records are retained.
func (db *DB) Migrate(ctx context.Context) (string, error) {
	if err := loadSchema(); err != nil {
		return "", err
	}
	err := db.WithTx(ctx, true, func(tx *Tx) error {
		if tx.Dialect == "postgresql" {
			if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(714295130845211)"); err != nil {
				return err
			}
		}
		tables, err := tableNames(ctx, tx)
		if err != nil {
			return err
		}
		count, err := revisionCount(ctx, tx, tables)
		if err != nil {
			return err
		}
		if count == len(schema.Revisions) {
			return verifyTables(ctx, tx, tables, len(schema.Revisions))
		}
		if count == 0 {
			for _, table := range schema.Tables {
				if tables[table.Name] {
					return errors.New("unversioned partial manager schema requires operator recovery")
				}
			}
			for _, table := range schema.Tables {
				ddl, ok := table.Create[tx.Dialect]
				if !ok {
					return errors.New("unsupported manager SQL dialect")
				}
				if _, err := tx.Exec(ctx, ddl); err != nil {
					return err
				}
			}
			for _, table := range schema.Tables {
				for _, index := range table.Indexes {
					if _, err := tx.Exec(ctx, index.Create[tx.Dialect]); err != nil {
						return err
					}
				}
			}
			for _, revision := range schema.Revisions {
				if err := tx.Insert(ctx, "jm_schema_revisions", map[string]any{"revision": revision}); err != nil {
					return err
				}
			}
			return nil
		}
		if err := verifyTables(ctx, tx, tables, count); err != nil {
			return err
		}
		if count == 1 {
			names := make([]string, 0, len(schema.Upgrades))
			for name := range schema.Upgrades {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				upgrade := schema.Upgrades[name]
				columns, err := columnsFor(ctx, tx, name)
				if err != nil {
					return err
				}
				if !columns[upgrade.Column] {
					if _, err := tx.Exec(ctx, "ALTER TABLE "+quoteID(name)+" ADD COLUMN "+upgrade.Definition[tx.Dialect]); err != nil {
						return err
					}
				}
			}
			indexes, err := indexesFor(ctx, tx, "jm_auth_sessions")
			if err != nil {
				return err
			}
			if !indexes["ix_jm_sessions_expiry"] {
				for _, index := range schemaTables["jm_auth_sessions"].Indexes {
					if index.Name == "ix_jm_sessions_expiry" {
						if _, err := tx.Exec(ctx, index.Create[tx.Dialect]); err != nil {
							return err
						}
					}
				}
			}
			if err := tx.Insert(ctx, "jm_schema_revisions", map[string]any{"revision": schema.Revisions[1]}); err != nil {
				return err
			}
		}
		for name, upgrade := range schema.Upgrades {
			columns, err := columnsFor(ctx, tx, name)
			if err != nil {
				return err
			}
			if !columns[upgrade.Column] {
				return errors.New("manager schema columns are incomplete; migration required")
			}
		}
		indexes, err := indexesFor(ctx, tx, "jm_auth_sessions")
		if err != nil {
			return err
		}
		if !indexes["ix_jm_sessions_expiry"] {
			return errors.New("manager schema indexes are incomplete; migration required")
		}
		if count < 3 {
			if tables["jm_admin_audit"] {
				return errors.New("unversioned administrative audit table requires operator recovery")
			}
			audit := schemaTables["jm_admin_audit"]
			if _, err := tx.Exec(ctx, audit.Create[tx.Dialect]); err != nil {
				return err
			}
			for _, index := range audit.Indexes {
				if _, err := tx.Exec(ctx, index.Create[tx.Dialect]); err != nil {
					return err
				}
			}
			if err := tx.Insert(ctx, "jm_schema_revisions", map[string]any{"revision": schema.Revisions[2]}); err != nil {
				return err
			}
		}
		if count < 4 {
			for _, name := range []string{"jm_studies", "jm_study_applications"} {
				if tables[name] {
					return errors.New("unversioned study table requires operator recovery")
				}
			}
			for _, name := range []string{"jm_studies", "jm_study_applications"} {
				table := schemaTables[name]
				if _, err := tx.Exec(ctx, table.Create[tx.Dialect]); err != nil {
					return err
				}
				for _, index := range table.Indexes {
					if _, err := tx.Exec(ctx, index.Create[tx.Dialect]); err != nil {
						return err
					}
				}
			}
			if err := tx.Insert(ctx, "jm_schema_revisions", map[string]any{"revision": schema.Revisions[3]}); err != nil {
				return err
			}
		}
		if count < 5 {
			if tables["jm_study_creators"] {
				return errors.New("unversioned study creator table requires operator recovery")
			}
			if _, err := tx.Exec(ctx, schemaTables["jm_study_creators"].Create[tx.Dialect]); err != nil {
				return err
			}
			if err := tx.Insert(ctx, "jm_schema_revisions", map[string]any{"revision": schema.Revisions[4]}); err != nil {
				return err
			}
		}
		tables, err = tableNames(ctx, tx)
		if err != nil {
			return err
		}
		return verifyTables(ctx, tx, tables, len(schema.Revisions))
	})
	if err != nil {
		return "", err
	}
	return CurrentRevision, nil
}
func quoteID(identifier string) string {
	// All callers establish membership in generated schema metadata first.
	return fmt.Sprintf("\"%s\"", strings.ReplaceAll(identifier, "\"", "\"\""))
}
