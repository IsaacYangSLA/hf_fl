package store

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/domain"
	"github.com/jackc/pgx/v5/pgconn"
	"modernc.org/sqlite"
)

const BaselineRevision = "0001_initial"
const SchemaRevision = "0003_workload_grants"
const Revision = SchemaRevision
const Ledger = "v2_schema_ledger"

//go:embed schema.json
var schemaBytes []byte

type defaultSpec struct {
	Kind  string `json:"kind"`
	Value any    `json:"value"`
}
type columnSpec struct {
	Name       string       `json:"name"`
	Kind       string       `json:"kind"`
	Nullable   bool         `json:"nullable"`
	PrimaryKey bool         `json:"primary_key"`
	Auto       bool         `json:"auto"`
	Default    *defaultSpec `json:"default"`
}
type tableSpec struct {
	Name    string       `json:"name"`
	Columns []columnSpec `json:"columns"`
}
type schemaData struct {
	Revision           string      `json:"revision"`
	Tables             []tableSpec `json:"tables"`
	SQLiteBaseline     []string    `json:"sqlite_baseline"`
	PostgreSQLBaseline []string    `json:"postgresql_baseline"`
}

var schemaOnce sync.Once
var schemaErr error
var frozen schemaData
var schemaTables map[string]tableSpec
var schemaKinds map[string]string

func loadSchema() error {
	schemaOnce.Do(func() {
		d := json.NewDecoder(bytes.NewReader(schemaBytes))
		d.UseNumber()
		if schemaErr = d.Decode(&frozen); schemaErr != nil {
			return
		}
		if frozen.Revision != SchemaRevision || len(frozen.Tables) != 15 {
			schemaErr = errors.New("invalid embedded exchange schema")
			return
		}
		schemaTables = map[string]tableSpec{}
		schemaKinds = map[string]string{}
		for _, t := range frozen.Tables {
			schemaTables[t.Name] = t
			for _, c := range t.Columns {
				if c.Kind == "json" || c.Kind == "bool" {
					schemaKinds[c.Name] = c.Kind
				}
			}
		}
	})
	return schemaErr
}
func (db *DB) Now(ctx context.Context) (float64, error) {
	var row domain.Object
	var err error
	if db.Dialect == "postgresql" {
		row, err = db.One(ctx, "SELECT EXTRACT(EPOCH FROM clock_timestamp())::double precision AS epoch")
	} else {
		row, err = db.One(ctx, "SELECT (julianday('now') - 2440587.5) * 86400.0 AS epoch")
	}
	if err != nil {
		return 0, err
	}
	n, ok := domain.Float(row["epoch"])
	if !ok {
		return 0, errors.New("invalid exchange database clock")
	}
	return n, nil
}
func (tx *Tx) Now(ctx context.Context) (float64, error) {
	var row domain.Object
	var err error
	if tx.Dialect == "postgresql" {
		row, err = tx.One(ctx, "SELECT EXTRACT(EPOCH FROM clock_timestamp())::double precision AS epoch")
	} else {
		row, err = tx.One(ctx, "SELECT (julianday('now') - 2440587.5) * 86400.0 AS epoch")
	}
	if err != nil {
		return 0, err
	}
	n, ok := domain.Float(row["epoch"])
	if !ok {
		return 0, errors.New("invalid exchange database clock")
	}
	return n, nil
}
func (db *DB) CheckRevision(ctx context.Context) error { return CheckRevision(ctx, db) }
func (db *DB) Check(ctx context.Context) error         { return Check(ctx, db) }
func (db *DB) Initialize(ctx context.Context) error    { return Initialize(ctx, db) }
func (db *DB) Migrate(ctx context.Context) error       { return Migrate(ctx, db) }

// CheckRevision performs no schema mutation or catalog scan.
func CheckRevision(ctx context.Context, db *DB) error {
	if db == nil || db.SQL == nil {
		return domain.Err(503, "database_unavailable")
	}
	rows, err := db.All(ctx, "SELECT revision FROM "+Ledger+" ORDER BY revision")
	if err != nil {
		var pe *pgconn.PgError
		var se *sqlite.Error
		if errors.As(err, &pe) && pe.Code == "42P01" || errors.As(err, &se) && se.Code() == 1 && strings.HasPrefix(se.Error(), "SQL logic error: no such table: "+Ledger+" ") {
			return domain.Err(503, "database_not_initialized")
		}
		return domain.Err(503, "database_unavailable")
	}
	if len(rows) != 1 || rows[0]["revision"] != SchemaRevision {
		return domain.Err(503, "database_revision_incompatible")
	}
	return nil
}
func Check(ctx context.Context, db *DB) error {
	if db == nil || db.SQL == nil {
		return domain.Err(503, "database_unavailable")
	}
	if err := loadSchema(); err != nil {
		return err
	}
	return db.WithTx(ctx, false, func(tx *Tx) error { return checkConnection(ctx, tx) })
}
func tables(ctx context.Context, tx *Tx) (map[string]bool, error) {
	query := "SELECT name FROM sqlite_master WHERE type='table'"
	if tx.Dialect == "postgresql" {
		query = "SELECT table_name AS name FROM information_schema.tables WHERE table_schema=current_schema() AND table_type='BASE TABLE'"
	}
	rows, err := tx.All(ctx, query)
	if err != nil {
		return nil, domain.Err(503, "database_unavailable")
	}
	out := map[string]bool{}
	for _, r := range rows {
		n, _ := r["name"].(string)
		if strings.HasPrefix(n, "exchange_") {
			return nil, domain.Err(503, "legacy_database_not_supported", "Deploy v2 into a fresh database and storage prefix")
		}
		out[n] = true
	}
	return out, nil
}
func columns(ctx context.Context, tx *Tx, table string) (map[string]bool, error) {
	var rows []domain.Object
	var err error
	if tx.Dialect == "postgresql" {
		rows, err = tx.All(ctx, "SELECT column_name AS name FROM information_schema.columns WHERE table_schema=current_schema() AND table_name=?", table)
	} else {
		rows, err = tx.All(ctx, "PRAGMA table_info("+quoteID(table)+")")
	}
	if err != nil {
		return nil, domain.Err(503, "database_unavailable")
	}
	out := map[string]bool{}
	for _, r := range rows {
		n, _ := r["name"].(string)
		out[n] = true
	}
	return out, nil
}
func checkTables(ctx context.Context, tx *Tx, present map[string]bool, revision string) error {
	if err := loadSchema(); err != nil {
		return err
	}
	for name, spec := range schemaTables {
		if revision != SchemaRevision && (name == "v2_managed_spaces" || name == "v2_workload_grants" || name == "v2_workload_revocations") {
			continue
		}
		if !present[name] {
			return domain.Err(503, "database_schema_incomplete")
		}
		cols, err := columns(ctx, tx, name)
		if err != nil {
			return err
		}
		for _, c := range spec.Columns {
			if !cols[c.Name] {
				return domain.Err(503, "database_schema_incomplete")
			}
		}
	}
	return nil
}
func checkConnection(ctx context.Context, tx *Tx) error {
	present, err := tables(ctx, tx)
	if err != nil {
		return err
	}
	if !present[Ledger] {
		return domain.Err(503, "database_not_initialized")
	}
	rows, err := tx.All(ctx, "SELECT revision FROM "+Ledger+" ORDER BY revision")
	if err != nil {
		return domain.Err(503, "database_unavailable")
	}
	if len(rows) != 1 || rows[0]["revision"] != SchemaRevision {
		return domain.Err(503, "database_revision_incompatible")
	}
	return checkTables(ctx, tx, present, SchemaRevision)
}
func Initialize(ctx context.Context, db *DB) error { return writeSchema(ctx, db, false) }
func Migrate(ctx context.Context, db *DB) error    { return writeSchema(ctx, db, true) }
func writeSchema(ctx context.Context, db *DB, upgrade bool) error {
	if db == nil || db.SQL == nil {
		return domain.Err(503, "database_unavailable")
	}
	if err := loadSchema(); err != nil {
		return err
	}
	if db.Dialect != "sqlite" && db.Dialect != "postgresql" {
		return domain.Err(503, "unsupported_database")
	}
	return db.WithTx(ctx, true, func(tx *Tx) error {
		if tx.Dialect == "postgresql" {
			if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(734802341)"); err != nil {
				return err
			}
		}
		present, err := tables(ctx, tx)
		if err != nil {
			return err
		}
		if present[Ledger] {
			if !upgrade {
				return checkConnection(ctx, tx)
			}
			rows, err := tx.All(ctx, "SELECT revision FROM "+Ledger)
			if err != nil {
				return err
			}
			if len(rows) != 1 {
				return domain.Err(503, "database_revision_incompatible")
			}
			rev, _ := rows[0]["revision"].(string)
			if err = checkTables(ctx, tx, present, rev); err != nil {
				return err
			}
			return upgradeSchema(ctx, tx, rev)
		}
		for name := range present {
			if strings.HasPrefix(name, "v2_") {
				return domain.Err(503, "database_schema_incomplete", "A partial unversioned schema cannot be initialized")
			}
		}
		baseline := frozen.SQLiteBaseline
		if tx.Dialect == "postgresql" {
			baseline = frozen.PostgreSQLBaseline
		}
		for _, s := range baseline {
			if _, err = tx.Exec(ctx, s); err != nil {
				return err
			}
		}
		if _, err = tx.Exec(ctx, "CREATE TABLE "+Ledger+" (revision VARCHAR(64) PRIMARY KEY)"); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, "INSERT INTO "+Ledger+" (revision) VALUES (?)", BaselineRevision); err != nil {
			return err
		}
		return upgradeSchema(ctx, tx, BaselineRevision)
	})
}
func upgradeSchema(ctx context.Context, tx *Tx, revision string) error {
	switch revision {
	case BaselineRevision:
		if err := eventSequence(ctx, tx); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "UPDATE "+Ledger+" SET revision=?", "0002_event_sequence"); err != nil {
			return err
		}
		fallthrough
	case "0002_event_sequence":
		if err := workloadGrants(ctx, tx); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "UPDATE "+Ledger+" SET revision=?", SchemaRevision); err != nil {
			return err
		}
	case SchemaRevision:
	default:
		return domain.Err(503, "database_revision_incompatible")
	}
	return checkConnection(ctx, tx)
}
func eventSequence(ctx context.Context, tx *Tx) error {
	if tx.Dialect != "sqlite" {
		return nil
	}
	row, err := tx.One(ctx, "SELECT MAX(COALESCE((SELECT MAX(id) FROM v2_events),0),COALESCE((SELECT MAX(event_floor) FROM v2_spaces),0)) AS high_water")
	if err != nil {
		return err
	}
	high, ok := domain.Int64(row["high_water"])
	if !ok {
		return errors.New("invalid exchange event sequence")
	}
	statements := []string{
		"CREATE TABLE v2_events_0002 (id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,space_id VARCHAR(64) NOT NULL,record_id VARCHAR(64),type VARCHAR(64) NOT NULL,principal_id VARCHAR(64) NOT NULL,payload JSON NOT NULL,created_at FLOAT NOT NULL,FOREIGN KEY(space_id) REFERENCES v2_spaces(id))",
		"INSERT INTO v2_events_0002 (id,space_id,record_id,type,principal_id,payload,created_at) SELECT id,space_id,record_id,type,principal_id,payload,created_at FROM v2_events",
		"DROP TABLE v2_events",
		"ALTER TABLE v2_events_0002 RENAME TO v2_events",
		"CREATE INDEX ix_v2_events_retention ON v2_events(created_at,id)",
		"CREATE INDEX ix_v2_events_space_cursor ON v2_events(space_id,id)",
	}
	for _, s := range statements {
		if _, err = tx.Exec(ctx, s); err != nil {
			return err
		}
	}
	result, err := tx.Exec(ctx, "UPDATE sqlite_sequence SET seq=? WHERE name='v2_events'", high)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		_, err = tx.Exec(ctx, "INSERT INTO sqlite_sequence(name,seq) VALUES('v2_events',?)", high)
	}
	return err
}
func workloadGrants(ctx context.Context, tx *Tx) error {
	jsonType := "JSON"
	if tx.Dialect == "postgresql" {
		jsonType = "JSONB"
	}
	statements := []string{
		"CREATE TABLE v2_managed_spaces (space_id VARCHAR(64) NOT NULL PRIMARY KEY,job_id VARCHAR(128) NOT NULL UNIQUE,created_at FLOAT NOT NULL,retired_at FLOAT,FOREIGN KEY(space_id) REFERENCES v2_spaces(id))",
		fmt.Sprintf("CREATE TABLE v2_workload_grants (id VARCHAR(64) NOT NULL PRIMARY KEY,space_id VARCHAR(64) NOT NULL,principal_id VARCHAR(64) NOT NULL,subject VARCHAR(256) NOT NULL,job_id VARCHAR(128) NOT NULL,attempt_id VARCHAR(128) NOT NULL,component_id VARCHAR(128) NOT NULL,epoch BIGINT NOT NULL,roles %s NOT NULL,bindings %s NOT NULL,certificate_thumbprint VARCHAR(43) NOT NULL,expires_at FLOAT NOT NULL,enabled BOOLEAN NOT NULL,created_at FLOAT NOT NULL,revoked_at FLOAT,FOREIGN KEY(space_id,principal_id) REFERENCES v2_members(space_id,principal_id))", jsonType, jsonType),
		"CREATE TABLE v2_workload_revocations (space_id VARCHAR(64) NOT NULL,attempt_id VARCHAR(128) NOT NULL,revoked_at FLOAT NOT NULL,PRIMARY KEY(space_id,attempt_id),FOREIGN KEY(space_id) REFERENCES v2_spaces(id))",
		"CREATE INDEX ix_v2_workload_grants_attempt ON v2_workload_grants(space_id,attempt_id,enabled)",
		"CREATE INDEX ix_v2_workload_grants_principal ON v2_workload_grants(space_id,principal_id,epoch)",
	}
	for _, s := range statements {
		if _, err := tx.Exec(ctx, s); err != nil {
			return err
		}
	}
	return nil
}
func quoteID(value string) string { return `"` + strings.ReplaceAll(value, `"`, `""`) + `"` }
