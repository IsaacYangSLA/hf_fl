package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/domain"
)

type inputRow struct {
	Table  string        `json:"table"`
	Values domain.Object `json:"values"`
}

func inputs(t *testing.T) []inputRow { return loadInputs(t, "orm_inputs.json") }
func loadInputs(t *testing.T, name string) []inputRow {
	t.Helper()
	raw, e := os.ReadFile(filepath.Join("testdata", name))
	if e != nil {
		t.Fatal(e)
	}
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.UseNumber()
	var out []inputRow
	if e = d.Decode(&out); e != nil {
		t.Fatal(e)
	}
	return out
}
func testDB(t *testing.T, backend string) (*DB, string) {
	t.Helper()
	ctx := context.Background()
	if backend == "sqlite" {
		u := "sqlite:///" + filepath.Join(t.TempDir(), "exchange.db")
		d, e := Open(ctx, u)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { d.Close() })
		return d, u
	}
	raw := os.Getenv("HF2L_EXCHANGE_TEST_DATABASE_URL")
	if raw == "" {
		raw = os.Getenv("EXCHANGE_GO_TEST_DATABASE_URL")
	}
	if raw == "" {
		t.Skip("set HF2L_EXCHANGE_TEST_DATABASE_URL for actual PostgreSQL foundation gate")
	}
	base, e := Open(ctx, raw)
	if e != nil {
		t.Fatal(e)
	}
	schema := "go_exchange_foundation_" + domain.NewID()
	if _, e = base.Exec(ctx, "CREATE SCHEMA "+quoteID(schema)); e != nil {
		base.Close()
		t.Fatal(e)
	}
	u, e := url.Parse(raw)
	if e != nil {
		t.Fatal(e)
	}
	query := u.Query()
	options := query.Get("options")
	if options != "" {
		options += " "
	}
	query.Set("options", options+"-csearch_path="+schema)
	u.RawQuery = query.Encode()
	child, e := Open(ctx, u.String())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		child.Close()
		_, e := base.Exec(context.Background(), "DROP SCHEMA "+quoteID(schema)+" CASCADE")
		base.Close()
		if e != nil {
			t.Errorf("owned PostgreSQL schema cleanup: %v", e)
		}
	})
	probe, e := child.One(ctx, "SELECT current_schema() AS active_namespace")
	if e != nil || probe["active_namespace"] != schema {
		t.Fatalf("owned PostgreSQL namespace not selected: %v", e)
	}
	return child, u.String()
}
func insertAll(t *testing.T, db *DB) {
	t.Helper()
	e := db.WithTx(context.Background(), true, func(tx *Tx) error {
		for _, r := range inputs(t) {
			if e := tx.Insert(context.Background(), r.Table, r.Values); e != nil {
				return fmt.Errorf("%s: %w", r.Table, e)
			}
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
}
func snapshot(t *testing.T, db *DB) domain.Object {
	t.Helper()
	result := domain.Object{}
	for _, r := range inputs(t) {
		rows, e := db.All(context.Background(), "SELECT * FROM "+quoteID(r.Table))
		if e != nil {
			t.Fatal(e)
		}
		result[r.Table] = rows
	}
	return result
}
func requireCode(t *testing.T, err error, code string) {
	t.Helper()
	if domain.ErrorCode(err) != code {
		t.Fatalf("error %v code=%q expected %q", err, domain.ErrorCode(err), code)
	}
}
func TestInitializeDefaultsTypesAndPersistence(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgresql"} {
		t.Run(backend, func(t *testing.T) {
			db, _ := testDB(t, backend)
			ctx := context.Background()
			requireCode(t, CheckRevision(ctx, db), "database_not_initialized")
			if e := Initialize(ctx, db); e != nil {
				t.Fatal(e)
			}
			if e := Check(ctx, db); e != nil {
				t.Fatal(e)
			}
			if e := CheckRevision(ctx, db); e != nil {
				t.Fatal(e)
			}
			insertAll(t, db)
			if e := Initialize(ctx, db); e != nil {
				t.Fatal("idempotent initialize", e)
			}
			rows := snapshot(t, db)
			if len(rows) != 15 {
				t.Fatalf("tables=%d", len(rows))
			}
			s, e := db.One(ctx, "SELECT * FROM v2_spaces")
			if e != nil {
				t.Fatal(e)
			}
			if s["allocated"] != int64(0) || s["quota_bytes"] != int64(107374182400) || s["profile"] != "generic.v1" {
				t.Fatalf("space defaults %#v", s)
			}
			b, e := db.One(ctx, "SELECT * FROM v2_blobs")
			if e != nil {
				t.Fatal(e)
			}
			if b["pending_deletion"] != false || b["state"] != "reserved" || b["part_size"] != int64(8388608) || b["object_version"] != nil {
				t.Fatalf("blob defaults %#v", b)
			}
			m, e := db.One(ctx, "SELECT * FROM v2_members")
			if e != nil {
				t.Fatal(e)
			}
			if _, ok := m["roles"].([]any); !ok {
				t.Fatalf("roles type %T", m["roles"])
			}
			rec, e := db.One(ctx, "SELECT * FROM v2_records")
			if e != nil {
				t.Fatal(e)
			}
			meta := rec["metadata_json"].(map[string]any)
			if meta["count"] != json.Number("123456789012345678901") || meta["float"] != json.Number("1.0") {
				t.Fatalf("persisted numeric types %#v", meta)
			}
			now, e := db.Now(ctx)
			if e != nil || now < float64(time.Now().Unix()-5) || now > float64(time.Now().Unix()+5) {
				t.Fatalf("DB clock %v %v", now, e)
			}
			if e = db.WithTx(ctx, false, func(tx *Tx) error {
				n, e := tx.Now(ctx)
				if e == nil && n <= 0 {
					return errors.New("invalid transaction clock")
				}
				return e
			}); e != nil {
				t.Fatal(e)
			}
			if db.Dialect == "postgresql" {
				if e = db.WithTx(ctx, false, func(tx *Tx) error {
					r, e := tx.One(ctx, "SHOW transaction_isolation")
					if e == nil && r["transaction_isolation"] != "repeatable read" {
						return fmt.Errorf("isolation %v", r)
					}
					return e
				}); e != nil {
					t.Fatal(e)
				}
			}
			missing, e := db.One(ctx, "SELECT id FROM v2_spaces WHERE id=?", "absent")
			if e != nil || missing != nil {
				t.Fatalf("One missing contract %#v %v", missing, e)
			}
		})
	}
}
func TestMutationValidationAndRollback(t *testing.T) {
	db, _ := testDB(t, "sqlite")
	ctx := context.Background()
	if e := Initialize(ctx, db); e != nil {
		t.Fatal(e)
	}
	boom := errors.New("rollback")
	if e := db.WithTx(ctx, true, func(tx *Tx) error {
		if e := tx.Insert(ctx, "v2_spaces", domain.Object{"id": "one", "name": "one"}); e != nil {
			return e
		}
		return boom
	}); !errors.Is(e, boom) {
		t.Fatal(e)
	}
	if row, e := db.One(ctx, "SELECT * FROM v2_spaces"); e != nil || row != nil {
		t.Fatalf("rollback failed %#v %v", row, e)
	}
	for _, item := range []struct {
		table string
		v     domain.Object
	}{
		{"unknown", domain.Object{"id": "x"}}, {"v2_spaces", domain.Object{"id": "x"}}, {"v2_spaces", domain.Object{"id": "x", "name": "x", "extra": 1}},
		{"v2_spaces", domain.Object{"id": "x", "name": "x", "quota_bytes": 1.0}},
		{"v2_spaces", domain.Object{"id": "x", "name": "x", "quota_bytes": true}},
		{"v2_members", domain.Object{"space_id": "missing", "principal_id": "user"}},
	} {
		if e := db.Insert(ctx, item.table, item.v); e == nil {
			t.Fatalf("unsafe insert accepted %s %#v", item.table, item.v)
		}
	}
	if e := db.Update(ctx, "v2_spaces", domain.Object{}, domain.Object{"name": "changed"}); e == nil {
		t.Fatal("unselected update accepted")
	}
	if e := db.Insert(ctx, "v2_spaces", domain.Object{"id": "x", "name": "x"}); e != nil {
		t.Fatal(e)
	}
	if e := db.Update(ctx, "v2_spaces", domain.Object{"id": "x"}, domain.Object{"metadata_bytes": int64(10)}); e != nil {
		t.Fatal(e)
	}
}
func TestSchemaGuardRejections(t *testing.T) {
	for _, which := range []string{"partial", "legacy", "unknown", "missing_column", "multiple_ledgers"} {
		t.Run(which, func(t *testing.T) {
			db, _ := testDB(t, "sqlite")
			ctx := context.Background()
			switch which {
			case "partial":
				db.Exec(ctx, "CREATE TABLE v2_spaces(id TEXT)")
			case "legacy":
				db.Exec(ctx, "CREATE TABLE exchange_spaces(id TEXT)")
			default:
				if e := Initialize(ctx, db); e != nil {
					t.Fatal(e)
				}
				if which == "unknown" {
					db.Exec(ctx, "UPDATE "+Ledger+" SET revision='9999_unknown'")
				}
				if which == "multiple_ledgers" {
					db.Exec(ctx, "INSERT INTO "+Ledger+"(revision) VALUES('9999_unknown')")
				}
				if which == "missing_column" {
					db.Exec(ctx, "ALTER TABLE v2_spaces DROP COLUMN event_floor")
				}
			}
			e := Initialize(ctx, db)
			code := "database_schema_incomplete"
			if which == "legacy" {
				code = "legacy_database_not_supported"
			}
			if which == "unknown" || which == "multiple_ledgers" {
				code = "database_revision_incompatible"
			}
			requireCode(t, e, code)
		})
	}
	requireCode(t, CheckRevision(context.Background(), nil), "database_unavailable")
}
func makeLegacy(t *testing.T, db *DB, revision string) {
	t.Helper()
	if e := loadSchema(); e != nil {
		t.Fatal(e)
	}
	e := db.WithTx(context.Background(), true, func(tx *Tx) error {
		ddl := frozen.SQLiteBaseline
		if tx.Dialect == "postgresql" {
			ddl = frozen.PostgreSQLBaseline
		}
		for _, q := range ddl {
			if _, e := tx.Exec(context.Background(), q); e != nil {
				return e
			}
		}
		if _, e := tx.Exec(context.Background(), "CREATE TABLE "+Ledger+"(revision VARCHAR(64) PRIMARY KEY)"); e != nil {
			return e
		}
		if revision == "0002_event_sequence" {
			if e := eventSequence(context.Background(), tx); e != nil {
				return e
			}
		}
		_, e := tx.Exec(context.Background(), "INSERT INTO "+Ledger+"(revision) VALUES(?)", revision)
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
}
func TestOrderedLegacyMigrationsPreserveEventHighWater(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgresql"} {
		for _, revision := range []string{BaselineRevision, "0002_event_sequence"} {
			t.Run(backend+"/"+revision, func(t *testing.T) {
				db, _ := testDB(t, backend)
				ctx := context.Background()
				makeLegacy(t, db, revision)
				if e := db.Insert(ctx, "v2_spaces", domain.Object{"id": "space", "name": "space", "event_floor": int64(100)}); e != nil {
					t.Fatal(e)
				}
				if e := db.Insert(ctx, "v2_events", domain.Object{"space_id": "space", "type": "old", "principal_id": "alice"}); e != nil {
					t.Fatal(e)
				}
				db.Exec(ctx, "DELETE FROM v2_events")
				requireCode(t, Initialize(ctx, db), "database_revision_incompatible")
				if e := Migrate(ctx, db); e != nil {
					t.Fatal(e)
				}
				if e := Check(ctx, db); e != nil {
					t.Fatal(e)
				}
				event := domain.Object{"space_id": "space", "type": "new", "principal_id": "alice"}
				if e := db.Insert(ctx, "v2_events", event); e != nil {
					t.Fatal(e)
				}
				id, ok := domain.Int64(event["id"])
				if !ok || id <= 0 {
					t.Fatalf("bad identity %#v", event)
				}
				if backend == "sqlite" && revision == BaselineRevision && id <= 100 {
					t.Fatalf("event cursor reused %d", id)
				}
				if e := Migrate(ctx, db); e != nil {
					t.Fatal(e)
				}
			})
		}
	}
}
func TestRebindPreservesQuotedQuestionMarks(t *testing.T) {
	query := `SELECT '?',"?", $$?$$, $tag$?$tag$, ? -- ?
/* ? /* ? */ ? */ WHERE a=? AND j ?| array['?']`
	result := rebind(query, "postgresql")
	if strings.Count(result, "$1") != 1 || !strings.Contains(result, "WHERE a=$2") || !strings.Contains(result, "?|") {
		t.Fatalf("unsafe rebind %s", result)
	}
}
func TestBidirectionalPythonPersistence(t *testing.T) { testBidirectionalPythonPersistence(t, false) }
func TestBidirectionalPythonNullPersistence(t *testing.T) {
	testBidirectionalPythonPersistence(t, true)
}
func testBidirectionalPythonPersistence(t *testing.T, explicitNull bool) {
	py := os.Getenv("HF2L_EXCHANGE_TEST_PYTHON")
	if py == "" {
		t.Skip("set HF2L_EXCHANGE_TEST_PYTHON for Python ORM compatibility oracle")
	}
	for _, backend := range []string{"sqlite", "postgresql"} {
		for _, direction := range []string{"python_to_go", "go_to_python"} {
			t.Run(backend+"/"+direction, func(t *testing.T) {
				db, u := testDB(t, backend)
				ctx := context.Background()
				action := "snapshot"
				if explicitNull {
					action = "snapshot_nulls"
				}
				if direction == "python_to_go" {
					action = "create"
					if explicitNull {
						action = "create_nulls"
					}
				} else {
					if e := Initialize(ctx, db); e != nil {
						t.Fatal(e)
					}
					if explicitNull {
						e := db.WithTx(ctx, true, func(tx *Tx) error {
							for _, r := range loadInputs(t, "orm_null_inputs.json") {
								if e := tx.Insert(ctx, r.Table, r.Values); e != nil {
									return e
								}
							}
							return nil
						})
						if e != nil {
							t.Fatal(e)
						}
					} else {
						insertAll(t, db)
					}
				}
				cmd := exec.CommandContext(ctx, py, "testdata/schema_oracle.py", action, u)
				raw, e := cmd.Output()
				if e != nil {
					if x, ok := e.(*exec.ExitError); ok {
						t.Fatalf("reference oracle failed: %s", x.Stderr)
					}
					t.Fatal(e)
				}
				if e := Check(ctx, db); e != nil {
					t.Fatal(e)
				}
				var expected domain.Object
				d := json.NewDecoder(strings.NewReader(string(raw)))
				d.UseNumber()
				if e = d.Decode(&expected); e != nil {
					t.Fatal(e)
				}
				actual := snapshot(t, db)
				// SQLAlchemy and Go may call their current-time defaults at different instants.
				// All other data, including numeric JSON types and every ORM default, must agree.
				for table, spec := range schemaTables {
					left := actual[table].([]map[string]any)[0]
					right := expected[table].([]any)[0].(map[string]any)
					for _, c := range spec.Columns {
						if c.Default != nil && c.Default.Kind == "now" {
							n, ok := domain.Float(left[c.Name])
							if !ok || n <= 0 {
								t.Fatalf("invalid current-time default %s.%s", table, c.Name)
							}
							delete(left, c.Name)
							delete(right, c.Name)
						}
					}
					l, e := domain.CanonicalJSON(left)
					if e != nil {
						t.Fatal(e)
					}
					rr, e := domain.CanonicalJSON(right)
					if e != nil {
						t.Fatal(e)
					}
					if string(l) != string(rr) {
						t.Fatalf("retained data differs %s:\nGo %s\nPython %s", table, l, rr)
					}
				}
			})
		}
	}
}

func TestPoolAcquisitionTimeoutDoesNotLimitTransactionWork(t *testing.T) {
	ctx := context.Background()
	db, e := OpenConfig(ctx, Config{URL: "sqlite:///:memory:", PoolTimeout: 20 * time.Millisecond})
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	if e = Initialize(ctx, db); e != nil {
		t.Fatal(e)
	}
	e = db.WithTx(ctx, true, func(tx *Tx) error {
		nested := db.WithTx(ctx, true, func(*Tx) error { return errors.New("unexpected nested connection") })
		if !errors.Is(nested, context.DeadlineExceeded) {
			return fmt.Errorf("pool wait not bounded: %v", nested)
		}
		// The acquisition deadline must not be the lifetime of an acquired transaction.
		time.Sleep(30 * time.Millisecond)
		return tx.Insert(ctx, "v2_spaces", domain.Object{"id": "slow", "name": "slow"})
	})
	if e != nil {
		t.Fatal(e)
	}
	if r, e := db.One(ctx, "SELECT id FROM v2_spaces WHERE id='slow'"); e != nil || r == nil {
		t.Fatalf("transaction improperly timed out %#v %v", r, e)
	}
}
func TestSQLiteReadTransactionsAreDeferredAndWritesImmediate(t *testing.T) {
	first, u := testDB(t, "sqlite")
	ctx := context.Background()
	if e := Initialize(ctx, first); e != nil {
		t.Fatal(e)
	}
	second, e := Open(ctx, u)
	if e != nil {
		t.Fatal(e)
	}
	defer second.Close()
	e = first.WithTx(ctx, false, func(tx *Tx) error {
		// Before a read statement, deferred BEGIN has acquired no RESERVED writer lock.
		// A second independent pool must be able to commit a write.
		bounded, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer cancel()
		return second.WithTx(bounded, true, func(other *Tx) error {
			return other.Insert(bounded, "v2_spaces", domain.Object{"id": "deferred", "name": "deferred"})
		})
	})
	if e != nil {
		t.Fatal("read transaction acquired a write reservation", e)
	}
	e = first.WithTx(ctx, true, func(tx *Tx) error {
		bounded, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
		defer cancel()
		err := second.WithTx(bounded, true, func(*Tx) error { return errors.New("second writer unexpectedly admitted") })
		if !errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("write reservation not held: %v", err)
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
}

func TestReferenceSchemaAndDefaultManifest(t *testing.T) {
	py := os.Getenv("HF2L_EXCHANGE_TEST_PYTHON")
	if py == "" {
		t.Skip("set HF2L_EXCHANGE_TEST_PYTHON for reference schema/default manifest check")
	}
	cmd := exec.CommandContext(context.Background(), py, "testdata/export_schema.py")
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("reference schema/default drift: %v %s", e, out)
	}
}

func TestDatabaseAggregateIntegerTypes(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgresql"} {
		t.Run(backend, func(t *testing.T) {
			db, _ := testDB(t, backend)
			query := "SELECT SUM(value) AS total FROM (SELECT 42 AS value)"
			if backend == "postgresql" {
				query = "SELECT SUM(value) AS total FROM (VALUES(42::bigint)) AS numbers(value)"
			}
			row, e := db.One(context.Background(), query)
			if e != nil {
				t.Fatal(e)
			}
			n, ok := domain.Int64(row["total"])
			if !ok || n != 42 {
				t.Fatalf("SQL aggregate type lost: value=%#v type=%T", row["total"], row["total"])
			}
			if backend == "postgresql" {
				row, e := db.One(context.Background(), "SELECT 123456789012345678901234567890::numeric AS large, '42'::text AS text_value, 0.5::numeric AS fraction")
				if e != nil {
					t.Fatal(e)
				}
				big, ok := domain.Integer(row["large"])
				if !ok || big.String() != "123456789012345678901234567890" {
					t.Fatalf("large numeric rounded: %#v", row["large"])
				}
				if _, ok := domain.Int64(row["large"]); ok {
					t.Fatal("large aggregate silently wrapped")
				}
				if row["text_value"] != "42" {
					t.Fatalf("ordinary text coerced: %T", row["text_value"])
				}
				fraction, ok := domain.Float(row["fraction"])
				if !ok || fraction != 0.5 {
					t.Fatal("finite numeric fraction lost")
				}
			}
		})
	}
}
