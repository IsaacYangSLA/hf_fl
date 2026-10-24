package worker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/config"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/store"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/transfers"
)

type fakeEngine struct {
	expire  func(context.Context, int) (int, error)
	work    func(context.Context, int) ([]string, []string, error)
	process func(context.Context, string, bool) (string, error)
}

func (f fakeEngine) Expire(ctx context.Context, batch int) (int, error) {
	if f.expire != nil {
		return f.expire(ctx, batch)
	}
	return 0, nil
}
func (f fakeEngine) Work(ctx context.Context, batch int) ([]string, []string, error) {
	if f.work != nil {
		return f.work(ctx, batch)
	}
	return nil, nil, nil
}
func (f fakeEngine) Process(ctx context.Context, id string, cleanup bool) (string, error) {
	if f.process != nil {
		return f.process(ctx, id, cleanup)
	}
	return "skipped", nil
}

func workerSettings() config.WorkerSettings {
	return config.WorkerSettings{
		VerifyConcurrency: 2, CleanupConcurrency: 1, BatchSize: 32,
		OperationRetentionSeconds: 100, EventRetentionSeconds: 200,
	}
}

func TestTickPoolsKeepIndependentCapacityAndCategory(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	verifyEntered := make(chan struct{}, 8)
	cleanupEntered := make(chan struct{}, 8)
	releaseVerify := make(chan struct{})
	releaseCleanup := make(chan struct{})
	defer func() {
		select {
		case <-releaseVerify:
		default:
			close(releaseVerify)
		}
		select {
		case <-releaseCleanup:
		default:
			close(releaseCleanup)
		}
	}()
	var verifyActive, cleanupActive, maxVerify, maxCleanup, pruned atomic.Int32
	maximum := func(target *atomic.Int32, value int32) {
		for old := target.Load(); value > old; old = target.Load() {
			if target.CompareAndSwap(old, value) {
				break
			}
		}
	}
	engine := fakeEngine{
		expire: func(context.Context, int) (int, error) { return 2, nil },
		work: func(context.Context, int) ([]string, []string, error) {
			return []string{"v1", "v2", "v3", "v4"}, []string{"c1", "c2", "c3"}, nil
		},
		process: func(ctx context.Context, id string, cleanup bool) (string, error) {
			if cleanup != strings.HasPrefix(id, "c") {
				return "", errors.New("wrong_pool_category")
			}
			if cleanup {
				maximum(&maxCleanup, cleanupActive.Add(1))
				defer cleanupActive.Add(-1)
				cleanupEntered <- struct{}{}
				select {
				case <-releaseCleanup:
					return "cleaned", nil
				case <-ctx.Done():
					return "", ctx.Err()
				}
			}
			maximum(&maxVerify, verifyActive.Add(1))
			defer verifyActive.Add(-1)
			verifyEntered <- struct{}{}
			select {
			case <-releaseVerify:
				return "verified", nil
			case <-ctx.Done():
				return "", ctx.Err()
			}
		},
	}
	type result struct {
		counts map[string]int
		err    error
	}
	done := make(chan result, 1)
	go func() {
		counts, err := tick(ctx, engine, workerSettings(), 0, func(context.Context, int) error {
			if verifyActive.Load() != 0 || cleanupActive.Load() != 0 {
				return errors.New("pruned_before_pools_quiesced")
			}
			pruned.Add(1)
			return nil
		})
		done <- result{counts, err}
	}()
	for n := 0; n < 2; n++ {
		select {
		case <-verifyEntered:
		case <-ctx.Done():
			t.Fatal("verification pool did not fill")
		}
	}
	select {
	case <-cleanupEntered:
		// Cleanup starts while the entire verification pool remains blocked.
	case <-ctx.Done():
		t.Fatal("cleanup starved behind verification")
	}
	if verifyActive.Load() != 2 || cleanupActive.Load() != 1 || pruned.Load() != 0 {
		t.Fatal("pool reservations were not independently bounded")
	}
	close(releaseCleanup)
	for n := 0; n < 2; n++ {
		select {
		case <-cleanupEntered:
		case <-ctx.Done():
			t.Fatal("cleanup could not progress independently")
		}
	}
	if verifyActive.Load() != 2 {
		t.Fatal("cleanup completion unexpectedly released verification")
	}
	close(releaseVerify)
	var got result
	select {
	case got = <-done:
	case <-ctx.Done():
		t.Fatal("worker pass did not finish")
	}
	if got.err != nil {
		t.Fatal(got.err)
	}
	if got.counts["verified"] != 4 || got.counts["cleaned"] != 3 || got.counts["expired"] != 2 || len(got.counts) != 8 {
		t.Fatalf("unexpected counters: %#v", got.counts)
	}
	if maxVerify.Load() != 2 || maxCleanup.Load() != 1 || pruned.Load() != 1 {
		t.Fatal("pool bounds or pruning order violated")
	}
}

func TestTickGuardsOperationFailuresWithoutLoggingProviderDetails(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)
	secret := "provider-credential-do-not-log"
	engine := fakeEngine{
		work: func(context.Context, int) ([]string, []string, error) {
			return []string{"ok", "error", "panic"}, nil, nil
		},
		process: func(_ context.Context, id string, _ bool) (string, error) {
			switch id {
			case "error":
				return "", errors.New(secret)
			case "panic":
				panic(secret)
			default:
				return "verified", nil
			}
		},
	}
	pruned := false
	counts, err := tick(context.Background(), engine, workerSettings(), 7, func(context.Context, int) error {
		pruned = true
		return nil
	})
	if err != nil || counts["verified"] != 1 || counts["retry"] != 2 || !pruned {
		t.Fatalf("operation failure escaped pass guard: %#v %v", counts, err)
	}
	if strings.Contains(logs.String(), secret) {
		t.Fatal("provider exception details leaked into worker logs")
	}
}

func TestTickPropagatesPassFailuresAndRejectsUnknownOutcomes(t *testing.T) {
	sentinel := errors.New("pass_failure")
	for _, stage := range []string{"expire", "work", "prune", "outcome"} {
		t.Run(stage, func(t *testing.T) {
			engine := fakeEngine{
				expire: func(context.Context, int) (int, error) {
					if stage == "expire" {
						return 0, sentinel
					}
					return 0, nil
				},
				work: func(context.Context, int) ([]string, []string, error) {
					if stage == "work" {
						return nil, nil, sentinel
					}
					return []string{"one"}, nil, nil
				},
				process: func(context.Context, string, bool) (string, error) {
					if stage == "outcome" {
						return "not-a-worker-outcome", nil
					}
					return "verified", nil
				},
			}
			_, err := tick(context.Background(), engine, workerSettings(), 1, func(context.Context, int) error {
				if stage == "prune" {
					return sentinel
				}
				return nil
			})
			if stage == "outcome" {
				if err == nil || err.Error() != "invalid_worker_outcome" {
					t.Fatalf("unknown outcome accepted: %v", err)
				}
			} else if !errors.Is(err, sentinel) {
				t.Fatalf("pass failure swallowed: %v", err)
			}
		})
	}
}

func TestTickCancellationWaitsForItsRunningOperations(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	entered := make(chan struct{}, 1)
	var active atomic.Int32
	engine := fakeEngine{
		work: func(context.Context, int) ([]string, []string, error) {
			return []string{"one"}, nil, nil
		},
		process: func(ctx context.Context, _ string, _ bool) (string, error) {
			active.Add(1)
			defer active.Add(-1)
			entered <- struct{}{}
			<-ctx.Done()
			return "", ctx.Err()
		},
	}
	done := make(chan error, 1)
	go func() {
		_, err := tick(ctx, engine, workerSettings(), 1, func(context.Context, int) error {
			return errors.New("prune_after_cancel")
		})
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("operation did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || active.Load() != 0 {
			t.Fatalf("cancellation returned before operations stopped: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled worker pass did not stop")
	}
}

func TestInvalidSettingsCannotCreateUnboundedOrStalledPools(t *testing.T) {
	if _, err := Tick(context.Background(), nil, 1); err == nil {
		t.Fatal("nil worker service accepted")
	}
	if err := Prune(context.Background(), nil, 1); err == nil {
		t.Fatal("nil pruning service accepted")
	}
	for _, settings := range []config.WorkerSettings{
		{VerifyConcurrency: 0, CleanupConcurrency: 1, BatchSize: 1},
		{VerifyConcurrency: 1, CleanupConcurrency: 0, BatchSize: 1},
		{VerifyConcurrency: 1, CleanupConcurrency: 1, BatchSize: 0},
	} {
		if _, err := tick(context.Background(), fakeEngine{}, settings, 0, func(context.Context, int) error { return nil }); err == nil {
			t.Fatal("invalid worker settings accepted")
		}
	}
}

func pruningDB(t *testing.T) *store.DB {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, "sqlite:///:memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := store.Initialize(ctx, db); err != nil {
		t.Fatal(err)
	}
	return db
}

func insert(t *testing.T, db *store.DB, table string, row domain.Object) {
	t.Helper()
	if err := db.Insert(context.Background(), table, row); err != nil {
		t.Fatalf("insert %s: %v", table, err)
	}
}

func ids(t *testing.T, db *store.DB, table string) []string {
	t.Helper()
	rows, err := db.All(context.Background(), "SELECT id FROM "+table+" ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	values := make([]string, len(rows))
	for n, row := range rows {
		values[n] = fmt.Sprint(row["id"])
	}
	sort.Strings(values)
	return values
}

func verifyPruningPhysicalOwnership(t *testing.T, db *store.DB) {
	now, err := db.Now(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	old, recent := now-1000, now+1000
	insert(t, db, "v2_spaces", domain.Object{"id": "a", "name": "A", "event_floor": int64(1000)})
	insert(t, db, "v2_spaces", domain.Object{"id": "b", "name": "B"})
	insert(t, db, "v2_schema_revisions", domain.Object{"id": "schema", "space_id": "a", "kind": "binary", "revision": 1, "schema": domain.Object{"type": "object"}})
	insert(t, db, "v2_records", domain.Object{"id": "record", "space_id": "a", "kind": "binary", "schema_revision_id": "schema", "creator": "creator", "expires_at": recent})
	insert(t, db, "v2_blobs", domain.Object{"id": "blob", "space_id": "a", "record_id": "record", "path": "model.bin", "size": int64(1), "sha256": strings.Repeat("0", 64), "expires_at": recent})
	for _, item := range []struct {
		id, state string
		updated   float64
		tokens    any
	}{
		{"delete-cleaned", "cleaned", old, []any{}},
		{"delete-cleaned-string-array", "cleaned", old, []string{}},
		{"retain-cleaned-marker", "cleaned", old, []any{"owned-provider-call"}},
		{"retain-cleaned-malformed-marker", "cleaned", old, []any{true}},
		{"retain-cleaned-null", "cleaned", old, nil},
		{"retain-cleaned-typednil", "cleaned", old, []string(nil)},
		{"retain-cleaned-object", "cleaned", old, domain.Object{}},
		{"retain-cleaned-string", "cleaned", old, "[]"},
		{"retain-cleaned-empty-token", "cleaned", old, []any{""}},
		{"retain-cleaned-duplicates", "cleaned", old, []any{"same-marker", "same-marker"}},
		{"retain-recent-cleaned", "cleaned", recent, []any{}},
		{"retain-verified", "verified", old, []any{}},
		{"retain-uploading", "uploading", old, []any{}},
		{"retain-cleanup", "cleanup", old, []any{}},
	} {
		insert(t, db, "v2_transfer_attempts", domain.Object{"id": item.id, "blob_id": "blob", "object_key": "opaque/" + item.id, "state": item.state, "updated_at": item.updated, "created_at": old, "mutation_tokens": item.tokens})
	}
	for n, item := range []struct {
		space, principal, scope string
		created                 float64
	}{
		{"a", "p", "scope", old},
		{"a", "other", "scope", recent},
		{"a", "p", "other-scope", recent},
		{"b", "p", "scope", recent},
	} {
		insert(t, db, "v2_operations", domain.Object{"space_id": item.space, "principal_id": item.principal, "scope": item.scope, "key": "same-key", "request_hash": fmt.Sprintf("hash-%d", n), "response": domain.Object{}, "created_at": item.created})
	}
	eventA := domain.Object{"space_id": "a", "type": "record.published", "principal_id": "p", "payload": domain.Object{}, "created_at": old}
	eventB := domain.Object{"space_id": "b", "type": "record.published", "principal_id": "p", "payload": domain.Object{}, "created_at": old}
	eventRecent := domain.Object{"space_id": "b", "type": "record.published", "principal_id": "p", "payload": domain.Object{}, "created_at": recent}
	insert(t, db, "v2_events", eventA)
	insert(t, db, "v2_events", eventB)
	insert(t, db, "v2_events", eventRecent)

	svc := &transfers.Service{DB: db, Settings: config.Settings{Worker: workerSettings()}}
	if err := Prune(context.Background(), svc, 100); err != nil {
		t.Fatal(err)
	}
	expected := []string{
		"retain-cleaned-malformed-marker", "retain-cleaned-marker", "retain-cleanup",
		"retain-recent-cleaned", "retain-uploading", "retain-verified",
		"retain-cleaned-null", "retain-cleaned-typednil", "retain-cleaned-object",
		"retain-cleaned-string", "retain-cleaned-empty-token", "retain-cleaned-duplicates",
	}
	sort.Strings(expected)
	if got := ids(t, db, "v2_transfer_attempts"); !reflect.DeepEqual(got, expected) {
		t.Fatalf("unsafe attempt pruning: %#v", got)
	}
	operations, err := db.All(context.Background(), "SELECT space_id,principal_id,scope FROM v2_operations ORDER BY space_id,principal_id,scope")
	if err != nil || len(operations) != 3 {
		t.Fatalf("compound operation key pruning removed unrelated history: %v %#v", err, operations)
	}
	for _, operation := range operations {
		if operation["space_id"] == "a" && operation["principal_id"] == "p" && operation["scope"] == "scope" {
			t.Fatal("expired operation was retained")
		}
	}
	if got := ids(t, db, "v2_events"); !reflect.DeepEqual(got, []string{fmt.Sprint(eventRecent["id"])}) {
		t.Fatalf("recent event removed: %#v", got)
	}
	spaceA, err := db.One(context.Background(), "SELECT event_floor FROM v2_spaces WHERE id='a'")
	if err != nil || spaceA["event_floor"] != int64(1000) {
		t.Fatalf("event floor regressed: %#v %v", spaceA, err)
	}
	spaceB, err := db.One(context.Background(), "SELECT event_floor FROM v2_spaces WHERE id='b'")
	if err != nil || spaceB["event_floor"] != eventB["id"] {
		t.Fatalf("expired event floor not advanced atomically: %#v %v", spaceB, err)
	}
}

func verifyPruneBatchLimits(t *testing.T, db *store.DB) {
	now, err := db.Now(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	insert(t, db, "v2_spaces", domain.Object{"id": "space", "name": "Space"})
	for n := 0; n < 3; n++ {
		insert(t, db, "v2_operations", domain.Object{"space_id": "space", "principal_id": "p", "scope": "scope", "key": fmt.Sprint(n), "request_hash": "hash", "response": domain.Object{}, "created_at": now - 1000 - float64(n)})
		insert(t, db, "v2_events", domain.Object{"space_id": "space", "type": "event", "principal_id": "p", "payload": domain.Object{}, "created_at": now - 1000})
	}
	for pass := 0; pass < 3; pass++ {
		if err := prune(context.Background(), db, workerSettings(), 1); err != nil {
			t.Fatal(err)
		}
		operations, err := db.All(context.Background(), "SELECT key FROM v2_operations")
		if err != nil || len(operations) != 2-pass {
			t.Fatalf("operation batch bound: %v %#v", err, operations)
		}
		if got := ids(t, db, "v2_events"); len(got) != 2-pass {
			t.Fatalf("event batch bound: %#v", got)
		}
		space, err := db.One(context.Background(), "SELECT event_floor FROM v2_spaces WHERE id='space'")
		if err != nil || space["event_floor"] != int64(pass+1) {
			t.Fatalf("event cursor floor mismatch: %#v %v", space, err)
		}
	}
}

func TestPruneUsesActualSchemaAndPreservesPhysicalOwnership(t *testing.T) {
	verifyPruningPhysicalOwnership(t, pruningDB(t))
}

func TestPruneHonorsPerCategoryBatchLimits(t *testing.T) {
	verifyPruneBatchLimits(t, pruningDB(t))
}

func pruningPostgresDB(t *testing.T) *store.DB {
	t.Helper()
	raw := os.Getenv("HF2L_EXCHANGE_TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("set HF2L_EXCHANGE_TEST_DATABASE_URL for isolated PostgreSQL worker retention tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := store.Open(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	schema := "go_worker_" + domain.NewID()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	var db *store.DB
	t.Cleanup(func() {
		if db != nil {
			_ = db.Close()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Error("owned worker test schema cleanup failed")
		}
	})
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal("invalid PostgreSQL worker test URL")
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	db, err = store.Open(ctx, parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	current, err := db.One(ctx, "SELECT current_schema() AS schema_name")
	if err != nil || current["schema_name"] != schema {
		t.Fatal("owned worker test schema binding failed")
	}
	if err := store.Initialize(ctx, db); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestPostgresPrunePreservesPhysicalOwnership(t *testing.T) {
	verifyPruningPhysicalOwnership(t, pruningPostgresDB(t))
}

func TestPostgresPruneHonorsPerCategoryBatchLimits(t *testing.T) {
	verifyPruneBatchLimits(t, pruningPostgresDB(t))
}
