package service

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/store"
)

func newCorePostgres(t *testing.T) (*Service, domain.Principal, string, Object) {
	t.Helper()
	base := os.Getenv("HF2L_GO_EXCHANGE_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("set HF2L_GO_EXCHANGE_TEST_DATABASE_URL to an explicitly disposable PostgreSQL database")
	}
	ctx := context.Background()
	admin, e := store.Open(ctx, base)
	if e != nil {
		t.Fatal(e)
	}
	namespace := "go_core_" + domain.NewID()
	if _, e = admin.Exec(ctx, "CREATE SCHEMA "+namespace); e != nil {
		admin.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if _, e := admin.Exec(context.Background(), "DROP SCHEMA "+namespace+" CASCADE"); e != nil {
			t.Errorf("owned schema cleanup: %v", e)
		}
		_ = admin.Close()
	})
	parsed, e := url.Parse(base)
	if e != nil {
		t.Fatal(e)
	}
	q := parsed.Query()
	q.Set("search_path", namespace)
	parsed.RawQuery = q.Encode()
	db, e := store.Open(ctx, parsed.String())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = db.Close() })
	if e = store.Initialize(ctx, db); e != nil {
		t.Fatal(e)
	}
	s := New(db, Options{})
	p := domain.Principal{ID: strings.Repeat("a", 64), Subject: "owner", BootstrapAdmin: true}
	space, e := s.CreateSpace(ctx, p, Object{"name": "Concurrent core"}, "space")
	if e != nil {
		t.Fatal(e)
	}
	sid := str(space["id"])
	revision, e := s.RegisterType(ctx, p, sid, "artifact", Object{"schema": Object{"type": "object"}}, "type")
	if e != nil {
		t.Fatal(e)
	}
	return s, p, sid, revision
}
func TestCorePostgresConcurrentAdmission(t *testing.T) {
	s, p, sid, rev := newCorePostgres(t)
	ctx := context.Background()
	if _, e := s.UpdateSpaceLimits(ctx, p, sid, Object{"quota_records": int64(1)}); e != nil {
		t.Fatal(e)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, e := s.CreateRecord(ctx, p, sid, Object{"kind": "artifact", "schema_revision_id": rev["id"]}, domain.NewID())
			results <- e
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	wins, denied := 0, 0
	for e := range results {
		if e == nil {
			wins++
			continue
		}
		var public *domain.Error
		if errors.As(e, &public) && public.Code == "metadata_quota_exceeded" {
			denied++
		} else {
			t.Fatalf("unexpected admission %v", e)
		}
	}
	row, e := s.DB.One(ctx, "SELECT record_count FROM v2_spaces WHERE id=?", sid)
	if e != nil || wins != 1 || denied != 1 || num(row["record_count"]) != 1 {
		t.Fatalf("concurrent quota wins%d denied%d row%v err%v", wins, denied, row, e)
	}
}
func TestCorePostgresConcurrentIdempotentCreation(t *testing.T) {
	s, p, sid, rev := newCorePostgres(t)
	ctx := context.Background()
	body := Object{"kind": "artifact", "schema_revision_id": rev["id"], "metadata": Object{"version": int64(1)}}
	start := make(chan struct{})
	results := make(chan Object, 2)
	failures := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			r, e := s.CreateRecord(ctx, p, sid, body, "same-key")
			results <- r
			failures <- e
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	close(failures)
	for e := range failures {
		if e != nil {
			t.Fatal(e)
		}
	}
	ids := map[string]bool{}
	for r := range results {
		ids[str(r["id"])] = true
	}
	row, e := s.DB.One(ctx, "SELECT record_count FROM v2_spaces WHERE id=?", sid)
	if e != nil || len(ids) != 1 || num(row["record_count"]) != 1 {
		t.Fatalf("idempotency duplicated effects %v %v %v", ids, row, e)
	}
}

func TestCorePostgresMalformedLedgerQuiescence(t *testing.T) {
	s, p, sid, rev := newCorePostgres(t)
	ctx := context.Background()
	held := int64(0)
	for name, markers := range malformedCoreMutationLedgers() {
		t.Run(name, func(t *testing.T) {
			r := coreCreate(t, s, p, sid, rev, domain.NewID(), Object{"attachments": []Object{{"path": "model", "size": int64(3), "sha256": strings.Repeat("a", 64)}}})
			rid := str(r["id"])
			bid := str(r["attachments"].([]Object)[0]["id"])
			aid := domain.NewID()
			if e := s.DB.Insert(ctx, "v2_transfer_attempts", Object{"id": aid, "blob_id": bid, "object_key": aid, "state": "cleaned", "mutation_tokens": markers}); e != nil {
				t.Fatal(e)
			}
			if _, e := s.WithdrawRecord(ctx, p, sid, rid); e != nil {
				t.Fatal(e)
			}
			attempt, e := s.DB.One(ctx, "SELECT state,mutation_tokens FROM v2_transfer_attempts WHERE id=?", aid)
			if e != nil || str(attempt["state"]) != "cleanup" {
				t.Fatalf("unknown PostgreSQL marker was not retained: %v %v", attempt, e)
			}
			_, valid := domain.MutationTokens(attempt["mutation_tokens"])
			if valid {
				t.Fatal("malformed persisted ledger unexpectedly became valid")
			}
			held += 3
			space, e := s.DB.One(ctx, "SELECT allocated,reclaiming FROM v2_spaces WHERE id=?", sid)
			if e != nil || num(space["allocated"]) != 0 || num(space["reclaiming"]) != held {
				t.Fatalf("PostgreSQL unknown cleanup released charge: %v %v", space, e)
			}
			if _, e = s.DB.Exec(ctx, "UPDATE v2_blobs SET state=? WHERE id=?", "cleaned", bid); e != nil {
				t.Fatal(e)
			}
			_, e = s.PurgeRecord(ctx, p, sid, rid)
			coreError(t, e, "cleanup_pending")
		})
	}
}
