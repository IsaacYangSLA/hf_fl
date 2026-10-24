package manager

import (
	"context"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

func newPostgresMgrFixture(t *testing.T) *mgrFixture {
	t.Helper()
	databaseURL := os.Getenv("JOBS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("JOBS_TEST_DATABASE_URL must point to an isolated PostgreSQL test database")
	}
	ctx := context.Background()
	base, e := store.Open(ctx, databaseURL)
	if e != nil {
		t.Fatal(e)
	}
	if base.Dialect != "postgresql" {
		base.Close()
		t.Fatal("PostgreSQL required")
	}
	namespace := "gm_core_" + domain.NewID()
	if _, e = base.Exec(ctx, "CREATE SCHEMA "+namespace); e != nil {
		base.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if _, e := base.Exec(ctx, "DROP SCHEMA "+namespace+" CASCADE"); e != nil {
			t.Error(e)
		}
		base.Close()
	})
	parsed, e := url.Parse(strings.Replace(databaseURL, "postgresql+psycopg://", "postgresql://", 1))
	if e != nil {
		t.Fatal("invalid PostgreSQL URL")
	}
	query := parsed.Query()
	query.Set("search_path", namespace)
	parsed.RawQuery = query.Encode()
	db, e := store.Open(ctx, parsed.String())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	if _, e = db.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	return populateMgrFixture(t, db)
}
func TestManagerPostgreSQLConcurrentCreationAndVersionedCancellation(t *testing.T) {
	f := newPostgresMgrFixture(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	ids := make(chan string, 8)
	failures := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := f.m.CreateJob(ctx, "owner", mgrSpec(), "same-operation")
			if e != nil {
				failures <- e
			} else {
				ids <- text(r["id"])
			}
		}()
	}
	wg.Wait()
	close(ids)
	close(failures)
	for e := range failures {
		t.Error(e)
	}
	if t.Failed() {
		return
	}
	id := ""
	for got := range ids {
		if id == "" {
			id = got
		}
		if got != id {
			t.Fatal("duplicate creation")
		}
	}
	row, e := f.db.One(ctx, "SELECT COUNT(*) AS n FROM jm_jobs")
	if e != nil || number(row["n"]) != 1 {
		t.Fatal(row, e)
	}
	statuses := make(chan error, 2)
	for _, k := range []string{"cancel-a", "cancel-b"} {
		wg.Add(1)
		go func(k string) { defer wg.Done(); _, e := f.m.Cancel(ctx, "owner", id, 1, k); statuses <- e }(k)
	}
	wg.Wait()
	close(statuses)
	success := 0
	for e := range statuses {
		if e == nil {
			success++
		} else {
			mgrError(t, e, 409, "job_version_conflict")
		}
	}
	if success != 1 {
		t.Fatal("lost optimistic fencing", success)
	}
	rows, e := f.db.All(ctx, "SELECT * FROM jm_outbox WHERE job_id = ? AND topic = ?", id, "fence_stop")
	if e != nil || len(rows) != 1 {
		t.Fatal("duplicate side effect", rows, e)
	}
}
func TestManagerPostgreSQLViewsFiltersAndCursorPrivacy(t *testing.T) {
	f := newPostgresMgrFixture(t)
	ctx := context.Background()
	s := mgrSpec()
	s.Name = "100% <classifier>"
	first, e := f.m.CreateJob(ctx, "owner", s, "one")
	if e != nil {
		t.Fatal(e)
	}
	f.create("two")
	page, e := f.m.ListJobs(ctx, "owner", Object{"view": "queued"}, 1, "")
	if e != nil || number(page["total"]) != 2 || text(page["next_cursor"]) == "" {
		t.Fatal(page, e)
	}
	_, e = f.m.ListJobs(ctx, "foreign", Object{"view": "queued"}, 1, text(page["next_cursor"]))
	mgrError(t, e, 422, "invalid_cursor")
	search, e := f.m.ListJobs(ctx, "owner", Object{"search": "100%"}, 50, "")
	if e != nil || number(search["total"]) != 1 {
		t.Fatal(search, e)
	}
	detail, e := f.m.GetJob(ctx, "owner", text(first["id"]))
	if e != nil || len(arr(detail["participants"])) != 2 {
		t.Fatal(detail, e)
	}
	catalog, e := f.m.Catalog(ctx, "owner")
	if e != nil || len(arr(catalog["sources"])) != 1 || len(arr(catalog["runtime_images"])) != 1 {
		t.Fatal(catalog, e)
	}
	if _, e = f.m.VisibleRevision(ctx, "owner"); e != nil {
		t.Fatal(e)
	}
}
