package gateway

import (
	"context"
	"net/url"
	"os"
	"testing"

	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/store"
)

// This opt-in gate creates and removes only its own UUID schema in an explicitly
// supplied disposable database. Production defaults never supply this setting.
func TestPostgreSQLPrivateGatewayLifecycle(t *testing.T) {
	dsn := os.Getenv("EXCHANGE_GO_GATEWAY_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set EXCHANGE_GO_GATEWAY_TEST_DATABASE_URL to an owned disposable PostgreSQL database")
	}
	ctx := context.Background()
	admin, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "go_gateway_" + domain.NewID()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		_ = admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Errorf("owned PostgreSQL schema cleanup: %v", err)
		}
		_ = admin.Close()
	})
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	f := newGatewayFixtureWithURL(t, parsed.String())
	receipt := f.begin()
	f.revoke()
	f.clock.Add(600)
	status, _ := f.post(Base+"/spaces/"+f.sid+"/authorize", nil)
	if status != 401 {
		t.Fatalf("expired authority accepted: status%d", status)
	}
	if f.mustPost(Base+"/settle", domain.Object{"receipt": receipt})["settled"] != true ||
		len(f.markers(f.bid)) != 0 {
		t.Fatal("exact expired-and-revoked PUT did not settle on PostgreSQL")
	}
	if f.mustPost(Base+"/settle", domain.Object{"receipt": receipt})["settled"] != false {
		t.Fatal("settlement replay was not idempotent")
	}
}
