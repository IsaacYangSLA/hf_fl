package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
	"golang.org/x/sys/unix"
)

func privateFile(t *testing.T, name, value string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func TestPrivateReaderRejectsLinksModesSpecialFilesAndBounds(t *testing.T) {
	path := privateFile(t, "credential", "private-value\n")
	value, err := ReadPrivateFile(path, 100)
	if err != nil || string(value) != "private-value\n" {
		t.Fatal("safe reader", err)
	}
	if _, err = ReadPrivateFile(path, 3); !errors.Is(err, ErrReferenceRefused) {
		t.Fatal("oversize accepted", err)
	}
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadPrivateFile(path, 100); !errors.Is(err, ErrReferenceRefused) {
		t.Fatal("public file accepted", err)
	}
	if err = os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(path), "alias")
	if err = os.Link(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadPrivateFile(path, 100); !errors.Is(err, ErrReferenceRefused) {
		t.Fatal("hardlink accepted", err)
	}
	if err = os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadPrivateFile(link, 100); !errors.Is(err, ErrReferenceRefused) {
		t.Fatal("symlink accepted", err)
	}
	dirLink := filepath.Join(t.TempDir(), "parent")
	if err = os.Symlink(filepath.Dir(path), dirLink); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadPrivateFile(filepath.Join(dirLink, filepath.Base(path)), 100); !errors.Is(err, ErrReferenceRefused) {
		t.Fatal("symlink ancestor accepted", err)
	}
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err = unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadPrivateFile(fifo, 100); !errors.Is(err, ErrReferenceRefused) {
		t.Fatal("special file accepted", err)
	}
	if strings.Contains(ErrReferenceRefused.Error(), path) {
		t.Fatal("secret path disclosed")
	}
}
func TestApprovalRequiresExplicitLeastPrivilege(t *testing.T) {
	path := privateFile(t, "credential", "value")
	good := Approval{ID: "license-ref", ProjectID: "research", Path: path, Roles: []string{"owner"}, OptionNames: []string{"license"}}
	if _, err := NewResolver(nil, filepath.Join(t.TempDir(), "deliveries"), map[string]Approval{good.ID: good}); err != nil {
		t.Fatal(err)
	}
	cases := []Approval{
		{ID: "license-ref", ProjectID: "research", Path: path, OptionNames: []string{"license"}},
		{ID: "license-ref", ProjectID: "research", Path: path, Roles: []string{"build"}, OptionNames: []string{"license"}},
		{ID: "license-ref", ProjectID: "research", Path: path, Roles: []string{"owner"}, OptionNames: []string{"aws_token"}},
		{ID: "license-ref", ProjectID: "research", Path: path, Roles: []string{"owner"}, OptionNames: []string{"source_dir"}},
		{ID: "license-ref", ProjectID: "research", Path: "relative", Roles: []string{"owner"}, OptionNames: []string{"license"}},
		{ID: "license-ref", ProjectID: "research", Path: path, Roles: []string{"owner"}, OptionNames: []string{"license"}, Purpose: "source_credentials"},
	}
	for _, approval := range cases {
		if _, err := NewResolver(nil, filepath.Join(t.TempDir(), "deliveries"), map[string]Approval{approval.ID: approval}); !errors.Is(err, ErrReferenceRefused) {
			t.Fatalf("bad scope accepted %#v %v", approval.Roles, err)
		}
	}
}
func secretDB(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(context.Background(), "sqlite:///"+filepath.Join(t.TempDir(), "manager.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err = db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return db
}
func secretSpec(t *testing.T) domain.JobSpec {
	t.Helper()
	raw := `{"project_id":"research","name":"Secret scope","source_id":"source","source_commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","runtime_image":"image","plugin":"lenet","secret_refs":{"license":"license-ref"},"participants":[{"participant_id":"alice","dataset_binding":"alice"},{"participant_id":"bob","dataset_binding":"bob"}],"components":[{"component_id":"owner","role":"owner","resources":{"pool_id":"cpu","cpu_millicores":1000,"memory_bytes":1024,"disk_bytes":1024}},{"component_id":"build","role":"build","resources":{"pool_id":"cpu","cpu_millicores":1000,"memory_bytes":1024,"disk_bytes":1024}}],"target_round":2,"max_duration_seconds":600}`
	spec, err := domain.DecodeJobSpec([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return spec
}
func secretFixture(t *testing.T) (*Resolver, *store.DB, map[string]any, map[string]any, domain.JobSpec, string) {
	t.Helper()
	ctx := context.Background()
	db := secretDB(t)
	spec := secretSpec(t)
	digest, err := spec.Digest()
	if err != nil {
		t.Fatal(err)
	}
	path := privateFile(t, "license", "original-secret\r\n")
	err = db.WithTx(ctx, true, func(tx *store.Tx) error {
		if err := tx.Insert(ctx, "jm_projects", map[string]any{"id": "research", "name": "Research"}); err != nil {
			return err
		}
		if err := tx.Insert(ctx, "jm_secret_references", map[string]any{"id": "license-ref", "project_id": "research", "reference": path, "enabled": true}); err != nil {
			return err
		}
		if err := tx.Insert(ctx, "jm_jobs", map[string]any{"id": "job", "project_id": "research", "creator_id": "creator", "name": "Job", "spec_json": spec.Map(), "spec_hash": digest, "state": "PROVISIONING", "epoch": 1, "target_round": 2}); err != nil {
			return err
		}
		return tx.Insert(ctx, "jm_attempts", map[string]any{"id": "attempt", "job_id": "job", "number": 1, "epoch": 1, "state": "PROVISIONING"})
	})
	if err != nil {
		t.Fatal(err)
	}
	job, err := db.One(ctx, "SELECT * FROM jm_jobs WHERE id='job'")
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := db.One(ctx, "SELECT * FROM jm_attempts WHERE id='attempt'")
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "deliveries")
	resolver, err := NewResolver(db, root, map[string]Approval{"license-ref": {ID: "license-ref", ProjectID: "research", Path: path, Roles: []string{"owner"}, OptionNames: []string{"license"}, ComponentIDs: []string{"owner"}}})
	if err != nil {
		t.Fatal(err)
	}
	return resolver, db, job, attempt, spec, path
}
func TestPlanningDoesNotReadSecretsOrCreateDirectories(t *testing.T) {
	resolver, _, job, attempt, spec, path := secretFixture(t)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	planned, err := resolver.Planned(context.Background(), job, attempt, spec.Components[0])
	if err != nil || planned.PrivatePath == "" || len(planned.RedactionValues) != 0 {
		t.Fatal("plan read missing material", planned.OptionNames, err)
	}
	if _, err = os.Stat(resolver.Root); !os.IsNotExist(err) {
		t.Fatal("planning created private directories", err)
	}
	encoded, err := json.Marshal(planned)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "private") || strings.Contains(string(encoded), resolver.Root) {
		t.Fatal("private path leaked through serialization")
	}
	if _, err = resolver.Resolve(context.Background(), job, attempt, spec.Components[0]); !errors.Is(err, ErrReferenceRefused) {
		t.Fatal("missing secret did not fail closed", err)
	}
}
func TestResolveScopesIdempotencyRevocationAndCleanup(t *testing.T) {
	ctx := context.Background()
	resolver, db, job, attempt, spec, path := secretFixture(t)
	resolved, err := resolver.Resolve(ctx, job, attempt, spec.Components[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved.OptionNames) != 1 || resolved.OptionNames[0] != "license" || len(resolved.RedactionValues) != 1 || resolved.RedactionValues[0] != "original-secret" {
		t.Fatal("wrong secret selection")
	}
	st, err := os.Stat(resolved.PrivatePath)
	if err != nil || st.Mode().Perm() != 0400 {
		t.Fatal("manifest not readonly/private", err)
	}
	manifest, err := ReadManifest(resolved.PrivatePath, resolved.Binding)
	if err != nil || manifest.Options["license"] != "original-secret" {
		t.Fatal("bound manifest", err)
	}
	if err = os.WriteFile(path, []byte("new-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	replay, err := resolver.Resolve(ctx, job, attempt, spec.Components[0])
	if err != nil || replay.RedactionValues[0] != "original-secret" {
		t.Fatal("replay changed pinned secret", err)
	}
	built, err := resolver.Resolve(ctx, job, attempt, spec.Components[1])
	if err != nil || built.PrivatePath != "" || len(built.RedactionValues) > 0 {
		t.Fatal("build received a secret", err)
	}
	components, err := components(spec)
	if err != nil {
		t.Fatal(err)
	}
	alice := components[2]
	participant, err := resolver.Resolve(ctx, job, attempt, alice)
	if err != nil || participant.PrivatePath != "" {
		t.Fatal("unapproved role received secret", err)
	}
	if _, err = ReadManifest(resolved.PrivatePath, Binding{JobID: "job", AttemptID: "attempt", ComponentID: "owner", Epoch: 2}); !errors.Is(err, ErrReferenceRefused) {
		t.Fatal("stale epoch accepted", err)
	}
	if removed, err := resolver.Cleanup(ctx, resolved.Binding, false); removed || !errors.Is(err, ErrReferenceRefused) {
		t.Fatal("unconfirmed cleanup allowed", removed, err)
	}
	if _, err = db.Exec(ctx, "UPDATE jm_secret_references SET enabled=? WHERE id='license-ref'", false); err != nil {
		t.Fatal(err)
	}
	if _, err = resolver.Resolve(ctx, job, attempt, spec.Components[0]); !errors.Is(err, ErrReferenceRefused) {
		t.Fatal("revoked secret replay allowed", err)
	}
	if removed, err := resolver.Cleanup(ctx, resolved.Binding, true); err != nil || !removed {
		t.Fatal("confirmed cleanup failed", removed, err)
	}
	if _, err = os.Stat(resolved.PrivatePath); !os.IsNotExist(err) {
		t.Fatal("manifest retained", err)
	}
	if _, err = os.Stat(filepath.Join(filepath.Dir(resolved.PrivatePath), ".secret-lock")); err != nil {
		t.Fatal("exclusion lock not preserved", err)
	}
	if removed, err := resolver.Cleanup(ctx, resolved.Binding, true); err != nil || !removed {
		t.Fatal("idempotent cleanup failed", removed, err)
	}
}
func TestResolverRejectsChangedSourceExecutionAndBroadDirectory(t *testing.T) {
	ctx := context.Background()
	resolver, _, job, attempt, spec, _ := secretFixture(t)
	foreign := domain.CloneMap(job)
	foreign["spec_hash"] = strings.Repeat("b", 64)
	if _, err := resolver.Resolve(ctx, foreign, attempt, spec.Components[0]); !errors.Is(err, ErrReferenceRefused) {
		t.Fatal("changed immutable specification accepted", err)
	}
	foreign = domain.CloneMap(job)
	foreign["epoch"] = int64(2)
	if _, err := resolver.Resolve(ctx, foreign, attempt, spec.Components[0]); !errors.Is(err, ErrReferenceRefused) {
		t.Fatal("wrong epoch accepted", err)
	}
	foreign = domain.CloneMap(job)
	foreign["state"] = "CANCELLED"
	if _, err := resolver.Resolve(ctx, foreign, attempt, spec.Components[0]); !errors.Is(err, ErrReferenceRefused) {
		t.Fatal("terminal job received secret", err)
	}
	if err := os.Mkdir(resolver.Root, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve(ctx, job, attempt, spec.Components[0]); !errors.Is(err, ErrReferenceRefused) {
		t.Fatal("broad delivery directory accepted", err)
	}
}
func TestSecretTextAndManifestStrictness(t *testing.T) {
	for _, value := range [][]byte{[]byte(""), []byte{0xff}, []byte("x\x00y"), []byte(strings.Repeat("x", MaxSecretBytes+1))} {
		if _, err := secretText(value); !errors.Is(err, ErrReferenceRefused) {
			t.Fatal("invalid text accepted", err)
		}
	}
	binding := Binding{JobID: "job", AttemptID: "attempt", ComponentID: "owner", Epoch: 1}
	for _, raw := range []string{
		`{"schema_version":1,"job_id":"job","attempt_id":"attempt","component_id":"owner","epoch":1.0,"role":"owner","options":{"license":"value"},"references":{"license":"ref"}}`,
		`{"schema_version":1,"job_id":"job","attempt_id":"attempt","component_id":"owner","epoch":1,"role":"build","options":{"license":"value"},"references":{"license":"ref"}}`,
		`{"schema_version":1,"job_id":"job","attempt_id":"attempt","component_id":"owner","epoch":1,"role":"owner","options":{"license":"value"},"references":{}}`,
	} {
		path := privateFile(t, "manifest.json", raw)
		if _, err := ReadManifest(path, binding); !errors.Is(err, ErrReferenceRefused) {
			t.Fatal("invalid manifest accepted", err)
		}
	}
}
