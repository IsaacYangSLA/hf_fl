package secrets

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
)

func TestLocalResolverUsesOnlyScopedLocalReferencesWithoutDatabase(t *testing.T) {
	ctx := context.Background()
	spec := secretSpec(t)
	spec.SecretRefs["foreign_license"] = "other-org-ref"
	component := spec.Components[0]
	binding := Binding{JobID: "job", AttemptID: "attempt", ComponentID: "owner", Epoch: 1}
	path := privateFile(t, "license", "local-license\n")
	root := filepath.Join(t.TempDir(), "deliveries")
	local, err := NewLocalResolver(root, map[string]Approval{"license-ref": {ID: "license-ref", ProjectID: "research", Path: path, Roles: []string{"owner"}, OptionNames: []string{"license"}, ComponentIDs: []string{"owner"}}})
	if err != nil {
		t.Fatal(err)
	}
	planned, err := local.PlannedAssignment(ctx, binding, spec, component)
	if err != nil || planned == "" {
		t.Fatal("local plan", err)
	}
	if _, err = os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("planning created a directory", err)
	}
	config := map[string]any{"secret_option_names": []string{"license"}}
	if err = local.MaterializeAssignment(ctx, binding, spec, component, config, planned); err != nil {
		t.Fatal(err)
	}
	manifest, err := ReadManifest(planned, binding)
	if err != nil || len(manifest.Options) != 1 || manifest.Options["license"] != "local-license" || manifest.References["license"] != "license-ref" {
		t.Fatal("local scope escaped", err)
	}
	if err = os.WriteFile(path, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = local.MaterializeAssignment(ctx, binding, spec, component, config, planned); err != nil {
		t.Fatal(err)
	}
	manifest, err = ReadManifest(planned, binding)
	if err != nil || manifest.Options["license"] != "local-license" {
		t.Fatal("local retry changed delivered material", err)
	}
	if removed, err := local.Cleanup(ctx, binding, false); removed || !errors.Is(err, ErrReferenceRefused) {
		t.Fatal("local premature cleanup", removed, err)
	}
	if removed, err := local.Cleanup(ctx, binding, true); err != nil || !removed {
		t.Fatal("local confirmed cleanup", removed, err)
	}
}
func TestLocalResolverConfigurationCannotExpandScopeOrPath(t *testing.T) {
	ctx := context.Background()
	spec := secretSpec(t)
	component := spec.Components[0]
	binding := Binding{JobID: "job", AttemptID: "attempt", ComponentID: "owner", Epoch: 1}
	path := privateFile(t, "license", "private")
	root := filepath.Join(t.TempDir(), "deliveries")
	local, err := NewLocalResolver(root, map[string]Approval{"license-ref": {ID: "license-ref", ProjectID: "research", Path: path, Roles: []string{"owner"}, OptionNames: []string{"license"}}})
	if err != nil {
		t.Fatal(err)
	}
	planned, err := local.PlannedAssignment(ctx, binding, spec, component)
	if err != nil {
		t.Fatal(err)
	}
	if err = local.MaterializeAssignment(ctx, binding, spec, component, map[string]any{"secret_option_names": []string{"license", "other"}}, planned); !errors.Is(err, ErrReferenceRefused) {
		t.Fatal("unapproved option added", err)
	}
	if err = local.MaterializeAssignment(ctx, binding, spec, component, map[string]any{"secret_option_names": []any{"license"}}, planned+"-elsewhere"); !errors.Is(err, ErrReferenceRefused) {
		t.Fatal("path rebound", err)
	}
	if _, err = os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("refused materialization touched directory", err)
	}
	bad := binding
	bad.ComponentID = "bob"
	if _, err = local.PlannedAssignment(ctx, bad, spec, component); !errors.Is(err, ErrReferenceRefused) {
		t.Fatal("component identity substituted", err)
	}
	badComponent := domain.ComponentSpec{ComponentID: "foreign", Role: "owner"}
	if _, err = local.PlannedAssignment(ctx, Binding{JobID: "job", AttemptID: "attempt", ComponentID: "foreign", Epoch: 1}, spec, badComponent); !errors.Is(err, ErrReferenceRefused) {
		t.Fatal("unassigned component adopted", err)
	}
	wrongProject, err := NewLocalResolver(root, map[string]Approval{"license-ref": {ID: "license-ref", ProjectID: "another", Path: path, Roles: []string{"owner"}, OptionNames: []string{"license"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = wrongProject.PlannedAssignment(ctx, binding, spec, component); !errors.Is(err, ErrReferenceRefused) {
		t.Fatal("foreign project reference adopted", err)
	}
}
func TestLocalResolverPlansWithoutReadingAndNeverDeliversBuildSecrets(t *testing.T) {
	ctx := context.Background()
	spec := secretSpec(t)
	path := privateFile(t, "license", "private")
	root := filepath.Join(t.TempDir(), "deliveries")
	local, err := NewLocalResolver(root, map[string]Approval{"license-ref": {ID: "license-ref", ProjectID: "research", Path: path, Roles: []string{"owner", "participant"}, OptionNames: []string{"license"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	owner := Binding{JobID: "job", AttemptID: "attempt", ComponentID: "owner", Epoch: 1}
	if planned, err := local.PlannedAssignment(ctx, owner, spec, spec.Components[0]); err != nil || planned == "" {
		t.Fatal("planning tried to read material", err)
	}
	build := Binding{JobID: "job", AttemptID: "attempt", ComponentID: "build", Epoch: 1}
	if planned, err := local.PlannedAssignment(ctx, build, spec, spec.Components[1]); err != nil || planned != "" {
		t.Fatal("build selected secrets", err)
	}
	if err = local.MaterializeAssignment(ctx, build, spec, spec.Components[1], map[string]any{"secret_option_names": []any{}}, ""); err != nil {
		t.Fatal("empty build materialization", err)
	}
	if _, err = os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("empty local selection touched directory", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = local.PlannedAssignment(cancelled, owner, spec, spec.Components[0]); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled local planning proceeded", err)
	}
}
