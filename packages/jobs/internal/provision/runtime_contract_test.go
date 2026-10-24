package provision

import (
	"os"
	"testing"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
)

func TestRuntimeContractMatchesPythonApplicationAdapter(t *testing.T) {
	bytes, e := os.ReadFile("testdata/runtime-contract.json")
	if e != nil {
		t.Fatal(e)
	}
	value, e := domain.DecodeJSON(bytes)
	if e != nil {
		t.Fatal(e)
	}
	rows, ok := array(obj(value)["fixtures"])
	if !ok || len(rows) != 6 {
		t.Fatal("missing reference fixtures")
	}
	for _, row := range rows {
		fixture := obj(row)
		t.Run(str(fixture["name"]), func(t *testing.T) {
			input := obj(fixture["input"])
			actual, e := NormalizeRuntimeConfig(input)
			if e != nil {
				t.Fatal(e)
			}
			if !same(actual, fixture["normalized"]) {
				got, _ := domain.CanonicalJSON(actual)
				want, _ := domain.CanonicalJSON(fixture["normalized"])
				t.Fatalf("normalization differs\n%s\n%s", got, want)
			}
			binding, e := RuntimeDurableBinding(input)
			if e != nil || !same(binding, fixture["durable_binding"]) {
				t.Fatal("durable binding differs", e, binding)
			}
			identity, e := RuntimeSourceIdentity(input)
			if e != nil || identity != fixture["source_identity"] {
				t.Fatal("listener source identity differs", e, identity, fixture["source_identity"])
			}
		})
	}
}
