package profiles

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/domain"
)

func obj(v any) domain.Object { m, _ := v.(map[string]any); return m }
func records(v any) []domain.Object {
	list := v.([]any)
	r := make([]domain.Object, len(list))
	for i, x := range list {
		r[i] = obj(x)
	}
	return r
}
func text(v any) string { s, _ := v.(string); return s }
func TestPythonProfileContractOracles(t *testing.T) {
	data, err := os.ReadFile("testdata/profiles_oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := domain.DecodeJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range obj(raw)["cases"].([]any) {
		c := obj(item)
		t.Run(text(c["name"]), func(t *testing.T) {
			p, err := Get(c["profile"])
			if err != nil {
				t.Fatal(err)
			}
			args := c["args"].([]any)
			var result any
			switch c["operation"] {
			case "policy_defaults":
				result = p.PolicyDefaults(text(args[0]))
			case "validate_policy":
				roles, _ := domain.Strings(args[1])
				err = p.ValidatePolicy(text(args[0]), roles, text(args[2]))
			case "validate_bindings":
				err = p.ValidateBindings(obj(args[0]), records(args[1]))
			case "record_base_id":
				result = p.RecordBaseID(text(args[0]), obj(args[1]))
			case "validate_publish":
				err = p.ValidatePublish(text(args[0]), obj(args[1]), obj(args[2]), obj(args[3]))
			case "selection_spec":
				result = p.SelectionSpec(text(args[0]), args[1])
			case "input_eligible":
				result = p.InputEligible(obj(args[0]), obj(args[1]))
			case "validate_input_current":
				err = p.ValidateInputCurrent(obj(args[0]), obj(args[1]))
			case "completion_inputs":
				result, err = p.CompletionInputs(obj(args[0]), records(args[1]), text(args[2]))
			case "validate_type":
				err = p.ValidateType(text(args[0]), obj(args[1]))
			case "validate_record":
				err = p.ValidateRecord(text(args[0]), obj(args[1]), obj(args[2]))
			case "validate_reference":
				err = p.ValidateReference(text(args[0]), obj(args[1]), records(args[2]), args[3])
			case "select_inputs":
				result = p.SelectInputs(records(args[0]), args[1])
			default:
				t.Fatal("unknown operation")
			}
			if expected, ok := c["error"]; ok {
				var e *domain.Error
				if !errors.As(err, &e) {
					t.Fatalf("expected%v got%T %v", expected, err, err)
				}
				ex := obj(expected)
				status, _ := domain.Int64(ex["status"])
				if int64(e.Status) != status || e.Code != ex["code"] || e.Detail != ex["detail"] {
					t.Fatalf("got%+v expected%v", e, expected)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			actual, e := domain.CanonicalJSON(result)
			if e != nil {
				t.Fatal(e)
			}
			expected, e := domain.CanonicalJSON(c["result"])
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(actual, expected) {
				t.Fatalf("actual%s expected%s", actual, expected)
			}
		})
	}
}
func TestRegistryCannotLoadApplicationCode(t *testing.T) {
	for _, name := range []any{nil, 1, "custom.v1", "os.system", "../profile"} {
		if _, err := Get(name); err == nil {
			t.Fatal("unknown registry profile accepted")
		}
	}
	names := Names()
	names[0] = "mutated"
	p, err := Get("generic.v1")
	if err != nil || p.Name() != "generic.v1" {
		t.Fatal("registry changed")
	}
}

func TestPythonBindingNumericAndCollectionEquality(t *testing.T) {
	p, _ := Get("fedavg.v1")
	m := domain.Object{"base_record_id": "base", "sample_count": 1}
	first := domain.Object{"participant": "Alice", "flag": true, "values": []string{"a", "b"}}
	current := domain.Object{"participant": "Alice", "flag": 1, "values": []any{"a", "b"}}
	if err := p.ValidatePublish("training.update", m, first, current); err != nil {
		t.Fatal(err)
	}
	if !p.InputEligible(domain.Object{"kind": "training.update", "creator_bindings": first}, domain.Object{"roles": []string{"contributor"}, "bindings": current}) {
		t.Fatal("equivalent Python bindings were rejected")
	}
	current["flag"] = 2
	if err := p.ValidatePublish("training.update", m, first, current); err == nil {
		t.Fatal("changed binding accepted")
	}
}
