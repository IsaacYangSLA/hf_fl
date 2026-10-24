package domain

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"reflect"
	"strings"
	"testing"
)

type referenceContracts struct {
	Canonical  []struct{ Name, Input, Expected, SHA256 string }
	Principals []struct{ Issuer, Subject, Expected string }
	Specs      []struct {
		Name, Input, Canonical, SHA256 string
		Valid                          bool
	}
	Locators []struct {
		Input      string
		Valid      bool
		Normalized json.RawMessage
	}
}

func reference(t *testing.T) referenceContracts {
	t.Helper()
	raw, err := os.ReadFile("testdata/python_contracts.json")
	if err != nil {
		t.Fatal(err)
	}
	var f referenceContracts
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f
}
func TestPythonCanonicalJSONGoldens(t *testing.T) {
	for _, c := range reference(t).Canonical {
		t.Run(c.Name, func(t *testing.T) {
			value, err := DecodeJSON([]byte(c.Input))
			if err != nil {
				t.Fatal(err)
			}
			actual, err := CanonicalJSON(value)
			if err != nil {
				t.Fatal(err)
			}
			if string(actual) != c.Expected {
				t.Fatalf("canonical bytes differ:\nGo: %s\nPython: %s", actual, c.Expected)
			}
			sum := sha256.Sum256(actual)
			if hex.EncodeToString(sum[:]) != c.SHA256 {
				t.Fatal("hash differs")
			}
		})
	}
}
func TestPythonPrincipalGoldens(t *testing.T) {
	for _, c := range reference(t).Principals {
		t.Run(c.Subject, func(t *testing.T) {
			if got := PrincipalID(c.Issuer, c.Subject); got != c.Expected {
				t.Fatalf("principal mismatch %s != %s", got, c.Expected)
			}
		})
	}
}
func TestPythonJobSpecificationGoldens(t *testing.T) {
	for _, c := range reference(t).Specs {
		t.Run(c.Name, func(t *testing.T) {
			spec, err := DecodeJobSpec([]byte(c.Input))
			if (err == nil) != c.Valid {
				t.Fatalf("validity differs: expected=%v err=%v", c.Valid, err)
			}
			if !c.Valid {
				var e *Error
				if !errors.As(err, &e) || e.Status != 422 || e.Code != "invalid_job_spec" {
					t.Fatalf("wrong structured error %#v", err)
				}
				return
			}
			got, err := CanonicalJSON(spec.Map())
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != c.Canonical {
				t.Fatalf("normalized specification differs:\nGo: %s\nPython: %s", got, c.Canonical)
			}
			digest, err := spec.Digest()
			if err != nil {
				t.Fatal(err)
			}
			if digest != c.SHA256 {
				t.Fatalf("specification digest differs %s != %s", digest, c.SHA256)
			}
			var recovered JobSpec
			if err := json.Unmarshal(got, &recovered); err != nil {
				t.Fatal(err)
			}
			again, _ := recovered.Digest()
			if again != digest {
				t.Fatal("roundtrip changed spec hash")
			}
		})
	}
}
func TestPythonArtifactLocatorGoldens(t *testing.T) {
	for i, c := range reference(t).Locators {
		t.Run(string(rune('A'+i)), func(t *testing.T) {
			l, err := DecodeArtifactLocator([]byte(c.Input))
			if (err == nil) != c.Valid {
				t.Fatalf("validity differs: expected=%v err=%v", c.Valid, err)
			}
			if !c.Valid {
				return
			}
			expected, err := DecodeJSON(c.Normalized)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := CanonicalJSON(l.Map())
			if err != nil {
				t.Fatal(err)
			}
			want, _ := CanonicalJSON(expected)
			if !bytes.Equal(actual, want) {
				t.Fatalf("locator changed %s != %s", actual, want)
			}
			value := l.Map()
			value["kind"] = "untrusted"
			if l.Kind == "untrusted" {
				t.Fatal("Map aliased locator")
			}
		})
	}
}
func TestRejectedJSONAndNonfiniteNumbers(t *testing.T) {
	for _, raw := range []string{`{"x":1} {"y":2}`, `{"x":NaN}`, `{"x":Infinity}`, `"\ud800"`, `"\udc00"`, `"\ud800\u0041"`, `{"x":`} {
		if _, err := DecodeJSON([]byte(raw)); err == nil {
			t.Fatalf("accepted invalid JSON %q", raw)
		}
	}
	if _, err := DecodeJSON([]byte{'"', 0xff, '"'}); err == nil {
		t.Fatal("accepted invalid UTF-8")
	}
	for _, value := range []any{math.NaN(), math.Inf(1), math.Inf(-1), json.Number("1e400"), json.Number("01"), json.Number("invalid"), make(chan int)} {
		if _, err := CanonicalJSON(value); err == nil {
			t.Fatalf("accepted non-JSON %#v", value)
		}
	}
}
func TestIntegerFloatAndUnicodeCanonicalTypes(t *testing.T) {
	for raw, want := range map[string]string{"-0": "0", "-0.0": "-0.0", "1.0": "1.0", "1e0": "1.0", "1000000.0": "1000000.0", "1e-7": "1e-07", "1e16": "1e+16", `"\ud83d\ude00"`: `"😀"`, `"<>&"`: `"<>&"`} {
		value, err := DecodeJSON([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		actual, err := CanonicalJSON(value)
		if err != nil {
			t.Fatal(err)
		}
		if string(actual) != want {
			t.Fatalf("%s => %s, expected %s", raw, actual, want)
		}
	}
}
func TestOptionCopiesAndDirectValidation(t *testing.T) {
	c := reference(t).Specs[1]
	spec, err := DecodeJobSpec([]byte(c.Input))
	if err != nil {
		t.Fatal(err)
	}
	original, err := spec.Digest()
	if err != nil {
		t.Fatal(err)
	}
	m := spec.Map()
	m["options"].(map[string]any)["lr"] = json.Number("99")
	m["components"].([]any)[0].(map[string]any)["role"] = "build"
	current, _ := spec.Digest()
	if original != current {
		t.Fatal("Map exposes specification aliases")
	}
	spec.Options["lr"] = math.Inf(1)
	if err := spec.Validate(); err == nil {
		t.Fatal("direct invalid option escaped validation")
	}
}
func TestExternalComponentCollisionAndReciprocalBindings(t *testing.T) {
	if ExternalComponentID(string([]byte{0xff})) != "" {
		t.Fatal("invalid Unicode component identity accepted")
	}
	s, err := DecodeJobSpec([]byte(reference(t).Specs[2].Input))
	if err != nil {
		t.Fatal(err)
	}
	s.Components = append(s.Components, ComponentSpec{ComponentID: ExternalComponentID("alice"), Role: "build", Resources: s.Components[0].Resources})
	if err := s.Validate(); err == nil {
		t.Fatal("reserved external component accepted")
	}
	s, err = DecodeJobSpec([]byte(reference(t).Specs[3].Input))
	if err != nil {
		t.Fatal(err)
	}
	bob := "bob"
	s.Components[1].ParticipantID = &bob
	if err := s.Validate(); err == nil {
		t.Fatal("unreciprocated participant accepted")
	}
}
func TestNestedUnknownFieldsAndNullDefaultsRejected(t *testing.T) {
	base := reference(t).Specs[0].Input
	for _, oldNew := range [][2]string{
		{`"components":[`, `"participants":[{"participant_id":"alice","dataset_binding":"data","surprise":true}],"components":[`},
		{`"component_id":"owner"`, `"component_id":"owner","role_extra":"owner"`},
		{`"pool_id":"cpu"`, `"pool_id":"cpu","sandbox_profile":null`},
		{`"pool_id":"cpu"`, `"pool_id":"cpu","gpu_count":null`},
	} {
		modified := strings.Replace(base, oldNew[0], oldNew[1], 1)
		if modified == base {
			t.Fatal("test fixture not changed")
		}
		if _, err := DecodeJobSpec([]byte(modified)); err == nil {
			t.Fatalf("invalid nested data accepted %s", modified)
		}
	}
}
func TestIDsErrorAndStateHelpers(t *testing.T) {
	ids := map[string]bool{}
	for i := 0; i < 100; i++ {
		id := NewID()
		if len(id) != 32 || ids[id] {
			t.Fatal("ID collision or size")
		}
		b, err := hex.DecodeString(id)
		if err != nil || b[6]>>4 != 4 || b[8]>>6 != 2 {
			t.Fatal("not UUID v4")
		}
		ids[id] = true
	}
	e := Err(403, "forbidden", map[string]any{"private": "hidden"})
	e.Headers = map[string]string{"Retry-After": "3"}
	if e.Error() != "forbidden" || e.Status != 403 || e.Headers["Retry-After"] != "3" {
		t.Fatal("error contract changed")
	}
	if !IsTerminal("CANCELLED") || IsTerminal("CANCELLING") || !IsJobState("NEEDS_ATTENTION") || IsJobState("unknown") {
		t.Fatal("state classification wrong")
	}
	if RoleLevel("admin") != 3 || RoleLevel("operator") != 2 || RoleLevel("reader") != 1 || RoleLevel("other") != 0 {
		t.Fatal("role hierarchy wrong")
	}
	for _, id := range []string{"a", "A-9_foo.bar"} {
		if err := ValidateIdentifier(id); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"", "../bad", "https://bad", "a\n", "_bad", "é"} {
		if ValidIdentifier(id) {
			t.Fatal("unconfined identifier accepted")
		}
	}
}
func TestClonePreservesLargeNumberAndFloat(t *testing.T) {
	input := map[string]any{"nested": []any{map[string]any{"integer": json.Number("9999999999999999999999999999999999"), "float": json.Number("1.0")}}}
	clone := CloneMap(input)
	clone["nested"].([]any)[0].(map[string]any)["float"] = json.Number("2.0")
	if reflect.DeepEqual(input, clone) {
		t.Fatal("clone mutation did not isolate")
	}
	raw, err := CanonicalJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"nested":[{"float":1.0,"integer":9999999999999999999999999999999999}]}` {
		t.Fatalf("numeric type changed: %s", raw)
	}
}

func TestASCIIJSONLedgerCompatibility(t *testing.T) {
	actual, err := CanonicalASCIIJSON(map[string]any{"label": "爱丽丝😀 <>&"})
	if err != nil {
		t.Fatal(err)
	}
	expected := `{"label":"\u7231\u4e3d\u4e1d\ud83d\ude00 <>&"}`
	if string(actual) != expected {
		t.Fatalf("ASCII ledger canonical JSON differs: %s", actual)
	}
	utf, err := CanonicalJSON(map[string]any{"label": "爱丽丝😀 <>&"})
	if err != nil || string(utf) == expected {
		t.Fatal("job hashes must retain UTF-8 JSON")
	}
}
