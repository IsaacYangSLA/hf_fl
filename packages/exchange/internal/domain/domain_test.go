package domain

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"regexp"
	"testing"
)

func TestPythonCanonicalOracles(t *testing.T) {
	raw, err := os.ReadFile("testdata/python_oracles.json")
	if err != nil {
		t.Fatal(err)
	}
	var data struct {
		Canonical  []struct{ Raw, Canonical, ASCII string }
		Principals []struct{ Issuer, Subject, ID string }
	}
	if err = json.Unmarshal(raw, &data); err != nil {
		t.Fatal(err)
	}
	for i, c := range data.Canonical {
		t.Run(fmt.Sprintf("canonical_%03d", i), func(t *testing.T) {
			v, err := DecodeJSON([]byte(c.Raw))
			if err != nil {
				t.Fatal(err)
			}
			got, err := CanonicalJSON(v)
			if err != nil || string(got) != c.Canonical {
				t.Fatalf("UTF8: %s %v; expected %s", got, err, c.Canonical)
			}
			got, err = CanonicalASCIIJSON(v)
			if err != nil || string(got) != c.ASCII {
				t.Fatalf("ASCII: %s %v; expected %s", got, err, c.ASCII)
			}
		})
	}
	for _, p := range data.Principals {
		if got := PrincipalID(p.Issuer, p.Subject); got != p.ID {
			t.Fatalf("principal oracle mismatch %s != %s", got, p.ID)
		}
	}
}
func TestJSONRejectsMalformedAndUnsafeValues(t *testing.T) {
	for _, s := range []string{`{"a":1} trailing`, `[1,]`, `01`, `"\ud800"`, `"\udc00"`, string([]byte{'"', 0xff, '"'})} {
		if _, err := DecodeJSON([]byte(s)); err == nil {
			t.Fatalf("unsafe JSON accepted %q", s)
		}
	}
	for _, v := range []any{math.NaN(), math.Inf(1), json.Number("1e400"), json.Number("01"), map[int]string{1: "bad"}, make(chan int)} {
		if _, err := CanonicalJSON(v); err == nil {
			t.Fatalf("unsafe canonical value accepted %T", v)
		}
	}
}
func TestNumericTypesAndBounds(t *testing.T) {
	for _, v := range []any{true, false, 1.0, float32(1), json.Number("1.0"), json.Number("1e0"), "1", nil} {
		if _, ok := Int64(v); ok {
			t.Fatalf("noninteger accepted: %#v", v)
		}
	}
	for _, v := range []any{int(1), int8(1), int64(1), uint(1), json.Number("1")} {
		if n, ok := Int64(v); !ok || n != 1 {
			t.Fatalf("integer refused: %#v", v)
		}
	}
	if n, ok := Integer(json.Number("123456789012345678901234567890")); !ok || n.String() != "123456789012345678901234567890" {
		t.Fatal("big metadata integer lost")
	}
	if _, ok := Int64(json.Number("9223372036854775808")); ok {
		t.Fatal("int64 overflow accepted")
	}
	if _, ok := Int64(uint64(math.MaxUint64)); ok {
		t.Fatal("unsigned overflow accepted")
	}
	for _, v := range []any{true, "1", nil, math.NaN(), math.Inf(-1), json.Number("1e400")} {
		if _, ok := Float(v); ok {
			t.Fatalf("unsafe float accepted: %#v", v)
		}
	}
	if n, ok := Float(json.Number("1.5")); !ok || n != 1.5 {
		t.Fatal("finite number refused")
	}
	if s, ok := Strings([]any{"a", "b"}); !ok || len(s) != 2 {
		t.Fatal("string list refused")
	}
	if _, ok := Strings([]any{"a", 1}); ok {
		t.Fatal("mixed list accepted")
	}
}
func TestStableErrorsAndRandomIdentities(t *testing.T) {
	e := Err(403, "role_required", "private explanation")
	if e.Error() != "role_required" || e.Detail != "private explanation" || ErrorCode(fmt.Errorf("wrapped: %w", e)) != "role_required" || StatusCode(e) != 403 {
		t.Fatal("error contract differs")
	}
	if e := Err(409, "conflict"); e.Detail != "conflict" {
		t.Fatal("default public detail differs")
	}
	pattern := regexp.MustCompile(`^[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}$`)
	seen := map[string]bool{}
	for range 100 {
		v := NewID()
		if !pattern.MatchString(v) || seen[v] {
			t.Fatalf("invalid/repeated UUID4 %s", v)
		}
		seen[v] = true
	}
}
func TestCloneHasIndependentNestedValues(t *testing.T) {
	input := Object{"nested": Object{"a": []any{Object{"v": "old"}}}, "strings": []string{"a"}}
	copy := CloneMap(input)
	copy["nested"].(Object)["a"].([]any)[0].(Object)["v"] = "new"
	copy["strings"].([]string)[0] = "b"
	if input["nested"].(Object)["a"].([]any)[0].(Object)["v"] != "old" || input["strings"].([]string)[0] != "a" {
		t.Fatal("clone aliases mutable source")
	}
}
