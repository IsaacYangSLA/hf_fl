package domain

import "testing"

func TestMutationTokensRequireUnderstoodOwnership(t *testing.T) {
	for name, value := range map[string]any{
		"null": nil, "typed_nil_strings": []string(nil), "typed_nil_values": []any(nil),
		"object": map[string]any{"pending": "unknown"}, "empty_object": map[string]any{},
		"string": "pending", "empty_string": "", "number": 1, "boolean": true,
		"null_member": []any{nil}, "number_member": []any{1},
		"object_member": []any{map[string]any{"pending": "unknown"}},
		"mixed_member":  []any{"known", 1}, "empty_member": []string{""},
		"duplicate": []string{"known", "known"},
	} {
		t.Run(name, func(t *testing.T) {
			if tokens, valid := MutationTokens(value); valid || tokens != nil {
				t.Fatalf("unsupported ledger became known: %T", value)
			}
		})
	}
	for name, value := range map[string]any{"empty_strings": []string{}, "empty_values": []any{}, "legacy_strings": []string{"legacy-opaque", "gateway-put-1-opaque"}, "decoded_values": []any{"legacy-opaque", "other"}} {
		t.Run(name, func(t *testing.T) {
			tokens, valid := MutationTokens(value)
			if !valid || tokens == nil {
				t.Fatal("valid ownership ledger rejected")
			}
		})
	}
	original := []string{"owned"}
	copy, valid := MutationTokens(original)
	if !valid {
		t.Fatal("valid ledger")
	}
	copy[0] = "changed"
	if original[0] != "owned" {
		t.Fatal("validation aliases input ledger")
	}
}
