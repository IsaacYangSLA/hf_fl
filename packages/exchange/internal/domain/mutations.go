package domain

// MutationTokens validates a persisted provider-mutation ownership ledger.
// Only a present JSON array of distinct, nonempty strings is understood. JSON
// null, unsupported shapes, and invalid members are uncertainty, never proof
// that no provider call remains. Typed nil slices serialize as null and are
// therefore rejected too.
func MutationTokens(value any) ([]string, bool) {
	var tokens []string
	switch x := value.(type) {
	case []string:
		if x == nil {
			return nil, false
		}
		tokens = append([]string{}, x...)
	case []any:
		if x == nil {
			return nil, false
		}
		tokens = make([]string, len(x))
		for i, item := range x {
			token, ok := item.(string)
			if !ok {
				return nil, false
			}
			tokens[i] = token
		}
	default:
		return nil, false
	}
	seen := make(map[string]struct{}, len(tokens))
	for _, token := range tokens {
		if token == "" {
			return nil, false
		}
		if _, exists := seen[token]; exists {
			return nil, false
		}
		seen[token] = struct{}{}
	}
	return tokens, true
}
