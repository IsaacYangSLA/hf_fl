package schema

import (
	"testing"

	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/domain"
)

// Frozen Python reference cases cover literal and class/range expansion in both
// directions, negatives, ASCII-only flags, and whole-schema logical contexts.
func TestPinnedPythonCaseFoldMinimumGoRegex(t *testing.T) {
	for _, raw := range oracle(t, "testdata/regex_go126_oracle.json") {
		c := object(raw)
		t.Run(c["name"].(string), func(t *testing.T) {
			re, err := compileRegexp(c["pattern"].(string))
			if err != nil {
				t.Fatal(err)
			}
			if got := re.MatchString(c["value"].(string)); got != c["match"].(bool) {
				t.Fatalf("fold differs from Python: actual%v expected%v", got, c["match"])
			}
		})
	}
}
func TestPinnedPythonCaseFoldCannotChangeLogicalSchemaBranch(t *testing.T) {
	for _, raw := range oracle(t, "testdata/regex_go126_schema_oracle.json") {
		c := object(raw)
		t.Run(c["name"].(string), func(t *testing.T) {
			args := c["args"].([]any)
			definition := args[1].(domain.Object)
			if err := ValidateSchema(definition); err != nil {
				t.Fatal(err)
			}
			result, err := ValidateMetadata(args[0], definition)
			assertOracle(t, c, result, err)
		})
	}
}
