package schema

import (
	"encoding/json"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"

	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/domain"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/santhosh-tekuri/jsonschema/v6/kind"
)

// Python preserves arbitrary JSON integers but loads decimal/exponent values as
// binary64. Keep that distinction for reference-compatible numeric assertions.
type pythonNumber struct {
	integer  *big.Int
	floating float64
	isFloat  bool
}

func number(value any) (pythonNumber, bool) {
	if n, ok := value.(json.Number); ok && strings.ContainsAny(string(n), ".eE") {
		f, err := strconv.ParseFloat(string(n), 64)
		return pythonNumber{floating: f, isFloat: true}, err == nil && !math.IsInf(f, 0) && !math.IsNaN(f)
	}
	switch value.(type) {
	case float32, float64:
		f, ok := domain.Float(value)
		return pythonNumber{floating: f, isFloat: true}, ok
	}
	if i, ok := domain.Integer(value); ok {
		return pythonNumber{integer: i}, true
	}
	return pythonNumber{}, false
}
func (n pythonNumber) float() float64 {
	if n.isFloat {
		return n.floating
	}
	f, _ := new(big.Float).SetInt(n.integer).Float64()
	return f
}
func (n pythonNumber) rat() *big.Rat {
	if n.isFloat {
		return new(big.Rat).SetFloat64(n.floating)
	}
	return new(big.Rat).SetInt(n.integer)
}
func multiple(instance, divisor pythonNumber) bool {
	if divisor.isFloat {
		if !instance.isFloat && math.IsInf(instance.float(), 0) {
			return false
		} // Reference float conversion raises; never accept by fallback.
		q := instance.float() / divisor.floating
		if !math.IsInf(q, 0) && !math.IsNaN(q) {
			return math.Trunc(q) == q
		}
		return new(big.Rat).Quo(instance.rat(), divisor.rat()).IsInt()
	}
	if !instance.isFloat {
		return new(big.Int).Mod(instance.integer, divisor.integer).Sign() == 0
	}
	d := divisor.float()
	if math.IsInf(d, 0) {
		return false
	}
	return math.Mod(instance.floating, d) == 0
}

// equalityKey implements JSON Schema's Python equality (booleans are distinct
// from numbers), including exact int-versus-binary64 comparisons. Its use for
// uniqueItems avoids adding a quadratic comparison loop to the worker path.
func equalityKey(value any) string {
	switch v := value.(type) {
	case nil:
		return "z"
	case bool:
		if v {
			return "b1"
		}
		return "b0"
	case string:
		return "s" + strconv.Quote(v)
	case []any:
		var b strings.Builder
		b.WriteString("a[")
		for _, item := range v {
			b.WriteString(equalityKey(item))
			b.WriteByte(',')
		}
		b.WriteByte(']')
		return b.String()
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		var b strings.Builder
		b.WriteString("o{")
		for _, key := range keys {
			b.WriteString(strconv.Quote(key))
			b.WriteByte(':')
			b.WriteString(equalityKey(v[key]))
			b.WriteByte(',')
		}
		b.WriteByte('}')
		return b.String()
	}
	if n, ok := number(value); ok {
		return "n" + n.rat().RatString()
	}
	// The boundary normalizes and validates JSON before invoking a vocabulary.
	panic("non-JSON value reached schema numeric assertions")
}

type pythonAssertions struct {
	multipleOf  *pythonNumber
	bounds      map[string]pythonNumber
	constant    *string
	enumeration map[string]bool
	hasEnum     bool
	unique      bool
}

func (s *pythonAssertions) Validate(ctx *jsonschema.ValidatorContext, value any) {
	if s.constant != nil && equalityKey(value) != *s.constant {
		ctx.AddError(&kind.Const{Got: value})
	}
	if s.hasEnum && !s.enumeration[equalityKey(value)] {
		ctx.AddError(&kind.Enum{Got: value})
	}
	if s.unique {
		if items, ok := value.([]any); ok {
			seen := map[string]int{}
			for i, item := range items {
				key := equalityKey(item)
				if previous, present := seen[key]; present {
					ctx.AddError(&kind.UniqueItems{Duplicates: [2]int{previous, i}})
					break
				}
				seen[key] = i
			}
		}
	}
	n, ok := number(value)
	if !ok {
		return
	}
	if s.multipleOf != nil && !multiple(n, *s.multipleOf) {
		ctx.AddError(&kind.MultipleOf{Got: n.rat(), Want: s.multipleOf.rat()})
	}
	for keyword, want := range s.bounds {
		cmp := n.rat().Cmp(want.rat())
		switch keyword {
		case "minimum":
			if cmp < 0 {
				ctx.AddError(&kind.Minimum{Got: n.rat(), Want: want.rat()})
			}
		case "maximum":
			if cmp > 0 {
				ctx.AddError(&kind.Maximum{Got: n.rat(), Want: want.rat()})
			}
		case "exclusiveMinimum":
			if cmp <= 0 {
				ctx.AddError(&kind.ExclusiveMinimum{Got: n.rat(), Want: want.rat()})
			}
		case "exclusiveMaximum":
			if cmp >= 0 {
				ctx.AddError(&kind.ExclusiveMaximum{Got: n.rat(), Want: want.rat()})
			}
		}
	}
}

var compatibilityKeywords = []string{"multipleOf", "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "const", "enum", "uniqueItems"}

// The standard validator still implements every structural/logical keyword.
// A private vocabulary changes only Python's numeric and equality semantics,
// including within references, conditionals, alternatives and negation.
func compatibilityCompiler(root any) (*jsonschema.Compiler, any, error) {
	keys := map[string]bool{}
	var collect func(any)
	collect = func(value any) {
		switch v := value.(type) {
		case map[string]any:
			for k, child := range v {
				keys[k] = true
				collect(child)
			}
		case []any:
			for _, child := range v {
				collect(child)
			}
		}
	}
	collect(root)
	replacements := map[string]string{}
	metaProperties := domain.Object{}
	for _, keyword := range compatibilityKeywords {
		key := "_hf2l_python_" + keyword
		for keys[key] {
			key += "_"
		}
		keys[key] = true
		replacements[keyword] = key
		var shape any = domain.Object{"type": "number"}
		switch keyword {
		case "multipleOf":
			shape = domain.Object{"type": "number", "exclusiveMinimum": 0}
		case "const":
			shape = true
		case "enum":
			shape = domain.Object{"type": "array"}
		case "uniqueItems":
			shape = domain.Object{"type": "boolean"}
		}
		metaProperties[key] = shape
	}
	if err := walkSchemas(root, func(node map[string]any) error {
		for _, keyword := range compatibilityKeywords {
			if value, present := node[keyword]; present {
				delete(node, keyword)
				node[replacements[keyword]] = value
			}
		}
		return nil
	}); err != nil {
		return nil, nil, err
	}
	metaCompiler := compiler()
	metaURL := "https://hf2l.invalid/exchange/python-numeric-vocabulary.json"
	if err := metaCompiler.AddResource(metaURL, domain.Object{"properties": metaProperties}); err != nil {
		return nil, nil, err
	}
	meta, err := metaCompiler.Compile(metaURL)
	if err != nil {
		return nil, nil, err
	}
	c := compiler()
	c.AssertVocabs()
	c.RegisterVocabulary(&jsonschema.Vocabulary{URL: metaURL, Schema: meta, Compile: func(_ *jsonschema.CompilerContext, obj map[string]any) (jsonschema.SchemaExt, error) {
		assertions := &pythonAssertions{bounds: map[string]pythonNumber{}}
		presentAny := false
		for _, keyword := range compatibilityKeywords {
			value, present := obj[replacements[keyword]]
			if !present {
				continue
			}
			presentAny = true
			switch keyword {
			case "multipleOf":
				n, ok := number(value)
				if !ok || n.rat().Sign() <= 0 {
					return nil, domain.Err(422, "invalid_schema")
				}
				assertions.multipleOf = &n
			case "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum":
				n, ok := number(value)
				if !ok {
					return nil, domain.Err(422, "invalid_schema")
				}
				assertions.bounds[keyword] = n
			case "const":
				key := equalityKey(value)
				assertions.constant = &key
			case "enum":
				items, ok := value.([]any)
				if !ok {
					return nil, domain.Err(422, "invalid_schema")
				}
				assertions.hasEnum = true
				assertions.enumeration = map[string]bool{}
				for _, item := range items {
					assertions.enumeration[equalityKey(item)] = true
				}
			case "uniqueItems":
				unique, ok := value.(bool)
				if !ok {
					return nil, domain.Err(422, "invalid_schema")
				}
				assertions.unique = unique
			}
		}
		if !presentAny {
			return nil, nil
		}
		return assertions, nil
	}})
	return c, root, nil
}
