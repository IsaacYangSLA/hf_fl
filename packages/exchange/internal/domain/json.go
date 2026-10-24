package domain

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

var jsonNumberPattern = regexp.MustCompile(`^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$`)

// DecodeJSON retains integer-vs-float lexical types, including integers above 2^53.
// Invalid UTF-8 or unpaired surrogates are rejected instead of silently replaced.
func DecodeJSON(raw []byte) (any, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("JSON is not valid UTF-8")
	}
	if err := validSurrogates(raw); err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value any
	if err := d.Decode(&value); err != nil {
		return nil, err
	}
	var trailing any
	if err := d.Decode(&trailing); err != io.EOF {
		return nil, errors.New("expected one JSON value")
	}
	return value, nil
}
func validSurrogates(raw []byte) error {
	inString := false
	for i := 0; i < len(raw); i++ {
		if raw[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return errors.New("incomplete JSON escape")
		}
		if raw[i] != 'u' {
			continue
		}
		if i+4 >= len(raw) {
			return errors.New("incomplete Unicode escape")
		}
		v, err := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if err != nil {
			return errors.New("invalid Unicode escape")
		}
		i += 4
		if v >= 0xd800 && v <= 0xdbff {
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return errors.New("unpaired high surrogate")
			}
			low, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return errors.New("unpaired high surrogate")
			}
			i += 6
		} else if v >= 0xdc00 && v <= 0xdfff {
			return errors.New("unpaired low surrogate")
		}
	}
	return nil
}

// CanonicalJSON matches Python json.dumps(sort_keys=True,separators=(",",":"),
// ensure_ascii=False,allow_nan=False), including float type and exponent spelling.
func CanonicalJSON(value any) ([]byte, error) { return canonical(value, false) }

// CanonicalASCIIJSON matches Python ensure_ascii=True for stable principals.
// Exchange body and schema hashes continue to use CanonicalJSON.
func CanonicalASCIIJSON(value any) ([]byte, error) { return canonical(value, true) }
func canonical(value any, ascii bool) ([]byte, error) {
	var b bytes.Buffer
	if err := appendCanonical(&b, reflect.ValueOf(value), ascii, 0); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
func appendCanonical(b *bytes.Buffer, v reflect.Value, ascii bool, depth int) error {
	if depth > 128 {
		return errors.New("JSON nesting exceeds limit")
	}
	if !v.IsValid() {
		b.WriteString("null")
		return nil
	}
	if v.Kind() == reflect.Interface || v.Kind() == reflect.Pointer {
		if v.IsNil() {
			b.WriteString("null")
			return nil
		}
		return appendCanonical(b, v.Elem(), ascii, depth+1)
	}
	if v.CanInterface() {
		switch n := v.Interface().(type) {
		case json.Number:
			s := string(n)
			if !jsonNumberPattern.MatchString(s) {
				return errors.New("invalid JSON number")
			}
			if !strings.ContainsAny(s, ".eE") {
				integer, ok := new(big.Int).SetString(s, 10)
				if !ok {
					return errors.New("invalid JSON integer")
				}
				b.WriteString(integer.String())
				return nil
			}
			f, err := strconv.ParseFloat(s, 64)
			if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
				return errors.New("JSON number is not finite")
			}
			b.WriteString(pythonFloat(f))
			return nil
		case interface{ Map() map[string]any }:
			return appendCanonical(b, reflect.ValueOf(n.Map()), ascii, depth+1)
		}
	}
	switch v.Kind() {
	case reflect.Bool:
		if v.Bool() {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case reflect.String:
		return appendString(b, v.String(), ascii)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		b.WriteString(strconv.FormatInt(v.Int(), 10))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		b.WriteString(strconv.FormatUint(v.Uint(), 10))
	case reflect.Float32, reflect.Float64:
		f := v.Float()
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return errors.New("JSON number is not finite")
		}
		b.WriteString(pythonFloat(f))
	case reflect.Map:
		if v.IsNil() {
			b.WriteString("null")
			return nil
		}
		if v.Type().Key().Kind() != reflect.String {
			return errors.New("JSON object keys must be strings")
		}
		keys := v.MapKeys()
		sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
		b.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := appendString(b, key.String(), ascii); err != nil {
				return err
			}
			b.WriteByte(':')
			if err := appendCanonical(b, v.MapIndex(key), ascii, depth+1); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	case reflect.Slice, reflect.Array:
		if v.Kind() == reflect.Slice && v.IsNil() {
			b.WriteString("null")
			return nil
		}
		b.WriteByte('[')
		for i := 0; i < v.Len(); i++ {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := appendCanonical(b, v.Index(i), ascii, depth+1); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case reflect.Struct:
		m := make(map[string]any)
		for i := 0; i < v.NumField(); i++ {
			field := v.Type().Field(i)
			if field.PkgPath != "" {
				continue
			}
			tag := strings.Split(field.Tag.Get("json"), ",")
			if tag[0] == "-" {
				continue
			}
			name := tag[0]
			if name == "" {
				name = field.Name
			}
			omit := false
			for _, o := range tag[1:] {
				if o == "omitempty" {
					omit = true
				}
			}
			if omit && v.Field(i).IsZero() {
				continue
			}
			m[name] = v.Field(i).Interface()
		}
		return appendCanonical(b, reflect.ValueOf(m), ascii, depth+1)
	default:
		return fmt.Errorf("unsupported JSON value %s", v.Kind())
	}
	return nil
}
func appendString(b *bytes.Buffer, s string, ascii bool) error {
	if !utf8.ValidString(s) {
		return errors.New("string is not valid UTF-8")
	}
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString("\\\"")
		case '\\':
			b.WriteString("\\\\")
		case '\b':
			b.WriteString("\\b")
		case '\f':
			b.WriteString("\\f")
		case '\n':
			b.WriteString("\\n")
		case '\r':
			b.WriteString("\\r")
		case '\t':
			b.WriteString("\\t")
		default:
			if r < 32 {
				fmt.Fprintf(b, "\\u%04x", r)
			} else if ascii && r >= 127 {
				if r > 0xffff {
					h, l := utf16.EncodeRune(r)
					fmt.Fprintf(b, "\\u%04x\\u%04x", h, l)
				} else {
					fmt.Fprintf(b, "\\u%04x", r)
				}
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return nil
}
func pythonFloat(f float64) string {
	if f == 0 {
		if math.Signbit(f) {
			return "-0.0"
		}
		return "0.0"
	}
	raw := strconv.FormatFloat(f, 'e', -1, 64)
	parts := strings.SplitN(raw, "e", 2)
	exponent, _ := strconv.Atoi(parts[1])
	mantissa := parts[0]
	if exponent >= -4 && exponent < 16 {
		sign := ""
		if strings.HasPrefix(mantissa, "-") {
			sign = "-"
			mantissa = mantissa[1:]
		}
		digits := strings.ReplaceAll(mantissa, ".", "")
		decimal := exponent + 1
		if decimal <= 0 {
			return sign + "0." + strings.Repeat("0", -decimal) + digits
		}
		if decimal >= len(digits) {
			return sign + digits + strings.Repeat("0", decimal-len(digits)) + ".0"
		}
		return sign + digits[:decimal] + "." + digits[decimal:]
	}
	sign := "+"
	if exponent < 0 {
		sign = "-"
		exponent = -exponent
	}
	return mantissa + "e" + sign + fmt.Sprintf("%02d", exponent)
}
func SpecHash(value any) (string, error) {
	raw, err := CanonicalJSON(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
func Hash(value any) (string, error) { return SpecHash(value) }

// PrincipalID intentionally uses ensure_ascii=True, unlike specification hashes.
func PrincipalID(issuer, subject string) string {
	raw, err := canonical([]string{issuer, subject}, true)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// CloneJSON gives callers independent nested option trees without changing types.
func CloneJSON(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, x := range v {
			out[k] = CloneJSON(x)
		}
		return out
	case map[string]string:
		out := make(map[string]string, len(v))
		for k, x := range v {
			out[k] = x
		}
		return out
	case []string:
		return append([]string{}, v...)
	case []any:
		out := make([]any, len(v))
		for i, x := range v {
			out[i] = CloneJSON(x)
		}
		return out
	default:
		return v
	}
}
func CloneMap(value map[string]any) map[string]any {
	if value == nil {
		return map[string]any{}
	}
	return CloneJSON(value).(map[string]any)
}
