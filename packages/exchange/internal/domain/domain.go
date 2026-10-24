// Package domain defines transport-independent Exchange identities and failures.
package domain

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"reflect"
	"strconv"
	"strings"
)

type Object = map[string]any

// Error carries a stable public failure. Error() excludes optional details.
type Error struct {
	Status  int               `json:"-"`
	Code    string            `json:"code"`
	Detail  string            `json:"detail"`
	Headers map[string]string `json:"-"`
}

func (e *Error) Error() string { return e.Code }
func Err(status int, code string, detail ...string) *Error {
	e := &Error{Status: status, Code: code, Detail: code}
	if len(detail) > 0 && detail[0] != "" {
		e.Detail = detail[0]
	}
	return e
}
func ErrorCode(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}
func StatusCode(err error) int {
	var e *Error
	if errors.As(err, &e) {
		return e.Status
	}
	return 500
}

type WorkloadIdentity struct {
	GrantID               string  `json:"grant_id"`
	SpaceID               string  `json:"space_id"`
	JobID                 string  `json:"job_id"`
	AttemptID             string  `json:"attempt_id"`
	ComponentID           string  `json:"component_id"`
	Epoch                 int64   `json:"epoch"`
	CertificateThumbprint string  `json:"certificate_thumbprint"`
	ExpiresAt             float64 `json:"expires_at"`
}
type Principal struct {
	ID             string            `json:"id"`
	Subject        string            `json:"subject"`
	BootstrapAdmin bool              `json:"bootstrap_admin"`
	Workload       *WorkloadIdentity `json:"workload,omitempty"`
}
type RecordIdentity struct{ ID, SpaceID, Kind, SchemaRevisionID string }
type ReferenceVersion struct {
	RecordID   string
	Generation int64
}

func (v ReferenceVersion) Token() string { return strconv.FormatInt(v.Generation, 10) }

type ClaimHandle struct {
	ID         string
	Fence      int64
	LeaseUntil float64
}
type BlobDeclaration struct {
	Path      string
	Size      int64
	SHA256    string
	MediaType string
}

// NewID produces the reference UUID4 hexadecimal identity.
func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("cryptographic randomness unavailable")
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return hex.EncodeToString(b[:])
}

// Integer accepts lexical JSON integers and native integer values. Floats and
// booleans are deliberately excluded, as with Python type(value) is int.
func Integer(value any) (*big.Int, bool) {
	if n, ok := value.(json.Number); ok {
		s := string(n)
		if !jsonNumberPattern.MatchString(s) || strings.ContainsAny(s, ".eE") {
			return nil, false
		}
		x, ok := new(big.Int).SetString(s, 10)
		return x, ok
	}
	if value == nil {
		return nil, false
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return big.NewInt(v.Int()), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return new(big.Int).SetUint64(v.Uint()), true
	}
	return nil, false
}
func Int64(value any) (int64, bool) {
	n, ok := Integer(value)
	if !ok || !n.IsInt64() {
		return 0, false
	}
	return n.Int64(), true
}

// Float accepts finite JSON/native numbers without accepting booleans or strings.
func Float(value any) (float64, bool) {
	if n, ok := value.(json.Number); ok {
		if !jsonNumberPattern.MatchString(string(n)) {
			return 0, false
		}
		f, err := strconv.ParseFloat(string(n), 64)
		return f, err == nil && !math.IsInf(f, 0) && !math.IsNaN(f)
	}
	if value == nil {
		return 0, false
	}
	v := reflect.ValueOf(value)
	var f float64
	switch v.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		f = float64(v.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		f = float64(v.Uint())
	case reflect.Float32, reflect.Float64:
		f = v.Float()
	default:
		return 0, false
	}
	return f, !math.IsInf(f, 0) && !math.IsNaN(f)
}
func Strings(value any) ([]string, bool) {
	switch v := value.(type) {
	case []string:
		return append([]string{}, v...), true
	case []any:
		out := make([]string, len(v))
		for i, x := range v {
			s, ok := x.(string)
			if !ok {
				return nil, false
			}
			out[i] = s
		}
		return out, true
	}
	return nil, false
}
