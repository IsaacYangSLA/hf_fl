// Package service implements transaction-owned Exchange commands.
package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/store"
)

type Object = domain.Object

type AuthOptions struct {
	AdminSubject               string
	WorkloadIssuer             string
	ProvisioningPrincipalIDs   []string
	DownloadBrokerPrincipalIDs []string
}
type Options struct {
	Auth                AuthOptions
	DraftSeconds        int64
	CoordinationSeconds int64
	PartSize            int64
}
type Service struct {
	DB       *store.DB
	Settings Options
}

func New(db *store.DB, options Options) *Service {
	if options.DraftSeconds == 0 {
		options.DraftSeconds = 86400
	}
	if options.CoordinationSeconds == 0 {
		options.CoordinationSeconds = 300
	}
	if options.PartSize == 0 {
		options.PartSize = 8388608
	}
	return &Service{DB: db, Settings: options}
}

var allRoles = []string{"admin", "contributor", "publisher", "reader"}
var terminalStates = map[string]bool{"withdrawn": true, "cancelled": true, "failed": true, "expired": true}
var terminalEvents = map[string]bool{"record.withdrawn": true, "record.cancelled": true, "record.failed": true, "record.expired": true}

func (s *Service) WithSpace(ctx context.Context, sid string, p domain.Principal, write, allowRetired bool, fn func(*store.Tx, Object, Object) error) error {
	return s.DB.WithTx(ctx, write, func(tx *store.Tx) error {
		query := "SELECT * FROM v2_spaces WHERE id=?"
		if write {
			query += tx.ForUpdate()
		}
		space, e := tx.One(ctx, query, sid)
		if e != nil {
			return e
		}
		if space == nil {
			return domain.Err(404, "space_not_found")
		}
		member, e := tx.One(ctx, "SELECT * FROM v2_members WHERE space_id=? AND principal_id=?", sid, p.ID)
		if e != nil {
			return e
		}
		if member == nil || len(stringsOf(member["roles"])) == 0 {
			return domain.Err(404, "space_not_found")
		}
		managed, e := tx.One(ctx, "SELECT * FROM v2_managed_spaces WHERE space_id=?", sid)
		if e != nil {
			return e
		}
		if p.Workload != nil {
			grant, e := s.MatchingGrant(ctx, tx, space, member, p, managed)
			if e != nil {
				return e
			}
			member = clone(member)
			member["roles"] = intersection(stringsOf(member["roles"]), stringsOf(grant["roles"]))
		} else if managed != nil {
			provisioner := contains(s.Settings.Auth.ProvisioningPrincipalIDs, p.ID)
			if !provisioner && !contains(s.Settings.Auth.DownloadBrokerPrincipalIDs, p.ID) {
				return domain.Err(404, "space_not_found")
			}
			if !provisioner {
				member = clone(member)
				member["roles"] = intersection(stringsOf(member["roles"]), []string{"reader"})
				if len(stringsOf(member["roles"])) == 0 {
					return domain.Err(404, "space_not_found")
				}
			}
		}
		if managed != nil && managed["retired_at"] != nil && write && !allowRetired {
			return domain.Err(409, "managed_space_retired")
		}
		return fn(tx, space, member)
	})
}

func Require(member Object, roles ...string) error {
	for _, r := range roles {
		if hasRole(member, r) {
			return nil
		}
	}
	return domain.Err(403, "role_required")
}
func (s *Service) Require(member Object, roles ...string) error { return Require(member, roles...) }

func (s *Service) Emit(ctx context.Context, tx *store.Tx, sid, kind string, p domain.Principal, recordID any, data Object) error {
	now, e := tx.Now(ctx)
	if e != nil {
		return e
	}
	if data == nil {
		data = Object{}
	}
	return tx.Insert(ctx, "v2_events", Object{"space_id": sid, "type": kind, "principal_id": p.ID, "record_id": recordID, "payload": data, "created_at": now})
}
func (s *Service) Once(ctx context.Context, tx *store.Tx, space Object, p domain.Principal, scope, key string, body any, action func() (Object, error)) (Object, error) {
	if key == "" || utf8.RuneCountInString(key) > 128 {
		return nil, domain.Err(422, "idempotency_key_required")
	}
	encoded, e := domain.CanonicalJSON(body)
	if e != nil {
		return nil, e
	}
	sum := sha256.Sum256(encoded)
	digest := hex.EncodeToString(sum[:])
	op, e := tx.One(ctx, "SELECT * FROM v2_operations WHERE space_id=? AND principal_id=? AND scope=? AND key=?", space["id"], p.ID, scope, key)
	if e != nil {
		return nil, e
	}
	if op != nil {
		if str(op["request_hash"]) != digest {
			return nil, domain.Err(409, "idempotency_conflict")
		}
		return obj(op["response"]), nil
	}
	result, e := action()
	if e != nil {
		return nil, e
	}
	now, e := tx.Now(ctx)
	if e != nil {
		return nil, e
	}
	e = tx.Insert(ctx, "v2_operations", Object{"space_id": space["id"], "principal_id": p.ID, "scope": scope, "key": key, "request_hash": digest, "response": result, "created_at": now})
	return result, e
}
func (s *Service) Record(ctx context.Context, tx *store.Tx, sid, rid string, member Object, p domain.Principal, write bool) (Object, error) {
	record, e := tx.One(ctx, "SELECT * FROM v2_records WHERE space_id=? AND id=?", sid, rid)
	if e != nil {
		return nil, e
	}
	if record == nil {
		return nil, domain.Err(404, "record_not_found")
	}
	if write {
		if e = Require(member, "contributor", "publisher"); e != nil {
			return nil, e
		}
		if str(record["creator"]) != p.ID {
			return nil, domain.Err(403, "record_owner_required")
		}
	} else if !visible(record, member, p) {
		return nil, domain.Err(404, "record_not_found")
	}
	return record, nil
}
func (s *Service) RecordForRead(ctx context.Context, tx *store.Tx, sid, rid string, member Object, p domain.Principal) (Object, error) {
	return s.Record(ctx, tx, sid, rid, member, p, false)
}
func (s *Service) RecordForWrite(ctx context.Context, tx *store.Tx, sid, rid string, member Object, p domain.Principal) (Object, error) {
	return s.Record(ctx, tx, sid, rid, member, p, true)
}
func (s *Service) Attachment(ctx context.Context, tx *store.Tx, sid, rid, bid string) (Object, error) {
	blob, e := tx.One(ctx, "SELECT * FROM v2_blobs WHERE id=? AND space_id=? AND record_id=?", bid, sid, rid)
	if e != nil {
		return nil, e
	}
	if blob == nil {
		return nil, domain.Err(404, "attachment_not_found")
	}
	return blob, nil
}
func (s *Service) CheckDraft(ctx context.Context, tx *store.Tx, record Object) error {
	if str(record["state"]) != "draft" {
		return domain.Err(409, "record_not_draft")
	}
	now, e := tx.Now(ctx)
	if e != nil {
		return e
	}
	if decimal(record["expires_at"]) <= now {
		return domain.Err(409, "draft_expired")
	}
	return nil
}
func visible(record, member Object, p domain.Principal) bool {
	if (hasRole(member, "reader") || hasRole(member, "contributor") || hasRole(member, "publisher")) && str(record["state"]) == "published" && flag(record["shared"]) {
		return true
	}
	if hasRole(member, "contributor") && str(record["creator"]) == p.ID {
		return true
	}
	return hasRole(member, "publisher") && (str(record["state"]) == "published" || str(record["creator"]) == p.ID)
}
func profileRecord(record Object) Object {
	return Object{"id": record["id"], "kind": record["kind"], "creator": record["creator"], "metadata": record["metadata_json"], "creator_bindings": record["creator_bindings"], "published_at": record["published_at"], "state": record["state"]}
}
func memberDict(member Object) Object {
	if member == nil {
		return nil
	}
	return selectFields(member, "principal_id", "subject", "roles", "bindings")
}
func spaceDict(space Object) Object {
	return selectFields(space, "id", "name", "profile", "quota_bytes", "principal_quota_bytes", "allocated", "reclaiming", "quota_records", "record_count", "quota_metadata_bytes", "metadata_bytes", "generation")
}
func typeDict(revision Object) Object {
	return selectFields(revision, "id", "space_id", "kind", "revision", "schema", "profile_version", "digest", "dialect")
}
func blobDict(blob Object) Object {
	return selectFields(blob, "id", "path", "size", "sha256", "media_type", "state", "part_size")
}
func selectFields(row Object, names ...string) Object {
	out := Object{}
	for _, n := range names {
		out[n] = row[n]
	}
	return out
}
func clone(v Object) Object {
	out := Object{}
	for k, x := range v {
		out[k] = x
	}
	return out
}
func get(v Object, key string, fallback any) any {
	if x, ok := v[key]; ok {
		return x
	}
	return fallback
}
func str(v any) string {
	if v == nil {
		return ""
	}
	if x, ok := v.(string); ok {
		return x
	}
	return fmt.Sprint(v)
}
func num(v any) int64 {
	if n, ok := domain.Int64(v); ok {
		return n
	}
	return 0
}
func decimal(v any) float64    { n, _ := domain.Float(v); return n }
func flag(v any) bool          { x, _ := v.(bool); return x }
func obj(v any) Object         { x, _ := v.(map[string]any); return x }
func stringsOf(v any) []string { x, _ := domain.Strings(v); return x }
func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
func hasRole(member Object, role string) bool { return contains(stringsOf(member["roles"]), role) }
func unique(values []string) []string {
	set := map[string]bool{}
	for _, v := range values {
		set[v] = true
	}
	out := []string{}
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
func intersection(a, b []string) []string {
	out := []string{}
	for _, v := range a {
		if contains(b, v) {
			out = append(out, v)
		}
	}
	return unique(out)
}
func update(ctx context.Context, tx *store.Tx, table string, where, row, values Object) error {
	if e := tx.Update(ctx, table, where, values); e != nil {
		return e
	}
	for k, v := range values {
		row[k] = v
	}
	return nil
}

func numberRat(v any) (*big.Rat, bool) {
	if b, ok := v.(bool); ok {
		if b {
			return big.NewRat(1, 1), true
		}
		return big.NewRat(0, 1), true
	}
	switch n := v.(type) {
	case json.Number:
		if !strings.ContainsAny(n.String(), ".eE") {
			r, ok := new(big.Rat).SetString(n.String())
			return r, ok
		}
		f, e := strconv.ParseFloat(n.String(), 64)
		if e != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			return nil, false
		}
		return new(big.Rat).SetFloat64(f), true
	case float64:
		if math.IsNaN(n) || math.IsInf(n, 0) {
			return nil, false
		}
		return new(big.Rat).SetFloat64(n), true
	case float32:
		return new(big.Rat).SetFloat64(float64(n)), true
	}
	val := reflect.ValueOf(v)
	if !val.IsValid() {
		return nil, false
	}
	switch val.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return new(big.Rat).SetInt64(val.Int()), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return new(big.Rat).SetInt(new(big.Int).SetUint64(val.Uint())), true
	}
	return nil, false
}

// equal follows Python JSON value equality for bindings, not body-hash equality.
func equal(a, b any) bool {
	if ar, ok := numberRat(a); ok {
		br, ok := numberRat(b)
		return ok && ar.Cmp(br) == 0
	}
	if am, ok := a.(map[string]any); ok {
		bm, ok := b.(map[string]any)
		if !ok || len(am) != len(bm) {
			return false
		}
		for k, v := range am {
			w, ok := bm[k]
			if !ok || !equal(v, w) {
				return false
			}
		}
		return true
	}
	av, bv := reflect.ValueOf(a), reflect.ValueOf(b)
	if av.IsValid() && (av.Kind() == reflect.Slice || av.Kind() == reflect.Array) {
		if !bv.IsValid() || (bv.Kind() != reflect.Slice && bv.Kind() != reflect.Array) || av.Len() != bv.Len() {
			return false
		}
		for i := 0; i < av.Len(); i++ {
			if !equal(av.Index(i).Interface(), bv.Index(i).Interface()) {
				return false
			}
		}
		return true
	}
	return reflect.DeepEqual(a, b)
}

// mutationTokensPending preserves the quiescence barrier even when a stored
// mutation ledger has a malformed shape. Unknown is not proof of absence.
func mutationTokensPending(value any) bool {
	tokens, valid := domain.MutationTokens(value)
	return !valid || len(tokens) != 0
}
