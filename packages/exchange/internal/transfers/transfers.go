// Package transfers implements durable, lease-fenced immutable blob transfers.
package transfers

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/config"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/service"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/storage"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/store"
)

type Object = domain.Object

const Protocol = "s3-multipart-v1"

type GatewayPutHandle struct {
	SpaceID      string `json:"space_id"`
	RecordID     string `json:"record_id"`
	AttachmentID string `json:"attachment_id"`
	AttemptID    string `json:"attempt_id"`
	ObjectKey    string `json:"object_key"`
	UploadID     string `json:"upload_id"`
	PartNumber   int    `json:"part_number"`
	Token        string `json:"token"`
}

type Service struct {
	Core     *service.Service
	DB       *store.DB
	Settings config.Settings
	Storage  storage.BlobStore
}

func New(core *service.Service, blobs storage.BlobStore, settings config.Settings) *Service {
	return &Service{Core: core, DB: core.DB, Settings: settings, Storage: blobs}
}
func str(v any) string     { s, _ := v.(string); return s }
func integer(v any) int64  { n, _ := domain.Int64(v); return n }
func number(v any) float64 { n, _ := domain.Float(v); return n }
func flag(v any) bool      { b, _ := v.(bool); return b }
func obj(v any) Object {
	m, _ := v.(map[string]any)
	if m == nil {
		return Object{}
	}
	return m
}
func list(v any) []any {
	switch x := v.(type) {
	case []any:
		return x
	case []string:
		r := make([]any, len(x))
		for i, s := range x {
			r[i] = s
		}
		return r
	default:
		return nil
	}
}
func hasToken(v any, token string) bool {
	if token == "" {
		return false
	}
	values, valid := domain.MutationTokens(v)
	if !valid {
		return false
	}
	for _, value := range values {
		if value == token {
			return true
		}
	}
	return false
}
func removeToken(v any, token string) any {
	values, valid := domain.MutationTokens(v)
	if !valid {
		return v // Never normalize unsupported ownership into an empty list.
	}
	result := []any{}
	for _, value := range values {
		if value != token {
			result = append(result, value)
		}
	}
	return result
}
func tokens(v any) ([]any, error) {
	values, valid := domain.MutationTokens(v)
	if !valid {
		return nil, domain.Err(409, "storage_mutation_uncertain")
	}
	result := make([]any, len(values))
	for i, value := range values {
		result[i] = value
	}
	return result, nil
}
func terminal(state string) bool {
	return state == "cancelled" || state == "expired" || state == "withdrawn" || state == "failed"
}
func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
func backoff(count int64) float64 {
	if count < 0 {
		count = 0
	}
	if count > 8 {
		count = 8
	}
	return float64(int64(1) << count)
}
func save(ctx context.Context, tx *store.Tx, table string, row Object, fields ...string) error {
	values := Object{}
	for _, key := range fields {
		values[key] = row[key]
	}
	return tx.Update(ctx, table, Object{"id": row["id"]}, values)
}
func (s *Service) attachment(ctx context.Context, tx *store.Tx, sid, rid, bid string, m Object, p domain.Principal, write bool) (Object, Object, error) {
	r, e := s.Core.Record(ctx, tx, sid, rid, m, p, write)
	if e != nil {
		return nil, nil, e
	}
	b, e := s.Core.Attachment(ctx, tx, sid, rid, bid)
	return r, b, e
}
func view(blob, attempt Object) Object {
	r := Object{"attachment_id": blob["id"], "state": blob["state"], "protocol": Protocol, "part_size": blob["part_size"]}
	if attempt != nil {
		r["attempt_id"] = attempt["id"]
	}
	return r
}
func upload(attempt Object) (storage.UploadHandle, error) {
	h := obj(attempt["upload_handle"])
	if str(h["id"]) == "" {
		return storage.UploadHandle{}, storage.Failure("storage_missing", false, false)
	}
	return storage.UploadHandle{ID: str(h["id"]), Key: str(attempt["object_key"])}, nil
}
func (s *Service) active(ctx context.Context, tx *store.Tx, blob Object) (Object, error) {
	attempt, e := tx.One(ctx, "SELECT * FROM v2_transfer_attempts WHERE blob_id=? AND operation='upload' AND state NOT IN ('cleanup','cleaned','failed') ORDER BY created_at DESC,id DESC LIMIT 1", blob["id"])
	if e != nil || attempt == nil {
		return attempt, e
	}
	if _, e = tokens(attempt["mutation_tokens"]); e != nil {
		return nil, e
	}
	return attempt, nil
}
func (s *Service) newAttempt(ctx context.Context, tx *store.Tx, blob Object, now float64) (Object, error) {
	id, token := domain.NewID(), domain.NewID()
	key := strings.Join([]string{str(blob["space_id"]), str(blob["id"]), id}, "/")
	if prefix := strings.Trim(s.Settings.Storage.Prefix, "/"); prefix != "" {
		key = prefix + "/" + key
	}
	a := Object{"id": id, "blob_id": blob["id"], "object_key": key, "operation": "upload", "state": "initiating", "token": token, "mutation_tokens": []any{token}, "lease_until": now + float64(s.Settings.Worker.LeaseSeconds), "retry_count": int64(0), "next_attempt": now, "last_error": nil, "upload_handle": Object{}, "grant_expires_at": float64(0), "created_at": now, "updated_at": now}
	if e := tx.Insert(ctx, "v2_transfer_attempts", a); e != nil {
		return nil, e
	}
	blob["state"] = "initiating"
	if e := save(ctx, tx, "v2_blobs", blob, "state"); e != nil {
		return nil, e
	}
	return a, nil
}
func (s *Service) Initiate(ctx context.Context, sid, rid, bid string, p domain.Principal) (Object, error) {
	var attempt, result Object
	e := s.Core.WithSpace(ctx, sid, p, true, false, func(tx *store.Tx, _ Object, m Object) error {
		r, b, e := s.attachment(ctx, tx, sid, rid, bid, m, p, true)
		if e != nil {
			return e
		}
		if str(r["state"]) != "draft" {
			return domain.Err(409, "record_not_draft")
		}
		a, e := s.active(ctx, tx, b)
		if e != nil {
			return e
		}
		if a != nil {
			if _, e := tokens(a["mutation_tokens"]); e != nil {
				return e
			}
			result = view(b, a)
			return nil
		}
		prior, e := tx.All(ctx, "SELECT * FROM v2_transfer_attempts WHERE blob_id=?", b["id"])
		if e != nil {
			return e
		}
		for _, item := range prior {
			markers, e := tokens(item["mutation_tokens"])
			if e != nil {
				return e
			}
			if len(markers) > 0 {
				return domain.Err(409, "storage_mutation_uncertain")
			}
		}
		if state := str(b["state"]); state == "verified" || state == "failed" || state == "cleaned" {
			result = view(b, nil)
			return nil
		}
		for _, item := range prior {
			if str(item["state"]) == "cleanup" {
				return domain.Err(409, "cleanup_pending")
			}
		}
		now, e := tx.Now(ctx)
		if e != nil {
			return e
		}
		if number(r["expires_at"]) <= now {
			return domain.Err(409, "draft_expired")
		}
		attempt, e = s.newAttempt(ctx, tx, b, now)
		return e
	})
	if e != nil || result != nil {
		return result, e
	}
	if _, e = s.execute(ctx, attempt); e != nil {
		return nil, e
	}
	e = s.Core.WithSpace(ctx, sid, p, false, false, func(tx *store.Tx, _ Object, m Object) error {
		_, b, e := s.attachment(ctx, tx, sid, rid, bid, m, p, false)
		if e != nil {
			return e
		}
		a, e := s.active(ctx, tx, b)
		if e != nil {
			return e
		}
		result = view(b, a)
		return nil
	})
	return result, e
}
func (s *Service) Parts(ctx context.Context, sid, rid, bid string, p domain.Principal) (Object, error) {
	var h storage.UploadHandle
	e := s.Core.WithSpace(ctx, sid, p, false, false, func(tx *store.Tx, _ Object, m Object) error {
		r, b, e := s.attachment(ctx, tx, sid, rid, bid, m, p, true)
		if e != nil {
			return e
		}
		a, e := s.active(ctx, tx, b)
		if e != nil {
			return e
		}
		if str(r["state"]) != "draft" || a == nil || str(a["state"]) != "uploading" {
			return domain.Err(409, "upload_not_ready")
		}
		h, e = upload(a)
		return e
	})
	if e != nil {
		return nil, e
	}
	parts, e := s.Storage.Parts(ctx, h)
	if e != nil {
		return nil, e
	}
	values := make([]any, len(parts))
	for i, p := range parts {
		values[i] = Object{"number": p.Number, "etag": p.ETag, "size": p.Size}
	}
	return Object{"parts": values}, nil
}
func validNumbers(numbers []int) bool {
	if len(numbers) == 0 || len(numbers) > 100 {
		return false
	}
	seen := map[int]bool{}
	for _, n := range numbers {
		if seen[n] {
			return false
		}
		seen[n] = true
	}
	return true
}
func grantObject(g storage.TransferGrant) Object {
	headers := g.Headers
	if headers == nil {
		headers = map[string]string{}
	}
	return Object{"url": g.URL, "headers": headers, "expires_at": g.ExpiresAt}
}
func (s *Service) Grants(ctx context.Context, sid, rid, bid string, p domain.Principal, numbers []int) (Object, error) {
	if !validNumbers(numbers) {
		return nil, domain.Err(422, "invalid_part_numbers")
	}
	var h storage.UploadHandle
	var attemptID string
	var now float64
	var seconds int
	sizes := make([]int64, len(numbers))
	e := s.Core.WithSpace(ctx, sid, p, false, false, func(tx *store.Tx, _ Object, m Object) error {
		r, b, e := s.attachment(ctx, tx, sid, rid, bid, m, p, true)
		if e != nil {
			return e
		}
		a, e := s.active(ctx, tx, b)
		if e != nil {
			return e
		}
		now, e = tx.Now(ctx)
		if e != nil {
			return e
		}
		if str(r["state"]) != "draft" || number(r["expires_at"]) <= now || a == nil || str(a["state"]) != "uploading" {
			return domain.Err(409, "upload_not_ready")
		}
		h, e = upload(a)
		if e != nil {
			return e
		}
		attemptID = str(a["id"])
		for i, n := range numbers {
			sizes[i], e = storage.PartSizeFor(n, integer(b["size"]), integer(b["part_size"]))
			if e != nil {
				return e
			}
		}
		seconds = int(min(s.Settings.Storage.GrantSeconds, int64(number(r["expires_at"])-now)))
		if seconds < 1 {
			seconds = 1
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	grants := make([]storage.TransferGrant, len(numbers))
	for i, n := range numbers {
		grants[i], e = s.Storage.UploadGrant(ctx, h, n, sizes[i], now+float64(seconds), seconds)
		if e != nil {
			return nil, e
		}
	}
	e = s.Core.WithSpace(ctx, sid, p, true, false, func(tx *store.Tx, _ Object, m Object) error {
		r, b, e := s.attachment(ctx, tx, sid, rid, bid, m, p, true)
		if e != nil {
			return e
		}
		a, e := tx.One(ctx, "SELECT * FROM v2_transfer_attempts WHERE id=?", attemptID)
		if e != nil {
			return e
		}
		current, e := tx.Now(ctx)
		if e != nil {
			return e
		}
		if str(r["state"]) != "draft" || number(r["expires_at"]) <= current || a == nil || str(a["state"]) != "uploading" {
			return domain.Err(409, "upload_not_ready")
		}
		if _, e = tokens(a["mutation_tokens"]); e != nil {
			return e
		}
		expiry := float64(0)
		for _, g := range grants {
			expiry = max(expiry, g.ExpiresAt)
		}
		a["grant_expires_at"] = max(number(a["grant_expires_at"]), expiry)
		b["grant_expires_at"] = max(number(b["grant_expires_at"]), expiry)
		if e = save(ctx, tx, "v2_transfer_attempts", a, "grant_expires_at"); e != nil {
			return e
		}
		return save(ctx, tx, "v2_blobs", b, "grant_expires_at")
	})
	if e != nil {
		return nil, e
	}
	values := make([]any, len(grants))
	for i, g := range grants {
		v := grantObject(g)
		v["number"] = numbers[i]
		v["size"] = sizes[i]
		values[i] = v
	}
	return Object{"grants": values}, nil
}
func (s *Service) BeginGatewayPut(ctx context.Context, p domain.Principal, sid, rid, bid string, part int) (GatewayPutHandle, Object, error) {
	var handle GatewayPutHandle
	var h storage.UploadHandle
	var size int64
	var now float64
	var seconds int
	if p.Workload == nil {
		return handle, nil, domain.Err(403, "workload_identity_required")
	}
	if part < 1 || part > 10000 {
		return handle, nil, domain.Err(422, "invalid_part_numbers")
	}
	e := s.Core.WithSpace(ctx, sid, p, true, false, func(tx *store.Tx, _ Object, m Object) error {
		r, b, e := s.attachment(ctx, tx, sid, rid, bid, m, p, true)
		if e != nil {
			return e
		}
		a, e := s.active(ctx, tx, b)
		if e != nil {
			return e
		}
		now, e = tx.Now(ctx)
		if e != nil {
			return e
		}
		if str(r["state"]) != "draft" || number(r["expires_at"]) <= now || flag(b["pending_deletion"]) || a == nil || str(a["state"]) != "uploading" {
			return domain.Err(409, "upload_not_ready")
		}
		h, e = upload(a)
		if e != nil {
			return domain.Err(409, "upload_not_ready")
		}
		suffix := strings.Join([]string{sid, str(b["id"]), str(a["id"])}, "/")
		if str(obj(a["upload_handle"])["key"]) != str(a["object_key"]) || !(str(a["object_key"]) == suffix || strings.HasSuffix(str(a["object_key"]), "/"+suffix)) {
			return domain.Err(409, "upload_not_ready")
		}
		size, e = storage.PartSizeFor(part, integer(b["size"]), integer(b["part_size"]))
		if e != nil {
			return domain.Err(422, "invalid_part_numbers")
		}
		markers, e := tokens(a["mutation_tokens"])
		if e != nil {
			return e
		}
		if len(markers) >= 100 {
			return domain.Err(409, "storage_mutation_uncertain")
		}
		handle = GatewayPutHandle{sid, rid, bid, str(a["id"]), str(a["object_key"]), h.ID, part, fmt.Sprintf("gateway-put-%d-%s", part, domain.NewID())}
		a["mutation_tokens"] = append(markers, handle.Token)
		a["updated_at"] = now
		seconds = int(min(s.Settings.Storage.GrantSeconds, int64(number(r["expires_at"])-now)))
		if seconds < 1 {
			seconds = 1
		}
		return save(ctx, tx, "v2_transfer_attempts", a, "mutation_tokens", "updated_at")
	})
	if e != nil {
		return handle, nil, e
	}
	grant, e := s.Storage.UploadGrant(ctx, h, part, size, now+float64(seconds), seconds)
	if e != nil {
		return handle, nil, e
	}
	e = s.Core.WithSpace(ctx, sid, p, true, false, func(tx *store.Tx, _ Object, m Object) error {
		r, b, e := s.attachment(ctx, tx, sid, rid, bid, m, p, true)
		if e != nil {
			return e
		}
		a, e := tx.One(ctx, "SELECT * FROM v2_transfer_attempts WHERE id=?", handle.AttemptID)
		if e != nil {
			return e
		}
		now, e := tx.Now(ctx)
		if e != nil {
			return e
		}
		if str(r["state"]) != "draft" || number(r["expires_at"]) <= now || a == nil || str(a["state"]) != "uploading" || str(a["blob_id"]) != bid || str(a["object_key"]) != handle.ObjectKey || str(obj(a["upload_handle"])["id"]) != handle.UploadID || str(obj(a["upload_handle"])["key"]) != handle.ObjectKey || !hasToken(a["mutation_tokens"], handle.Token) {
			return domain.Err(409, "upload_not_ready")
		}
		a["grant_expires_at"] = max(number(a["grant_expires_at"]), grant.ExpiresAt)
		b["grant_expires_at"] = max(number(b["grant_expires_at"]), grant.ExpiresAt)
		if e = save(ctx, tx, "v2_transfer_attempts", a, "grant_expires_at"); e != nil {
			return e
		}
		return save(ctx, tx, "v2_blobs", b, "grant_expires_at")
	})
	if e != nil {
		return handle, nil, e
	}
	result := grantObject(grant)
	result["number"] = part
	result["size"] = size
	return handle, result, nil
}
func (s *Service) FinishGatewayPut(ctx context.Context, h GatewayPutHandle) (bool, error) {
	if h.PartNumber < 1 || h.PartNumber > 10000 || !strings.HasPrefix(h.Token, fmt.Sprintf("gateway-put-%d-", h.PartNumber)) {
		return false, nil
	}
	settled := false
	e := s.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		space, e := tx.One(ctx, "SELECT * FROM v2_spaces WHERE id=?"+tx.ForUpdate(), h.SpaceID)
		if e != nil || space == nil {
			return e
		}
		b, e := tx.One(ctx, "SELECT * FROM v2_blobs WHERE id=?", h.AttachmentID)
		if e != nil {
			return e
		}
		a, e := tx.One(ctx, "SELECT * FROM v2_transfer_attempts WHERE id=?"+tx.ForUpdate(), h.AttemptID)
		if e != nil {
			return e
		}
		if b == nil || str(b["space_id"]) != h.SpaceID || str(b["record_id"]) != h.RecordID || a == nil || str(a["blob_id"]) != h.AttachmentID || str(a["object_key"]) != h.ObjectKey || str(obj(a["upload_handle"])["id"]) != h.UploadID || str(obj(a["upload_handle"])["key"]) != h.ObjectKey {
			return nil
		}
		if _, e := tokens(a["mutation_tokens"]); e != nil {
			return e
		}
		if !hasToken(a["mutation_tokens"], h.Token) {
			return nil
		}
		now, e := tx.Now(ctx)
		if e != nil {
			return e
		}
		a["mutation_tokens"] = removeToken(a["mutation_tokens"], h.Token)
		a["updated_at"] = now
		if e = save(ctx, tx, "v2_transfer_attempts", a, "mutation_tokens", "updated_at"); e != nil {
			return e
		}
		if e = s.rearmCleanup(ctx, tx, space, b, a); e != nil {
			return e
		}
		settled = true
		return nil
	})
	return settled, e
}
func (s *Service) Complete(ctx context.Context, sid, rid, bid string, p domain.Principal) (Object, error) {
	var attempt, result Object
	e := s.Core.WithSpace(ctx, sid, p, true, false, func(tx *store.Tx, _ Object, m Object) error {
		r, b, e := s.attachment(ctx, tx, sid, rid, bid, m, p, true)
		if e != nil {
			return e
		}
		if str(r["state"]) != "draft" {
			return domain.Err(409, "record_not_draft")
		}
		a, e := s.active(ctx, tx, b)
		if e != nil {
			return e
		}
		if a == nil || str(a["state"]) != "uploading" {
			result = view(b, a)
			return nil
		}
		now, e := tx.Now(ctx)
		if e != nil {
			return e
		}
		if number(r["expires_at"]) <= now {
			return domain.Err(409, "draft_expired")
		}
		markers, e := tokens(a["mutation_tokens"])
		if e != nil {
			return e
		}
		if len(markers) > 0 {
			return domain.Err(409, "storage_mutation_uncertain")
		}
		token := domain.NewID()
		a["state"] = "completing"
		a["token"] = token
		a["lease_until"] = now + float64(s.Settings.Worker.LeaseSeconds)
		a["mutation_tokens"] = append(markers, token)
		a["updated_at"] = now
		a["next_attempt"] = now
		b["state"] = "completing"
		if e = save(ctx, tx, "v2_blobs", b, "state"); e != nil {
			return e
		}
		if e = save(ctx, tx, "v2_transfer_attempts", a, "state", "token", "lease_until", "mutation_tokens", "updated_at", "next_attempt"); e != nil {
			return e
		}
		attempt = a
		return nil
	})
	if e != nil || result != nil {
		return result, e
	}
	outcome, e := s.execute(ctx, attempt)
	if e != nil {
		return nil, e
	}
	if outcome == "invalid_parts" {
		return nil, domain.Err(409, "invalid_parts")
	}
	e = s.Core.WithSpace(ctx, sid, p, false, false, func(tx *store.Tx, _ Object, m Object) error {
		_, b, e := s.attachment(ctx, tx, sid, rid, bid, m, p, false)
		if e != nil {
			return e
		}
		a, e := s.active(ctx, tx, b)
		if e != nil {
			return e
		}
		result = view(b, a)
		return nil
	})
	return result, e
}
func (s *Service) Download(ctx context.Context, sid, rid, bid string, p domain.Principal) (Object, error) {
	var stored storage.StoredObject
	var now float64
	var size int64
	var digest string
	e := s.Core.WithSpace(ctx, sid, p, false, false, func(tx *store.Tx, _ Object, m Object) error {
		r, b, e := s.attachment(ctx, tx, sid, rid, bid, m, p, false)
		if e != nil {
			return e
		}
		if str(r["state"]) != "published" || str(b["state"]) != "verified" {
			return domain.Err(409, "attachment_not_available")
		}
		if _, e := s.active(ctx, tx, b); e != nil {
			return e
		}
		stored = storage.StoredObject{Key: str(b["object_key"]), Version: str(b["object_version"])}
		size = integer(b["verified_size"])
		digest = str(b["verified_sha256"])
		now, e = tx.Now(ctx)
		return e
	})
	if e != nil {
		return nil, e
	}
	seconds := int(s.Settings.Storage.GrantSeconds)
	grant, e := s.Storage.DownloadGrant(ctx, stored, now+float64(seconds), seconds)
	if e != nil {
		return nil, e
	}
	e = s.Core.WithSpace(ctx, sid, p, true, false, func(tx *store.Tx, _ Object, m Object) error {
		r, b, e := s.attachment(ctx, tx, sid, rid, bid, m, p, false)
		if e != nil {
			return e
		}
		if str(r["state"]) != "published" || str(b["state"]) != "verified" {
			return domain.Err(409, "attachment_not_available")
		}
		b["grant_expires_at"] = max(number(b["grant_expires_at"]), grant.ExpiresAt)
		if e = save(ctx, tx, "v2_blobs", b, "grant_expires_at"); e != nil {
			return e
		}
		a, e := s.active(ctx, tx, b)
		if e != nil {
			return e
		}
		if a != nil {
			a["grant_expires_at"] = max(number(a["grant_expires_at"]), grant.ExpiresAt)
			return save(ctx, tx, "v2_transfer_attempts", a, "grant_expires_at")
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	result := grantObject(grant)
	result["size"] = size
	result["sha256"] = digest
	return result, nil
}

// locked loads a transfer under its owning space's lifecycle lock.
func (s *Service) locked(ctx context.Context, tx *store.Tx, id string) (Object, Object, Object, Object, error) {
	a, e := tx.One(ctx, "SELECT * FROM v2_transfer_attempts WHERE id=?", id)
	if e != nil || a == nil {
		return nil, nil, nil, nil, e
	}
	b, e := tx.One(ctx, "SELECT * FROM v2_blobs WHERE id=?", a["blob_id"])
	if e != nil || b == nil {
		return nil, nil, nil, nil, e
	}
	space, e := tx.One(ctx, "SELECT * FROM v2_spaces WHERE id=?"+tx.ForUpdate(), b["space_id"])
	if e != nil || space == nil {
		return nil, nil, nil, nil, e
	}
	a, e = tx.One(ctx, "SELECT * FROM v2_transfer_attempts WHERE id=?"+tx.ForUpdate(), id)
	if e != nil || a == nil {
		return nil, nil, nil, nil, e
	}
	b, e = tx.One(ctx, "SELECT * FROM v2_blobs WHERE id=?", a["blob_id"])
	if e != nil || b == nil {
		return nil, nil, nil, nil, e
	}
	r, e := tx.One(ctx, "SELECT * FROM v2_records WHERE id=?", b["record_id"])
	return space, b, a, r, e
}
func (s *Service) Acquire(ctx context.Context, id string, cleanup *bool) (Object, error) {
	var result Object
	quarantined := false
	e := s.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		space, b, a, r, e := s.locked(ctx, tx, id)
		_ = space
		if e != nil || a == nil || r == nil {
			return e
		}
		now, e := tx.Now(ctx)
		if e != nil {
			return e
		}
		if cleanup != nil && (str(a["state"]) == "cleanup") != *cleanup {
			return nil
		}
		if number(a["next_attempt"]) > now || number(a["lease_until"]) > now {
			return nil
		}
		markers, e := tokens(a["mutation_tokens"])
		if e != nil {
			// Unsupported ownership cannot prove quiescence. Defer only its
			// scheduling metadata so this row cannot monopolize every batch;
			// preserve its exact state, ledger, token, lease and byte charges.
			a["last_error"] = "storage_mutation_uncertain"
			a["next_attempt"] = now + float64(s.Settings.Worker.RecoverAfter)
			if e = save(ctx, tx, "v2_transfer_attempts", a, "last_error", "next_attempt"); e != nil {
				return e
			}
			quarantined = true
			return nil
		}
		if str(a["state"]) == "cleanup" && len(markers) > 0 {
			a["last_error"] = "storage_mutation_uncertain"
			a["next_attempt"] = now + float64(s.Settings.Worker.RecoverAfter)
			return save(ctx, tx, "v2_transfer_attempts", a, "last_error", "next_attempt")
		}
		if str(a["state"]) == "cleanup" && number(a["grant_expires_at"]) > now {
			return nil
		}
		switch str(a["state"]) {
		case "initiating":
			a["state"] = "cleanup"
			a["operation"] = "cleanup"
			a["next_attempt"] = now
			a["updated_at"] = now
			a["token"] = nil
			a["lease_until"] = nil
			if e = save(ctx, tx, "v2_transfer_attempts", a, "state", "operation", "next_attempt", "updated_at", "token", "lease_until"); e != nil {
				return e
			}
			if str(r["state"]) != "draft" {
				return nil
			}
			if len(markers) > 0 {
				b["state"] = "reserved"
				a["last_error"] = "storage_mutation_uncertain"
				if e = save(ctx, tx, "v2_blobs", b, "state"); e != nil {
					return e
				}
				return save(ctx, tx, "v2_transfer_attempts", a, "last_error")
			}
			previous := a
			a, e = s.newAttempt(ctx, tx, b, now)
			if e != nil {
				return e
			}
			for _, key := range []string{"retry_count", "last_error", "created_at", "updated_at"} {
				a[key] = previous[key]
			}
			if e = save(ctx, tx, "v2_transfer_attempts", a, "retry_count", "last_error", "created_at", "updated_at"); e != nil {
				return e
			}
		case "completing", "verifying", "cleanup":
			if str(a["state"]) == "completing" && len(markers) > 0 {
				a["last_error"] = "storage_mutation_uncertain"
				a["next_attempt"] = now + float64(s.Settings.Worker.RecoverAfter)
				return save(ctx, tx, "v2_transfer_attempts", a, "last_error", "next_attempt")
			}
			token := domain.NewID()
			a["token"] = token
			a["lease_until"] = now + float64(s.Settings.Worker.LeaseSeconds)
			if str(a["state"]) == "completing" {
				a["mutation_tokens"] = append(markers, token)
			}
			if e = save(ctx, tx, "v2_transfer_attempts", a, "token", "lease_until", "mutation_tokens"); e != nil {
				return e
			}
		default:
			return nil
		}
		result = a
		return nil
	})
	if e == nil && quarantined {
		// Returning the public uncertainty after commit keeps the bounded
		// backoff durable; returning it inside the transaction would undo it.
		return nil, domain.Err(409, "storage_mutation_uncertain")
	}
	return result, e
}
func owned(current, attempt Object, now float64) bool {
	return current != nil && str(current["token"]) != "" && str(current["token"]) == str(attempt["token"]) && number(current["lease_until"]) > now
}
func (s *Service) ReleaseLease(ctx context.Context, attempt Object) error {
	_, e := s.DB.Exec(ctx, "UPDATE v2_transfer_attempts SET token=NULL,lease_until=NULL WHERE id=? AND token=?", attempt["id"], attempt["token"])
	return e
}

// heartbeatEvery uses bounded integer arithmetic: configuration permits any
// positive int64 seconds, which can exceed time.Duration's representation.
func heartbeatEvery(seconds int64) time.Duration {
	const longest = time.Duration(1<<63 - 1)
	if seconds <= 0 {
		return 20 * time.Millisecond
	}
	whole, remainder := seconds/3, seconds%3
	if whole > int64(longest/time.Second) {
		return longest
	}
	interval := time.Duration(whole) * time.Second
	fraction := time.Duration(remainder) * time.Second / 3
	if interval > longest-fraction {
		return longest
	}
	interval += fraction
	if interval < 20*time.Millisecond {
		return 20 * time.Millisecond
	}
	return interval
}

func (s *Service) heartbeat(ctx context.Context, attempt Object) func() {
	stop := make(chan struct{})
	done := make(chan struct{})
	var once sync.Once
	interval := heartbeatEvery(s.Settings.Worker.LeaseSeconds)
	go func() {
		defer close(done)
		timer := time.NewTicker(interval)
		defer timer.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ctx.Done():
				return
			case <-timer.C:
				e := s.DB.WithTx(ctx, true, func(tx *store.Tx) error {
					now, e := tx.Now(ctx)
					if e != nil {
						return e
					}
					r, e := tx.Exec(ctx, "UPDATE v2_transfer_attempts SET lease_until=? WHERE id=? AND token=? AND lease_until>?", now+float64(s.Settings.Worker.LeaseSeconds), attempt["id"], attempt["token"], now)
					if e != nil {
						return e
					}
					n, e := r.RowsAffected()
					if e != nil {
						return e
					}
					if n != 1 {
						return errors.New("lease_lost")
					}
					return nil
				})
				if e != nil {
					return
				}
			}
		}
	}()
	return func() { once.Do(func() { close(stop) }); <-done }
}
func (s *Service) Commit(ctx context.Context, attempt Object, state string, result any) (bool, error) {
	committed := false
	e := s.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		space, b, a, r, e := s.locked(ctx, tx, str(attempt["id"]))
		if e != nil || a == nil || r == nil {
			return e
		}
		now, e := tx.Now(ctx)
		if e != nil {
			return e
		}
		if !owned(a, attempt, now) || a["state"] != attempt["state"] {
			return nil
		}
		markers, e := tokens(a["mutation_tokens"])
		if e != nil {
			return e
		}
		if state != "cleaned" && str(r["state"]) != "draft" {
			return nil
		}
		if state == "cleaned" && len(markers) > 0 {
			a["last_error"] = "storage_mutation_uncertain"
			a["retry_count"] = integer(a["retry_count"]) + 1
			a["next_attempt"] = now + backoff(integer(a["retry_count"]))
			a["token"] = nil
			a["lease_until"] = nil
			return save(ctx, tx, "v2_transfer_attempts", a, "last_error", "retry_count", "next_attempt", "token", "lease_until")
		}
		if (str(attempt["state"]) == "initiating" || str(attempt["state"]) == "completing") && (state == "uploading" || state == "verifying") {
			a["mutation_tokens"] = removeToken(a["mutation_tokens"], str(attempt["token"]))
		}
		a["state"] = state
		a["updated_at"] = now
		a["token"] = nil
		a["lease_until"] = nil
		a["retry_count"] = int64(0)
		a["last_error"] = nil
		a["next_attempt"] = now
		switch state {
		case "uploading":
			if result != nil {
				h, ok := result.(storage.UploadHandle)
				if !ok {
					return domain.Err(503, "internal_transfer_error")
				}
				a["upload_handle"] = Object{"id": h.ID, "key": h.Key}
			}
		case "verifying":
			stored, ok := result.(storage.StoredObject)
			if !ok {
				return domain.Err(503, "internal_transfer_error")
			}
			h := domain.CloneMap(obj(a["upload_handle"]))
			h["version"] = stored.Version
			a["upload_handle"] = h
			r["expires_at"] = max(number(r["expires_at"]), now+float64(s.Settings.Worker.FailureSeconds))
			if e = save(ctx, tx, "v2_records", r, "expires_at"); e != nil {
				return e
			}
		case "verified":
			v, ok := result.(storage.Verification)
			if !ok {
				return domain.Err(503, "internal_transfer_error")
			}
			b["object_key"] = a["object_key"]
			b["object_version"] = obj(a["upload_handle"])["version"]
			b["verified_size"] = v.Size
			b["verified_sha256"] = v.SHA256
			if e = save(ctx, tx, "v2_blobs", b, "object_key", "object_version", "verified_size", "verified_sha256"); e != nil {
				return e
			}
		case "failed":
			a["last_error"] = str(result)
			if a["last_error"] == "" {
				a["last_error"] = "transfer_failed"
			}
		case "cleaned":
			a["upload_handle"] = Object{}
		}
		if e = save(ctx, tx, "v2_transfer_attempts", a, "state", "updated_at", "token", "lease_until", "retry_count", "last_error", "next_attempt", "mutation_tokens", "upload_handle"); e != nil {
			return e
		}
		if state == "failed" {
			if e = s.Core.ReleaseRecord(ctx, tx, space, r, "failed"); e != nil {
				return e
			}
		}
		worker := domain.Principal{ID: "worker", Subject: "worker"}
		if state == "cleaned" {
			history, e := tx.All(ctx, "SELECT id,state,mutation_tokens FROM v2_transfer_attempts WHERE blob_id=? ORDER BY id"+tx.ForUpdate(), b["id"])
			if e != nil {
				return e
			}
			allClean := true
			for _, item := range history {
				markers, valid := domain.MutationTokens(item["mutation_tokens"])
				if str(item["state"]) != "cleaned" || !valid || len(markers) != 0 {
					allClean = false
				}
			}
			// A clean current key is only one part of physical absence. Even a
			// historical cleaned label cannot hide uncertain ownership elsewhere
			// in this attachment's retained attempt history.
			if allClean && flag(b["pending_deletion"]) {
				space["reclaiming"] = integer(space["reclaiming"]) - integer(b["size"])
				b["pending_deletion"] = false
				b["state"] = "cleaned"
				if e = save(ctx, tx, "v2_spaces", space, "reclaiming"); e != nil {
					return e
				}
				if e = save(ctx, tx, "v2_blobs", b, "pending_deletion", "state"); e != nil {
					return e
				}
			}
			if e = s.Core.Emit(ctx, tx, str(space["id"]), "attachment.cleaned", worker, b["record_id"], Object{"attachment_id": b["id"]}); e != nil {
				return e
			}
			committed = true
			return nil
		}
		if state != "failed" {
			b["state"] = state
			if e = save(ctx, tx, "v2_blobs", b, "state"); e != nil {
				return e
			}
		}
		if e = s.Core.Emit(ctx, tx, str(space["id"]), "attachment."+state, worker, b["record_id"], Object{"attachment_id": b["id"]}); e != nil {
			return e
		}
		committed = true
		return nil
	})
	return committed, e
}
func (s *Service) retry(ctx context.Context, attempt Object, failure *storage.StorageFailure) error {
	return s.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		_, _, a, _, e := s.locked(ctx, tx, str(attempt["id"]))
		if e != nil || a == nil {
			return e
		}
		now, e := tx.Now(ctx)
		if e != nil {
			return e
		}
		if !owned(a, attempt, now) || a["state"] != attempt["state"] {
			return nil
		}
		a["retry_count"] = integer(a["retry_count"]) + 1
		a["last_error"] = failure.Code
		a["next_attempt"] = now + backoff(integer(a["retry_count"]))
		a["token"] = nil
		a["lease_until"] = nil
		return save(ctx, tx, "v2_transfer_attempts", a, "retry_count", "last_error", "next_attempt", "token", "lease_until")
	})
}
func (s *Service) execute(ctx context.Context, attempt Object) (outcome string, err error) {
	if attempt == nil {
		return "skipped", nil
	}
	resolved := true
	stop := s.heartbeat(ctx, attempt)
	defer func() {
		if recover() != nil {
			resolved = false
			outcome = "retry"
			err = domain.Err(503, "internal_transfer_error")
		}
		stop()
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if str(attempt["state"]) == "initiating" || str(attempt["state"]) == "completing" {
			if resolved {
				if e := s.settleMutation(cleanupCtx, attempt); e != nil && err == nil {
					err = e
				}
			}
			if e := s.abandon(cleanupCtx, attempt); e != nil && err == nil {
				err = e
			}
		}
		if e := s.ReleaseLease(cleanupCtx, attempt); e != nil && err == nil {
			err = e
		}
	}()
	b, e := s.DB.One(ctx, "SELECT * FROM v2_blobs WHERE id=?", attempt["blob_id"])
	if e != nil {
		return "retry", e
	}
	if b == nil {
		return "skipped", nil
	}
	current, e := s.DB.One(ctx, "SELECT mutation_tokens FROM v2_transfer_attempts WHERE id=?", attempt["id"])
	if e != nil {
		return "retry", e
	}
	if current == nil {
		return "skipped", nil
	}
	if _, e = tokens(current["mutation_tokens"]); e != nil {
		return "retry", e
	}
	now, e := s.DB.Now(ctx)
	if e != nil {
		return "retry", e
	}
	if str(attempt["state"]) != "cleanup" && now-number(attempt["updated_at"]) > float64(s.Settings.Worker.FailureSeconds) {
		ok, e := s.Commit(ctx, attempt, "failed", "transfer_deadline_exceeded")
		if e != nil {
			return "retry", e
		}
		if ok {
			return "failed", nil
		}
		return "skipped", nil
	}
	state := ""
	var result any
	outcome = "skipped"
	switch str(attempt["state"]) {
	case "cleanup":
		allowed := false
		e = s.DB.WithTx(ctx, true, func(tx *store.Tx) error {
			_, _, a, _, e := s.locked(ctx, tx, str(attempt["id"]))
			if e != nil || a == nil {
				return e
			}
			n, e := tx.Now(ctx)
			if e != nil {
				return e
			}
			markers, e := tokens(a["mutation_tokens"])
			if e != nil {
				return e
			}
			allowed = str(a["state"]) == "cleanup" && len(markers) == 0 && owned(a, attempt, n)
			return nil
		})
		if e != nil {
			return "retry", e
		}
		if !allowed {
			return "skipped", nil
		}
		e = s.Storage.Cleanup(ctx, str(attempt["object_key"]))
		state = "cleaned"
		outcome = "cleaned"
	case "initiating":
		result, e = s.Storage.Start(ctx, str(attempt["object_key"]))
		state = "uploading"
		outcome = "recovered"
	case "completing":
		var h storage.UploadHandle
		h, e = upload(attempt)
		if e == nil {
			result, e = s.Storage.Complete(ctx, h, integer(b["size"]), integer(b["part_size"]))
		}
		state = "verifying"
		outcome = "recovered"
	case "verifying":
		result, e = s.Storage.Verify(ctx, storage.StoredObject{Key: str(attempt["object_key"]), Version: str(obj(attempt["upload_handle"])["version"])}, integer(b["size"]), str(b["sha256"]))
		state = "verified"
		outcome = "verified"
	default:
		return "skipped", nil
	}
	if e != nil {
		var failure *storage.StorageFailure
		if !errors.As(e, &failure) {
			failure = storage.Failure("internal_transfer_error", true, true)
		}
		resolved = !failure.Uncertain
		if failure.Code == "invalid_parts" && str(attempt["state"]) == "completing" {
			ok, e := s.Commit(ctx, attempt, "uploading", nil)
			if e != nil {
				return "retry", e
			}
			if ok {
				return "invalid_parts", nil
			}
			return "skipped", nil
		}
		if failure.Retryable || str(attempt["state"]) == "cleanup" {
			if e = s.retry(ctx, attempt, failure); e != nil {
				return "retry", e
			}
			return "retry", nil
		}
		ok, e := s.Commit(ctx, attempt, "failed", failure.Code)
		if e != nil {
			return "retry", e
		}
		if ok {
			return "failed", nil
		}
		return "skipped", nil
	}
	ok, e := s.Commit(ctx, attempt, state, result)
	if e != nil {
		return "retry", e
	}
	if ok {
		return outcome, nil
	}
	if str(attempt["state"]) == "initiating" || str(attempt["state"]) == "completing" {
		if e = s.abandon(ctx, attempt); e != nil {
			return "retry", e
		}
	}
	return "skipped", nil
}
func (s *Service) rearmCleanup(ctx context.Context, tx *store.Tx, space, b, a Object) error {
	if _, e := tokens(a["mutation_tokens"]); e != nil {
		return e
	}
	if state := str(a["state"]); state != "cleanup" && state != "cleaned" {
		return nil
	}
	r, e := tx.One(ctx, "SELECT * FROM v2_records WHERE id=?", b["record_id"])
	if e != nil || r == nil {
		return e
	}
	now, e := tx.Now(ctx)
	if e != nil {
		return e
	}
	a["state"] = "cleanup"
	a["operation"] = "cleanup"
	a["next_attempt"] = max(now, number(a["grant_expires_at"]))
	a["token"] = nil
	a["lease_until"] = nil
	if e = save(ctx, tx, "v2_transfer_attempts", a, "state", "operation", "next_attempt", "token", "lease_until"); e != nil {
		return e
	}
	if terminal(str(r["state"])) && !flag(b["pending_deletion"]) {
		b["pending_deletion"] = true
		b["state"] = "cleanup"
		space["reclaiming"] = integer(space["reclaiming"]) + integer(b["size"])
		if e = save(ctx, tx, "v2_blobs", b, "pending_deletion", "state"); e != nil {
			return e
		}
		return save(ctx, tx, "v2_spaces", space, "reclaiming")
	}
	return nil
}
func (s *Service) settleMutation(ctx context.Context, attempt Object) error {
	return s.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		space, b, a, _, e := s.locked(ctx, tx, str(attempt["id"]))
		if e != nil || a == nil {
			return e
		}
		if str(a["object_key"]) != str(attempt["object_key"]) {
			return nil
		}
		if _, e := tokens(a["mutation_tokens"]); e != nil {
			return e
		}
		if hasToken(a["mutation_tokens"], str(attempt["token"])) {
			a["mutation_tokens"] = removeToken(a["mutation_tokens"], str(attempt["token"]))
			if e = save(ctx, tx, "v2_transfer_attempts", a, "mutation_tokens"); e != nil {
				return e
			}
			return s.rearmCleanup(ctx, tx, space, b, a)
		}
		return nil
	})
}
func (s *Service) abandon(ctx context.Context, attempt Object) error {
	return s.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		space, b, a, _, e := s.locked(ctx, tx, str(attempt["id"]))
		if e != nil || a == nil {
			return e
		}
		if _, e := tokens(a["mutation_tokens"]); e != nil {
			return e
		}
		// A settled call already fenced earlier cleanup atomically. Once its
		// marker is gone, this snapshot has no authority to clear a successor's
		// cleanup lease. Unknown calls retain their exact marker and may rearm.
		if str(a["object_key"]) != str(attempt["object_key"]) || !hasToken(a["mutation_tokens"], str(attempt["token"])) {
			return nil
		}
		return s.rearmCleanup(ctx, tx, space, b, a)
	})
}
func (s *Service) Process(ctx context.Context, id string, cleanup bool) (string, error) {
	attempt, e := s.Acquire(ctx, id, &cleanup)
	if e != nil {
		return "retry", e
	}
	if attempt == nil {
		return "skipped", nil
	}
	return s.execute(ctx, attempt)
}
func (s *Service) Work(ctx context.Context, batch int) ([]string, []string, error) {
	var verify, cleanup []string
	e := s.DB.WithTx(ctx, false, func(tx *store.Tx) error {
		now, e := tx.Now(ctx)
		if e != nil {
			return e
		}
		rows, e := tx.All(ctx, "SELECT id FROM v2_transfer_attempts WHERE (lease_until IS NULL OR lease_until<=?) AND next_attempt<=? AND state IN ('initiating','completing','verifying') ORDER BY next_attempt,id LIMIT ?", now, now, batch)
		if e != nil {
			return e
		}
		for _, r := range rows {
			verify = append(verify, str(r["id"]))
		}
		rows, e = tx.All(ctx, "SELECT id FROM v2_transfer_attempts WHERE (lease_until IS NULL OR lease_until<=?) AND next_attempt<=? AND state='cleanup' AND grant_expires_at<=? ORDER BY next_attempt,id LIMIT ?", now, now, now, batch)
		if e != nil {
			return e
		}
		for _, r := range rows {
			cleanup = append(cleanup, str(r["id"]))
		}
		return nil
	})
	return verify, cleanup, e
}
func (s *Service) Expire(ctx context.Context, batch int) (int, error) {
	now, e := s.DB.Now(ctx)
	if e != nil {
		return 0, e
	}
	rows, e := s.DB.All(ctx, "SELECT id FROM v2_records WHERE state='draft' AND expires_at<=? ORDER BY expires_at LIMIT ?", now, batch)
	if e != nil {
		return 0, e
	}
	count := 0
	for _, row := range rows {
		e = s.DB.WithTx(ctx, true, func(tx *store.Tx) error {
			r, e := tx.One(ctx, "SELECT * FROM v2_records WHERE id=?", row["id"])
			if e != nil || r == nil {
				return e
			}
			space, e := tx.One(ctx, "SELECT * FROM v2_spaces WHERE id=?"+tx.ForUpdate(), r["space_id"])
			if e != nil || space == nil {
				return e
			}
			r, e = tx.One(ctx, "SELECT * FROM v2_records WHERE id=?", row["id"])
			if e != nil || r == nil {
				return e
			}
			now, e := tx.Now(ctx)
			if e != nil {
				return e
			}
			if str(r["state"]) == "draft" && number(r["expires_at"]) <= now {
				if e = s.Core.ReleaseRecord(ctx, tx, space, r, "expired"); e != nil {
					return e
				}
				count++
			}
			return nil
		})
		if e != nil {
			return count, e
		}
	}
	return count, nil
}
