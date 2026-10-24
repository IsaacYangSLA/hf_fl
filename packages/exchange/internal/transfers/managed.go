package transfers

import (
	"context"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/storage"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/store"
)

const ManagedProtocol = "hf2l-managed-v1"

// ManagedService exposes structured operations, never origin storage grants.
type ManagedService struct{ *Service }

func NewManaged(raw *Service) *ManagedService { return &ManagedService{raw} }
func operation(sid, rid, bid, method string, part *int) Object {
	op := Object{"space_id": sid, "record_id": rid, "attachment_id": bid, "method": method}
	if part != nil {
		op["part_number"] = *part
	}
	return Object{"protocol": ManagedProtocol, "operation": op, "headers": Object{}}
}
func (s *ManagedService) Initiate(ctx context.Context, sid, rid, bid string, p domain.Principal) (Object, error) {
	r, e := s.Service.Initiate(ctx, sid, rid, bid, p)
	if e != nil {
		return nil, e
	}
	managed, e := s.Core.IsManagedSpace(ctx, sid)
	if e != nil {
		return nil, e
	}
	if managed {
		r["protocol"] = ManagedProtocol
	}
	return r, nil
}
func (s *ManagedService) Complete(ctx context.Context, sid, rid, bid string, p domain.Principal) (Object, error) {
	r, e := s.Service.Complete(ctx, sid, rid, bid, p)
	if e != nil {
		return nil, e
	}
	managed, e := s.Core.IsManagedSpace(ctx, sid)
	if e != nil {
		return nil, e
	}
	if managed {
		r["protocol"] = ManagedProtocol
	}
	return r, nil
}
func (s *ManagedService) Grants(ctx context.Context, sid, rid, bid string, p domain.Principal, numbers []int) (Object, error) {
	managed, e := s.Core.IsManagedSpace(ctx, sid)
	if e != nil {
		return nil, e
	}
	if !managed {
		return s.Service.Grants(ctx, sid, rid, bid, p, numbers)
	}
	if !validNumbers(numbers) {
		return nil, domain.Err(422, "invalid_part_numbers")
	}
	values := make([]any, len(numbers))
	e = s.Core.WithSpace(ctx, sid, p, false, false, func(tx *store.Tx, _ Object, m Object) error {
		r, b, e := s.attachment(ctx, tx, sid, rid, bid, m, p, true)
		if e != nil {
			return e
		}
		a, e := s.active(ctx, tx, b)
		if e != nil {
			return e
		}
		now, e := tx.Now(ctx)
		if e != nil {
			return e
		}
		if str(r["state"]) != "draft" || number(r["expires_at"]) <= now || a == nil || str(a["state"]) != "uploading" {
			return domain.Err(409, "upload_not_ready")
		}
		for i, n := range numbers {
			size, e := storage.PartSizeFor(n, integer(b["size"]), integer(b["part_size"]))
			if e != nil {
				return domain.Err(422, "invalid_part_numbers")
			}
			v := operation(sid, rid, bid, "PUT", &n)
			v["number"] = n
			v["size"] = size
			values[i] = v
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	return Object{"grants": values}, nil
}
func (s *ManagedService) Download(ctx context.Context, sid, rid, bid string, p domain.Principal) (Object, error) {
	managed, e := s.Core.IsManagedSpace(ctx, sid)
	if e != nil {
		return nil, e
	}
	if !managed {
		return s.Service.Download(ctx, sid, rid, bid, p)
	}
	var result Object
	e = s.Core.WithSpace(ctx, sid, p, false, false, func(tx *store.Tx, _ Object, m Object) error {
		r, b, e := s.attachment(ctx, tx, sid, rid, bid, m, p, false)
		if e != nil {
			return e
		}
		if str(r["state"]) != "published" || str(b["state"]) != "verified" {
			return domain.Err(409, "attachment_not_available")
		}
		result = operation(sid, rid, bid, "GET", nil)
		result["size"] = b["verified_size"]
		result["sha256"] = b["verified_sha256"]
		return nil
	})
	return result, e
}
