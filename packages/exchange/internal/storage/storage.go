// Package storage provides version-bound opaque blob transfers.
package storage

import (
	"context"
	"errors"
	"math"
)

const MultipartProtocol = "s3-multipart-v1"

type UploadHandle struct {
	ID  string `json:"id"`
	Key string `json:"key"`
}
type UploadedPart struct {
	Number int    `json:"number"`
	ETag   string `json:"etag"`
	Size   int64  `json:"size"`
}
type StoredObject struct {
	Key     string `json:"key"`
	Version string `json:"version"`
}
type Verification struct {
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}
type TransferGrant struct {
	URL       string            `json:"url"`
	Headers   map[string]string `json:"headers"`
	ExpiresAt float64           `json:"expires_at"`
}

// StorageFailure never exposes provider endpoints, credentials or raw errors.
type StorageFailure struct {
	Code      string
	Retryable bool
	Uncertain bool
}

func (e *StorageFailure) Error() string { return e.Code }
func Failure(code string, retryable, uncertain bool) *StorageFailure {
	return &StorageFailure{Code: code, Retryable: retryable, Uncertain: uncertain}
}
func AsFailure(err error) *StorageFailure {
	var failure *StorageFailure
	if errors.As(err, &failure) {
		return failure
	}
	return Failure("storage_unavailable", true, true)
}

type BlobStore interface {
	Protocol() string
	Check(context.Context) error
	Start(context.Context, string) (UploadHandle, error)
	Parts(context.Context, UploadHandle) ([]UploadedPart, error)
	UploadGrant(context.Context, UploadHandle, int, int64, float64, int) (TransferGrant, error)
	Complete(context.Context, UploadHandle, int64, int64) (StoredObject, error)
	Verify(context.Context, StoredObject, int64, string) (Verification, error)
	DownloadGrant(context.Context, StoredObject, float64, int) (TransferGrant, error)
	Cleanup(context.Context, string) error
}
type Store = BlobStore

func PartSizeFor(number int, size, partSize int64) (int64, error) {
	if size < 0 || partSize <= 0 || number < 1 {
		return 0, Failure("invalid_part_number", false, false)
	}
	count := int64(1)
	if size > 0 {
		count = 1 + (size-1)/partSize
	}
	if int64(number) > count {
		return 0, Failure("invalid_part_number", false, false)
	}
	offset := int64(number - 1)
	if offset > math.MaxInt64/partSize {
		return 0, Failure("invalid_part_number", false, false)
	}
	left := size - offset*partSize
	if left < partSize {
		return left, nil
	}
	return partSize, nil
}
