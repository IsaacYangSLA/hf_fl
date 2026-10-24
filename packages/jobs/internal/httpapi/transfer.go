package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
)

// streamVerified withholds the last bounded chunk until the reader confirms
// EOF and final integrity. A backend's final hash error must never look like a
// complete successful Content-Length response to the caller.
func streamVerified(w http.ResponseWriter, reader io.Reader, size int64, expectedSHA string, authorize func() error) (started bool, err error) {
	buffer := make([]byte, 65536)
	digest := sha256.New()
	remaining := size
	for remaining > 0 {
		available := min(int64(len(buffer)), remaining)
		n, readErr := reader.Read(buffer[:available])
		if n < 0 || int64(n) > available {
			return started, errors.New("invalid transfer reader")
		}
		if n == 0 {
			if readErr == nil {
				readErr = io.ErrNoProgress
			}
			return started, readErr
		}
		if readErr != nil && readErr != io.EOF {
			return started, readErr
		}
		digest.Write(buffer[:n])
		if int64(n) == remaining {
			var extra [1]byte
			count, finalErr := reader.Read(extra[:])
			if count != 0 || finalErr != io.EOF {
				if finalErr == nil {
					finalErr = errors.New("transfer exceeds declared size")
				}
				return started, finalErr
			}
			if expectedSHA != "" && hex.EncodeToString(digest.Sum(nil)) != expectedSHA {
				return started, errors.New("transfer digest mismatch")
			}
			if err = authorize(); err != nil {
				return started, err
			}
			started = true
			_, err = w.Write(buffer[:n])
			return started, err
		}
		if readErr == io.EOF {
			return started, io.ErrUnexpectedEOF
		}
		if err = authorize(); err != nil {
			return started, err
		}
		started = true
		if _, err = w.Write(buffer[:n]); err != nil {
			return started, err
		}
		remaining -= int64(n)
	}
	var extra [1]byte
	count, finalErr := reader.Read(extra[:])
	if count != 0 || finalErr != io.EOF {
		if finalErr == nil {
			finalErr = errors.New("transfer exceeds declared size")
		}
		return started, finalErr
	}
	if expectedSHA != "" && hex.EncodeToString(digest.Sum(nil)) != expectedSHA {
		return started, errors.New("transfer digest mismatch")
	}
	if err = authorize(); err != nil {
		return started, err
	}
	w.WriteHeader(http.StatusOK)
	return true, nil
}
func transferFailure(w http.ResponseWriter, started bool, err error, code string) error {
	if err == nil || started {
		return nil
	}
	w.Header().Del("Content-Length")
	w.Header().Del("Content-Disposition")
	w.Header().Del("X-Content-SHA256")
	var d *domain.Error
	if errors.As(err, &d) {
		return d
	}
	return domain.Err(http.StatusBadGateway, code)
}
