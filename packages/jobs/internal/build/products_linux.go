//go:build linux

package build

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/source"
)

// StageProducts requires caller-side retention reservation before any write.
// It publishes a new read-only directory atomically, or verifies an identical replay.
func StageProducts(destination string, products Products) (int64, error) {
	if !filepath.IsAbs(destination) || filepath.Clean(destination) != destination || destination == "/" || len(products.Manifest) == 0 || len(products.Manifest) > 1024 || len(products.Manifest) != len(products.Payloads) {
		return 0, failure("invalid_build_products")
	}
	var total int64
	for name, d := range products.Manifest {
		if !wheelPattern.MatchString(name) || len(name) > 255 || d.SizeBytes < 1 || d.SizeBytes > MaxBuildBytes-total || !sha256Pattern.MatchString(d.SHA256) {
			return 0, failure("invalid_build_products")
		}
		body, ok := products.Payloads[name]
		if !ok {
			return 0, failure("invalid_build_products")
		}
		if e := verifyBytes(body, d); e != nil {
			return 0, e
		}
		total += d.SizeBytes
	}
	if total != products.LogicalBytes {
		return 0, failure("build_product_size_mismatch")
	}
	if e := source.EnsurePrivateDirectory(filepath.Dir(destination)); e != nil {
		return 0, e
	}
	if info, e := os.Lstat(destination); e == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0222 != 0 {
			return 0, failure("build_products_changed")
		}
		if e := VerifyProducts(destination, products.Manifest); e != nil {
			return 0, e
		}
	} else if os.IsNotExist(e) {
		temporary, e := os.MkdirTemp(filepath.Dir(destination), ".build-staging-")
		if e != nil {
			return 0, e
		}
		defer os.RemoveAll(temporary)
		staged := filepath.Join(temporary, "products")
		if e = os.Mkdir(staged, 0700); e != nil {
			return 0, e
		}
		names := make([]string, 0, len(products.Payloads))
		for n := range products.Payloads {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, name := range names {
			f, e := os.OpenFile(filepath.Join(staged, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if e != nil {
				return 0, e
			}
			_, e = f.Write(products.Payloads[name])
			if e == nil {
				e = f.Sync()
			}
			closeErr := f.Close()
			if e != nil {
				return 0, e
			}
			if closeErr != nil {
				return 0, closeErr
			}
			if e = os.Chmod(filepath.Join(staged, name), 0444); e != nil {
				return 0, e
			}
		}
		if e = source.PublishDirectory(staged, destination); e != nil {
			return 0, e
		}
		if e = os.Chmod(destination, 0555); e != nil {
			return 0, e
		}
	} else {
		return 0, e
	}
	physical, e := source.PhysicalBytes(destination, source.Approval{MaxFiles: int64(len(products.Manifest)), MaxBytes: MaxBuildBytes})
	if e != nil {
		return 0, e
	}
	if physical < total {
		return 0, failure("build_physical_footprint_unproven")
	}
	return physical, nil
}
func VerifyProducts(path string, manifest map[string]Descriptor) error {
	tr, e := source.OpenTree(path, source.Limits{MaxFiles: 1024, MaxEntries: 1024, MaxFileBytes: MaxBuildBytes, MaxTotalBytes: MaxBuildBytes})
	if e != nil {
		return e
	}
	defer tr.Close()
	files, e := tr.List()
	if e != nil {
		return e
	}
	if len(files) != len(manifest) {
		return failure("build_products_changed")
	}
	for _, f := range files {
		d, ok := manifest[f.Path]
		if !ok || d.SHA256 != f.SHA256 || d.SizeBytes != f.SizeBytes {
			return failure("build_products_changed")
		}
	}
	return nil
}

// Product performs current-assignment authorization before every transmitted chunk.
type Product struct {
	Content     io.ReadCloser
	SizeBytes   int64
	SHA256      string
	AccessValid func(context.Context) bool
}

func (p *Product) Stream(ctx context.Context, w io.Writer) error {
	if p.Content == nil || p.AccessValid == nil {
		return failure("invalid_external_build_product")
	}
	defer p.Content.Close()
	buffer := make([]byte, ChunkBytes)
	var total int64
	digest := sha256.New()
	for {
		if e := ctx.Err(); e != nil {
			return e
		}
		n, e := p.Content.Read(buffer)
		if n > 0 {
			if !p.AccessValid(ctx) {
				return domain.Err(404, "participant_assignment_not_found")
			}
			if int64(n) > p.SizeBytes-total {
				return domain.Err(502, "external_build_size_mismatch")
			}
			digest.Write(buffer[:n])
			written, writeErr := w.Write(buffer[:n])
			total += int64(written)
			if writeErr != nil {
				return writeErr
			}
			if written != n {
				return io.ErrShortWrite
			}
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
	}
	if total != p.SizeBytes || hex.EncodeToString(digest.Sum(nil)) != p.SHA256 {
		return domain.Err(502, "external_build_hash_mismatch")
	}
	return nil
}

// RemoteStager must retain partial bytes privately and publish only in Commit.
type RemoteStager interface {
	Reserve(context.Context, int64) error
	Begin(context.Context, string, Descriptor) error
	WriteChunk(context.Context, string, int64, []byte) error
	Commit(context.Context, string) error
	Abort(context.Context, string) error
}

// StageRemote streams authenticated opaque wheels into a job-scoped materializer.
func StageRemote(ctx context.Context, httpClient *http.Client, endpoint, token string, manifest map[string]Descriptor, limit int64, stager RemoteStager) (map[string]Descriptor, error) {
	if httpClient == nil || stager == nil || len(token) < 1 || len(token) > 16384 || strings.ContainsAny(token, "\r\n") {
		return nil, domain.Err(401, "node_grant_required")
	}
	u, e := url.Parse(endpoint)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(endpoint, "\r\n\x00") {
		return nil, failure("invalid_external_manager_endpoint")
	}
	approved, e := ValidateManifest(manifest, limit)
	if e != nil {
		return nil, e
	}
	var total int64
	for _, d := range approved {
		total += d.SizeBytes
	}
	if e = stager.Reserve(ctx, total); e != nil {
		return nil, e
	}
	client := *httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	names := make([]string, 0, len(approved))
	for name := range approved {
		names = append(names, name)
	}
	sort.Strings(names)
	receipts := map[string]Descriptor{}
	for _, name := range names {
		d := approved[name]
		if e = stager.Begin(ctx, name, d); e != nil {
			return nil, e
		}
		e = func() error {
			complete := false
			defer func() {
				if !complete {
					_ = stager.Abort(context.Background(), name)
				}
			}()
			request, e := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(endpoint, "/")+"/"+url.PathEscape(name), nil)
			if e != nil {
				return e
			}
			request.Header.Set("Authorization", "Bearer "+token)
			request.Header.Set("Accept-Encoding", "identity")
			response, e := client.Do(request)
			if e != nil {
				return domain.Err(503, "external_build_unavailable")
			}
			defer response.Body.Close()
			if response.StatusCode >= 300 && response.StatusCode < 400 {
				return domain.Err(503, "external_manager_redirect_forbidden")
			}
			if response.StatusCode >= 400 {
				return remoteError(response)
			}
			if response.StatusCode != 200 {
				return domain.Err(502, "external_build_invalid_reply")
			}
			if encoding := response.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
				return domain.Err(502, "external_build_invalid_reply")
			}
			if response.ContentLength >= 0 && response.ContentLength != d.SizeBytes {
				return domain.Err(502, "external_build_size_mismatch")
			}
			digest := sha256.New()
			buffer := make([]byte, ChunkBytes)
			var offset int64
			for {
				n, err := response.Body.Read(buffer)
				if n > 0 {
					if int64(n) > d.SizeBytes-offset {
						return domain.Err(502, "external_build_size_mismatch")
					}
					digest.Write(buffer[:n])
					if err := stager.WriteChunk(ctx, name, offset, buffer[:n]); err != nil {
						return err
					}
					offset += int64(n)
				}
				if err == io.EOF {
					break
				}
				if err != nil {
					return domain.Err(503, "external_build_unavailable")
				}
			}
			if offset != d.SizeBytes {
				return domain.Err(502, "external_build_size_mismatch")
			}
			if hex.EncodeToString(digest.Sum(nil)) != d.SHA256 {
				return domain.Err(502, "external_build_hash_mismatch")
			}
			if e = stager.Commit(ctx, name); e != nil {
				return e
			}
			complete = true
			return nil
		}()
		if e != nil {
			return nil, fmt.Errorf("stage approved build product: %w", e)
		}
		receipts[name] = d
	}
	return receipts, nil
}

// NewProduct verifies all opaque bytes before any response body is disclosed.
func NewProduct(content []byte, expected Descriptor, accessValid func(context.Context) bool) (*Product, error) {
	if accessValid == nil || expected.SizeBytes < 1 || expected.SizeBytes > MaxBuildBytes || !sha256Pattern.MatchString(expected.SHA256) {
		return nil, failure("invalid_external_build_product")
	}
	if err := verifyBytes(content, expected); err != nil {
		return nil, domain.Err(409, "external_build_changed")
	}
	return &Product{io.NopCloser(bytes.NewReader(content)), expected.SizeBytes, expected.SHA256, accessValid}, nil
}
func remoteError(response *http.Response) error {
	body, err := io.ReadAll(io.LimitReader(response.Body, ChunkBytes+1))
	if err != nil || len(body) > ChunkBytes {
		return domain.Err(502, "external_build_invalid_reply")
	}
	code := "external_build_unavailable"
	if value, err := domain.DecodeJSON(body); err == nil {
		if object, ok := value.(map[string]any); ok {
			if details, ok := object["error"].(map[string]any); ok {
				if value, ok := details["code"].(string); ok && validErrorCode(value) {
					code = value
				}
			}
		}
	}
	return domain.Err(response.StatusCode, code)
}
func validErrorCode(value string) bool {
	if len(value) < 1 || len(value) > 100 {
		return false
	}
	for _, c := range value {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}
