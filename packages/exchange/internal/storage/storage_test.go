package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/config"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

type fakeS3 struct {
	versioning func(*s3.GetBucketVersioningInput) (*s3.GetBucketVersioningOutput, error)
	head       func(*s3.HeadObjectInput) (*s3.HeadObjectOutput, error)
	start      func(*s3.CreateMultipartUploadInput) (*s3.CreateMultipartUploadOutput, error)
	parts      func(*s3.ListPartsInput) (*s3.ListPartsOutput, error)
	complete   func(*s3.CompleteMultipartUploadInput) (*s3.CompleteMultipartUploadOutput, error)
	get        func(*s3.GetObjectInput) (*s3.GetObjectOutput, error)
	abort      func(*s3.AbortMultipartUploadInput) (*s3.AbortMultipartUploadOutput, error)
	uploads    func(*s3.ListMultipartUploadsInput) (*s3.ListMultipartUploadsOutput, error)
	versions   func(*s3.ListObjectVersionsInput) (*s3.ListObjectVersionsOutput, error)
	delete     func(*s3.DeleteObjectInput) (*s3.DeleteObjectOutput, error)
}

func unexpected() error { return errors.New("unexpected provider call") }
func (f *fakeS3) GetBucketVersioning(_ context.Context, in *s3.GetBucketVersioningInput, _ ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
	if f.versioning != nil {
		return f.versioning(in)
	}
	return nil, unexpected()
}
func (f *fakeS3) HeadObject(_ context.Context, in *s3.HeadObjectInput, _ ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	if f.head != nil {
		return f.head(in)
	}
	return nil, unexpected()
}
func (f *fakeS3) CreateMultipartUpload(_ context.Context, in *s3.CreateMultipartUploadInput, _ ...func(*s3.Options)) (*s3.CreateMultipartUploadOutput, error) {
	if f.start != nil {
		return f.start(in)
	}
	return nil, unexpected()
}
func (f *fakeS3) ListParts(_ context.Context, in *s3.ListPartsInput, _ ...func(*s3.Options)) (*s3.ListPartsOutput, error) {
	if f.parts != nil {
		return f.parts(in)
	}
	return nil, unexpected()
}
func (f *fakeS3) CompleteMultipartUpload(_ context.Context, in *s3.CompleteMultipartUploadInput, _ ...func(*s3.Options)) (*s3.CompleteMultipartUploadOutput, error) {
	if f.complete != nil {
		return f.complete(in)
	}
	return nil, unexpected()
}
func (f *fakeS3) GetObject(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	if f.get != nil {
		return f.get(in)
	}
	return nil, unexpected()
}
func (f *fakeS3) AbortMultipartUpload(_ context.Context, in *s3.AbortMultipartUploadInput, _ ...func(*s3.Options)) (*s3.AbortMultipartUploadOutput, error) {
	if f.abort != nil {
		return f.abort(in)
	}
	return nil, unexpected()
}
func (f *fakeS3) ListMultipartUploads(_ context.Context, in *s3.ListMultipartUploadsInput, _ ...func(*s3.Options)) (*s3.ListMultipartUploadsOutput, error) {
	if f.uploads != nil {
		return f.uploads(in)
	}
	return nil, unexpected()
}
func (f *fakeS3) ListObjectVersions(_ context.Context, in *s3.ListObjectVersionsInput, _ ...func(*s3.Options)) (*s3.ListObjectVersionsOutput, error) {
	if f.versions != nil {
		return f.versions(in)
	}
	return nil, unexpected()
}
func (f *fakeS3) DeleteObject(_ context.Context, in *s3.DeleteObjectInput, _ ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	if f.delete != nil {
		return f.delete(in)
	}
	return nil, unexpected()
}

type fakeSigner struct {
	upload   func(*s3.UploadPartInput) (*v4.PresignedHTTPRequest, error)
	download func(*s3.GetObjectInput) (*v4.PresignedHTTPRequest, error)
}

func (f fakeSigner) PresignUploadPart(_ context.Context, in *s3.UploadPartInput, _ ...func(*s3.PresignOptions)) (*v4.PresignedHTTPRequest, error) {
	if f.upload != nil {
		return f.upload(in)
	}
	return nil, unexpected()
}
func (f fakeSigner) PresignGetObject(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.PresignOptions)) (*v4.PresignedHTTPRequest, error) {
	if f.download != nil {
		return f.download(in)
	}
	return nil, unexpected()
}
func testSettings() config.StorageSettings {
	s := config.DefaultStorage()
	s.Bucket = "fixture-bucket"
	s.Endpoint = "https://private.example.invalid"
	s.Region = "us-east-1"
	s.AccessKey = "fixture-access"
	s.SecretKey = "fixture-secret"
	return s
}
func testStore(t *testing.T, f *fakeS3) *S3BlobStore {
	t.Helper()
	s, e := NewWithClients(testSettings(), f, fakeSigner{})
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func apiError(code string) error {
	return &smithy.GenericAPIError{Code: code, Message: "provider detail must not leak"}
}
func codeIs(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil || AsFailure(err).Code != code {
		t.Fatalf("want %s got %v", code, err)
	}
}

func TestPartSizeFor(t *testing.T) {
	for _, c := range []struct {
		n                int
		size, part, want int64
	}{{1, 0, 5, 0}, {1, 8, 5, 5}, {2, 8, 5, 3}, {2, 10, 5, 5}, {1, math.MaxInt64, math.MaxInt64, math.MaxInt64}} {
		got, e := PartSizeFor(c.n, c.size, c.part)
		if e != nil || got != c.want {
			t.Fatalf("%+v: %d %v", c, got, e)
		}
	}
	for _, c := range []struct {
		n          int
		size, part int64
	}{{0, 1, 5}, {2, 0, 5}, {3, 8, 5}, {1, -1, 5}, {1, 1, 0}, {math.MaxInt, math.MaxInt64, math.MaxInt64}} {
		_, e := PartSizeFor(c.n, c.size, c.part)
		codeIs(t, e, "invalid_part_number")
	}
}
func TestNormalizeFailure(t *testing.T) {
	for _, c := range []struct {
		provider, code string
		retry, unknown bool
	}{
		{"NoSuchKey", "storage_missing", false, false}, {"NoSuchUpload", "storage_missing", false, false}, {"NoSuchVersion", "storage_missing", false, false}, {"404", "storage_missing", false, false}, {"NotFound", "storage_missing", false, false},
		{"AccessDenied", "storage_misconfigured", true, false}, {"SignatureDoesNotMatch", "storage_misconfigured", true, false},
		{"InvalidPart", "invalid_parts", false, false}, {"EntityTooSmall", "invalid_parts", false, false}, {"UnknownProviderFailure", "storage_unavailable", true, true},
	} {
		e := AsFailure(normalize(fmt.Errorf("wrapped: %w", apiError(c.provider))))
		if e.Code != c.code || e.Retryable != c.retry || e.Uncertain != c.unknown || strings.Contains(e.Error(), "provider detail") {
			t.Fatalf("wrong normalized failure %+v", e)
		}
	}
	existing := Failure("retained", true, false)
	if normalize(fmt.Errorf("wrap: %w", existing)) != existing {
		t.Fatal("failure identity lost")
	}
}
func TestCheckVersioningAndPrefix(t *testing.T) {
	f := &fakeS3{versioning: func(in *s3.GetBucketVersioningInput) (*s3.GetBucketVersioningOutput, error) {
		if aws.ToString(in.Bucket) != "fixture-bucket" {
			t.Fatal("wrong bucket")
		}
		return &s3.GetBucketVersioningOutput{Status: types.BucketVersioningStatusEnabled}, nil
	}, head: func(in *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
		if !strings.HasPrefix(aws.ToString(in.Key), "exchange-v2/readiness/") {
			t.Fatal("readiness escaped prefix")
		}
		return nil, apiError("404")
	}}
	if e := testStore(t, f).Check(context.Background()); e != nil {
		t.Fatal(e)
	}
	f.versioning = func(*s3.GetBucketVersioningInput) (*s3.GetBucketVersioningOutput, error) {
		return &s3.GetBucketVersioningOutput{}, nil
	}
	codeIs(t, testStore(t, f).Check(context.Background()), "storage_misconfigured")
	f.versioning = func(*s3.GetBucketVersioningInput) (*s3.GetBucketVersioningOutput, error) {
		return nil, apiError("AccessDenied")
	}
	codeIs(t, testStore(t, f).Check(context.Background()), "storage_misconfigured")
}
func TestPartsPaginationSortedAndProgress(t *testing.T) {
	f := &fakeS3{parts: func(in *s3.ListPartsInput) (*s3.ListPartsOutput, error) {
		if aws.ToString(in.Key) != "owned" || aws.ToString(in.UploadId) != "upload" {
			t.Fatal("binding lost")
		}
		if in.PartNumberMarker == nil {
			return &s3.ListPartsOutput{Parts: []types.Part{{PartNumber: aws.Int32(2), Size: aws.Int64(3), ETag: aws.String("two")}}, IsTruncated: aws.Bool(true), NextPartNumberMarker: aws.String("2")}, nil
		}
		return &s3.ListPartsOutput{Parts: []types.Part{{PartNumber: aws.Int32(1), Size: aws.Int64(5), ETag: aws.String("one")}}}, nil
	}}
	parts, e := testStore(t, f).Parts(context.Background(), UploadHandle{ID: "upload", Key: "owned"})
	if e != nil || len(parts) != 2 || parts[0].Number != 1 || parts[1].Number != 2 {
		t.Fatalf("%v %v", parts, e)
	}
	f.parts = func(*s3.ListPartsInput) (*s3.ListPartsOutput, error) {
		return &s3.ListPartsOutput{IsTruncated: aws.Bool(true), NextPartNumberMarker: aws.String("same")}, nil
	}
	_, e = testStore(t, f).Parts(context.Background(), UploadHandle{})
	codeIs(t, e, "storage_unavailable")
}
func TestCompleteRecoveryAndExactParts(t *testing.T) {
	f := &fakeS3{head: func(*s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
		return &s3.HeadObjectOutput{VersionId: aws.String("existing-version")}, nil
	}}
	got, e := testStore(t, f).Complete(context.Background(), UploadHandle{ID: "lost-reply", Key: "owned"}, 8, 5)
	if e != nil || got.Version != "existing-version" || got.Key != "owned" {
		t.Fatalf("%+v %v", got, e)
	}
	f.head = func(*s3.HeadObjectInput) (*s3.HeadObjectOutput, error) { return nil, apiError("NotFound") }
	f.parts = func(*s3.ListPartsInput) (*s3.ListPartsOutput, error) {
		return &s3.ListPartsOutput{Parts: []types.Part{{PartNumber: aws.Int32(1), Size: aws.Int64(5), ETag: aws.String("one")}, {PartNumber: aws.Int32(2), Size: aws.Int64(3), ETag: aws.String("two")}}}, nil
	}
	calls := 0
	f.complete = func(in *s3.CompleteMultipartUploadInput) (*s3.CompleteMultipartUploadOutput, error) {
		calls++
		if aws.ToString(in.Key) != "owned" || aws.ToString(in.UploadId) != "upload" || len(in.MultipartUpload.Parts) != 2 {
			t.Fatal("completion binding lost")
		}
		return &s3.CompleteMultipartUploadOutput{VersionId: aws.String("version")}, nil
	}
	got, e = testStore(t, f).Complete(context.Background(), UploadHandle{ID: "upload", Key: "owned"}, 8, 5)
	if e != nil || got.Version != "version" || calls != 1 {
		t.Fatalf("%+v %v %d", got, e, calls)
	}
	_, e = testStore(t, f).Complete(context.Background(), UploadHandle{}, 9, 5)
	codeIs(t, e, "invalid_parts")
	if calls != 1 {
		t.Fatal("invalid parts completed")
	}
	f.complete = func(*s3.CompleteMultipartUploadInput) (*s3.CompleteMultipartUploadOutput, error) {
		return &s3.CompleteMultipartUploadOutput{VersionId: aws.String("null")}, nil
	}
	_, e = testStore(t, f).Complete(context.Background(), UploadHandle{}, 8, 5)
	codeIs(t, e, "storage_misconfigured")
}

type failureReader struct{}

func (failureReader) Read([]byte) (int, error) { return 0, errors.New("read failure") }
func (failureReader) Close() error             { return nil }
func TestVerifyExactVersionAndIntegrity(t *testing.T) {
	data := []byte("opaque checkpoint, not model code")
	sum := sha256.Sum256(data)
	f := &fakeS3{get: func(in *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
		if aws.ToString(in.VersionId) != "immutable-version" || aws.ToString(in.Key) != "owned" {
			t.Fatal("wrong immutable version")
		}
		return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(data))}, nil
	}}
	s := testStore(t, f)
	stored := StoredObject{Key: "owned", Version: "immutable-version"}
	v, e := s.Verify(context.Background(), stored, int64(len(data)), hex.EncodeToString(sum[:]))
	if e != nil || v.Size != int64(len(data)) {
		t.Fatalf("%+v %v", v, e)
	}
	_, e = s.Verify(context.Background(), stored, int64(len(data))+1, hex.EncodeToString(sum[:]))
	codeIs(t, e, "verification_failed")
	_, e = s.Verify(context.Background(), stored, int64(len(data)), strings.Repeat("0", 64))
	codeIs(t, e, "verification_failed")
	f.get = func(*s3.GetObjectInput) (*s3.GetObjectOutput, error) {
		return &s3.GetObjectOutput{Body: failureReader{}}, nil
	}
	_, e = s.Verify(context.Background(), stored, 0, "")
	codeIs(t, e, "storage_unavailable")
}
func signedRequest(raw string) *v4.PresignedHTTPRequest {
	return &v4.PresignedHTTPRequest{URL: raw, SignedHeader: http.Header{"X-Fixture": []string{"signed"}, "Host": []string{"bound.example"}}}
}
func TestGrantActualSignedExpiryAndHeaders(t *testing.T) {
	settings := testSettings()
	f := fakeSigner{upload: func(in *s3.UploadPartInput) (*v4.PresignedHTTPRequest, error) {
		if aws.ToInt64(in.ContentLength) != 0 || aws.ToInt32(in.PartNumber) != 1 {
			t.Fatal("zero-size upload declaration lost")
		}
		return signedRequest("https://bound.example/object?X-Amz-Date=20261024T000000Z&X-Amz-Expires=300"), nil
	}}
	s, e := NewWithClients(settings, &fakeS3{}, f)
	if e != nil {
		t.Fatal(e)
	}
	g, e := s.UploadGrant(context.Background(), UploadHandle{}, 1, 0, 1, 300)
	if e != nil || g.ExpiresAt != float64(time.Date(2026, 10, 24, 0, 5, 0, 0, time.UTC).Unix()) || g.Headers["Content-Length"] != "0" || g.Headers["X-Fixture"] != "signed" {
		t.Fatalf("%+v %v", g, e)
	}
	if _, ok := g.Headers["Host"]; ok {
		t.Fatal("host must be transport controlled")
	}
	for _, raw := range []string{"http://remote.example/x?X-Amz-Date=20261024T000000Z&X-Amz-Expires=300", "https://user:pass@bound.example/x?X-Amz-Date=20261024T000000Z&X-Amz-Expires=300", "https://bound.example/x?X-Amz-Date=20261024T000000Z&X-Amz-Expires=300&X-Amz-Expires=301"} {
		_, e = s.grant(signedRequest(raw), 0)
		if e == nil {
			t.Fatal("unsafe/ambiguous grant accepted")
		}
	}
}
func TestNativePresignerPublicEndpointAndSessionToken(t *testing.T) {
	settings := testSettings()
	settings.PublicEndpoint = "https://public.example.invalid"
	settings.SessionToken = "fixture-session"
	s, e := NewS3(context.Background(), settings)
	if e != nil {
		t.Fatal(e)
	}
	before := time.Now().Unix()
	g, e := s.UploadGrant(context.Background(), UploadHandle{ID: "private-upload", Key: "prefix/opaque"}, 1, 0, 0, 300)
	if e != nil {
		t.Fatal(e)
	}
	u, e := url.Parse(g.URL)
	if e != nil {
		t.Fatal(e)
	}
	if u.Host != "public.example.invalid" || u.Query().Get("X-Amz-Security-Token") != "fixture-session" || g.Headers["Content-Length"] != "0" || g.ExpiresAt < float64(before+300) || g.ExpiresAt > float64(time.Now().Unix()+300) {
		t.Fatalf("presigner binding wrong: host=%s headers=%v", u.Host, g.Headers)
	}
	emptySHA := sha256.Sum256(nil)
	boundHash := u.Query().Get("X-Amz-Content-Sha256")
	if boundHash == "" {
		boundHash = g.Headers["X-Amz-Content-Sha256"]
	}
	if boundHash != hex.EncodeToString(emptySHA[:]) {
		t.Fatalf("empty upload lacks signed payload hash; signedheaders=%s", u.Query().Get("X-Amz-SignedHeaders"))
	}
	positive, e := s.UploadGrant(context.Background(), UploadHandle{ID: "private-upload", Key: "prefix/opaque"}, 1, 123, 0, 300)
	if e != nil {
		t.Fatal(e)
	}
	positiveURL, _ := url.Parse(positive.URL)
	if !strings.Contains(positiveURL.Query().Get("X-Amz-SignedHeaders"), "content-length") {
		t.Fatal("nonempty upload length not signed")
	}
	if strings.Contains(strings.ToLower(u.RawQuery), "checksum") {
		t.Fatal("protocol unexpectedly requires unadvertised checksum")
	}
	g, e = s.DownloadGrant(context.Background(), StoredObject{Key: "prefix/opaque", Version: "immutable-version"}, 0, 300)
	if e != nil {
		t.Fatal(e)
	}
	u, _ = url.Parse(g.URL)
	if u.Query().Get("versionId") != "immutable-version" || u.Host != "public.example.invalid" {
		t.Fatal("download version/public endpoint binding lost")
	}
}
func TestCredentialRefreshRetainsSessionTokens(t *testing.T) {
	var calls atomic.Int64
	provider := aws.NewCredentialsCache(aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		n := calls.Add(1)
		return aws.Credentials{AccessKeyID: fmt.Sprintf("fixture-%d", n), SecretAccessKey: "fixture-secret", SessionToken: fmt.Sprintf("token-%d", n), CanExpire: true, Expires: time.Now().Add(-time.Second)}, nil
	}))
	client := s3.New(s3.Options{Region: "us-east-1", Credentials: provider, BaseEndpoint: aws.String("https://public.example.invalid"), UsePathStyle: true, RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired})
	s, e := NewWithClients(testSettings(), client, s3.NewPresignClient(client))
	if e != nil {
		t.Fatal(e)
	}
	first, e := s.DownloadGrant(context.Background(), StoredObject{Key: "owned", Version: "v"}, 0, 300)
	if e != nil {
		t.Fatal(e)
	}
	second, e := s.DownloadGrant(context.Background(), StoredObject{Key: "owned", Version: "v"}, 0, 300)
	if e != nil {
		t.Fatal(e)
	}
	a, _ := url.Parse(first.URL)
	b, _ := url.Parse(second.URL)
	if calls.Load() < 2 || a.Query().Get("X-Amz-Security-Token") == b.Query().Get("X-Amz-Security-Token") {
		t.Fatalf("temporary credentials/session token did not refresh; provider calls=%d", calls.Load())
	}
}
func TestProviderHTTPClientDoesNotRedirect(t *testing.T) {
	var reached atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached.Add(1) }))
	defer target.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()
	response, e := storageHTTPClient().Get(origin.URL)
	if e != nil {
		t.Fatal(e)
	}
	defer response.Body.Close()
	if response.StatusCode != 307 || reached.Load() != 0 {
		t.Fatal("provider redirect followed")
	}
}
func TestCleanupExactKeysVersionsAndAbortProof(t *testing.T) {
	uploads := true
	versions := true
	aborted := false
	deleted := []string{}
	f := &fakeS3{
		uploads: func(*s3.ListMultipartUploadsInput) (*s3.ListMultipartUploadsOutput, error) {
			if uploads {
				return &s3.ListMultipartUploadsOutput{Uploads: []types.MultipartUpload{{Key: aws.String("owned"), UploadId: aws.String("upload")}, {Key: aws.String("owned-foreign"), UploadId: aws.String("foreign")}}}, nil
			}
			return &s3.ListMultipartUploadsOutput{}, nil
		},
		abort: func(in *s3.AbortMultipartUploadInput) (*s3.AbortMultipartUploadOutput, error) {
			if aws.ToString(in.Key) != "owned" || aws.ToString(in.UploadId) != "upload" {
				t.Fatal("foreign upload touched")
			}
			aborted = true
			uploads = false
			return &s3.AbortMultipartUploadOutput{}, nil
		},
		parts: func(*s3.ListPartsInput) (*s3.ListPartsOutput, error) {
			if !aborted {
				t.Fatal("absence proof before abort")
			}
			return nil, apiError("NoSuchUpload")
		},
		versions: func(*s3.ListObjectVersionsInput) (*s3.ListObjectVersionsOutput, error) {
			if versions {
				return &s3.ListObjectVersionsOutput{Versions: []types.ObjectVersion{{Key: aws.String("owned"), VersionId: aws.String("v1")}, {Key: aws.String("owned-foreign"), VersionId: aws.String("untouched")}}, DeleteMarkers: []types.DeleteMarkerEntry{{Key: aws.String("owned"), VersionId: aws.String("marker")}}}, nil
			}
			return &s3.ListObjectVersionsOutput{}, nil
		},
		delete: func(in *s3.DeleteObjectInput) (*s3.DeleteObjectOutput, error) {
			if aws.ToString(in.Key) != "owned" {
				t.Fatal("foreign key touched")
			}
			deleted = append(deleted, aws.ToString(in.VersionId))
			if len(deleted) == 2 {
				versions = false
			}
			return &s3.DeleteObjectOutput{}, nil
		},
	}
	if e := testStore(t, f).Cleanup(context.Background(), "owned"); e != nil {
		t.Fatal(e)
	}
	if !aborted || len(deleted) != 2 || deleted[0] != "v1" || deleted[1] != "marker" {
		t.Fatalf("incomplete cleanup %v %v", aborted, deleted)
	}
}
func TestCleanupUncertaintyNeverProvesAbsence(t *testing.T) {
	for _, which := range []string{"abort_pending", "abort_unknown", "delete_unknown", "version_remains", "upload_remains", "repeated_marker"} {
		t.Run(which, func(t *testing.T) {
			f := &fakeS3{
				uploads: func(*s3.ListMultipartUploadsInput) (*s3.ListMultipartUploadsOutput, error) {
					return &s3.ListMultipartUploadsOutput{}, nil
				},
				versions: func(*s3.ListObjectVersionsInput) (*s3.ListObjectVersionsOutput, error) {
					return &s3.ListObjectVersionsOutput{}, nil
				},
			}
			switch which {
			case "abort_pending", "abort_unknown":
				f.uploads = func(*s3.ListMultipartUploadsInput) (*s3.ListMultipartUploadsOutput, error) {
					return &s3.ListMultipartUploadsOutput{Uploads: []types.MultipartUpload{{Key: aws.String("owned"), UploadId: aws.String("upload")}}}, nil
				}
				f.abort = func(*s3.AbortMultipartUploadInput) (*s3.AbortMultipartUploadOutput, error) {
					if which == "abort_unknown" {
						return nil, errors.New("lost reply")
					}
					return &s3.AbortMultipartUploadOutput{}, nil
				}
				f.parts = func(*s3.ListPartsInput) (*s3.ListPartsOutput, error) { return &s3.ListPartsOutput{}, nil }
			case "delete_unknown", "version_remains":
				f.versions = func(*s3.ListObjectVersionsInput) (*s3.ListObjectVersionsOutput, error) {
					return &s3.ListObjectVersionsOutput{Versions: []types.ObjectVersion{{Key: aws.String("owned"), VersionId: aws.String("v")}}}, nil
				}
				f.delete = func(*s3.DeleteObjectInput) (*s3.DeleteObjectOutput, error) {
					if which == "delete_unknown" {
						return nil, errors.New("lost reply")
					}
					return &s3.DeleteObjectOutput{}, nil
				}
			case "upload_remains":
				calls := 0
				f.uploads = func(*s3.ListMultipartUploadsInput) (*s3.ListMultipartUploadsOutput, error) {
					calls++
					if calls == 1 {
						return &s3.ListMultipartUploadsOutput{}, nil
					}
					return &s3.ListMultipartUploadsOutput{Uploads: []types.MultipartUpload{{Key: aws.String("owned"), UploadId: aws.String("new")}}}, nil
				}
			case "repeated_marker":
				f.versions = func(*s3.ListObjectVersionsInput) (*s3.ListObjectVersionsOutput, error) {
					return &s3.ListObjectVersionsOutput{IsTruncated: aws.Bool(true), NextKeyMarker: aws.String("same")}, nil
				}
			}
			if e := testStore(t, f).Cleanup(context.Background(), "owned"); e == nil {
				t.Fatal("uncertain cleanup accepted")
			}
		})
	}
}

func TestAmbientCredentialChainRefresh(t *testing.T) {
	var calls atomic.Int64
	credentialsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "fixture-container-auth" {
			t.Error("credential provider lost configured authorization")
			http.Error(w, "denied", 403)
			return
		}
		n := calls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]string{"AccessKeyId": fmt.Sprintf("ambient-%d", n), "SecretAccessKey": "fixture-secret", "Token": fmt.Sprintf("ambient-token-%d", n), "Expiration": time.Now().Add(-time.Second).UTC().Format(time.RFC3339)})
	}))
	defer credentialsServer.Close()
	blank := filepath.Join(t.TempDir(), "empty")
	if e := os.WriteFile(blank, nil, 0600); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE", "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_SESSION_NAME", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"} {
		t.Setenv(name, "")
	}
	t.Setenv("AWS_CONFIG_FILE", blank)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", blank)
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", credentialsServer.URL)
	t.Setenv("AWS_CONTAINER_AUTHORIZATION_TOKEN", "fixture-container-auth")
	settings := testSettings()
	settings.AccessKey = ""
	settings.SecretKey = ""
	store, e := NewS3(context.Background(), settings)
	if e != nil {
		t.Fatal(e)
	}
	first, e := store.DownloadGrant(context.Background(), StoredObject{Key: "owned", Version: "v"}, 0, 300)
	if e != nil {
		t.Fatal(e)
	}
	second, e := store.DownloadGrant(context.Background(), StoredObject{Key: "owned", Version: "v"}, 0, 300)
	if e != nil {
		t.Fatal(e)
	}
	a, _ := url.Parse(first.URL)
	b, _ := url.Parse(second.URL)
	if calls.Load() < 2 || a.Query().Get("X-Amz-Security-Token") == b.Query().Get("X-Amz-Security-Token") {
		t.Fatal("default temporary credential chain did not refresh")
	}
	for _, u := range []*url.URL{a, b} {
		identity := strings.Split(u.Query().Get("X-Amz-Credential"), "/")[0]
		if u.Query().Get("X-Amz-Security-Token") != "ambient-token-"+strings.TrimPrefix(identity, "ambient-") {
			t.Fatal("session token and signing identity mixed")
		}
	}
}

func TestAWSCAServiceTrustIsPreserved(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Query().Has("versioning") {
			w.Header().Set("Content-Type", "application/xml")
			_, _ = io.WriteString(w, "<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>Enabled</Status></VersioningConfiguration>")
			return
		}
		if r.Method == http.MethodHead {
			w.WriteHeader(404)
			return
		}
		http.Error(w, "unexpected operation", 400)
	}))
	defer server.Close()
	certFile := filepath.Join(t.TempDir(), "service-ca.pem")
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if e := os.WriteFile(certFile, encoded, 0600); e != nil {
		t.Fatal(e)
	}
	t.Setenv("AWS_CA_BUNDLE", certFile)
	settings := testSettings()
	settings.Endpoint = server.URL
	store, e := NewS3(context.Background(), settings)
	if e != nil {
		t.Fatalf("AWS_CA_BUNDLE construction failed: %v", e)
	}
	if e = store.Check(context.Background()); e != nil {
		t.Fatalf("configured service CA not trusted: %v", e)
	}
	t.Setenv("AWS_CA_BUNDLE", "")
	untrusted, e := NewS3(context.Background(), settings)
	if e != nil {
		t.Fatal(e)
	}
	deniedCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	codeIs(t, untrusted.Check(deniedCtx), "storage_unavailable")
}
