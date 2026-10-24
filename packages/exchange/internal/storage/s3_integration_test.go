package storage

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/config"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// This opt-in provider gate owns a fresh bucket. It does not bypass the
// application's grant-drain/accounting logic: that has separate lifecycle tests.
func TestRealS3MultipartStore(t *testing.T) {
	path := os.Getenv("HF2L_GO_EXCHANGE_STORAGE_CONFIG")
	if path == "" {
		if os.Getenv("HF2L_GO_REQUIRE_STORAGE_INTEGRATION") == "1" {
			t.Fatal("owned S3 fixture configuration required")
		}
		t.Skip("set HF2L_GO_EXCHANGE_STORAGE_CONFIG for an owned S3 fixture")
	}
	info, e := os.Lstat(path)
	if e != nil {
		t.Fatal("storage fixture configuration unavailable")
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 65536 {
		t.Fatal("storage fixture configuration must be a private bounded regular file")
	}
	data, e := os.ReadFile(path)
	if e != nil {
		t.Fatal("storage fixture configuration unreadable")
	}
	var fixture struct {
		Endpoint  string `json:"endpoint"`
		AccessKey string `json:"access_key"`
		SecretKey string `json:"secret_key"`
		Region    string `json:"region"`
	}
	if e = json.Unmarshal(data, &fixture); e != nil {
		t.Fatal("storage fixture configuration invalid")
	}
	parsed, parseErr := url.Parse(fixture.Endpoint)
	local := false
	if parseErr == nil {
		host := parsed.Hostname()
		local = host == "localhost"
		if ip := net.ParseIP(host); ip != nil {
			local = local || ip.IsLoopback()
		}
	}
	if !local || fixture.AccessKey == "" || fixture.SecretKey == "" || fixture.Region == "" {
		t.Fatal("integration gate requires explicit owned loopback storage and fixture credentials")
	}

	random := make([]byte, 12)
	if _, e = rand.Read(random); e != nil {
		t.Fatal(e)
	}
	bucket := "hf2l-go-storage-" + hex.EncodeToString(random)
	settings := config.DefaultStorage()
	settings.Endpoint = fixture.Endpoint
	settings.AccessKey = fixture.AccessKey
	settings.SecretKey = fixture.SecretKey
	settings.Region = fixture.Region
	settings.Bucket = bucket
	settings.AllowLocalHTTP = true
	settings.PartSize = 5 * 1024 * 1024
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	store, e := NewS3(ctx, settings)
	if e != nil {
		t.Fatalf("native storage construction: %v", e)
	}
	client := store.client.(*s3.Client)
	if _, e = client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); e != nil {
		t.Fatalf("owned fixture bucket creation: %v", normalize(e))
	}
	report := map[string]any{"passed": false, "zero_byte_upload": false, "zero_byte_tamper_denied": false, "normal_multipart": false, "exact_version_download": false, "lost_completion_recovery": false, "all_versions_and_multipart_removed": false, "foreign_prefix_preserved": false, "bucket_removed": false}
	defer func() {
		cleanupCtx, done := context.WithTimeout(context.Background(), time.Minute)
		defer done()
		clean := cleanupOwnedTestBucket(cleanupCtx, client, bucket)
		report["bucket_removed"] = clean == nil
		if clean != nil {
			t.Errorf("owned bucket cleanup failed: %v", normalize(clean))
		}
		if t.Failed() {
			report["passed"] = false
		}
		if output := os.Getenv("HF2L_GO_EXCHANGE_STORAGE_ARTIFACTS"); output != "" {
			if e := os.MkdirAll(output, 0700); e != nil {
				t.Error("storage receipt directory unavailable")
				return
			}
			encoded, _ := json.MarshalIndent(report, "", "  ")
			if e := os.WriteFile(filepath.Join(output, "storage-provider-report.json"), encoded, 0600); e != nil {
				t.Error("storage receipt unavailable")
			}
		}
	}()
	codeIs(t, store.Check(ctx), "storage_misconfigured")
	if _, e = client.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: aws.String(bucket), VersioningConfiguration: &types.VersioningConfiguration{Status: types.BucketVersioningStatusEnabled}}); e != nil {
		t.Fatalf("fixture versioning: %v", normalize(e))
	}
	if e = store.Check(ctx); e != nil {
		t.Fatal(e)
	}
	httpClient := storageHTTPClient()
	upload := func(grant TransferGrant, payload []byte) int {
		t.Helper()
		req, e := http.NewRequestWithContext(ctx, http.MethodPut, grant.URL, bytes.NewReader(payload))
		if e != nil {
			t.Fatal("upload request construction failed")
		}
		for k, v := range grant.Headers {
			req.Header.Set(k, v)
		}
		req.ContentLength = int64(len(payload))
		response, e := httpClient.Do(req)
		if e != nil {
			t.Fatalf("actual signed upload failed: %v", AsFailure(e))
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 65536))
		response.Body.Close()
		return response.StatusCode
	}
	for _, test := range []struct {
		name    string
		payload []byte
	}{
		{"empty", nil}, {"multipart", bytes.Repeat([]byte{0x5a}, 5*1024*1024+12345)},
	} {
		key := settings.Prefix + "owned/" + test.name
		handle, e := store.Start(ctx, key)
		if e != nil {
			t.Fatal(e)
		}
		count := 1
		if len(test.payload) > 0 {
			count = 1 + (len(test.payload)-1)/int(settings.PartSize)
		}
		for n := 1; n <= count; n++ {
			length, e := PartSizeFor(n, int64(len(test.payload)), settings.PartSize)
			if e != nil {
				t.Fatal(e)
			}
			grant, e := store.UploadGrant(ctx, handle, n, length, float64(time.Now().Unix()+300), 300)
			if e != nil {
				t.Fatal(e)
			}
			if test.name == "empty" {
				status := upload(grant, []byte("tampered-nonempty"))
				if status >= 200 && status < 300 {
					t.Fatal("zero-byte capability allowed a nonempty upload")
				}
				report["zero_byte_tamper_denied"] = true
			}
			start := (n - 1) * int(settings.PartSize)
			end := start + int(length)
			status := upload(grant, test.payload[start:end])
			if status < 200 || status >= 300 {
				t.Fatalf("actual signed upload denied, status%d", status)
			}
		}
		stored, e := store.Complete(ctx, handle, int64(len(test.payload)), settings.PartSize)
		if e != nil {
			t.Fatal(e)
		}
		recovered, e := store.Complete(ctx, handle, int64(len(test.payload)), settings.PartSize)
		if e != nil || recovered != stored {
			t.Fatal("lost completion response could not recover exact existing version")
		}
		report["lost_completion_recovery"] = true
		digest := sha256.Sum256(test.payload)
		if _, e = store.Verify(ctx, stored, int64(len(test.payload)), hex.EncodeToString(digest[:])); e != nil {
			t.Fatal(e)
		}
		// A later version must never change the checkpoint named by a download grant.
		if _, e = client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(bucket), Key: aws.String(key), Body: strings.NewReader("replacement-version")}); e != nil {
			t.Fatal(normalize(e))
		}
		grant, e := store.DownloadGrant(ctx, stored, 0, 300)
		if e != nil {
			t.Fatal(e)
		}
		req, e := http.NewRequestWithContext(ctx, http.MethodGet, grant.URL, nil)
		if e != nil {
			t.Fatal(e)
		}
		for k, v := range grant.Headers {
			req.Header.Set(k, v)
		}
		response, e := httpClient.Do(req)
		if e != nil {
			t.Fatal(AsFailure(e))
		}
		downloaded, e := io.ReadAll(io.LimitReader(response.Body, int64(len(test.payload))+1))
		response.Body.Close()
		if e != nil || response.StatusCode != 200 || !bytes.Equal(downloaded, test.payload) {
			t.Fatal("immutable version download changed")
		}
		report["exact_version_download"] = true
		sibling := key + "-foreign"
		if _, e = client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(bucket), Key: aws.String(sibling), Body: strings.NewReader("preserve-neighbor")}); e != nil {
			t.Fatal(normalize(e))
		}
		if _, e = store.Start(ctx, key); e != nil {
			t.Fatal(e)
		}
		if _, e = client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)}); e != nil {
			t.Fatal(normalize(e))
		}
		if e = store.Cleanup(ctx, key); e != nil {
			t.Fatal(e)
		}
		versions, e := client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: aws.String(bucket), Prefix: aws.String(key)})
		if e != nil {
			t.Fatal(normalize(e))
		}
		for _, item := range versions.Versions {
			if aws.ToString(item.Key) == key {
				t.Fatal("owned object version remains")
			}
		}
		for _, item := range versions.DeleteMarkers {
			if aws.ToString(item.Key) == key {
				t.Fatal("owned deletion marker remains")
			}
		}
		uploads, e := client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: aws.String(bucket), Prefix: aws.String(key)})
		if e != nil {
			t.Fatal(normalize(e))
		}
		for _, item := range uploads.Uploads {
			if aws.ToString(item.Key) == key {
				t.Fatal("owned multipart upload remains")
			}
		}
		if _, e = client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(bucket), Key: aws.String(sibling)}); e != nil {
			t.Fatal("neighbor with same prefix removed")
		}
		report["foreign_prefix_preserved"] = true
		report["all_versions_and_multipart_removed"] = true
		if test.name == "empty" {
			report["zero_byte_upload"] = true
		} else {
			report["normal_multipart"] = true
		}
	}
	report["passed"] = true
}
func cleanupOwnedTestBucket(ctx context.Context, client *s3.Client, bucket string) error {
	uploads := s3.NewListMultipartUploadsPaginator(client, &s3.ListMultipartUploadsInput{Bucket: aws.String(bucket)})
	for uploads.HasMorePages() {
		page, e := uploads.NextPage(ctx)
		if e != nil {
			return e
		}
		for _, item := range page.Uploads {
			if _, e = client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{Bucket: aws.String(bucket), Key: item.Key, UploadId: item.UploadId}); e != nil {
				return e
			}
		}
	}
	versions := s3.NewListObjectVersionsPaginator(client, &s3.ListObjectVersionsInput{Bucket: aws.String(bucket)})
	for versions.HasMorePages() {
		page, e := versions.NextPage(ctx)
		if e != nil {
			return e
		}
		for _, item := range page.Versions {
			if _, e = client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(bucket), Key: item.Key, VersionId: item.VersionId}); e != nil {
				return e
			}
		}
		for _, item := range page.DeleteMarkers {
			if _, e = client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(bucket), Key: item.Key, VersionId: item.VersionId}); e != nil {
				return e
			}
		}
	}
	_, e := client.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String(bucket)})
	return e
}
