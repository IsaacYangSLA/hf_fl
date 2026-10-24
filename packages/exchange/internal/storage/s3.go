package storage

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/config"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/middleware"
)

type S3API interface {
	GetBucketVersioning(context.Context, *s3.GetBucketVersioningInput, ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error)
	HeadObject(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	CreateMultipartUpload(context.Context, *s3.CreateMultipartUploadInput, ...func(*s3.Options)) (*s3.CreateMultipartUploadOutput, error)
	ListParts(context.Context, *s3.ListPartsInput, ...func(*s3.Options)) (*s3.ListPartsOutput, error)
	CompleteMultipartUpload(context.Context, *s3.CompleteMultipartUploadInput, ...func(*s3.Options)) (*s3.CompleteMultipartUploadOutput, error)
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	AbortMultipartUpload(context.Context, *s3.AbortMultipartUploadInput, ...func(*s3.Options)) (*s3.AbortMultipartUploadOutput, error)
	ListMultipartUploads(context.Context, *s3.ListMultipartUploadsInput, ...func(*s3.Options)) (*s3.ListMultipartUploadsOutput, error)
	ListObjectVersions(context.Context, *s3.ListObjectVersionsInput, ...func(*s3.Options)) (*s3.ListObjectVersionsOutput, error)
	DeleteObject(context.Context, *s3.DeleteObjectInput, ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
}
type Presigner interface {
	PresignUploadPart(context.Context, *s3.UploadPartInput, ...func(*s3.PresignOptions)) (*v4.PresignedHTTPRequest, error)
	PresignGetObject(context.Context, *s3.GetObjectInput, ...func(*s3.PresignOptions)) (*v4.PresignedHTTPRequest, error)
}
type S3BlobStore struct {
	settings config.StorageSettings
	client   S3API
	signer   Presigner
}

var _ BlobStore = (*S3BlobStore)(nil)

type idleReadConn struct{ net.Conn }

func (c *idleReadConn) Read(p []byte) (int, error) {
	if err := c.Conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return 0, err
	}
	return c.Conn.Read(p)
}
func storageHTTPClient() *http.Client {
	return storageHTTPClientWithTransport(http.DefaultTransport.(*http.Transport).Clone())
}
func storageHTTPClientWithTransport(tr *http.Transport) *http.Client {
	dialer := &net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}
	tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := dialer.DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return &idleReadConn{conn}, nil
	}
	tr.TLSHandshakeTimeout = 3 * time.Second
	tr.ResponseHeaderTimeout = 30 * time.Second
	return &http.Client{Transport: tr, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
}
func NewS3(ctx context.Context, settings config.StorageSettings) (*S3BlobStore, error) {
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	options := []func(*awscfg.LoadOptions) error{
		awscfg.WithRegion(settings.Region),
		awscfg.WithRetryMaxAttempts(4),
		// Match the established multipart protocol: clients upload opaque bytes and
		// the worker independently verifies their declared SHA-256 and exact size.
		// Unrequested optional checksum headers must not change the SDK contract.
		awscfg.WithRequestChecksumCalculation(aws.RequestChecksumCalculationWhenRequired),
		awscfg.WithResponseChecksumValidation(aws.ResponseChecksumValidationWhenRequired),
	}
	if settings.AccessKey != "" {
		options = append(options, awscfg.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(settings.AccessKey, settings.SecretKey, settings.SessionToken)))
	}
	cfg, err := awscfg.LoadDefaultConfig(ctx, options...)
	if err != nil {
		return nil, normalize(err)
	}
	// Resolve the official AWS_CA_BUNDLE before installing bounded networking.
	// A plain custom client during LoadDefaultConfig would bypass SDK CA support.
	if builder, ok := cfg.HTTPClient.(*awshttp.BuildableClient); ok {
		cfg.HTTPClient = storageHTTPClientWithTransport(builder.GetTransport())
	} else if cfg.HTTPClient == nil {
		cfg.HTTPClient = storageHTTPClient()
	} else {
		return nil, Failure("storage_misconfigured", true, false)
	}

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		if settings.Endpoint != "" {
			o.BaseEndpoint = aws.String(settings.Endpoint)
			o.UsePathStyle = true
		}
	})
	signerClient := client
	if settings.PublicEndpoint != "" {
		signerClient = s3.NewFromConfig(cfg, func(o *s3.Options) { o.BaseEndpoint = aws.String(settings.PublicEndpoint); o.UsePathStyle = true })
	}
	return &S3BlobStore{settings: settings, client: client, signer: s3.NewPresignClient(signerClient)}, nil
}
func NewWithClients(settings config.StorageSettings, client S3API, signer Presigner) (*S3BlobStore, error) {
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	if client == nil || signer == nil {
		return nil, Failure("storage_misconfigured", true, false)
	}
	return &S3BlobStore{settings: settings, client: client, signer: signer}, nil
}
func (s *S3BlobStore) Protocol() string { return MultipartProtocol }

// Config returns the fixed operator-selected backend configuration.
func (s *S3BlobStore) Config() config.StorageSettings { return s.settings }
func normalize(err error) error {
	if err == nil {
		return nil
	}
	var failure *StorageFailure
	if errors.As(err, &failure) {
		return failure
	}
	var api smithy.APIError
	if errors.As(err, &api) {
		switch api.ErrorCode() {
		case "NoSuchKey", "NoSuchUpload", "NoSuchVersion", "404", "NotFound":
			return Failure("storage_missing", false, false)
		case "AccessDenied", "InvalidAccessKeyId", "SignatureDoesNotMatch", "403":
			return Failure("storage_misconfigured", true, false)
		case "InvalidPart", "InvalidPartOrder", "EntityTooSmall":
			return Failure("invalid_parts", false, false)
		}
	}
	return Failure("storage_unavailable", true, true)
}
func requiredVersion(version *string) (string, error) {
	if version == nil || *version == "" || *version == "null" {
		return "", Failure("storage_misconfigured", true, false)
	}
	return *version, nil
}
func (s *S3BlobStore) recoverObject(ctx context.Context, key string) (*StoredObject, error) {
	result, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(s.settings.Bucket), Key: aws.String(key)})
	if err != nil {
		normalized := AsFailure(normalize(err))
		if normalized.Code == "storage_missing" {
			return nil, nil
		}
		return nil, normalized
	}
	if result == nil {
		return nil, Failure("storage_unavailable", true, true)
	}
	version, err := requiredVersion(result.VersionId)
	if err != nil {
		return nil, err
	}
	return &StoredObject{Key: key, Version: version}, nil
}
func (s *S3BlobStore) Check(ctx context.Context) error {
	result, err := s.client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: aws.String(s.settings.Bucket)})
	if err != nil {
		return normalize(err)
	}
	if result == nil || result.Status != types.BucketVersioningStatusEnabled {
		return Failure("storage_misconfigured", true, false)
	}
	random := make([]byte, 16)
	if _, err = rand.Read(random); err != nil {
		return Failure("storage_unavailable", true, true)
	}
	prefix := strings.Trim(s.settings.Prefix, "/")
	key := "readiness/" + hex.EncodeToString(random)
	if prefix != "" {
		key = prefix + "/" + key
	}
	_, err = s.recoverObject(ctx, key)
	return err
}
func (s *S3BlobStore) Start(ctx context.Context, key string) (UploadHandle, error) {
	result, err := s.client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: aws.String(s.settings.Bucket), Key: aws.String(key)})
	if err != nil {
		return UploadHandle{}, normalize(err)
	}
	if result == nil || result.UploadId == nil || *result.UploadId == "" {
		return UploadHandle{}, Failure("storage_unavailable", true, true)
	}
	return UploadHandle{ID: *result.UploadId, Key: key}, nil
}
func (s *S3BlobStore) Parts(ctx context.Context, handle UploadHandle) ([]UploadedPart, error) {
	parts := []UploadedPart{}
	var marker *string
	seen := map[string]bool{}
	for {
		result, err := s.client.ListParts(ctx, &s3.ListPartsInput{Bucket: aws.String(s.settings.Bucket), Key: aws.String(handle.Key), UploadId: aws.String(handle.ID), PartNumberMarker: marker})
		if err != nil {
			return nil, normalize(err)
		}
		if result == nil {
			return nil, Failure("storage_unavailable", true, true)
		}
		for _, p := range result.Parts {
			if p.PartNumber == nil || p.Size == nil || p.ETag == nil || *p.PartNumber < 1 || *p.Size < 0 || *p.ETag == "" {
				return nil, Failure("storage_unavailable", true, true)
			}
			parts = append(parts, UploadedPart{Number: int(*p.PartNumber), ETag: *p.ETag, Size: *p.Size})
		}
		if !aws.ToBool(result.IsTruncated) {
			break
		}
		next := aws.ToString(result.NextPartNumberMarker)
		if next == "" || seen[next] {
			return nil, Failure("storage_unavailable", true, true)
		}
		seen[next] = true
		marker = result.NextPartNumberMarker
	}
	sort.Slice(parts, func(i, j int) bool { return parts[i].Number < parts[j].Number })
	return parts, nil
}
func (s *S3BlobStore) grant(request *v4.PresignedHTTPRequest, expiresAt float64) (TransferGrant, error) {
	if request == nil {
		return TransferGrant{}, Failure("storage_unavailable", true, true)
	}
	parsed, err := url.Parse(request.URL)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" {
		return TransferGrant{}, Failure("insecure_storage_grant", false, false)
	}
	host := parsed.Hostname()
	local := host == "localhost" || host == "testserver"
	if ip := net.ParseIP(host); ip != nil {
		local = local || ip.IsLoopback()
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && local && s.settings.AllowLocalHTTP) {
		return TransferGrant{}, Failure("insecure_storage_grant", false, false)
	}
	query := parsed.Query()
	if len(query["X-Amz-Date"]) != 1 || len(query["X-Amz-Expires"]) != 1 {
		return TransferGrant{}, Failure("storage_unavailable", true, true)
	}
	signed, err := time.Parse("20060102T150405Z", query.Get("X-Amz-Date"))
	if err != nil {
		return TransferGrant{}, Failure("storage_unavailable", true, true)
	}
	seconds, err := strconv.ParseInt(query.Get("X-Amz-Expires"), 10, 64)
	if err != nil || seconds < 1 || seconds > 3600 {
		return TransferGrant{}, Failure("storage_unavailable", true, true)
	}
	expiresAt = float64(signed.Unix() + seconds)
	headers := map[string]string{}
	for key, values := range request.SignedHeader {
		if strings.EqualFold(key, "Host") {
			continue
		}
		headers[http.CanonicalHeaderKey(key)] = strings.Join(values, ",")
	}
	return TransferGrant{URL: request.URL, Headers: headers, ExpiresAt: expiresAt}, nil
}
func grantSeconds(seconds int) error {
	if seconds < 1 || seconds > 3600 {
		return Failure("storage_misconfigured", true, false)
	}
	return nil
}
func (s *S3BlobStore) UploadGrant(ctx context.Context, handle UploadHandle, number int, size int64, expiresAt float64, seconds int) (TransferGrant, error) {
	if err := grantSeconds(seconds); err != nil {
		return TransferGrant{}, err
	}
	if number < 1 || number > 10000 || size < 0 {
		return TransferGrant{}, Failure("invalid_part_number", false, false)
	}
	request, err := s.signer.PresignUploadPart(ctx, &s3.UploadPartInput{Bucket: aws.String(s.settings.Bucket), Key: aws.String(handle.Key), UploadId: aws.String(handle.ID), PartNumber: aws.Int32(int32(number)), ContentLength: aws.Int64(size)}, func(o *s3.PresignOptions) {
		o.Expires = time.Duration(seconds) * time.Second
		if size == 0 {
			// The official SigV4 signer omits Content-Length for zero. Bind the
			// empty payload cryptographically using its supported hash middleware.
			o.ClientOptions = append(o.ClientOptions, func(options *s3.Options) {
				options.APIOptions = append(options.APIOptions, func(stack *middleware.Stack) error {
					if err := v4.RemoveComputePayloadSHA256Middleware(stack); err != nil {
						return err
					}
					if err := v4.AddComputePayloadSHA256Middleware(stack); err != nil {
						return err
					}
					return v4.AddContentSHA256HeaderMiddleware(stack)
				})
			})
		}
	})
	if err != nil {
		return TransferGrant{}, normalize(err)
	}
	grant, err := s.grant(request, expiresAt)
	if err != nil {
		return TransferGrant{}, err
	}
	grant.Headers["Content-Length"] = strconv.FormatInt(size, 10)
	return grant, nil
}
func (s *S3BlobStore) Complete(ctx context.Context, handle UploadHandle, size, partSize int64) (StoredObject, error) {
	if existing, err := s.recoverObject(ctx, handle.Key); err != nil {
		return StoredObject{}, err
	} else if existing != nil {
		return *existing, nil
	}
	if size < 0 || partSize <= 0 {
		return StoredObject{}, Failure("invalid_parts", false, false)
	}
	parts, err := s.Parts(ctx, handle)
	if err != nil {
		return StoredObject{}, err
	}
	count := int64(1)
	if size > 0 {
		count = 1 + (size-1)/partSize
	}
	if int64(len(parts)) != count || count > 10000 {
		return StoredObject{}, Failure("invalid_parts", false, false)
	}
	completed := make([]types.CompletedPart, 0, len(parts))
	for i, p := range parts {
		expected, err := PartSizeFor(i+1, size, partSize)
		if err != nil || p.Number != i+1 || p.Size != expected {
			return StoredObject{}, Failure("invalid_parts", false, false)
		}
		completed = append(completed, types.CompletedPart{PartNumber: aws.Int32(int32(p.Number)), ETag: aws.String(p.ETag)})
	}
	result, err := s.client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{Bucket: aws.String(s.settings.Bucket), Key: aws.String(handle.Key), UploadId: aws.String(handle.ID), MultipartUpload: &types.CompletedMultipartUpload{Parts: completed}})
	if err != nil {
		return StoredObject{}, normalize(err)
	}
	if result == nil {
		return StoredObject{}, Failure("storage_unavailable", true, true)
	}
	version, err := requiredVersion(result.VersionId)
	if err != nil {
		return StoredObject{}, err
	}
	return StoredObject{Key: handle.Key, Version: version}, nil
}
func (s *S3BlobStore) Verify(ctx context.Context, stored StoredObject, size int64, digest string) (Verification, error) {
	result, err := s.client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(s.settings.Bucket), Key: aws.String(stored.Key), VersionId: aws.String(stored.Version)})
	if err != nil {
		return Verification{}, normalize(err)
	}
	if result == nil || result.Body == nil {
		return Verification{}, Failure("storage_unavailable", true, true)
	}
	defer result.Body.Close()
	h := sha256.New()
	n, err := io.Copy(h, result.Body)
	if err != nil {
		return Verification{}, normalize(err)
	}
	actual := Verification{Size: n, SHA256: hex.EncodeToString(h.Sum(nil))}
	if actual.Size != size || actual.SHA256 != digest {
		return Verification{}, Failure("verification_failed", false, false)
	}
	return actual, nil
}
func (s *S3BlobStore) DownloadGrant(ctx context.Context, stored StoredObject, expiresAt float64, seconds int) (TransferGrant, error) {
	if err := grantSeconds(seconds); err != nil {
		return TransferGrant{}, err
	}
	request, err := s.signer.PresignGetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(s.settings.Bucket), Key: aws.String(stored.Key), VersionId: aws.String(stored.Version)}, func(o *s3.PresignOptions) { o.Expires = time.Duration(seconds) * time.Second })
	if err != nil {
		return TransferGrant{}, normalize(err)
	}
	return s.grant(request, expiresAt)
}
func (s *S3BlobStore) abortConfirm(ctx context.Context, key, id string) error {
	_, err := s.client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{Bucket: aws.String(s.settings.Bucket), Key: aws.String(key), UploadId: aws.String(id)})
	if err != nil && AsFailure(normalize(err)).Code != "storage_missing" {
		return normalize(err)
	}
	_, err = s.client.ListParts(ctx, &s3.ListPartsInput{Bucket: aws.String(s.settings.Bucket), Key: aws.String(key), UploadId: aws.String(id)})
	if err != nil {
		failure := AsFailure(normalize(err))
		if failure.Code == "storage_missing" {
			return nil
		}
		return failure
	}
	return Failure("cleanup_incomplete", true, false)
}
func (s *S3BlobStore) eachUpload(ctx context.Context, key string, visit func(types.MultipartUpload) error) error {
	var keyMarker, uploadMarker *string
	seen := map[string]bool{}
	for {
		result, err := s.client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: aws.String(s.settings.Bucket), Prefix: aws.String(key), KeyMarker: keyMarker, UploadIdMarker: uploadMarker})
		if err != nil {
			return normalize(err)
		}
		if result == nil {
			return Failure("storage_unavailable", true, true)
		}
		for _, item := range result.Uploads {
			if aws.ToString(item.Key) == key {
				if err = visit(item); err != nil {
					return err
				}
			}
		}
		if !aws.ToBool(result.IsTruncated) {
			return nil
		}
		marker := fmt.Sprintf("%s\x00%s", aws.ToString(result.NextKeyMarker), aws.ToString(result.NextUploadIdMarker))
		if aws.ToString(result.NextKeyMarker) == "" || seen[marker] {
			return Failure("storage_unavailable", true, true)
		}
		seen[marker] = true
		keyMarker = result.NextKeyMarker
		uploadMarker = result.NextUploadIdMarker
	}
}
func (s *S3BlobStore) eachVersion(ctx context.Context, key string, visit func(string) error) error {
	var keyMarker, versionMarker *string
	seen := map[string]bool{}
	for {
		result, err := s.client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: aws.String(s.settings.Bucket), Prefix: aws.String(key), KeyMarker: keyMarker, VersionIdMarker: versionMarker})
		if err != nil {
			return normalize(err)
		}
		if result == nil {
			return Failure("storage_unavailable", true, true)
		}
		for _, item := range result.Versions {
			if aws.ToString(item.Key) == key {
				if item.VersionId == nil || *item.VersionId == "" {
					return Failure("storage_unavailable", true, true)
				}
				if err = visit(*item.VersionId); err != nil {
					return err
				}
			}
		}
		for _, item := range result.DeleteMarkers {
			if aws.ToString(item.Key) == key {
				if item.VersionId == nil || *item.VersionId == "" {
					return Failure("storage_unavailable", true, true)
				}
				if err = visit(*item.VersionId); err != nil {
					return err
				}
			}
		}
		if !aws.ToBool(result.IsTruncated) {
			return nil
		}
		marker := fmt.Sprintf("%s\x00%s", aws.ToString(result.NextKeyMarker), aws.ToString(result.NextVersionIdMarker))
		if aws.ToString(result.NextKeyMarker) == "" || seen[marker] {
			return Failure("storage_unavailable", true, true)
		}
		seen[marker] = true
		keyMarker = result.NextKeyMarker
		versionMarker = result.NextVersionIdMarker
	}
}
func (s *S3BlobStore) Cleanup(ctx context.Context, key string) error {
	if err := s.eachUpload(ctx, key, func(item types.MultipartUpload) error {
		if item.UploadId == nil || *item.UploadId == "" {
			return Failure("storage_unavailable", true, true)
		}
		return s.abortConfirm(ctx, key, *item.UploadId)
	}); err != nil {
		return err
	}
	if err := s.eachVersion(ctx, key, func(version string) error {
		_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(s.settings.Bucket), Key: aws.String(key), VersionId: aws.String(version)})
		return normalize(err)
	}); err != nil {
		return err
	}
	// Affirm absence after successful deletion. Provider uncertainty or any
	// remaining version/upload retains physical reclamation accounting.
	if err := s.eachUpload(ctx, key, func(types.MultipartUpload) error { return Failure("cleanup_incomplete", true, false) }); err != nil {
		return err
	}
	return s.eachVersion(ctx, key, func(string) error { return Failure("cleanup_incomplete", true, false) })
}
