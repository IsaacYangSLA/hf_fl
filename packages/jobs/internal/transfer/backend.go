package transfer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
)

// GatewayBackendSettings describes the independent Exchange service's private
// gateway adapter. This is not the public Exchange listener.
type GatewayBackendSettings struct {
	Endpoint          string
	BackendSecret     string
	CAFile            string
	ClientCertificate string
	ClientKey         string
	Timeout           time.Duration
	Client            *http.Client
	Clock             func() time.Time
}
type HTTPGatewayBackend struct {
	settings GatewayBackendSettings
	client   *http.Client
}

func NewHTTPGatewayBackend(s GatewayBackendSettings) (*HTTPGatewayBackend, error) {
	endpoint, e := serviceEndpoint(s.Endpoint)
	if e != nil {
		return nil, e
	}
	s.Endpoint = endpoint
	if len([]byte(s.BackendSecret)) < 32 {
		return nil, errors.New("private backend assertion secret required")
	}
	if s.Timeout == 0 {
		s.Timeout = 60 * time.Second
	}
	if s.Timeout <= 0 {
		return nil, errors.New("positive backend timeout required")
	}
	if s.Clock == nil {
		s.Clock = time.Now
	}
	client := s.Client
	if client == nil {
		client, e = newClient(s.CAFile, s.ClientCertificate, s.ClientKey, s.Timeout)
		if e != nil {
			return nil, e
		}
	}
	return &HTTPGatewayBackend{s, client}, nil
}
func (b *HTTPGatewayBackend) Close() { b.client.CloseIdleConnections() }
func (b *HTTPGatewayBackend) call(ctx context.Context, id WorkloadIdentity, path string, payload any) (map[string]json.RawMessage, error) {
	if id.Token == "" || !thumbprintRE.MatchString(id.CertificateThumbprint) {
		return nil, domain.Err(401, "invalid_workload_token")
	}
	data, e := domain.CanonicalJSON(payload)
	if e != nil {
		return nil, e
	}
	target := "/internal/transfers/v1" + path
	req, e := http.NewRequestWithContext(ctx, "POST", b.settings.Endpoint+target, bytes.NewReader(data))
	if e != nil {
		return nil, e
	}
	authorization := "Bearer " + id.Token
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authorization)
	req.Header.Set("Accept-Encoding", "identity")
	assertion, e := BackendAssertionHeaders(b.settings.BackendSecret, "POST", target, authorization, id.CertificateThumbprint, b.settings.Clock())
	if e != nil {
		return nil, e
	}
	for k, v := range assertion {
		req.Header[k] = v
	}
	// Never retry begin or settle: an absent acknowledgement is not evidence
	// that the provider mutation did not occur.
	response, e := b.client.Do(req)
	if e != nil {
		return nil, domain.Err(503, "exchange_gateway_backend_unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		return nil, domain.Err(502, "unsafe_backend_response")
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if e != nil || len(raw) > 1<<20 {
		return nil, domain.Err(502, "invalid_backend_response")
	}
	var result map[string]json.RawMessage
	if json.Unmarshal(raw, &result) != nil || result == nil {
		return nil, domain.Err(502, "invalid_backend_response")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var envelope struct {
			Code string `json:"code"`
		}
		if json.Unmarshal(result["error"], &envelope) != nil || !errorCodeRE.MatchString(envelope.Code) {
			return nil, domain.Err(503, "exchange_gateway_backend_unavailable")
		}
		return nil, domain.Err(response.StatusCode, envelope.Code)
	}
	return result, nil
}

var errorCodeRE = regexp.MustCompile("^[a-z][a-z0-9_]{0,127}$")

func gatewayPath(space, record, attachment string, number int) (string, error) {
	for _, v := range []string{space, record, attachment} {
		if e := identifier(v); e != nil {
			return "", e
		}
	}
	path := "/spaces/" + space + "/records/" + record + "/attachments/" + attachment
	if number != 0 {
		if number < 1 || number > 10000 {
			return "", domain.Err(422, "invalid_part_number")
		}
		path += "/parts/" + strconv.Itoa(number)
	}
	return path, nil
}
func decodeGrant(raw map[string]json.RawMessage) (OriginGrant, error) {
	for _, field := range []string{"size", "expires_at"} {
		var value any
		decoder := json.NewDecoder(bytes.NewReader(raw[field]))
		decoder.UseNumber()
		if decoder.Decode(&value) != nil {
			return OriginGrant{}, domain.Err(502, "invalid_origin_descriptor")
		}
		number, ok := value.(json.Number)
		if !ok {
			return OriginGrant{}, domain.Err(502, "invalid_origin_descriptor")
		}
		if field == "size" {
			if _, err := number.Int64(); err != nil {
				return OriginGrant{}, domain.Err(502, "invalid_origin_descriptor")
			}
		} else if _, err := number.Float64(); err != nil {
			return OriginGrant{}, domain.Err(502, "invalid_origin_descriptor")
		}
	}

	for _, key := range []string{"url", "expires_at", "size"} {
		if _, ok := raw[key]; !ok {
			return OriginGrant{}, domain.Err(502, "invalid_origin_descriptor")
		}
	}
	data, e := json.Marshal(raw)
	if e != nil {
		return OriginGrant{}, e
	}
	var grant OriginGrant
	if json.Unmarshal(data, &grant) != nil {
		return grant, domain.Err(502, "invalid_origin_descriptor")
	}
	return grant, nil
}
func (b *HTTPGatewayBackend) Authorize(ctx context.Context, id WorkloadIdentity) error {
	if e := identifier(id.SpaceID); e != nil {
		return e
	}
	_, e := b.call(ctx, id, "/spaces/"+id.SpaceID+"/authorize", map[string]any{})
	return e
}
func (b *HTTPGatewayBackend) UploadGrant(ctx context.Context, id WorkloadIdentity, space, record, attachment string, number int) (OriginGrant, error) {
	path, e := gatewayPath(space, record, attachment, number)
	if e != nil {
		return OriginGrant{}, e
	}
	raw, e := b.call(ctx, id, path+"/grant", map[string]any{})
	if e != nil {
		return OriginGrant{}, e
	}
	return decodeGrant(raw)
}
func (b *HTTPGatewayBackend) BeginUpload(ctx context.Context, id WorkloadIdentity, space, record, attachment string, number int) (string, OriginGrant, error) {
	path, e := gatewayPath(space, record, attachment, number)
	if e != nil {
		return "", OriginGrant{}, e
	}
	raw, e := b.call(ctx, id, path+"/begin", map[string]any{})
	if e != nil {
		return "", OriginGrant{}, e
	}
	var receipt string
	var values map[string]json.RawMessage
	if json.Unmarshal(raw["receipt"], &receipt) != nil || receipt == "" || len(receipt) > 16384 || json.Unmarshal(raw["grant"], &values) != nil {
		return "", OriginGrant{}, domain.Err(502, "invalid_origin_mutation_fence")
	}
	grant, e := decodeGrant(values)
	return receipt, grant, e
}
func (b *HTTPGatewayBackend) FinishUpload(ctx context.Context, id WorkloadIdentity, receipt string) (bool, error) {
	if receipt == "" || len(receipt) > 16384 {
		return false, domain.Err(422, "invalid_origin_mutation_fence")
	}
	raw, e := b.call(ctx, id, "/settle", map[string]any{"receipt": receipt})
	if e != nil {
		return false, e
	}
	var settled bool
	if json.Unmarshal(raw["settled"], &settled) != nil {
		return false, domain.Err(502, "invalid_backend_response")
	}
	return settled, nil
}
func (b *HTTPGatewayBackend) DownloadGrant(ctx context.Context, id WorkloadIdentity, space, record, attachment string) (OriginGrant, error) {
	path, e := gatewayPath(space, record, attachment, 0)
	if e != nil {
		return OriginGrant{}, e
	}
	raw, e := b.call(ctx, id, path+"/download", map[string]any{})
	if e != nil {
		return OriginGrant{}, e
	}
	return decodeGrant(raw)
}

// CheckStorage qualifies the independent Exchange storage provider through the
// private adapter. The operator supplies its authenticated provisioning token;
// the caller cannot select another endpoint, bucket or prefix in this request.
func (b *HTTPGatewayBackend) CheckStorage(ctx context.Context, authorization, peerThumbprint string) (map[string]any, error) {
	token, e := bearer(authorization)
	if e != nil {
		return nil, e
	}
	raw, e := b.call(ctx, WorkloadIdentity{ExecutionBinding: ExecutionBinding{CertificateThumbprint: peerThumbprint}, Token: token}, "/storage/check", map[string]any{})
	if e != nil {
		return nil, e
	}
	data, e := json.Marshal(raw)
	if e != nil {
		return nil, e
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var result map[string]any
	if decoder.Decode(&result) != nil || result["checked"] != true || result["versioning"] != "Enabled" || result["protocol"] != "s3-multipart-v1" {
		return nil, domain.Err(502, "invalid_storage_attestation")
	}
	for _, key := range []string{"endpoint", "bucket", "prefix", "region"} {
		if _, ok := result[key].(string); !ok {
			return nil, domain.Err(502, "invalid_storage_attestation")
		}
	}
	return result, nil
}
