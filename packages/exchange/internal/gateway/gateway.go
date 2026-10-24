// Package gateway implements the separately deployed private Exchange transfer backend.
package gateway

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/auth"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/config"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/service"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/storage"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/store"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/transfers"
)

const Base = "/internal/transfers/v1"
const MaxBodyBytes int64 = 16384

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
var receiptEncoding = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
var receiptSignature = regexp.MustCompile(`^[a-f0-9]{64}$`)

var receiptDomain = []byte("hf2l-exchange-gateway-put-v1\x00")

type Options struct {
	Audience string
	Now      func() time.Time
}

type backend struct {
	core         *service.Service
	engine       *transfers.Service
	settings     config.Settings
	identity     *auth.Authenticator
	provisioning *auth.Authenticator
	now          func() time.Time
	limit        int64
}

// New constructs only the private transfer API. It must never be mounted on the
// public Exchange listener. The listener must require and verify client certificates;
// the handler also checks verified TLS state before considering signed assertions.
func New(core *service.Service, engine *transfers.Service, settings config.Settings, options Options) (http.Handler, error) {
	if err := settings.Validate("server"); err != nil {
		return nil, err
	}
	if core == nil || core.DB == nil || engine == nil || engine.Storage == nil {
		return nil, fmt.Errorf("private gateway backend requires native service and transfers")
	}
	if options.Audience == "" {
		options.Audience = "hf2l-transfer"
	}
	if !settings.Auth.WorkloadsEnabled() || options.Audience == settings.Auth.WorkloadAudience {
		return nil, fmt.Errorf("private gateway backend requires a separate fixed transfer audience")
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	transferSettings := settings.Auth
	transferSettings.WorkloadAudience = options.Audience
	identity, err := auth.NewWithOptions(transferSettings, auth.Options{Now: now})
	if err != nil {
		return nil, err
	}
	provisioning, err := auth.NewWithOptions(settings.Auth, auth.Options{Now: now})
	if err != nil {
		return nil, err
	}
	limit := settings.MaxBodyBytes
	if limit > MaxBodyBytes {
		limit = MaxBodyBytes
	}
	return &backend{core: core, engine: engine, settings: settings, identity: identity,
		provisioning: provisioning, now: now, limit: limit}, nil
}

func (b *backend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := r.Header.Get("X-Request-ID")
	if !requestIDPattern.MatchString(requestID) {
		requestID = domain.NewID()
	}
	w.Header().Set("X-Request-ID", requestID)
	defer func() {
		if recover() != nil {
			slog.Error("private transfer request panic", "request_id", requestID)
			writeError(w, domain.Err(500, "internal_error"), requestID)
		}
	}()
	if r.TLS == nil {
		writeError(w, domain.Err(426, "https_required"), requestID)
		return
	}
	if len(r.TLS.VerifiedChains) == 0 {
		writeError(w, domain.Err(401, "invalid_backend_assertion"), requestID)
		return
	}
	if r.ContentLength < -1 {
		writeError(w, domain.Err(400, "invalid_content_length"), requestID)
		return
	}
	if r.ContentLength > b.limit {
		writeError(w, domain.Err(413, "request_too_large"), requestID)
		return
	}
	body := r.Body
	if body == nil {
		body = http.NoBody
	}
	raw, err := io.ReadAll(io.LimitReader(body, b.limit+1))
	if err != nil {
		writeError(w, domain.Err(400, "invalid_request"), requestID)
		return
	}
	if int64(len(raw)) > b.limit {
		writeError(w, domain.Err(413, "request_too_large"), requestID)
		return
	}
	result, err := b.dispatch(r, raw)
	if err != nil {
		var known *domain.Error
		var provider *storage.StorageFailure
		if !errors.As(err, &known) && !errors.As(err, &provider) {
			slog.Error("private transfer request failed", "request_id", requestID,
				"error_type", fmt.Sprintf("%T", err))
		}
		writeError(w, err, requestID)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(result)
}

func writeError(w http.ResponseWriter, err error, requestID string) {
	status, code := 500, "internal_error"
	headers := map[string]string{}
	var known *domain.Error
	var provider *storage.StorageFailure
	if errors.As(err, &known) {
		status, code = known.Status, known.Code
		headers = known.Headers
	} else if errors.As(err, &provider) {
		status, code = 409, provider.Code
		if provider.Retryable {
			status = 503
			headers["Retry-After"] = "3"
		}
	}
	for name, value := range headers {
		w.Header().Set(name, value)
	}
	w.Header().Set("X-Request-ID", requestID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(domain.Object{"error": domain.Object{
		"code": code, "detail": "", "request_id": requestID}})
}

func headerValues(h http.Header, name string) []string {
	var values []string
	for key, entries := range h {
		if strings.EqualFold(key, name) {
			values = append(values, entries...)
		}
	}
	return values
}

func (b *backend) boundary(r *http.Request, raw []byte, settlement bool, ids ...string) (string, string, domain.Object, error) {
	for _, name := range []string{"Authorization", "X-HF2L-Backend-Timestamp", "X-HF2L-TLS-Thumbprint", "X-HF2L-Backend-Signature"} {
		if len(headerValues(r.Header, name)) != 1 {
			return "", "", nil, domain.Err(401, "invalid_backend_assertion")
		}
	}
	for _, name := range []string{"Cookie", "Proxy-Authorization", "X-Forwarded-Client-Cert"} {
		if len(headerValues(r.Header, name)) != 0 {
			return "", "", nil, domain.Err(400, "forbidden_transfer_credentials")
		}
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		return "", "", nil, domain.Err(400, "unexpected_transfer_query")
	}
	if strings.Contains(r.URL.EscapedPath(), "%") {
		return "", "", nil, domain.Err(400, "noncanonical_transfer_target")
	}
	for _, id := range ids {
		if !identifier.MatchString(id) {
			return "", "", nil, domain.Err(422, "invalid_resource_identifier")
		}
	}
	authorization := headerValues(r.Header, "Authorization")[0]
	thumbprint, err := auth.VerifiedBackendThumbprint(b.settings.Auth, r.Method, r.URL.Path, authorization, r.Header, b.now())
	if err != nil {
		return "", "", nil, err
	}
	if len(raw) != 0 {
		mediaType := strings.TrimSpace(strings.SplitN(r.Header.Get("Content-Type"), ";", 2)[0])
		if !strings.EqualFold(mediaType, "application/json") {
			return "", "", nil, domain.Err(415, "json_required")
		}
	}
	body := domain.Object{}
	if len(raw) != 0 {
		body, err = strictObject(raw)
		if err != nil {
			return "", "", nil, err
		}
	}
	if !settlement && len(body) != 0 {
		return "", "", nil, domain.Err(422, "invalid_request")
	}
	if err := store.CheckRevision(r.Context(), b.core.DB); err != nil {
		var known *domain.Error
		if errors.As(err, &known) {
			return "", "", nil, &domain.Error{Status: 503, Code: known.Code, Detail: known.Code, Headers: map[string]string{"Retry-After": "3"}}
		}
		return "", "", nil, &domain.Error{Status: 503, Code: "database_unavailable", Detail: "database_unavailable", Headers: map[string]string{"Retry-After": "3"}}
	}
	return authorization, thumbprint, body, nil
}

func (b *backend) principal(r *http.Request, raw []byte, sid string, ids ...string) (domain.Principal, string, error) {
	all := append([]string{sid}, ids...)
	authorization, thumbprint, _, err := b.boundary(r, raw, false, all...)
	if err != nil {
		return domain.Principal{}, "", err
	}
	p, err := b.identity.AuthenticateTransfer(r.Context(), authorization, thumbprint)
	if err != nil {
		return domain.Principal{}, "", err
	}
	if p.Workload == nil {
		return domain.Principal{}, "", domain.Err(401, "workload_identity_required")
	}
	if p.Workload.SpaceID != sid {
		return domain.Principal{}, "", domain.Err(404, "resource_not_found")
	}
	if _, err = b.core.VerifyWorkloadGrant(r.Context(), p, sid); err != nil {
		return domain.Principal{}, "", err
	}
	return p, authorization, nil
}

func (b *backend) dispatch(r *http.Request, raw []byte) (domain.Object, error) {
	if r.Method != http.MethodPost {
		if matchPath(r.URL.Path) != nil {
			return nil, &domain.Error{Status: 405, Code: "http_error", Headers: map[string]string{"Allow": "POST"}}
		}
		return nil, domain.Err(404, "not_found")
	}
	route := matchPath(r.URL.Path)
	if route == nil {
		return nil, domain.Err(404, "not_found")
	}
	switch route["operation"] {
	case "settle":
		authorization, thumbprint, body, err := b.boundary(r, raw, true)
		if err != nil {
			return nil, err
		}
		if len(body) != 1 {
			return nil, domain.Err(422, "invalid_request")
		}
		receipt, ok := body["receipt"]
		if !ok {
			return nil, domain.Err(422, "invalid_request")
		}
		handle, err := openReceipt(b.settings.Auth.TrustedBackendSecret, receipt, authorization, thumbprint)
		if err != nil {
			return nil, err
		}
		settled, err := b.engine.FinishGatewayPut(r.Context(), handle)
		return domain.Object{"settled": settled}, err
	case "storage":
		authorization, _, _, err := b.boundary(r, raw, false)
		if err != nil {
			return nil, err
		}
		p, err := b.provisioning.Authenticate(r.Context(), authorization, false, "")
		if err != nil {
			return nil, err
		}
		if p.Workload != nil || !contains(b.settings.Auth.ProvisioningPrincipalIDs, p.ID) {
			return nil, domain.Err(403, "provisioning_principal_required")
		}
		s3, ok := b.engine.Storage.(*storage.S3BlobStore)
		if !ok {
			return nil, domain.Err(503, "storage_backend_unavailable")
		}
		actual := namespace(s3.Config())
		if !equalNamespace(actual, namespace(b.settings.Storage)) {
			return nil, domain.Err(503, "storage_backend_mismatch")
		}
		if err = s3.Check(r.Context()); err != nil {
			return nil, err
		}
		actual["protocol"], actual["versioning"], actual["checked"] = s3.Protocol(), "Enabled", true
		return actual, nil
	case "authorize":
		p, _, err := b.principal(r, raw, route["space"])
		if err != nil {
			return nil, err
		}
		return b.core.VerifyWorkloadGrant(r.Context(), p, route["space"])
	case "grant", "begin":
		number, err := strconv.Atoi(route["number"])
		if err != nil {
			return nil, domain.Err(422, "invalid_request")
		}
		if number < 1 || number > 10000 {
			return nil, domain.Err(422, "invalid_part_number")
		}
		p, authorization, err := b.principal(r, raw, route["space"], route["record"], route["attachment"])
		if err != nil {
			return nil, err
		}
		if route["operation"] == "grant" {
			result, err := b.engine.Grants(r.Context(), route["space"], route["record"], route["attachment"], p, []int{number})
			if err != nil {
				return nil, err
			}
			entries, ok := objects(result["grants"])
			if !ok || len(entries) != 1 {
				return nil, domain.Err(503, "invalid_origin_descriptor")
			}
			got, ok := domain.Int64(entries[0]["number"])
			if !ok || got != int64(number) {
				return nil, domain.Err(503, "invalid_origin_descriptor")
			}
			return entries[0], nil
		}
		handle, grant, err := b.engine.BeginGatewayPut(r.Context(), p, route["space"], route["record"], route["attachment"], number)
		if err != nil {
			return nil, err
		}
		receipt, err := sealReceipt(b.settings.Auth.TrustedBackendSecret, receiptPayload(p, authorization, handle))
		if err != nil {
			return nil, err
		}
		return domain.Object{"receipt": receipt, "grant": grant}, nil
	case "download":
		p, _, err := b.principal(r, raw, route["space"], route["record"], route["attachment"])
		if err != nil {
			return nil, err
		}
		return b.engine.Download(r.Context(), route["space"], route["record"], route["attachment"], p)
	}
	return nil, domain.Err(404, "not_found")
}

func matchPath(path string) map[string]string {
	if path == Base+"/settle" {
		return map[string]string{"operation": "settle"}
	}
	if path == Base+"/storage/check" {
		return map[string]string{"operation": "storage"}
	}
	if !strings.HasPrefix(path, Base+"/spaces/") {
		return nil
	}
	parts := strings.Split(strings.TrimPrefix(path, Base+"/spaces/"), "/")
	if len(parts) == 2 && parts[1] == "authorize" {
		return map[string]string{"operation": "authorize", "space": parts[0]}
	}
	if len(parts) == 8 && parts[1] == "records" && parts[3] == "attachments" && parts[5] == "parts" && (parts[7] == "grant" || parts[7] == "begin") {
		return map[string]string{"operation": parts[7], "space": parts[0], "record": parts[2], "attachment": parts[4], "number": parts[6]}
	}
	if len(parts) == 6 && parts[1] == "records" && parts[3] == "attachments" && parts[5] == "download" {
		return map[string]string{"operation": "download", "space": parts[0], "record": parts[2], "attachment": parts[4]}
	}
	return nil
}

func namespace(c config.StorageSettings) domain.Object {
	return domain.Object{"endpoint": strings.TrimRight(c.Endpoint, "/"), "bucket": c.Bucket, "prefix": strings.Trim(c.Prefix, "/"), "region": c.Region}
}

func equalNamespace(a, b domain.Object) bool {
	for _, k := range []string{"endpoint", "bucket", "prefix", "region"} {
		if a[k] != b[k] {
			return false
		}
	}
	return true
}

func contains(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}

func objects(value any) ([]domain.Object, bool) {
	switch values := value.(type) {
	case []domain.Object:
		return values, true
	case []any:
		out := make([]domain.Object, len(values))
		for i, value := range values {
			obj, ok := value.(map[string]any)
			if !ok {
				return nil, false
			}
			out[i] = obj
		}
		return out, true
	default:
		return nil, false
	}
}

// Kept as a separate verifier so every accepted request is bounded and
// duplicate names cannot be interpreted differently across security layers.
func strictObject(raw []byte) (domain.Object, error) {
	if !utf8.Valid(raw) {
		return nil, domain.Err(422, "invalid_request")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	value, err := readJSON(dec, 0)
	if err != nil {
		return nil, domain.Err(422, "invalid_request")
	}
	if _, err = dec.Token(); err != io.EOF {
		return nil, domain.Err(422, "invalid_request")
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, domain.Err(422, "invalid_request")
	}
	return object, nil
}

func readJSON(dec *json.Decoder, depth int) (any, error) {
	if depth > 64 {
		return nil, fmt.Errorf("JSON nesting limit")
	}
	token, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			object := domain.Object{}
			for dec.More() {
				key, err := dec.Token()
				if err != nil {
					return nil, err
				}
				name, ok := key.(string)
				if !ok {
					return nil, fmt.Errorf("JSON object key")
				}
				if _, duplicate := object[name]; duplicate {
					return nil, fmt.Errorf("duplicate JSON key")
				}
				child, err := readJSON(dec, depth+1)
				if err != nil {
					return nil, err
				}
				object[name] = child
			}
			close, err := dec.Token()
			if err != nil || close != json.Delim('}') {
				return nil, fmt.Errorf("JSON object closing")
			}
			return object, nil
		case '[':
			array := []any{}
			for dec.More() {
				child, err := readJSON(dec, depth+1)
				if err != nil {
					return nil, err
				}
				array = append(array, child)
			}
			close, err := dec.Token()
			if err != nil || close != json.Delim(']') {
				return nil, fmt.Errorf("JSON array closing")
			}
			return array, nil
		}
		return nil, fmt.Errorf("unexpected JSON delimiter")
	case json.Number:
		if _, ok := domain.Float(value); !ok {
			return nil, fmt.Errorf("nonfinite JSON number")
		}
	}
	return token, nil
}

func receiptPayload(p domain.Principal, authorization string, h transfers.GatewayPutHandle) domain.Object {
	digest := sha256.Sum256([]byte(authorization))
	w := p.Workload
	return domain.Object{
		"version": int64(1), "authorization_sha256": hex.EncodeToString(digest[:]),
		"owner": domain.Object{"principal_id": p.ID, "subject": p.Subject, "grant_id": w.GrantID,
			"space_id": w.SpaceID, "job_id": w.JobID, "attempt_id": w.AttemptID, "component_id": w.ComponentID,
			"epoch": w.Epoch, "certificate_thumbprint": w.CertificateThumbprint},
		"put": domain.Object{"space_id": h.SpaceID, "record_id": h.RecordID, "attachment_id": h.AttachmentID,
			"attempt_id": h.AttemptID, "object_key": h.ObjectKey, "upload_id": h.UploadID,
			"part_number": h.PartNumber, "token": h.Token},
	}
}

func sealReceipt(secret string, payload domain.Object) (string, error) {
	raw, err := domain.CanonicalASCIIJSON(payload)
	if err != nil {
		return "", domain.Err(503, "invalid_origin_mutation_fence")
	}
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(receiptDomain)
	_, _ = mac.Write([]byte(encoded))
	receipt := encoded + "." + hex.EncodeToString(mac.Sum(nil))
	if len(receipt) > int(MaxBodyBytes)-64 {
		return "", domain.Err(503, "gateway_put_receipt_too_large")
	}
	return receipt, nil
}

func exactKeys(object domain.Object, names ...string) bool {
	if len(object) != len(names) {
		return false
	}
	for _, name := range names {
		if _, ok := object[name]; !ok {
			return false
		}
	}
	return true
}

func asObject(value any) (domain.Object, bool) {
	object, ok := value.(map[string]any)
	return object, ok
}

func boundedString(value any, max int) (string, bool) {
	text, ok := value.(string)
	return text, ok && utf8.ValidString(text) && utf8.RuneCountInString(text) >= 1 && utf8.RuneCountInString(text) <= max
}

func openReceipt(secret string, value any, authorization, thumbprint string) (transfers.GatewayPutHandle, error) {
	invalid := func() (transfers.GatewayPutHandle, error) {
		return transfers.GatewayPutHandle{}, domain.Err(401, "invalid_gateway_put_receipt")
	}
	text, ok := value.(string)
	if !ok || len(text) < 1 || len(text) > int(MaxBodyBytes)-64 {
		return invalid()
	}
	parts := strings.Split(text, ".")
	if len(parts) != 2 || !receiptEncoding.MatchString(parts[0]) || !receiptSignature.MatchString(parts[1]) {
		return invalid()
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(receiptDomain)
	_, _ = mac.Write([]byte(parts[0]))
	signature, err := hex.DecodeString(parts[1])
	if err != nil || !hmac.Equal(signature, mac.Sum(nil)) {
		return invalid()
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return invalid()
	}
	payload, err := strictObject(raw)
	if err != nil || !exactKeys(payload, "version", "authorization_sha256", "owner", "put") {
		return invalid()
	}
	version, ok := domain.Int64(payload["version"])
	if !ok || version != 1 {
		return invalid()
	}
	digest := sha256.Sum256([]byte(authorization))
	authDigest, ok := payload["authorization_sha256"].(string)
	if !ok || !hmac.Equal([]byte(authDigest), []byte(hex.EncodeToString(digest[:]))) {
		return invalid()
	}
	owner, ok := asObject(payload["owner"])
	if !ok || !exactKeys(owner, "principal_id", "subject", "grant_id", "space_id", "job_id", "attempt_id", "component_id", "epoch", "certificate_thumbprint") {
		return invalid()
	}
	for name, value := range owner {
		if name != "epoch" {
			if _, ok := boundedString(value, 256); !ok {
				return invalid()
			}
		}
	}
	epoch, ok := domain.Int64(owner["epoch"])
	if !ok || epoch < 1 {
		return invalid()
	}
	ownerThumb, _ := owner["certificate_thumbprint"].(string)
	if !hmac.Equal([]byte(ownerThumb), []byte(thumbprint)) {
		return invalid()
	}
	put, ok := asObject(payload["put"])
	if !ok || !exactKeys(put, "space_id", "record_id", "attachment_id", "attempt_id", "object_key", "upload_id", "part_number", "token") {
		return invalid()
	}
	fields := map[string]string{}
	for _, name := range []string{"space_id", "record_id", "attachment_id", "attempt_id"} {
		text, ok := put[name].(string)
		if !ok || !identifier.MatchString(text) {
			return invalid()
		}
		fields[name] = text
	}
	for _, name := range []string{"object_key", "upload_id", "token"} {
		text, ok := boundedString(put[name], 4096)
		if !ok {
			return invalid()
		}
		fields[name] = text
	}
	number, ok := domain.Int64(put["part_number"])
	if !ok || number < 1 || number > 10000 || fields["space_id"] != owner["space_id"] ||
		!strings.HasPrefix(fields["token"], "gateway-put-"+strconv.FormatInt(number, 10)+"-") {
		return invalid()
	}
	return transfers.GatewayPutHandle{SpaceID: fields["space_id"], RecordID: fields["record_id"],
		AttachmentID: fields["attachment_id"], AttemptID: fields["attempt_id"], ObjectKey: fields["object_key"],
		UploadID: fields["upload_id"], PartNumber: int(number), Token: fields["token"]}, nil
}
