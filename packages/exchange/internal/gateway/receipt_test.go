package gateway

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/transfers"
)

func wantError(t *testing.T, err error, status int, code string) {
	t.Helper()
	var actual *domain.Error
	if !errors.As(err, &actual) || actual.Status != status || actual.Code != code {
		t.Fatalf("error = %T %v, want %d %s", err, err, status, code)
	}
}

func samplePayload() (domain.Object, string, string) {
	authorization, thumb := "Bearer fixture-original-authorization", strings.Repeat("a", 43)
	sum := sha256.Sum256([]byte(authorization))
	return domain.Object{
		"version": int64(1), "authorization_sha256": hex.EncodeToString(sum[:]),
		"owner": domain.Object{"principal_id": strings.Repeat("b", 64), "subject": "participant-a",
			"grant_id": "grant-a", "space_id": "space-a", "job_id": "job-a", "attempt_id": "attempt-a",
			"component_id": "component-a", "epoch": int64(1), "certificate_thumbprint": thumb},
		"put": domain.Object{"space_id": "space-a", "record_id": "record-a", "attachment_id": "attachment-a",
			"attempt_id": "attempt-a", "object_key": "private/object-a", "upload_id": "upload-a",
			"part_number": int64(1), "token": "gateway-put-1-unique-marker"},
	}, authorization, thumb
}

func TestPythonReceiptOracles(t *testing.T) {
	raw, err := os.ReadFile("testdata/python_receipts.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		SourceSHA256 string `json:"source_sha256"`
		Cases        []struct {
			Name, Secret, Authorization, Thumbprint, Receipt string
			Payload                                          domain.Object
			Put                                              transfers.GatewayPutHandle
		}
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err = dec.Decode(&fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.SourceSHA256) != 64 || len(fixture.Cases) != 3 {
		t.Fatal("missing reference source binding")
	}
	for _, item := range fixture.Cases {
		t.Run(item.Name, func(t *testing.T) {
			actual, err := sealReceipt(item.Secret, item.Payload)
			if err != nil || actual != item.Receipt {
				t.Fatalf("native seal differs from Python oracle: %v", err)
			}
			handle, err := openReceipt(item.Secret, item.Receipt, item.Authorization, item.Thumbprint)
			if err != nil || !reflect.DeepEqual(handle, item.Put) {
				t.Fatalf("native opening of Python receipt differs: %v", err)
			}
		})
	}
}

func TestReceiptExactAuthorityBindingAndRotation(t *testing.T) {
	payload, authorization, thumb := samplePayload()
	secret := "fixture-secret-with-at-least-thirty-two-bytes"
	receipt, err := sealReceipt(secret, payload)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := openReceipt(secret, receipt, authorization, thumb)
	if err != nil || handle.Token != "gateway-put-1-unique-marker" {
		t.Fatalf("valid receipt: %+v %v", handle, err)
	}
	if strings.Contains(receipt, authorization) {
		t.Fatal("receipt contains bearer authorization")
	}
	parts := strings.Split(receipt, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || strings.Contains(string(raw), authorization) {
		t.Fatal("payload leaked bearer authorization")
	}
	for _, test := range []struct {
		name, key, token, cert string
		receipt                any
	}{
		{"different-original-token", secret, authorization + "-different", thumb, receipt},
		{"different-certificate", secret, authorization, strings.Repeat("c", 43), receipt},
		{"rotated-key", secret + "-rotated", authorization, thumb, receipt},
		{"tampered-signature", secret, authorization, thumb, receipt[:len(receipt)-1] + "!"},
		{"tampered-payload", secret, authorization, thumb, "a" + receipt},
		{"empty", secret, authorization, thumb, ""},
		{"multiple-dots", secret, authorization, thumb, receipt + ".more"},
		{"padding", secret, authorization, thumb, parts[0] + "=." + parts[1]},
		{"wrong-type-number", secret, authorization, thumb, 1},
		{"wrong-type-null", secret, authorization, thumb, nil},
		{"too-long", secret, authorization, thumb, strings.Repeat("a", int(MaxBodyBytes))},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := openReceipt(test.key, test.receipt, test.token, test.cert)
			wantError(t, err, 401, "invalid_gateway_put_receipt")
		})
	}
}

func TestReceiptRejectsSignedMalformedPayload(t *testing.T) {
	base, authorization, thumb := samplePayload()
	secret := "fixture-secret-with-at-least-thirty-two-bytes"
	tests := []struct {
		name   string
		mutate func(domain.Object)
	}{
		{"unknown-root", func(v domain.Object) { v["extra"] = true }},
		{"missing-root", func(v domain.Object) { delete(v, "version") }},
		{"float-version", func(v domain.Object) { v["version"] = json.Number("1.0") }},
		{"boolean-version", func(v domain.Object) { v["version"] = true }},
		{"other-version", func(v domain.Object) { v["version"] = 2 }},
		{"authorization-type", func(v domain.Object) { v["authorization_sha256"] = 1 }},
		{"owner-type", func(v domain.Object) { v["owner"] = []any{} }},
		{"owner-extra", func(v domain.Object) { v["owner"].(map[string]any)["extra"] = "x" }},
		{"owner-missing", func(v domain.Object) { delete(v["owner"].(map[string]any), "job_id") }},
		{"owner-empty", func(v domain.Object) { v["owner"].(map[string]any)["subject"] = "" }},
		{"owner-large", func(v domain.Object) { v["owner"].(map[string]any)["subject"] = strings.Repeat("a", 257) }},
		{"owner-epoch-zero", func(v domain.Object) { v["owner"].(map[string]any)["epoch"] = 0 }},
		{"owner-epoch-float", func(v domain.Object) { v["owner"].(map[string]any)["epoch"] = json.Number("1.0") }},
		{"owner-epoch-overflow", func(v domain.Object) { v["owner"].(map[string]any)["epoch"] = json.Number("9223372036854775808") }},
		{"put-type", func(v domain.Object) { v["put"] = nil }},
		{"put-extra", func(v domain.Object) { v["put"].(map[string]any)["extra"] = "x" }},
		{"put-invalid-id", func(v domain.Object) { v["put"].(map[string]any)["record_id"] = "../foreign" }},
		{"put-invalid-object", func(v domain.Object) { v["put"].(map[string]any)["object_key"] = "" }},
		{"put-invalid-upload", func(v domain.Object) { v["put"].(map[string]any)["upload_id"] = true }},
		{"put-invalid-token", func(v domain.Object) { v["put"].(map[string]any)["token"] = "some-other-marker" }},
		{"put-part-zero", func(v domain.Object) { v["put"].(map[string]any)["part_number"] = 0 }},
		{"put-part-large", func(v domain.Object) { v["put"].(map[string]any)["part_number"] = 10001 }},
		{"put-part-float", func(v domain.Object) { v["put"].(map[string]any)["part_number"] = json.Number("1.0") }},
		{"put-foreign-space", func(v domain.Object) { v["put"].(map[string]any)["space_id"] = "foreign" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := domain.CloneMap(base)
			test.mutate(payload)
			receipt, err := sealReceipt(secret, payload)
			if err != nil {
				t.Fatal(err)
			}
			_, err = openReceipt(secret, receipt, authorization, thumb)
			wantError(t, err, 401, "invalid_gateway_put_receipt")
		})
	}
}

func TestReceiptSizeBound(t *testing.T) {
	payload, _, _ := samplePayload()
	payload["put"].(map[string]any)["object_key"] = strings.Repeat("a", int(MaxBodyBytes))
	_, err := sealReceipt("fixture-secret", payload)
	wantError(t, err, 503, "gateway_put_receipt_too_large")
}

func TestStrictJSONObject(t *testing.T) {
	valid := []string{`{}`, `{"receipt":"opaque"}`, `{"nested":{"values":[1,true,null,"x"]}}`}
	for _, raw := range valid {
		if _, err := strictObject([]byte(raw)); err != nil {
			t.Fatalf("valid JSON %q: %v", raw, err)
		}
	}
	invalid := []string{`[]`, `null`, `true`, `1`, `{"x":1,"x":2}`, `{"x":{"a":1,"a":2}}`, `{"x":NaN}`, `{"x":Infinity}`, `{"x":1e9999}`, `{`, `{} {}`, "{\"x\":\"\xff\"}", strings.Repeat("[", 65) + strings.Repeat("]", 65)}
	for _, raw := range invalid {
		_, err := strictObject([]byte(raw))
		wantError(t, err, 422, "invalid_request")
	}
}

func TestOnlySixPrivateRoutesMatch(t *testing.T) {
	for _, path := range []string{
		Base + "/storage/check", Base + "/settle", Base + "/spaces/space/authorize",
		Base + "/spaces/space/records/record/attachments/blob/parts/1/grant",
		Base + "/spaces/space/records/record/attachments/blob/parts/1/begin",
		Base + "/spaces/space/records/record/attachments/blob/download",
	} {
		if matchPath(path) == nil {
			t.Fatalf("route absent %s", path)
		}
	}
	for _, path := range []string{"/v2/spaces", "/docs", "/openapi.json", Base, Base + "/settle/", "//" + Base, Base + "/spaces/x/records/y/attachments/z/parts/1", Base + "/spaces/x/records/y/attachments/z/parts/1/finish"} {
		if matchPath(path) != nil {
			t.Fatalf("unexpected private route %s", path)
		}
	}
}
