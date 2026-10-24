package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/config"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/domain"
)

func constantEqual(a, b string) bool {
	return hmac.Equal([]byte(a), []byte(b))
}

// BackendAssertionHeaders binds the trusted ingress's verified TLS identity to
// the exact request. It does not make an ordinary public listener trust headers.
func BackendAssertionHeaders(secret, method, target, authorization, thumbprint string, timestamp time.Time) http.Header {
	stamp := strconv.FormatInt(timestamp.Unix(), 10)
	raw, err := domain.CanonicalASCIIJSON([]any{strings.ToUpper(method), target, authorization, thumbprint, stamp})
	if err != nil {
		return nil
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(raw)
	return http.Header{
		"X-Hf2l-Backend-Timestamp": []string{stamp},
		"X-Hf2l-Tls-Thumbprint":    []string{thumbprint},
		"X-Hf2l-Backend-Signature": []string{hex.EncodeToString(mac.Sum(nil))},
	}
}

func oneHeader(headers http.Header, name string) (string, bool) {
	var values []string
	for key, found := range headers {
		if strings.EqualFold(key, name) {
			values = append(values, found...)
		}
	}
	if len(values) != 1 {
		return "", false
	}
	return values[0], true
}

// VerifiedBackendThumbprint accepts a certificate assertion only from the
// configured trusted backend key and only within its narrow replay window.
func VerifiedBackendThumbprint(settings config.AuthSettings, method, target, authorization string, headers http.Header, now time.Time) (string, error) {
	fail := func() (string, error) { return "", domain.Err(401, "invalid_backend_assertion") }
	stamp, stampOK := oneHeader(headers, "X-HF2L-Backend-Timestamp")
	thumbprint, thumbOK := oneHeader(headers, "X-HF2L-TLS-Thumbprint")
	signature, sigOK := oneHeader(headers, "X-HF2L-Backend-Signature")
	if !settings.WorkloadsEnabled() || len([]byte(settings.TrustedBackendSecret)) < 32 || !stampOK || !thumbOK || !sigOK || !thumbprintPattern.MatchString(thumbprint) || stamp == "" {
		return fail()
	}
	for _, value := range stamp {
		if value < '0' || value > '9' {
			return fail()
		}
	}
	seconds, err := strconv.ParseInt(stamp, 10, 64)
	if err != nil {
		return fail()
	}
	// Avoid integer subtraction overflow for adversarial timestamps. Match the
	// reference's fractional current-time comparison at the thirty-second edge.
	delta := float64(now.UnixMicro())/1e6 - float64(seconds)
	if delta < -30 || delta > 30 {
		return fail()
	}
	raw, err := domain.CanonicalASCIIJSON([]any{strings.ToUpper(method), target, authorization, thumbprint, stamp})
	if err != nil {
		return fail()
	}
	mac := hmac.New(sha256.New, []byte(settings.TrustedBackendSecret))
	_, _ = mac.Write(raw)
	expected := hex.EncodeToString(mac.Sum(nil))
	if !constantEqual(signature, expected) {
		return fail()
	}
	return thumbprint, nil
}
