package auth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"io"
	"math"
	"math/big"
	"net/http"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/domain"
)

const maxJWKSBytes = 1 << 20
const maxJWKSKeys = 256

func (a *Authenticator) signingKey(ctx context.Context, header domain.Object) (*rsa.PublicKey, error) {
	kid, ok := header["kid"].(string)
	if !ok || kid == "" || len(kid) > 1024 {
		return nil, invalidToken()
	}
	timer := time.NewTimer(a.keyTimeout)
	defer timer.Stop()
	select {
	case a.keyLock <- struct{}{}:
		defer func() { <-a.keyLock }()
	case <-ctx.Done():
		return nil, identityUnavailable()
	case <-timer.C:
		return nil, identityUnavailable()
	}
	now := a.now()
	if now.Before(a.retryAfter) {
		return nil, identityUnavailable()
	}
	if now.Before(a.cacheUntil) {
		if key := a.cache[kid]; key != nil {
			return key, nil
		}
	}
	keys, unavailable, err := a.fetchKeys(ctx)
	if unavailable {
		a.retryAfter = a.now().Add(3 * time.Second)
		return nil, identityUnavailable()
	}
	if err != nil {
		return nil, invalidToken()
	}
	a.cache, a.cacheUntil = keys, a.now().Add(a.cacheLifetime)
	if key := keys[kid]; key != nil {
		return key, nil
	}
	return nil, invalidToken()
}

func (a *Authenticator) fetchKeys(ctx context.Context) (map[string]*rsa.PublicKey, bool, error) {
	fetchContext, cancel := context.WithTimeout(ctx, a.keyTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(fetchContext, http.MethodGet, a.settings.JWKSURL, nil)
	if err != nil {
		return nil, true, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := a.client.Do(request)
	if err != nil {
		return nil, true, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, true, errors.New("identity key endpoint unavailable")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxJWKSBytes+1))
	if err != nil {
		return nil, true, err
	}
	if len(raw) > maxJWKSBytes {
		return nil, false, errors.New("invalid identity key response")
	}
	decoded, err := domain.DecodeJSON(raw)
	if err != nil {
		return nil, false, errors.New("invalid identity key response")
	}
	object, ok := decoded.(map[string]any)
	if !ok {
		return nil, false, errors.New("invalid identity key response")
	}
	keys, ok := object["keys"].([]any)
	if !ok || len(keys) == 0 || len(keys) > maxJWKSKeys {
		return nil, false, errors.New("invalid identity key response")
	}
	result := map[string]*rsa.PublicKey{}
	for _, value := range keys {
		jwk, ok := value.(map[string]any)
		if !ok {
			return nil, false, errors.New("invalid identity key response")
		}
		if jwk["kty"] != "RSA" {
			continue
		}
		if usage, exists := jwk["use"]; exists && usage != "sig" {
			continue
		}
		if alg, exists := jwk["alg"]; exists && alg != "RS256" {
			continue
		}
		kid, kidOK := jwk["kid"].(string)
		if !kidOK || kid == "" || len(kid) > 1024 {
			continue
		}
		if _, duplicate := result[kid]; duplicate {
			return nil, false, errors.New("ambiguous identity key")
		}
		n, nOK := jwk["n"].(string)
		e, eOK := jwk["e"].(string)
		if !nOK || !eOK || len(n) > 4096 || len(e) > 16 {
			return nil, false, errors.New("invalid identity key")
		}
		modulus, errN := base64.RawURLEncoding.Strict().DecodeString(n)
		exponent, errE := base64.RawURLEncoding.Strict().DecodeString(e)
		if errN != nil || errE != nil || len(modulus) == 0 || len(exponent) == 0 {
			return nil, false, errors.New("invalid identity key")
		}
		nInt, eInt := new(big.Int).SetBytes(modulus), new(big.Int).SetBytes(exponent)
		if nInt.BitLen() < 1024 || nInt.BitLen() > 16384 || !eInt.IsInt64() || eInt.Int64() < 3 || eInt.Int64() > math.MaxInt32 || eInt.Int64()%2 == 0 {
			return nil, false, errors.New("invalid identity key")
		}
		result[kid] = &rsa.PublicKey{N: nInt, E: int(eInt.Int64())}
	}
	if len(result) == 0 {
		return nil, false, errors.New("no identity signing keys")
	}
	return result, false, nil
}
