package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

var cookiePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{40,128}$`)
var csrfPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Provider interface {
	AuthorizationURL(context.Context, string, string, string) (string, error)
	ExchangeCode(context.Context, string, string, string) (Identity, error)
	OnlineCheck(context.Context, string, string) (bool, error)
	AuthenticateAccessToken(context.Context, string) (Identity, error)
	LogoutIdentity(context.Context, string) (LogoutIdentity, error)
}
type Service struct {
	DB           *store.DB
	Config       Config
	Provider     Provider
	Clock        func() time.Time
	cleanupMu    sync.Mutex
	cleanupAfter time.Time
}

func New(db *store.DB, cfg Config, p Provider) (*Service, error) {
	cfg.OIDC = cfg.OIDC.defaults()
	if db == nil || db.SQL == nil {
		return nil, errors.New("authentication database is required")
	}
	if e := validateConfig(cfg); e != nil {
		return nil, e
	}
	if p == nil {
		var e error
		p, e = NewOIDCProvider(cfg.OIDC, nil)
		if e != nil {
			return nil, e
		}
	}
	return &Service{DB: db, Config: cfg, Provider: p, Clock: func() time.Time { return time.Now().UTC() }}, nil
}
func (s *Service) now() time.Time { return s.Clock().UTC() }
func (s *Service) principal(issuer, subject string) Principal {
	id := domain.PrincipalID(issuer, subject)
	op := false
	for _, p := range s.Config.PlatformOperatorIDs {
		if p == id {
			op = true
			break
		}
	}
	return Principal{ID: id, Issuer: issuer, Subject: subject, PlatformOperator: op}
}
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	_, e := rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b), e
}
func tokenHash(token string) (string, error) {
	if !cookiePattern.MatchString(token) {
		return "", failure(401, "invalid_session")
	}
	return digest(token), nil
}
func (s *Service) csrf(token string) (string, error) {
	if _, e := tokenHash(token); e != nil {
		return "", e
	}
	h := hmac.New(sha256.New, []byte(s.Config.SessionSecret))
	h.Write([]byte("hf2l-jobs-csrf:" + token))
	return hex.EncodeToString(h.Sum(nil)), nil
}
func str(row map[string]any, key string) string          { v, _ := row[key].(string); return v }
func timestamp(row map[string]any, key string) time.Time { v, _ := store.Time(row[key]); return v }
func (s *Service) PruneExpired(ctx context.Context) (map[string]int64, error) {
	now := s.now()
	result := map[string]int64{}
	err := s.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		for _, entry := range [][2]string{{"sessions", "jm_auth_sessions"}, {"login_attempts", "auth_login_attempts"}, {"logout_replays", "auth_logout_replays"}} {
			key, table := entry[0], entry[1]
			r, e := tx.Exec(ctx, "DELETE FROM "+table+" WHERE expires_at <= ?", now)
			if e != nil {
				return e
			}
			n, e := r.RowsAffected()
			if e != nil {
				return e
			}
			result[key] = n
		}
		return nil
	})
	return result, err
}
func (s *Service) BeginLogin(ctx context.Context) (LoginStart, error) {
	s.cleanupMu.Lock()
	if !s.now().Before(s.cleanupAfter) {
		_, err := s.PruneExpired(ctx)
		if err != nil {
			s.cleanupMu.Unlock()
			return LoginStart{}, err
		}
		s.cleanupAfter = s.now().Add(time.Minute)
	}
	s.cleanupMu.Unlock()
	state, e := randomToken(32)
	if e != nil {
		return LoginStart{}, e
	}
	cookie, e := randomToken(32)
	if e != nil {
		return LoginStart{}, e
	}
	verifier, e := randomToken(48)
	if e != nil {
		return LoginStart{}, e
	}
	nonce, e := randomToken(32)
	if e != nil {
		return LoginStart{}, e
	}
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])
	target, e := s.Provider.AuthorizationURL(ctx, state, nonce, challenge)
	if e != nil {
		return LoginStart{}, e
	}
	err := s.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		return tx.Insert(ctx, "auth_login_attempts", map[string]any{"id": digest(state), "cookie_hash": digest(cookie), "verifier": verifier, "nonce": nonce, "expires_at": s.now().Add(LoginLifetime), "used_at": nil})
	})
	return LoginStart{target, cookie}, err
}
func (s *Service) FinishLogin(ctx context.Context, code, state, cookie string) (SessionIssue, error) {
	stateHash, e := tokenHash(state)
	if e != nil {
		return SessionIssue{}, e
	}
	cookieHash, e := tokenHash(cookie)
	if e != nil {
		return SessionIssue{}, e
	}
	now := s.now()
	var verifier, nonce string
	err := s.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		row, e := tx.One(ctx, "SELECT * FROM auth_login_attempts WHERE id = ?"+tx.ForUpdate(), stateHash)
		if e != nil {
			return e
		}
		if row == nil || row["used_at"] != nil || !now.Before(timestamp(row, "expires_at")) || !equal(str(row, "cookie_hash"), cookieHash) {
			return failure(401, "invalid_authorization_state")
		}
		verifier, nonce = str(row, "verifier"), str(row, "nonce")
		r, e := tx.Exec(ctx, "UPDATE auth_login_attempts SET used_at = ?, verifier = ?, nonce = ? WHERE id = ? AND used_at IS NULL AND expires_at > ?", now, "", "", stateHash, now)
		if e != nil {
			return e
		}
		n, e := r.RowsAffected()
		if e != nil {
			return e
		}
		if n != 1 {
			return failure(401, "invalid_authorization_state")
		}
		return nil
	})
	if err != nil {
		return SessionIssue{}, err
	}
	ident, err := s.Provider.ExchangeCode(ctx, code, verifier, nonce)
	if err != nil {
		return SessionIssue{}, err
	}
	if ident.Issuer != s.Config.OIDC.Issuer || ident.Subject == "" {
		return SessionIssue{}, failure(401, "invalid_access_token")
	}
	principal := s.principal(ident.Issuer, ident.Subject)
	token, err := randomToken(32)
	if err != nil {
		return SessionIssue{}, err
	}
	csrf, _ := s.csrf(token)
	var access, sid any
	if ident.AccessToken != "" {
		access = ident.AccessToken
	}
	if ident.ProviderSID != "" {
		sid = ident.ProviderSID
	}
	err = s.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		return tx.Insert(ctx, "jm_auth_sessions", map[string]any{"id": digest(token), "principal_id": principal.ID, "issuer": ident.Issuer, "subject": ident.Subject, "csrf_hash": digest(csrf), "access_token": access, "provider_sid": sid, "created_at": now, "last_seen_at": now, "checked_at": now, "expires_at": now.Add(SessionIdle), "absolute_expires_at": now.Add(SessionAbsolute), "revoked_at": nil})
	})
	return SessionIssue{token, csrf, principal}, err
}
func (s *Service) AuthenticateSession(ctx context.Context, token string, touch bool) (Principal, error) {
	id, e := tokenHash(token)
	if e != nil {
		return Principal{}, e
	}
	now := s.now()
	var principal Principal
	revoked := false
	err := s.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		row, e := tx.One(ctx, "SELECT * FROM jm_auth_sessions WHERE id = ?"+tx.ForUpdate(), id)
		if e != nil {
			return e
		}
		if row == nil || row["revoked_at"] != nil {
			return failure(401, "invalid_session")
		}
		absolute := timestamp(row, "absolute_expires_at")
		if absolute.IsZero() {
			absolute = timestamp(row, "created_at").Add(SessionAbsolute)
		}
		if !now.Before(timestamp(row, "expires_at")) || !now.Before(absolute) || now.Sub(timestamp(row, "last_seen_at")) >= SessionIdle {
			return failure(401, "session_expired")
		}
		issuer, subject := str(row, "issuer"), str(row, "subject")
		if issuer != s.Config.OIDC.Issuer || str(row, "principal_id") != domain.PrincipalID(issuer, subject) {
			return failure(401, "invalid_session")
		}
		updates := map[string]any{}
		if now.Sub(timestamp(row, "checked_at")) >= IdentityRecheck {
			active, e := s.Provider.OnlineCheck(ctx, str(row, "access_token"), subject)
			if e != nil {
				return e
			}
			if !active {
				updates["revoked_at"] = now
				updates["access_token"] = nil
				revoked = true
			} else {
				updates["checked_at"] = now
			}
		}
		if !revoked && touch {
			expires := now.Add(SessionIdle)
			if absolute.Before(expires) {
				expires = absolute
			}
			updates["last_seen_at"] = now
			updates["expires_at"] = expires
		}
		principal = s.principal(issuer, subject)
		if len(updates) > 0 {
			return tx.Update(ctx, "jm_auth_sessions", map[string]any{"id": id}, updates)
		}
		return nil
	})
	if err != nil {
		return Principal{}, err
	}
	if revoked {
		return Principal{}, failure(401, "identity_revoked")
	}
	return principal, nil
}
func (s *Service) AuthenticateRequest(ctx context.Context, authorization, cookie string, touch bool) (Principal, error) {
	if authorization != "" {
		if cookie != "" {
			return Principal{}, failure(401, "ambiguous_authentication")
		}
		parts := strings.SplitN(authorization, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") || parts[1] == "" || strings.Contains(parts[1], " ") {
			return Principal{}, failure(401, "invalid_access_token")
		}
		ident, e := s.Provider.AuthenticateAccessToken(ctx, parts[1])
		if e != nil {
			return Principal{}, e
		}
		if ident.Issuer != s.Config.OIDC.Issuer || ident.Subject == "" {
			return Principal{}, failure(401, "invalid_access_token")
		}
		return s.principal(ident.Issuer, ident.Subject), nil
	}
	if cookie == "" {
		return Principal{}, failure(401, "authentication_required")
	}
	return s.AuthenticateSession(ctx, cookie, touch)
}
func (s *Service) SessionInfo(ctx context.Context, cookie string) (map[string]any, error) {
	principal, e := s.AuthenticateSession(ctx, cookie, true)
	if e != nil {
		return nil, e
	}
	csrf, e := s.csrf(cookie)
	if e != nil {
		return nil, e
	}
	permissions := []string{}
	if principal.PlatformOperator {
		permissions = append(permissions, "platform_operator")
	}
	return map[string]any{"authenticated": true, "principal": map[string]any{"principal_id": principal.ID, "display_name": principal.Subject}, "csrf_token": csrf, "permissions": permissions, "login_url": "/auth/login"}, nil
}
func (s *Service) RequireCSRF(ctx context.Context, cookie, csrf, origin string) error {
	expected, e := s.csrf(cookie)
	if e != nil {
		return e
	}
	if !csrfPattern.MatchString(csrf) || !equal(csrf, expected) {
		return failure(403, "csrf_invalid")
	}
	if origin != Origin(s.Config.OIDC.RedirectURI) {
		return failure(403, "csrf_origin_invalid")
	}
	row, e := s.DB.One(ctx, "SELECT * FROM jm_auth_sessions WHERE id = ?", digest(cookie))
	if e != nil {
		return e
	}
	if row == nil || row["revoked_at"] != nil {
		return failure(401, "invalid_session")
	}
	if !equal(str(row, "csrf_hash"), digest(expected)) {
		return failure(403, "csrf_invalid")
	}
	return nil
}
func (s *Service) Logout(ctx context.Context, cookie, csrf, origin string) error {
	if e := s.RequireCSRF(ctx, cookie, csrf, origin); e != nil {
		return e
	}
	return s.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		return tx.Update(ctx, "jm_auth_sessions", map[string]any{"id": digest(cookie)}, map[string]any{"revoked_at": s.now(), "access_token": nil})
	})
}
func (s *Service) RevokeSubject(ctx context.Context, issuer, subject string) (int64, error) {
	r, e := s.DB.Exec(ctx, "UPDATE jm_auth_sessions SET revoked_at = ?, access_token = NULL WHERE issuer = ? AND subject = ? AND revoked_at IS NULL", s.now(), issuer, subject)
	if e != nil {
		return 0, e
	}
	return r.RowsAffected()
}
func (s *Service) BackchannelLogout(ctx context.Context, token string) error {
	id, e := s.Provider.LogoutIdentity(ctx, token)
	if e != nil {
		return e
	}
	if id.Subject == "" && id.SID == "" {
		return failure(401, "invalid_logout_token")
	}
	replay := domain.PrincipalID(s.Config.OIDC.Issuer, id.JTI)
	now := s.now()
	// The unique replay insertion and session revocation share one transaction.
	// Serialize through the replay row on PostgreSQL; insert conflicts reject repeats.
	return s.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		row, e := tx.One(ctx, "SELECT id FROM auth_logout_replays WHERE id = ?", replay)
		if e != nil {
			return e
		}
		if row != nil {
			return failure(401, "logout_token_replayed")
		}
		if e := tx.Insert(ctx, "auth_logout_replays", map[string]any{"id": replay, "expires_at": now.Add(5 * time.Minute)}); e != nil {
			// Unique-key conflicts are a replay even when another process won the race.
			if strings.Contains(strings.ToLower(e.Error()), "unique") || strings.Contains(strings.ToLower(e.Error()), "duplicate") {
				return failure(401, "logout_token_replayed")
			}
			return e
		}
		query := "UPDATE jm_auth_sessions SET revoked_at = ?, access_token = NULL WHERE issuer = ? AND revoked_at IS NULL"
		args := []any{now, s.Config.OIDC.Issuer}
		if id.Subject != "" {
			query += " AND subject = ?"
			args = append(args, id.Subject)
		}
		if id.SID != "" {
			query += " AND provider_sid = ?"
			args = append(args, id.SID)
		}
		_, e = tx.Exec(ctx, query, args...)
		return e
	})
}
