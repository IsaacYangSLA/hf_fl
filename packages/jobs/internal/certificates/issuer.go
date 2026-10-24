// Package certificates issues execution-bound client certificates using a fixed operator CA.
package certificates

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"time"
)

const MaxPEMBytes = 64 * 1024
const MaxLifetimeSeconds int64 = 30 * 86400
const MaxGraceSeconds int64 = 300

// ErrRefused never embeds certificate material, private keys, or operator paths.
var ErrRefused = errors.New("certificate_issuance_refused")

type Config struct {
	CACertificatePEM   []byte
	CAPrivateKeyPEM    []byte
	CACertificateFile  string
	CAPrivateKeyFile   string
	GraceSeconds       *int64
	MaxLifetimeSeconds int64
	Clock              func() time.Time
}
type Binding struct {
	JobID       string
	AttemptID   string
	ComponentID string
	SpaceID     string
	Epoch       int64
}
type Issued struct {
	CertificatePEM        string  `json:"certificate_pem"`
	CertificateThumbprint string  `json:"certificate_thumbprint"`
	ExpiresAt             float64 `json:"expires_at"`
}
type Issuer struct {
	certificate *x509.Certificate
	key         crypto.Signer
	clock       func() time.Time
	grace       int64
	lifetime    int64
}

func (i *Issuer) String() string { return "<CertificateIssuer fixed trusted CA>" }

func singlePEM(data []byte, labels ...string) (*pem.Block, error) {
	if len(data) == 0 || len(data) > MaxPEMBytes {
		return nil, ErrRefused
	}
	data = bytes.TrimSpace(data)
	block, rest := pem.Decode(data)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 || len(block.Headers) != 0 {
		return nil, ErrRefused
	}
	matched := false
	for _, label := range labels {
		if block.Type == label {
			matched = true
		}
	}
	if !matched {
		return nil, ErrRefused
	}
	// pem.Decode can skip a non-PEM prefix, which is not an accepted single block.
	if !bytes.HasPrefix(data, []byte("-----BEGIN "+block.Type+"-----")) {
		return nil, ErrRefused
	}
	return block, nil
}
func approvedPublic(key any) bool {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen() >= 2048 && k.N.BitLen() <= 8192 && k.E == 65537
	case *ecdsa.PublicKey:
		return k.Curve == elliptic.P256()
	default:
		return false
	}
}
func parseSigner(data []byte) (crypto.Signer, error) {
	b, e := singlePEM(data, "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY")
	if e != nil {
		return nil, e
	}
	var key any
	switch b.Type {
	case "PRIVATE KEY":
		key, e = x509.ParsePKCS8PrivateKey(b.Bytes)
	case "RSA PRIVATE KEY":
		key, e = x509.ParsePKCS1PrivateKey(b.Bytes)
	case "EC PRIVATE KEY":
		key, e = x509.ParseECPrivateKey(b.Bytes)
	}
	if e != nil {
		return nil, ErrRefused
	}
	signer, ok := key.(crypto.Signer)
	if !ok || !approvedPublic(signer.Public()) {
		return nil, ErrRefused
	}
	return signer, nil
}
func NewIssuer(cfg Config) (*Issuer, error) {
	var e error
	if len(cfg.CACertificatePEM) == 0 && cfg.CACertificateFile != "" {
		cfg.CACertificatePEM, e = ReadPEMFile(cfg.CACertificateFile, false)
		if e != nil {
			return nil, e
		}
	}
	if len(cfg.CAPrivateKeyPEM) == 0 && cfg.CAPrivateKeyFile != "" {
		cfg.CAPrivateKeyPEM, e = ReadPEMFile(cfg.CAPrivateKeyFile, true)
		if e != nil {
			return nil, e
		}
	}
	b, e := singlePEM(cfg.CACertificatePEM, "CERTIFICATE")
	if e != nil {
		return nil, e
	}
	cert, e := x509.ParseCertificate(b.Bytes)
	if e != nil {
		return nil, ErrRefused
	}
	key, e := parseSigner(cfg.CAPrivateKeyPEM)
	if e != nil {
		return nil, e
	}
	if !cert.IsCA || !cert.BasicConstraintsValid || !approvedPublic(cert.PublicKey) {
		return nil, ErrRefused
	}
	a, e := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if e != nil {
		return nil, ErrRefused
	}
	z, e := x509.MarshalPKIXPublicKey(key.Public())
	if e != nil || !bytes.Equal(a, z) {
		return nil, ErrRefused
	}
	// Missing KeyUsage is allowed by the original contract; explicit restrictions apply.
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 15}) && cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, ErrRefused
		}
	}
	grace := MaxGraceSeconds
	if cfg.GraceSeconds != nil {
		grace = *cfg.GraceSeconds
	}
	life := cfg.MaxLifetimeSeconds
	if life == 0 {
		life = MaxLifetimeSeconds
	}
	if grace < 0 || grace > MaxGraceSeconds || life < 1 || life > MaxLifetimeSeconds {
		return nil, ErrRefused
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	issuer := &Issuer{cert, key, clock, grace, life}
	if e = issuer.caValid(clock()); e != nil {
		return nil, e
	}
	return issuer, nil
}
func (i *Issuer) caValid(now time.Time) error {
	if now.Before(i.certificate.NotBefore) || !now.Before(i.certificate.NotAfter) {
		return ErrRefused
	}
	return nil
}

// ValidateCSR accepts one RSA CSR with a valid signature and no requested extensions.
// It does not read any files or use the CA.
func ValidateCSR(data []byte) (*x509.CertificateRequest, error) {
	b, e := singlePEM(data, "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST")
	if e != nil {
		return nil, e
	}
	csr, e := x509.ParseCertificateRequest(b.Bytes)
	if e != nil {
		return nil, ErrRefused
	}
	k, ok := csr.PublicKey.(*rsa.PublicKey)
	if !ok || !approvedPublic(k) || csr.CheckSignature() != nil || len(csr.Extensions) != 0 || len(csr.ExtraExtensions) != 0 {
		return nil, ErrRefused
	}
	return csr, nil
}
func validID(v string) bool {
	if len(v) < 1 || len(v) > 128 {
		return false
	}
	for n, c := range []byte(v) {
		if c > 127 || !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || n > 0 && (c == '_' || c == '.' || c == '-')) {
			return false
		}
	}
	return true
}
func (b Binding) Validate() error {
	if !validID(b.JobID) || !validID(b.AttemptID) || !validID(b.ComponentID) || !validID(b.SpaceID) || b.Epoch < 1 {
		return ErrRefused
	}
	return nil
}
func keyIdentifier(public any) ([]byte, error) {
	der, e := x509.MarshalPKIXPublicKey(public)
	if e != nil {
		return nil, ErrRefused
	}
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		Key       asn1.BitString
	}
	if _, e = asn1.Unmarshal(der, &spki); e != nil {
		return nil, ErrRefused
	}
	h := sha1.Sum(spki.Key.RightAlign())
	return h[:], nil
}
func Thumbprint(der []byte) string {
	h := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(h[:])
}
func CSRDigest(csr *x509.CertificateRequest) string {
	h := sha256.Sum256(csr.Raw)
	return hex.EncodeToString(h[:])
}
func (i *Issuer) Issue(csrPEM []byte, binding Binding, deadline time.Time) (Issued, error) {
	fail := Issued{}
	if e := binding.Validate(); e != nil {
		return fail, e
	}
	now := i.clock().UTC()
	if e := i.caValid(now); e != nil {
		return fail, e
	}
	if !deadline.After(now) {
		return fail, ErrRefused
	}
	csr, e := ValidateCSR(csrPEM)
	if e != nil {
		return fail, e
	}
	expires := deadline.Add(time.Duration(i.grace) * time.Second)
	if t := now.Add(time.Duration(i.lifetime) * time.Second); t.Before(expires) {
		expires = t
	}
	if i.certificate.NotAfter.Before(expires) {
		expires = i.certificate.NotAfter
	}
	expires = expires.UTC().Truncate(time.Second)
	start := now.Add(-30 * time.Second)
	if i.certificate.NotBefore.After(start) {
		start = i.certificate.NotBefore
	}
	start = start.UTC().Truncate(time.Second)
	if !expires.After(now) {
		return fail, ErrRefused
	}
	encoded, _ := json.Marshal([]any{binding.JobID, binding.AttemptID, binding.ComponentID, binding.Epoch, binding.SpaceID})
	digest := sha256.Sum256(encoded)
	subjectID, e := keyIdentifier(csr.PublicKey)
	if e != nil {
		return fail, e
	}
	issuerID := i.certificate.SubjectKeyId
	if len(issuerID) == 0 {
		issuerID, e = keyIdentifier(i.certificate.PublicKey)
		if e != nil {
			return fail, e
		}
	}
	limit := new(big.Int).Lsh(big.NewInt(1), 159)
	serial, e := rand.Int(rand.Reader, limit)
	if e != nil {
		return fail, ErrRefused
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: hex.EncodeToString(digest[:])},
		NotBefore: start, NotAfter: expires, BasicConstraintsValid: true, IsCA: false,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		SubjectKeyId: subjectID, AuthorityKeyId: issuerID,
	}
	der, e := x509.CreateCertificate(rand.Reader, template, i.certificate, csr.PublicKey, i.key)
	if e != nil {
		return fail, ErrRefused
	}
	return Issued{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), Thumbprint(der), float64(expires.Unix())}, nil
}

// CSRPEMDigest preserves the exact input representation used by durable issuance operations.
func CSRPEMDigest(csrPEM []byte) string { h := sha256.Sum256(csrPEM); return hex.EncodeToString(h[:]) }
