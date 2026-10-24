package app

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"time"
)

type ListenerOptions struct {
	Host             string
	Port             int
	CertificateFile  string
	KeyFile          string
	ClientCAFile     string
	TransferAudience string
}

func localBind(host string) bool {
	if strings.EqualFold(host, "localhost") || strings.EqualFold(host, "testserver") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
func trustedTLSFile(path string, private bool, limit int64) ([]byte, error) {
	if path == "" {
		return nil, errors.New("TLS file is required")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("TLS file unavailable")
	}
	f := os.NewFile(uintptr(fd), "trusted-tls-file")
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > limit || st.Mode().Perm()&0022 != 0 {
		return nil, errors.New("TLS file must be a bounded protected regular file")
	}
	if private && st.Mode().Perm()&0077 != 0 {
		return nil, errors.New("TLS private key permissions are unsafe")
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && int(sys.Uid) != os.Geteuid() && sys.Uid != 0 {
		return nil, errors.New("TLS file owner is untrusted")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, errors.New("TLS file read failed")
	}
	return b, nil
}
func leafServerPurpose(cert *x509.Certificate, now time.Time) bool {
	if cert.IsCA || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return false
	}
	for _, purpose := range cert.ExtKeyUsage {
		if purpose == x509.ExtKeyUsageServerAuth {
			return true
		}
	}
	return false
}
func clientCAs(data []byte, now time.Time) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	count := 0
	for len(strings.TrimSpace(string(data))) > 0 {
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, errors.New("client CA bundle is invalid")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
			return nil, errors.New("client CA certificate is invalid")
		}
		pool.AddCert(cert)
		count++
		data = rest
	}
	if count == 0 {
		return nil, errors.New("client CA bundle is empty")
	}
	return pool, nil
}

// TLSConfig is separate from handler composition so invalid listener authority
// fails before accepting any network traffic.
func TLSConfig(mode string, o ListenerOptions, allowLocalHTTP bool) (*tls.Config, error) {
	if (o.CertificateFile == "") != (o.KeyFile == "") {
		return nil, errors.New("TLS certificate and key must be supplied together")
	}
	if mode == "gateway" && (o.CertificateFile == "" || o.ClientCAFile == "") {
		return nil, errors.New("private gateway requires TLS and a client CA")
	}
	if o.CertificateFile == "" {
		if o.ClientCAFile != "" {
			return nil, errors.New("client CA requires TLS")
		}
		if allowLocalHTTP && localBind(o.Host) {
			return nil, nil
		}
		return nil, errors.New("HTTPS listener certificate and key are required")
	}
	certData, err := trustedTLSFile(o.CertificateFile, false, 1024*1024)
	if err != nil {
		return nil, err
	}
	keyData, err := trustedTLSFile(o.KeyFile, true, 64*1024)
	if err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair(certData, keyData)
	if err != nil {
		return nil, errors.New("TLS certificate and key do not match")
	}
	if len(pair.Certificate) == 0 {
		return nil, errors.New("TLS certificate is empty")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || !leafServerPurpose(leaf, time.Now()) {
		return nil, errors.New("TLS server certificate purpose or validity is invalid")
	}
	pair.Leaf = leaf
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}
	if o.ClientCAFile != "" {
		caData, err := trustedTLSFile(o.ClientCAFile, false, 1024*1024)
		if err != nil {
			return nil, err
		}
		pool, err := clientCAs(caData, time.Now())
		if err != nil {
			return nil, err
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}
