//go:build linux

package transfer

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"golang.org/x/sys/unix"
)

type IssuedCertificate struct {
	CertificatePEM        string
	CertificateThumbprint string
}
type CertificateProvider func(context.Context, ExecutionIdentity, string, []byte, time.Time) (IssuedCertificate, error)
type SupervisorConfig struct {
	Root                string
	SocketRoot          string
	ClientCACertificate string
	ClientCAKey         string
	ServiceCAFile       string
	ExchangeEndpoint    string
	GatewayEndpoint     string
	WorkloadIssuer      string
	WorkloadPublicKey   string
	ExchangeAudience    string
	GatewayAudience     string
	TokenProvider       func(context.Context, ExecutionBinding, bool) (string, error)
	CertificateProvider CertificateProvider
}
type BindingResult struct {
	Binding               ExecutionBinding `json:"binding"`
	CertificateThumbprint string           `json:"certificate_thumbprint"`
	ProxyEndpoint         string           `json:"proxy_endpoint"`
}
type ownedRoot struct {
	path     string
	fd       int
	dev, ino uint64
}

func openOwnedRoot(path string, create bool) (*ownedRoot, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("private root must be a clean absolute path")
	}
	fd, e := unix.Open("/", unix.O_DIRECTORY|unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if part == "" || part == "." || part == ".." {
			unix.Close(fd)
			return nil, errors.New("unsafe private root")
		}
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e == unix.ENOENT && create {
			if e = unix.Mkdirat(fd, part, 0700); e != nil && e != unix.EEXIST {
				unix.Close(fd)
				return nil, e
			}
			next, e = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
		unix.Close(fd)
		if e != nil {
			return nil, e
		}
		fd = next
	}
	var st unix.Stat_t
	if e = unix.Fstat(fd, &st); e != nil {
		unix.Close(fd)
		return nil, e
	}
	if st.Uid != uint32(os.Geteuid()) || st.Mode&077 != 0 {
		unix.Close(fd)
		return nil, errors.New("private root is not operator owned")
	}
	return &ownedRoot{path, fd, uint64(st.Dev), st.Ino}, nil
}
func (r *ownedRoot) check() error {
	var st unix.Stat_t
	if e := unix.Lstat(r.path, &st); e != nil {
		return e
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || uint64(st.Dev) != r.dev || st.Ino != r.ino || st.Uid != uint32(os.Geteuid()) || st.Mode&077 != 0 {
		return errors.New("private root identity changed")
	}
	return nil
}
func (r *ownedRoot) directory(parts []string, create bool) (int, error) {
	if e := r.check(); e != nil {
		return -1, e
	}
	fd, e := unix.Dup(r.fd)
	if e != nil {
		return -1, e
	}
	for _, part := range parts {
		if identifier(part) != nil {
			unix.Close(fd)
			return -1, errors.New("unsafe private component")
		}
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e == unix.ENOENT && create {
			if e = unix.Mkdirat(fd, part, 0700); e != nil && e != unix.EEXIST {
				unix.Close(fd)
				return -1, e
			}
			next, e = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
		unix.Close(fd)
		if e != nil {
			return -1, e
		}
		fd = next
		var st unix.Stat_t
		if e = unix.Fstat(fd, &st); e != nil {
			unix.Close(fd)
			return -1, e
		}
		if uint64(st.Dev) != r.dev || st.Uid != uint32(os.Geteuid()) || st.Mode&077 != 0 {
			unix.Close(fd)
			return -1, errors.New("private directory ownership changed")
		}
	}
	return fd, nil
}
func privateStat(fd int, name string) (*unix.Stat_t, error) {
	var st unix.Stat_t
	if e := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); e != nil {
		return nil, e
	}
	var parent unix.Stat_t
	if e := unix.Fstat(fd, &parent); e != nil {
		return nil, e
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) || st.Dev != parent.Dev || st.Mode&077 != 0 || st.Size > 65536 {
		return nil, errors.New("unsafe private material")
	}
	return &st, nil
}
func privateRead(fd int, name string) ([]byte, error) {
	st, e := privateStat(fd, name)
	if e != nil {
		return nil, e
	}
	fileFD, e := unix.Openat(fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fileFD), name)
	defer f.Close()
	var opened unix.Stat_t
	if e = unix.Fstat(fileFD, &opened); e != nil {
		return nil, e
	}
	if st.Dev != opened.Dev || st.Ino != opened.Ino || st.Size != opened.Size {
		return nil, errors.New("private material changed")
	}
	b, e := io.ReadAll(io.LimitReader(f, 65537))
	if e != nil {
		return nil, e
	}
	if len(b) > 65536 {
		return nil, errors.New("private material too large")
	}
	return b, nil
}
func privateWrite(fd int, name string, value []byte, replace bool) error {
	if len(value) > 65536 {
		return errors.New("private material too large")
	}
	temporary := name + ".tmp-" + domain.NewID()
	fileFD, e := unix.Openat(fd, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return e
	}
	f := os.NewFile(uintptr(fileFD), temporary)
	defer func() { f.Close(); unix.Unlinkat(fd, temporary, 0) }()
	if _, e = f.Write(value); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if !replace {
		if e = unix.Linkat(fd, temporary, fd, name, 0); e != nil {
			return e
		}
		if e = unix.Unlinkat(fd, temporary, 0); e != nil {
			return e
		}
	} else {
		if _, e = privateStat(fd, name); e != nil && e != unix.ENOENT {
			return e
		}
		if e = unix.Renameat(fd, temporary, fd, name); e != nil {
			return e
		}
	}
	return unix.Fsync(fd)
}
func socketStat(fd int, name string) (*unix.Stat_t, error) {
	var st, parent unix.Stat_t
	if e := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); e != nil {
		return nil, e
	}
	if e := unix.Fstat(fd, &parent); e != nil {
		return nil, e
	}
	if st.Mode&unix.S_IFMT != unix.S_IFSOCK || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 || st.Dev != parent.Dev {
		return nil, errors.New("unsafe proxy socket")
	}
	return &st, nil
}
func unlinkSame(fd int, name string, expected *unix.Stat_t) error {
	var st unix.Stat_t
	if e := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); e == unix.ENOENT {
		return nil
	} else if e != nil {
		return e
	}
	if st.Dev != expected.Dev || st.Ino != expected.Ino {
		return errors.New("private resource replaced")
	}
	if e := unix.Unlinkat(fd, name, 0); e != nil {
		return e
	}
	return unix.Fsync(fd)
}
func readPrivatePath(path string) ([]byte, error) {
	root, e := openOwnedRoot(filepath.Dir(path), false)
	if e != nil {
		return nil, e
	}
	defer unix.Close(root.fd)
	return privateRead(root.fd, filepath.Base(path))
}
func parsePrivateKey(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid private key")
	}
	if k, e := x509.ParsePKCS8PrivateKey(block.Bytes); e == nil {
		if signer, ok := k.(crypto.Signer); ok {
			return signer, nil
		}
	}
	if k, e := x509.ParsePKCS1PrivateKey(block.Bytes); e == nil {
		return k, nil
	}
	return nil, errors.New("invalid private signing key")
}
func samePublic(a, b any) bool {
	x, e := x509.MarshalPKIXPublicKey(a)
	if e != nil {
		return false
	}
	y, e := x509.MarshalPKIXPublicKey(b)
	return e == nil && bytes.Equal(x, y)
}

type supervisedProxy struct {
	binding        ExecutionBinding
	endpoint       string
	materialFD     int
	socketFD       int
	socketInfo     *unix.Stat_t
	controlInfo    *unix.Stat_t
	server         *http.Server
	listener       *net.UnixListener
	control        *net.UnixListener
	done           chan struct{}
	controlDone    chan struct{}
	drainUncertain atomic.Bool
}

func (p *supervisedProxy) running() bool {
	select {
	case <-p.done:
		return p.drainUncertain.Load()
	default:
		return true
	}
}

type Supervisor struct {
	config           SupervisorConfig
	root, socketRoot *ownedRoot
	ca               *x509.Certificate
	caKey            crypto.Signer
	mu               sync.Mutex
	active           map[string]*supervisedProxy
	adopted          map[string]ExecutionBinding
	closed           bool
}

func NewSupervisor(c SupervisorConfig) (*Supervisor, error) {
	if c.SocketRoot == "" {
		c.SocketRoot = c.Root
	}
	if c.TokenProvider == nil {
		return nil, errors.New("current execution credential provider required")
	}
	if (c.ClientCAKey == "") == (c.CertificateProvider == nil) {
		return nil, errors.New("configure exactly one private CA key or authenticated CSR provider")
	}
	var e error
	c.ExchangeEndpoint, e = serviceEndpoint(c.ExchangeEndpoint)
	if e != nil {
		return nil, e
	}
	c.GatewayEndpoint, e = serviceEndpoint(c.GatewayEndpoint)
	if e != nil {
		return nil, e
	}
	if c.WorkloadIssuer == "" || c.WorkloadPublicKey == "" || c.ServiceCAFile == "" {
		return nil, errors.New("fixed workload and TLS trust configuration required")
	}
	data, e := os.ReadFile(c.ClientCACertificate)
	if e != nil {
		return nil, e
	}
	ca, e := certFromPEM(data)
	if e != nil {
		return nil, e
	}
	if !ca.IsCA || !ca.BasicConstraintsValid || ca.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("execution certificate authority is invalid")
	}
	var signer crypto.Signer
	if c.ClientCAKey != "" {
		raw, e := readPrivatePath(c.ClientCAKey)
		if e != nil {
			return nil, e
		}
		signer, e = parsePrivateKey(raw)
		if e != nil {
			return nil, e
		}
		if !samePublic(signer.Public(), ca.PublicKey) {
			return nil, errors.New("execution CA key mismatch")
		}
	}
	root, e := openOwnedRoot(c.Root, true)
	if e != nil {
		return nil, e
	}
	sockets := root
	if c.SocketRoot != c.Root {
		sockets, e = openOwnedRoot(c.SocketRoot, true)
		if e != nil {
			unix.Close(root.fd)
			return nil, e
		}
	}
	return &Supervisor{config: c, root: root, socketRoot: sockets, ca: ca, caKey: signer, active: map[string]*supervisedProxy{}, adopted: map[string]ExecutionBinding{}}, nil
}
func (s *Supervisor) Endpoint(id ExecutionIdentity) (string, error) {
	if e := id.Validate(); e != nil {
		return "", e
	}
	endpoint := filepath.Join(s.config.SocketRoot, "p", id.Key(), "s")
	if len([]byte(endpoint)) >= 108 {
		return "", errors.New("private proxy socket path exceeds AF_UNIX limit")
	}
	return endpoint, nil
}
func materialParts(id ExecutionIdentity) []string {
	return []string{id.JobID, "attempts", id.AttemptID, id.ComponentID}
}
func (s *Supervisor) materialize(ctx context.Context, id ExecutionIdentity, space string, deadline time.Time) (ExecutionBinding, string, string, int, error) {
	fail := func(e error) (ExecutionBinding, string, string, int, error) { return ExecutionBinding{}, "", "", -1, e }
	if e := id.Validate(); e != nil {
		return fail(e)
	}
	if e := identifier(space); e != nil {
		return fail(e)
	}
	ledger, e := s.root.directory([]string{"purge-ledger"}, true)
	if e != nil {
		return fail(e)
	}
	_, e = privateStat(ledger, id.Key()+".json")
	unix.Close(ledger)
	if e == nil {
		return fail(errors.New("purged execution proxy cannot be recreated"))
	}
	if e != unix.ENOENT {
		return fail(e)
	}
	fd, e := s.root.directory(materialParts(id), true)
	if e != nil {
		return fail(e)
	}
	failed := true
	defer func() {
		if failed {
			unix.Close(fd)
		}
	}()
	if e = unix.Flock(fd, unix.LOCK_EX); e != nil {
		return fail(e)
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	expected := map[string]any{"job_id": id.JobID, "attempt_id": id.AttemptID, "component_id": id.ComponentID, "space_id": space, "epoch": id.Epoch}
	metadata, _ := domain.CanonicalJSON(expected)
	names := []string{"proxy-identity.json", "proxy-cert.pem", "proxy-key.pem"}
	present := make([]bool, 3)
	for i, name := range names {
		_, e := privateStat(fd, name)
		if e == nil {
			present[i] = true
		} else if e != unix.ENOENT {
			return fail(e)
		}
	}
	all := present[0] && present[1] && present[2]
	pending := s.config.CertificateProvider != nil && present[0] && !present[1] && present[2]
	anyPresent := present[0] || present[1] || present[2]
	if anyPresent && !all && !pending {
		return fail(errors.New("incomplete proxy material requires reconciliation"))
	}
	now := time.Now()
	expiry := now.Add(30 * 24 * time.Hour)
	if !deadline.IsZero() && deadline.Add(time.Hour).Before(expiry) {
		expiry = deadline.Add(time.Hour)
	}
	if s.ca.NotAfter.Before(expiry) {
		expiry = s.ca.NotAfter
	}
	if !expiry.After(now.Add(5 * time.Minute)) {
		return fail(errors.New("execution CA expires too soon"))
	}
	var signer crypto.Signer
	var cert *x509.Certificate
	if all || pending {
		saved, e := privateRead(fd, names[0])
		if e != nil {
			return fail(e)
		}
		var original map[string]any
		d := json.NewDecoder(bytes.NewReader(saved))
		d.UseNumber()
		if d.Decode(&original) != nil {
			return fail(errors.New("invalid proxy identity"))
		}
		encoded, e := domain.CanonicalJSON(original)
		if e != nil || !bytes.Equal(encoded, metadata) {
			return fail(errors.New("proxy material belongs to another execution"))
		}
		key, e := privateRead(fd, names[2])
		if e != nil {
			return fail(e)
		}
		signer, e = parsePrivateKey(key)
		if e != nil {
			return fail(e)
		}
		if all {
			raw, e := privateRead(fd, names[1])
			if e != nil {
				return fail(e)
			}
			cert, e = certFromPEM(raw)
			if e != nil {
				return fail(e)
			}
		}
	} else {
		signer, e = rsa.GenerateKey(rand.Reader, 2048)
		if e != nil {
			return fail(e)
		}
	}
	if cert == nil {
		if s.config.CertificateProvider != nil {
			if !pending {
				encoded, e := x509.MarshalPKCS8PrivateKey(signer)
				if e != nil {
					return fail(e)
				}
				if e = privateWrite(fd, names[2], pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), false); e != nil {
					return fail(e)
				}
				if e = privateWrite(fd, names[0], metadata, false); e != nil {
					return fail(e)
				}
			}
			csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "hf2l-execution"}}, signer)
			if e != nil {
				return fail(e)
			}
			issued, e := s.config.CertificateProvider(ctx, id, space, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}), expiry)
			if e != nil {
				return fail(e)
			}
			cert, e = certFromPEM([]byte(issued.CertificatePEM))
			if e != nil {
				return fail(e)
			}
			if CertificateThumbprint(cert.Raw) != issued.CertificateThumbprint || cert.NotAfter.After(expiry) {
				return fail(errors.New("CSR issuer returned a different certificate binding"))
			}
		} else {
			serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 159))
			if e != nil {
				return fail(e)
			}
			template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "hf2l-execution"}, NotBefore: now.Add(-time.Minute), NotAfter: expiry, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true, IsCA: false}
			der, e := x509.CreateCertificate(rand.Reader, template, s.ca, signer.Public(), s.caKey)
			if e != nil {
				return fail(e)
			}
			cert, e = x509.ParseCertificate(der)
			if e != nil {
				return fail(e)
			}
		}
		if e = s.validateLeaf(cert, signer); e != nil {
			return fail(e)
		}
		if s.config.CertificateProvider == nil {
			encoded, e := x509.MarshalPKCS8PrivateKey(signer)
			if e != nil {
				return fail(e)
			}
			if e = privateWrite(fd, names[2], pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), false); e != nil {
				return fail(e)
			}
		}
		if e = privateWrite(fd, names[1], pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), false); e != nil {
			return fail(e)
		}
		if s.config.CertificateProvider == nil {
			if e = privateWrite(fd, names[0], metadata, false); e != nil {
				return fail(e)
			}
		}
	}
	if e = s.validateLeaf(cert, signer); e != nil {
		return fail(e)
	}
	binding := ExecutionBinding{id.JobID, id.AttemptID, id.ComponentID, space, id.Epoch, CertificateThumbprint(cert.Raw)}
	directory := filepath.Join(append([]string{s.config.Root}, materialParts(id)...)...)
	failed = false
	return binding, filepath.Join(directory, names[1]), filepath.Join(directory, names[2]), fd, nil
}
func (s *Supervisor) validateLeaf(cert *x509.Certificate, key crypto.Signer) error {
	if cert.CheckSignatureFrom(s.ca) != nil || cert.IsCA || !cert.BasicConstraintsValid || !samePublic(cert.PublicKey, key.Public()) {
		return errors.New("execution certificate does not match its authority and key")
	}
	good := false
	for _, u := range cert.ExtKeyUsage {
		if u == x509.ExtKeyUsageClientAuth {
			good = true
		}
	}
	now := time.Now()
	if !good || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return errors.New("execution certificate is not current for client authentication")
	}
	return nil
}
func peerUID(c *net.UnixConn) (uint32, error) {
	raw, e := c.SyscallConn()
	if e != nil {
		return 0, e
	}
	var uid uint32
	var inner error
	e = raw.Control(func(fd uintptr) {
		var cred *unix.Ucred
		cred, inner = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if inner == nil {
			uid = cred.Uid
		}
	})
	if e != nil {
		return 0, e
	}
	return uid, inner
}

type controlRequest struct {
	Binding              ExecutionBinding `json:"binding"`
	Operation            string           `json:"operation"`
	TerminationConfirmed bool             `json:"termination_confirmed"`
}
type controlResponse struct {
	Binding  ExecutionBinding `json:"binding"`
	Running  bool             `json:"running"`
	OwnerPID int              `json:"owner_pid"`
}

func privateProxyOperation(ctx context.Context, path string, binding ExecutionBinding, operation string, confirmed bool) (controlResponse, error) {
	var result controlResponse
	c, e := (&net.Dialer{Timeout: 12 * time.Second}).DialContext(ctx, "unix", filepath.Join(filepath.Dir(path), "c"))
	if e != nil {
		return result, e
	}
	defer c.Close()
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return result, errors.New("private proxy control is not Unix")
	}
	uid, e := peerUID(uc)
	if e != nil || uid != uint32(os.Geteuid()) {
		return result, errors.New("untrusted proxy control owner")
	}
	_ = c.SetDeadline(time.Now().Add(12 * time.Second))
	if e = json.NewEncoder(c).Encode(controlRequest{binding, operation, confirmed}); e != nil {
		return result, e
	}
	reader := bufio.NewReader(io.LimitReader(c, 4097))
	line, e := reader.ReadBytes('\n')
	if e != nil || len(line) > 4096 {
		return result, errors.New("invalid private proxy response")
	}
	d := json.NewDecoder(bytes.NewReader(line))
	d.DisallowUnknownFields()
	if d.Decode(&result) != nil || result.Binding != binding || result.OwnerPID < 1 {
		return result, errors.New("private proxy binding changed")
	}
	return result, nil
}
func (s *Supervisor) startControl(p *supervisedProxy) error {
	alias := fmt.Sprintf("/proc/self/fd/%d/c", p.socketFD)
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: alias, Net: "unix"})
	if e != nil {
		return e
	}
	listener.SetUnlinkOnClose(false)
	if e = unix.Fchmodat(p.socketFD, "c", 0600, 0); e != nil {
		listener.Close()
		return e
	}
	p.control = listener
	p.controlDone = make(chan struct{})
	p.controlInfo, e = socketStat(p.socketFD, "c")
	if e != nil {
		listener.Close()
		return e
	}
	go func() {
		defer close(p.controlDone)
		for {
			c, e := listener.AcceptUnix()
			if e != nil {
				return
			}
			go func(c *net.UnixConn) {
				defer c.Close()
				uid, e := peerUID(c)
				if e != nil || uid != uint32(os.Geteuid()) {
					return
				}
				_ = c.SetDeadline(time.Now().Add(12 * time.Second))
				reader := bufio.NewReader(io.LimitReader(c, 4097))
				line, e := reader.ReadBytes('\n')
				if e != nil || len(line) > 4096 {
					return
				}
				var command controlRequest
				d := json.NewDecoder(bytes.NewReader(line))
				d.DisallowUnknownFields()
				if d.Decode(&command) != nil || command.Binding != p.binding {
					return
				}
				switch command.Operation {
				case "status":
				case "stop":
					if !command.TerminationConfirmed {
						return
					}
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					p.drainUncertain.Store(true)
					if err := p.server.Shutdown(ctx); err == nil {
						p.drainUncertain.Store(false)
						_ = p.control.Close()
					}
				default:
					return
				}
				_ = json.NewEncoder(c).Encode(controlResponse{p.binding, p.running(), os.Getpid()})
			}(c)
		}
	}()
	return nil
}
func (s *Supervisor) Ensure(ctx context.Context, id ExecutionIdentity, space string, deadline time.Time) (BindingResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return BindingResult{}, errors.New("proxy supervisor is closed")
	}
	endpoint, e := s.Endpoint(id)
	if e != nil {
		return BindingResult{}, e
	}
	if e = s.root.check(); e != nil {
		return BindingResult{}, e
	}
	if e = s.socketRoot.check(); e != nil {
		return BindingResult{}, e
	}
	if p := s.active[id.Key()]; p != nil {
		if p.binding.Identity() != id || p.binding.SpaceID != space || !p.running() {
			return BindingResult{}, errors.New("existing proxy changed or stopped; reconcile first")
		}
		return BindingResult{p.binding, p.binding.CertificateThumbprint, endpoint}, nil
	}
	binding, cert, key, materialFD, e := s.materialize(ctx, id, space, deadline)
	if e != nil {
		return BindingResult{}, e
	}
	socketFD, e := s.socketRoot.directory([]string{"p", id.Key()}, true)
	if e != nil {
		unix.Close(materialFD)
		return BindingResult{}, e
	}
	failed := true
	defer func() {
		if failed {
			unix.Close(materialFD)
			unix.Close(socketFD)
		}
	}()
	if e = unix.Flock(socketFD, unix.LOCK_EX); e != nil {
		return BindingResult{}, e
	}
	defer unix.Flock(socketFD, unix.LOCK_UN)
	alias := fmt.Sprintf("/proc/self/fd/%d/s", socketFD)
	if info, e := socketStat(socketFD, "s"); e == nil {
		connection, e := net.DialTimeout("unix", alias, 500*time.Millisecond)
		if e == nil {
			connection.Close()
			response, e := privateProxyOperation(ctx, endpoint, binding, "status", false)
			if e != nil || !response.Running {
				return BindingResult{}, errors.New("unknown or unhealthy proxy cannot be adopted")
			}
			s.adopted[id.Key()] = binding
			return BindingResult{binding, binding.CertificateThumbprint, endpoint}, nil
		}
		if !errors.Is(e, unix.ECONNREFUSED) && !errors.Is(e, unix.ENOENT) {
			return BindingResult{}, e
		}
		if e = unlinkSame(socketFD, "s", info); e != nil {
			return BindingResult{}, e
		}
	} else if e != unix.ENOENT {
		return BindingResult{}, e
	}
	if info, e := socketStat(socketFD, "c"); e == nil {
		response, e := privateProxyOperation(ctx, endpoint, binding, "status", false)
		if e == nil && response.Running {
			return BindingResult{}, errors.New("control socket reports a live missing proxy")
		}
		if e = unlinkSame(socketFD, "c", info); e != nil {
			return BindingResult{}, e
		}
	} else if e != unix.ENOENT {
		return BindingResult{}, e
	}
	settings := ProxySettings{ExchangeEndpoint: s.config.ExchangeEndpoint, GatewayEndpoint: s.config.GatewayEndpoint, ClientCertificate: cert, ClientKey: key, CAFile: s.config.ServiceCAFile, Binding: binding, WorkloadIssuer: s.config.WorkloadIssuer, WorkloadPublicKey: s.config.WorkloadPublicKey, ExchangeAudience: s.config.ExchangeAudience, GatewayAudience: s.config.GatewayAudience}
	settings.ExchangeToken = func(ctx context.Context) (string, error) { return s.config.TokenProvider(ctx, binding, false) }
	settings.GatewayToken = func(ctx context.Context) (string, error) { return s.config.TokenProvider(ctx, binding, true) }
	handler, e := NewProxy(settings)
	if e != nil {
		return BindingResult{}, e
	}
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: alias, Net: "unix"})
	if e != nil {
		return BindingResult{}, e
	}
	listener.SetUnlinkOnClose(false)
	if e = unix.Fchmodat(socketFD, "s", 0666, 0); e != nil {
		listener.Close()
		return BindingResult{}, e
	}
	info, e := socketStat(socketFD, "s")
	if e != nil {
		listener.Close()
		return BindingResult{}, e
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 30 * time.Second, ReadTimeout: 300 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 65536}
	p := &supervisedProxy{binding: binding, endpoint: endpoint, materialFD: materialFD, socketFD: socketFD, socketInfo: info, server: server, listener: listener, done: make(chan struct{})}
	go func() { defer close(p.done); _ = server.Serve(limitConnections(listener, 64)) }()
	if e = s.startControl(p); e != nil {
		_ = server.Close()
		return BindingResult{}, e
	}
	s.active[id.Key()] = p
	delete(s.adopted, id.Key())
	failed = false
	return BindingResult{binding, binding.CertificateThumbprint, endpoint}, nil
}

// Alive observes an exact existing proxy without creating files, keys, sockets
// or a replacement process. A running sandbox must be fenced if this proof is
// unavailable; it must not silently receive a replacement proxy.
func (s *Supervisor) Alive(ctx context.Context, id ExecutionIdentity) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false, errors.New("proxy supervisor is closed")
	}
	if e := id.Validate(); e != nil {
		return false, e
	}
	if e := s.root.check(); e != nil {
		return false, e
	}
	if e := s.socketRoot.check(); e != nil {
		return false, e
	}
	if p := s.active[id.Key()]; p != nil {
		if p.binding.Identity() != id {
			return false, errors.New("proxy identity changed")
		}
		return p.running(), nil
	}
	material, e := s.root.directory(materialParts(id), false)
	if e == unix.ENOENT {
		sockets, x := s.socketRoot.directory([]string{"p", id.Key()}, false)
		if x == unix.ENOENT {
			return false, nil
		}
		if x != nil {
			return false, x
		}
		defer unix.Close(sockets)
		files, x := inventory(sockets, map[string]bool{"s": true, "c": true}, true)
		if x != nil {
			return false, x
		}
		if len(files) > 0 {
			return false, errors.New("proxy sockets have no bound private identity")
		}
		return false, nil
	}
	if e != nil {
		return false, e
	}
	defer unix.Close(material)
	raw, e := privateRead(material, "proxy-identity.json")
	if e != nil {
		return false, e
	}
	var saved struct {
		JobID       string `json:"job_id"`
		AttemptID   string `json:"attempt_id"`
		ComponentID string `json:"component_id"`
		SpaceID     string `json:"space_id"`
		Epoch       int64  `json:"epoch"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&saved) != nil || saved.JobID != id.JobID || saved.AttemptID != id.AttemptID || saved.ComponentID != id.ComponentID || saved.Epoch != id.Epoch || identifier(saved.SpaceID) != nil {
		return false, errors.New("proxy material belongs to another execution")
	}
	raw, e = privateRead(material, "proxy-cert.pem")
	if e != nil {
		return false, e
	}
	cert, e := certFromPEM(raw)
	if e != nil {
		return false, e
	}
	key, e := privateRead(material, "proxy-key.pem")
	if e != nil {
		return false, e
	}
	signer, e := parsePrivateKey(key)
	if e != nil {
		return false, e
	}
	if e = s.validateLeaf(cert, signer); e != nil {
		return false, e
	}
	binding := ExecutionBinding{id.JobID, id.AttemptID, id.ComponentID, saved.SpaceID, id.Epoch, CertificateThumbprint(cert.Raw)}
	sockets, e := s.socketRoot.directory([]string{"p", id.Key()}, false)
	if e == unix.ENOENT {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	defer unix.Close(sockets)
	if _, e = socketStat(sockets, "s"); e == unix.ENOENT {
		return false, nil
	} else if e != nil {
		return false, e
	}
	endpoint, e := s.Endpoint(id)
	if e != nil {
		return false, e
	}
	status, e := privateProxyOperation(ctx, endpoint, binding, "status", false)
	if e == nil {
		return status.Running, nil
	}
	connection, probeErr := net.DialTimeout("unix", endpoint, 500*time.Millisecond)
	if probeErr == nil {
		connection.Close()
		return false, errors.New("live proxy has no authenticated private status")
	}
	if errors.Is(probeErr, unix.ECONNREFUSED) || errors.Is(probeErr, unix.ENOENT) {
		return false, nil
	}
	return false, e
}
func (s *Supervisor) Restore(ctx context.Context, id ExecutionIdentity, space string, deadline time.Time) (BindingResult, error) {
	return s.Ensure(ctx, id, space, deadline)
}
func (s *Supervisor) stopLocked(ctx context.Context, id ExecutionIdentity, confirmed bool) (bool, error) {
	if !confirmed {
		return false, errors.New("runtime termination or fencing must be confirmed before proxy stop")
	}
	if e := id.Validate(); e != nil {
		return false, e
	}
	p := s.active[id.Key()]
	if p != nil {
		if p.binding.Identity() != id {
			return false, errors.New("proxy identity changed")
		}
		deadline, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		p.drainUncertain.Store(true)
		if e := p.server.Shutdown(deadline); e != nil {
			return false, nil
		}
		p.drainUncertain.Store(false)
		if closer, ok := p.server.Handler.(io.Closer); ok {
			_ = closer.Close()
		}
		<-p.done
		if e := p.control.Close(); e != nil && !errors.Is(e, net.ErrClosed) {
			return false, e
		}
		<-p.controlDone
		if e := unlinkSame(p.socketFD, "s", p.socketInfo); e != nil {
			return false, e
		}
		if e := unlinkSame(p.socketFD, "c", p.controlInfo); e != nil {
			return false, e
		}
		unix.Close(p.materialFD)
		unix.Close(p.socketFD)
		delete(s.active, id.Key())
		delete(s.adopted, id.Key())
		return true, nil
	}
	if b, ok := s.adopted[id.Key()]; ok {
		path, e := s.Endpoint(id)
		if e != nil {
			return false, e
		}
		result, e := privateProxyOperation(ctx, path, b, "stop", true)
		if e != nil {
			return false, e
		}
		if result.Running {
			return false, nil
		}
		fd, e := s.socketRoot.directory([]string{"p", id.Key()}, false)
		if e != nil {
			return false, e
		}
		defer unix.Close(fd)
		if info, e := socketStat(fd, "s"); e == nil {
			if e = unlinkSame(fd, "s", info); e != nil {
				return false, e
			}
		} else if e != unix.ENOENT {
			return false, e
		}
		// The adopted owner's control remains available until its supervisor exits;
		// purge refuses it unless the data listener is proven stopped.
		delete(s.adopted, id.Key())
		return true, nil
	}
	path, e := s.Endpoint(id)
	if e != nil {
		return false, e
	}
	fd, e := s.socketRoot.directory([]string{"p", id.Key()}, false)
	if errors.Is(e, unix.ENOENT) {
		return true, nil
	}
	if e != nil {
		return false, e
	}
	defer unix.Close(fd)
	if _, e = socketStat(fd, "s"); errors.Is(e, unix.ENOENT) {
		return true, nil
	} else if e != nil {
		return false, e
	}
	c, e := net.DialTimeout("unix", path, 500*time.Millisecond)
	if e == nil {
		c.Close()
		return false, nil
	}
	if errors.Is(e, unix.ECONNREFUSED) || errors.Is(e, unix.ENOENT) {
		return true, nil
	}
	return false, e
}
func (s *Supervisor) Stop(ctx context.Context, id ExecutionIdentity, confirmed bool) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopLocked(ctx, id, confirmed)
}
func inventory(fd int, allowed map[string]bool, sockets bool) (map[string]*unix.Stat_t, error) {
	dup, e := unix.Dup(fd)
	if e != nil {
		return nil, e
	}
	directory := os.NewFile(uintptr(dup), "private")
	defer directory.Close()
	names, e := directory.Readdirnames(-1)
	if e != nil {
		return nil, e
	}
	out := map[string]*unix.Stat_t{}
	for _, name := range names {
		if !allowed[name] {
			return nil, errors.New("unknown private proxy material requires reconciliation")
		}
		var st *unix.Stat_t
		if sockets {
			st, e = socketStat(fd, name)
		} else {
			st, e = privateStat(fd, name)
		}
		if e != nil {
			return nil, e
		}
		out[name] = st
	}
	return out, nil
}
func removePrivateDirectory(root *ownedRoot, parts []string, opened int) error {
	parent, e := root.directory(parts[:len(parts)-1], false)
	if e != nil {
		return e
	}
	defer unix.Close(parent)
	var original, current unix.Stat_t
	if e = unix.Fstat(opened, &original); e != nil {
		return e
	}
	if e = unix.Fstatat(parent, parts[len(parts)-1], &current, unix.AT_SYMLINK_NOFOLLOW); e != nil {
		return e
	}
	if original.Dev != current.Dev || original.Ino != current.Ino || current.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("private directory replaced before purge")
	}
	if e = unix.Unlinkat(parent, parts[len(parts)-1], unix.AT_REMOVEDIR); e != nil {
		return e
	}
	return unix.Fsync(parent)
}
func (s *Supervisor) Purge(ctx context.Context, id ExecutionIdentity, confirmed bool) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !confirmed {
		return false, errors.New("runtime termination must be confirmed before proxy purge")
	}
	if e := id.Validate(); e != nil {
		return false, e
	}
	stopped, e := s.stopLocked(ctx, id, true)
	if e != nil || !stopped {
		return false, e
	}
	material, e := s.root.directory(materialParts(id), false)
	if e != nil && e != unix.ENOENT {
		return false, e
	}
	if e == nil {
		defer unix.Close(material)
	}
	sockets, e := s.socketRoot.directory([]string{"p", id.Key()}, false)
	if e != nil && e != unix.ENOENT {
		return false, e
	}
	if e == nil {
		defer unix.Close(sockets)
	}
	ledger, e := s.root.directory([]string{"purge-ledger"}, true)
	if e != nil {
		return false, e
	}
	defer unix.Close(ledger)
	auditName := id.Key() + ".json"
	var audit map[string]any
	if raw, e := privateRead(ledger, auditName); e == nil {
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber()
		if d.Decode(&audit) != nil {
			return false, errors.New("invalid proxy purge receipt")
		}
	} else if e != unix.ENOENT {
		return false, e
	}
	expected := map[string]any{"job_id": id.JobID, "attempt_id": id.AttemptID, "component_id": id.ComponentID, "epoch": id.Epoch}
	if audit != nil {
		for k, v := range expected {
			a, _ := domain.CanonicalJSON(audit[k])
			b, _ := domain.CanonicalJSON(v)
			if !bytes.Equal(a, b) {
				return false, errors.New("proxy purge receipt identity mismatch")
			}
		}
	}
	materialFiles := map[string]*unix.Stat_t{}
	socketFiles := map[string]*unix.Stat_t{}
	if material >= 0 {
		materialFiles, e = inventory(material, map[string]bool{"proxy-identity.json": true, "proxy-key.pem": true, "proxy-cert.pem": true}, false)
		if e != nil {
			return false, e
		}
	}
	if sockets >= 0 {
		socketFiles, e = inventory(sockets, map[string]bool{"s": true, "c": true}, true)
		if e != nil {
			return false, e
		}
	}
	if materialFiles["proxy-identity.json"] != nil {
		raw, e := privateRead(material, "proxy-identity.json")
		if e != nil {
			return false, e
		}
		var saved map[string]any
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber()
		if d.Decode(&saved) != nil || len(saved) != 5 {
			return false, errors.New("invalid proxy material identity")
		}
		for k, v := range expected {
			a, _ := domain.CanonicalJSON(saved[k])
			b, _ := domain.CanonicalJSON(v)
			if !bytes.Equal(a, b) {
				return false, errors.New("private material belongs to another execution")
			}
		}
		space, ok := saved["space_id"].(string)
		if !ok || identifier(space) != nil {
			return false, errors.New("invalid proxy space")
		}
		if audit == nil {
			audit = saved
			audit["status"] = "purging"
			audit["certificate_thumbprint"] = nil
			audit["purged_at"] = nil
		} else if audit["space_id"] != space {
			return false, errors.New("purge space changed")
		}
	} else if len(materialFiles) > 0 && audit == nil {
		return false, errors.New("private material has no trusted identity")
	}
	if audit == nil {
		if len(socketFiles) > 0 {
			return false, errors.New("unbound proxy sockets cannot be purged")
		}
		audit = expected
		audit["space_id"] = nil
		audit["certificate_thumbprint"] = nil
		audit["purged_at"] = nil
		audit["status"] = "purging"
	}
	if materialFiles["proxy-cert.pem"] != nil {
		raw, e := privateRead(material, "proxy-cert.pem")
		if e != nil {
			return false, e
		}
		cert, e := certFromPEM(raw)
		if e != nil {
			return false, e
		}
		if cert.CheckSignatureFrom(s.ca) != nil || cert.IsCA {
			return false, errors.New("purge certificate authority mismatch")
		}
		good := false
		for _, u := range cert.ExtKeyUsage {
			if u == x509.ExtKeyUsageClientAuth {
				good = true
			}
		}
		if !good {
			return false, errors.New("purge certificate purpose mismatch")
		}
		if materialFiles["proxy-key.pem"] != nil {
			key, e := privateRead(material, "proxy-key.pem")
			if e != nil {
				return false, e
			}
			signer, e := parsePrivateKey(key)
			if e != nil || !samePublic(signer.Public(), cert.PublicKey) {
				return false, errors.New("private purge key mismatch")
			}
		}
		thumb := CertificateThumbprint(cert.Raw)
		if previous := audit["certificate_thumbprint"]; previous != nil && previous != thumb {
			return false, errors.New("purge certificate binding changed")
		}
		audit["certificate_thumbprint"] = thumb
	}
	encoded, e := domain.CanonicalJSON(audit)
	if e != nil {
		return false, e
	}
	if e = privateWrite(ledger, auditName, encoded, true); e != nil {
		return false, e
	}
	for name, st := range materialFiles {
		if e = unlinkSame(material, name, st); e != nil {
			return false, e
		}
	}
	for name, st := range socketFiles {
		if e = unlinkSame(sockets, name, st); e != nil {
			return false, e
		}
	}
	if material >= 0 {
		if e = removePrivateDirectory(s.root, materialParts(id), material); e != nil {
			return false, e
		}
	}
	if sockets >= 0 {
		if e = removePrivateDirectory(s.socketRoot, []string{"p", id.Key()}, sockets); e != nil {
			return false, e
		}
	}
	audit["status"] = "purged"
	audit["purged_at"] = float64(time.Now().UnixNano()) / 1e9
	encoded, e = domain.CanonicalJSON(audit)
	if e != nil {
		return false, e
	}
	if e = privateWrite(ledger, auditName, encoded, true); e != nil {
		return false, e
	}
	return true, nil
}
func (s *Supervisor) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	for _, p := range s.active {
		_ = p.server.Close()
		if closer, ok := p.server.Handler.(io.Closer); ok {
			_ = closer.Close()
		}
		<-p.done
		_ = p.control.Close()
		<-p.controlDone
		_ = unlinkSame(p.socketFD, "c", p.controlInfo)
		unix.Close(p.materialFD)
		unix.Close(p.socketFD)
	}
	s.active = map[string]*supervisedProxy{}
	s.adopted = map[string]ExecutionBinding{}
	if s.socketRoot != s.root {
		unix.Close(s.socketRoot.fd)
	}
	return unix.Close(s.root.fd)
}

type UnixSettings struct {
	SocketPath string
	Mode       os.FileMode
}

func NewUnixServer(settings UnixSettings, handler http.Handler) (*http.Server, net.Listener, error) {
	if !filepath.IsAbs(settings.SocketPath) || filepath.Clean(settings.SocketPath) != settings.SocketPath || len([]byte(settings.SocketPath)) >= 108 {
		return nil, nil, errors.New("invalid private socket path")
	}
	mode := settings.Mode
	if mode == 0 {
		mode = 0600
	}
	if mode != 0600 && mode != 0666 {
		return nil, nil, errors.New("invalid private socket mode")
	}
	root, e := openOwnedRoot(filepath.Dir(settings.SocketPath), false)
	if e != nil {
		return nil, nil, e
	}
	// The root is intentionally kept open until the listener closes.
	name := filepath.Base(settings.SocketPath)
	if identifier(name) != nil {
		unix.Close(root.fd)
		return nil, nil, errors.New("invalid private socket name")
	}
	var st unix.Stat_t
	if e = unix.Fstatat(root.fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); e != unix.ENOENT {
		unix.Close(root.fd)
		return nil, nil, errors.New("private socket already exists or is unsafe")
	}
	alias := fmt.Sprintf("/proc/self/fd/%d/%s", root.fd, name)
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: alias, Net: "unix"})
	if e != nil {
		unix.Close(root.fd)
		return nil, nil, e
	}
	listener.SetUnlinkOnClose(false)
	if e = unix.Fchmodat(root.fd, name, uint32(mode), 0); e != nil {
		listener.Close()
		unix.Close(root.fd)
		return nil, nil, e
	}
	info, e := socketStat(root.fd, name)
	if e != nil {
		listener.Close()
		unix.Close(root.fd)
		return nil, nil, e
	}
	wrapped := &ownedUnixListener{UnixListener: listener, root: root, name: name, info: info}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 30 * time.Second, ReadTimeout: 300 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 65536}
	return server, limitConnections(wrapped, 64), nil
}

type ownedUnixListener struct {
	*net.UnixListener
	root *ownedRoot
	name string
	info *unix.Stat_t
	once sync.Once
}

func (l *ownedUnixListener) Close() error {
	e := l.UnixListener.Close()
	l.once.Do(func() { _ = unlinkSame(l.root.fd, l.name, l.info); unix.Close(l.root.fd) })
	return e
}
