package app

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/config"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/transfer"
)

func listenerAddress(args Arguments, values map[string]any, defaultPort int) (string, error) {
	host, e := config.GetString(values, "host", "127.0.0.1")
	if e != nil {
		return "", e
	}
	if args.Host != "" {
		host = args.Host
	}
	port, e := config.GetInt(values, "port", int64(defaultPort), 1, 65535)
	if e != nil {
		return "", e
	}
	if args.PortSet {
		port = int64(args.Port)
	}
	if strings.TrimSpace(host) != host || host == "" || strings.ContainsAny(host, "/\x00\r\n") {
		return "", config.Invalid()
	}
	return net.JoinHostPort(host, strconv.FormatInt(port, 10)), nil
}
func serverTimeout(s config.Settings, values map[string]any) (time.Duration, error) {
	n, e := config.GetInt(values, "graceful_shutdown_timeout_seconds", int64(s.GracefulShutdownTimeoutSeconds), 1, 60)
	return time.Duration(n) * time.Second, e
}
func serve(ctx context.Context, srv *http.Server, listener net.Listener, grace time.Duration) error {
	defer listener.Close()
	result := make(chan error, 1)
	go func() { result <- srv.Serve(listener) }()
	select {
	case err := <-result:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), grace)
		defer cancel()
		err := srv.Shutdown(shutdown)
		if err != nil {
			_ = srv.Close()
		}
		serveErr := <-result
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			return serveErr
		}
		return nil
	}
}
func newHTTPServer(address string, h http.Handler) *http.Server {
	return &http.Server{Addr: address, Handler: h, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20, ErrorLog: log.New(io.Discard, "", 0)}
}
func RunHTTP(ctx context.Context, s config.Settings, args Arguments, h http.Handler) error {
	values, e := s.Section("service", false)
	if e != nil {
		return e
	}
	if e = config.Keys(values, nil, []string{"host", "port", "tls_certificate", "tls_key", "graceful_shutdown_timeout_seconds"}); e != nil {
		return e
	}
	addr, e := listenerAddress(args, values, 8082)
	if e != nil {
		return e
	}
	cert, e := config.GetString(values, "tls_certificate", "")
	if e != nil {
		return e
	}
	key, e := config.GetString(values, "tls_key", "")
	if e != nil {
		return e
	}
	if (cert == "") != (key == "") {
		return config.Invalid()
	}
	host, _, _ := net.SplitHostPort(addr)
	ip := net.ParseIP(host)
	local := host == "localhost" || ip != nil && ip.IsLoopback()
	if cert == "" && (!local || !s.OIDC.AllowLocalHTTP) {
		return config.Invalid()
	}
	grace, e := serverTimeout(s, values)
	if e != nil {
		return e
	}
	srv := newHTTPServer(addr, h)
	if cert != "" {
		certPEM, e := config.ReadFile(cert, 65536, false)
		if e != nil {
			return e
		}
		keyPEM, e := config.ReadFile(key, 65536, true)
		if e != nil {
			return e
		}
		pair, e := tls.X509KeyPair(certPEM, keyPEM)
		if e != nil {
			return config.Invalid()
		}
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, NextProtos: []string{"http/1.1"}}
	}
	listener, e := net.Listen("tcp", addr)
	if e != nil {
		return e
	}
	if srv.TLSConfig != nil {
		listener = tls.NewListener(listener, srv.TLSConfig)
	}
	return serve(ctx, srv, listener, grace)
}
func RunMTLS(ctx context.Context, s config.Settings, args Arguments, h http.Handler, values map[string]any) error {
	defer closeHandler(h)
	address, e := listenerAddress(args, values, 8443)
	if e != nil {
		return e
	}
	cert, e := config.GetString(values, "tls_certificate", "")
	if e != nil || cert == "" {
		return config.Invalid()
	}
	key, e := config.GetString(values, "tls_key", "")
	if e != nil || key == "" {
		return config.Invalid()
	}
	ca, e := config.GetString(values, "client_ca_file", "")
	if e != nil || ca == "" {
		return config.Invalid()
	}
	if _, e = config.ReadSecret(key); e != nil {
		return e
	}
	limit := s.MaxBodyBytes
	if args.Command == "gateway" {
		limit, e = config.GetInt(values, "max_part_bytes", 64<<20, 1, 1<<40)
		if e != nil {
			return e
		}
	}
	if args.Command == "managed-node" || args.Command == "participant-agent" {
		limit = 4 << 20
	}
	server, listener, e := transfer.NewMTLSServer(transfer.MTLSSettings{Address: address, Certificate: cert, Key: key, ClientCA: ca, MaxRequestBytes: limit}, h)
	if e != nil {
		return e
	}
	grace := time.Duration(s.GracefulShutdownTimeoutSeconds) * time.Second
	return serve(ctx, server, listener, grace)
}
func Poll(ctx context.Context, once bool, interval time.Duration, tick func(context.Context) (any, error)) (any, error) {
	if interval < 100*time.Millisecond || interval > 60*time.Second {
		return nil, config.Invalid()
	}
	var last any
	for {
		if e := ctx.Err(); e != nil {
			return last, nil
		}
		result, e := tick(ctx)
		if e != nil {
			return nil, e
		}
		last = result
		if once {
			return result, nil
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return last, nil
		case <-timer.C:
		}
	}
}

func closeHandler(h http.Handler) {
	if c, ok := h.(io.Closer); ok {
		_ = c.Close()
	}
}
