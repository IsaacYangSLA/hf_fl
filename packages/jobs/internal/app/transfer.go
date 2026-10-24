package app

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/config"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/transfer"
)

func GatewayBackend(s config.Settings) (*transfer.HTTPGatewayBackend, error) {
	values, e := s.Section("gateway", true)
	if e != nil {
		return nil, e
	}
	endpoint, e := cfgText(values, "backend_endpoint")
	if e != nil {
		return nil, e
	}
	secretFile, e := cfgText(values, "backend_secret_file")
	if e != nil {
		return nil, e
	}
	secret, e := config.ReadSecret(secretFile)
	if e != nil {
		return nil, e
	}
	ca, e := config.GetString(values, "ca_file", "")
	if e != nil {
		return nil, e
	}
	cert, e := config.GetString(values, "backend_client_certificate", "")
	if e != nil {
		return nil, e
	}
	key, e := config.GetString(values, "backend_client_key", "")
	if e != nil {
		return nil, e
	}
	if key != "" {
		if _, e = config.ReadSecret(key); e != nil {
			return nil, e
		}
	}
	return transfer.NewHTTPGatewayBackend(transfer.GatewayBackendSettings{Endpoint: endpoint, BackendSecret: secret, CAFile: ca, ClientCertificate: cert, ClientKey: key, Timeout: 60 * time.Second})
}
func RunGateway(ctx context.Context, s config.Settings, args Arguments) error {
	if s.Workload == nil {
		return config.Invalid()
	}
	values, e := s.Section("gateway", true)
	if e != nil {
		return e
	}
	if e = config.Keys(values, []string{"tls_certificate", "tls_key", "client_ca_file", "backend_endpoint", "backend_secret_file"}, []string{"host", "port", "origin_endpoints", "origin_ca_file", "allow_local_origin_http", "max_part_bytes", "max_download_bytes", "ca_file", "backend_client_certificate", "backend_client_key"}); e != nil {
		return e
	}
	backend, e := GatewayBackend(s)
	if e != nil {
		return e
	}
	defer backend.Close()
	origins := []string{}
	if v, ok := values["origin_endpoints"]; ok {
		origins, e = stringsValue(v)
		if e != nil {
			return e
		}
	}
	originCA, e := config.GetString(values, "origin_ca_file", "")
	if e != nil {
		return e
	}
	allowLocal, e := config.GetBool(values, "allow_local_origin_http", false)
	if e != nil {
		return e
	}
	maxPart, e := config.GetInt(values, "max_part_bytes", 64<<20, 1, 1<<40)
	if e != nil {
		return e
	}
	maxDownload, e := config.GetInt(values, "max_download_bytes", 1<<40, 1, 1<<50)
	if e != nil {
		return e
	}
	h, e := transfer.NewGateway(transfer.GatewaySettings{Verifier: transfer.WorkloadVerifier{Issuer: s.Workload.Issuer, Audience: s.Workload.GatewayAudience, Scope: "transfer", PublicKey: s.Workload.PublicKey}, OriginEndpoints: origins, OriginCAFile: originCA, MaxPartBytes: maxPart, MaxDownloadBytes: maxDownload, AllowLocalOriginHTTP: allowLocal}, backend)
	if e != nil {
		return e
	}
	return RunMTLS(ctx, s, args, h, values)
}
func RunEdge(ctx context.Context, s config.Settings, args Arguments) error {
	boundaries, e := s.Section("boundaries", true)
	if e != nil {
		return e
	}
	values, ok := boundaries["exchange"].(map[string]any)
	if !ok {
		return config.Invalid()
	}
	if e = config.Keys(values, []string{"tls_certificate", "tls_key", "client_ca_file", "backend_endpoint", "backend_secret_file"}, []string{"host", "port", "ca_file", "backend_client_certificate", "backend_client_key"}); e != nil {
		return e
	}
	endpoint, e := cfgText(values, "backend_endpoint")
	if e != nil {
		return e
	}
	secretFile, e := cfgText(values, "backend_secret_file")
	if e != nil {
		return e
	}
	secret, e := config.ReadSecret(secretFile)
	if e != nil {
		return e
	}
	ca, e := config.GetString(values, "ca_file", "")
	if e != nil {
		return e
	}
	clientCertificate, e := config.GetString(values, "backend_client_certificate", "")
	if e != nil {
		return e
	}
	clientKey, e := config.GetString(values, "backend_client_key", "")
	if e != nil {
		return e
	}
	if clientKey != "" {
		if _, e = config.ReadSecret(clientKey); e != nil {
			return e
		}
	}
	h, e := transfer.NewEdge(transfer.EdgeSettings{BackendEndpoint: endpoint, BackendSecret: secret, CAFile: ca, ClientCertificate: clientCertificate, ClientKey: clientKey, MaxControlBytes: s.MaxBodyBytes, Timeout: 60 * time.Second})
	if e != nil {
		return e
	}
	return RunMTLS(ctx, s, args, h, values)
}
func RunProxy(ctx context.Context, s config.Settings) error {
	if s.Workload == nil {
		return config.Invalid()
	}
	values, e := s.Section("proxy", true)
	if e != nil {
		return e
	}
	if e = config.Keys(values, []string{"exchange_endpoint", "gateway_endpoint", "client_certificate", "client_key", "ca_file", "binding", "exchange_token_file", "gateway_token_file", "socket_path"}, nil); e != nil {
		return e
	}
	key := strValue(values["client_key"])
	if _, e = config.ReadSecret(key); e != nil {
		return e
	}
	var binding transfer.ExecutionBinding
	if e = config.DecodeSection(objMap(values["binding"]), &binding); e != nil {
		return e
	}
	exchangeToken, e := cfgText(values, "exchange_token_file")
	if e != nil {
		return e
	}
	gatewayToken, e := cfgText(values, "gateway_token_file")
	if e != nil {
		return e
	}
	if _, e = config.ReadSecret(exchangeToken); e != nil {
		return e
	}
	if _, e = config.ReadSecret(gatewayToken); e != nil {
		return e
	}
	settings := transfer.ProxySettings{ExchangeEndpoint: strValue(values["exchange_endpoint"]), GatewayEndpoint: strValue(values["gateway_endpoint"]), ClientCertificate: strValue(values["client_certificate"]), ClientKey: key, CAFile: strValue(values["ca_file"]), Binding: binding, WorkloadIssuer: s.Workload.Issuer, WorkloadPublicKey: s.Workload.PublicKey, ExchangeAudience: s.Workload.ExchangeAudience, GatewayAudience: s.Workload.GatewayAudience, ExchangeToken: func(context.Context) (string, error) { return config.ReadSecret(exchangeToken) }, GatewayToken: func(context.Context) (string, error) { return config.ReadSecret(gatewayToken) }}
	h, e := transfer.NewProxy(settings)
	if e != nil {
		return e
	}
	defer closeHandler(h)
	server, listener, e := transfer.NewUnixServer(transfer.UnixSettings{SocketPath: strValue(values["socket_path"])}, h)
	if e != nil {
		return e
	}
	return serve(ctx, server, listener, time.Duration(s.GracefulShutdownTimeoutSeconds)*time.Second)
}
func CertificateThumbprint(path string) (string, error) {
	data, e := config.ReadFile(path, 65536, false)
	if e != nil {
		return "", e
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", config.Invalid()
	}
	for len(bytes.TrimSpace(rest)) > 0 {
		var extra *pem.Block
		extra, rest = pem.Decode(rest)
		if extra == nil || extra.Type != "CERTIFICATE" {
			return "", config.Invalid()
		}
		if _, err := x509.ParseCertificate(extra.Bytes); err != nil {
			return "", config.Invalid()
		}
	}
	cert, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		return "", config.Invalid()
	}
	return transfer.CertificateThumbprint(cert.Raw), nil
}
