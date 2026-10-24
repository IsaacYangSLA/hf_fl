package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/config"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/exchange"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/executor"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/manager"
)

func EnsureBroker(s *Services) error {
	if s.Broker != nil {
		return nil
	}
	if s.Settings.Workload == nil {
		return config.Invalid()
	}
	w := s.Settings.Workload
	broker, e := exchange.NewBroker(exchange.BrokerSettings{Issuer: w.Issuer, ExchangeAudience: w.ExchangeAudience, GatewayAudience: w.GatewayAudience, NodeAudience: w.NodeAudience, KeyID: w.KeyID, PublicKeyPEM: []byte(w.PublicKey), PrivateKeyPEM: []byte(w.PrivateKey)})
	if e != nil {
		return e
	}
	s.Broker = broker
	return nil
}
func ConfigureAdminPolicy(ctx context.Context, s *Services) error {
	values, e := s.Settings.Section("provisioner", false)
	if e != nil {
		return e
	}
	storageID := strValue(values["storage_pool_id"])
	if storageID == "" {
		n, _ := s.Settings.Section("node", false)
		storageID = strValue(n["pool_id"])
	}
	hosts := []string{}
	if v, ok := values["allowed_source_hosts"]; ok {
		hosts, e = stringsValue(v)
		if e != nil {
			return e
		}
	}
	s.Manager.AdminPolicy = &manager.AdminPolicy{StoragePoolID: storageID, StorageRoot: strValue(values["root"]), AllowedSourceHosts: hosts, QualifyObjectStore: func(ctx context.Context) (string, manager.Object, error) { return qualifyObjectStore(ctx, s) }}
	s.Manager.PoolQualifier = func(ctx context.Context, value map[string]any) (bool, error) { return QualifyPool(ctx, s, value) }
	return nil
}
func QualifyPool(ctx context.Context, s *Services, value map[string]any) (bool, error) {
	fail := func() (bool, error) { return false, domain.Err(409, "pool_qualification_required") }
	nodeID, poolID := strValue(value["node_id"]), strValue(value["id"])
	if nodeID == "" || poolID == "" {
		return fail()
	}
	var capacity map[string]int64
	nodes, _ := s.Settings.Section("nodes", false)
	if _, registered := objMap(nodes["endpoints"])[nodeID]; registered {
		if e := EnsureBroker(s); e != nil {
			return fail()
		}
		var e error
		capacity, e = QualifyRegisteredPool(ctx, s, value)
		if e != nil {
			return fail()
		}
	} else {
		local, e := CreateNodeAgent(ctx, s.Settings, nil)
		if e != nil {
			return fail()
		}
		defer local.Close()
		if local.NodeID != nodeID || local.PoolID != poolID {
			return fail()
		}
		capacity = map[string]int64{"cpu_millicores": local.Capacity.CPUMillis, "memory_bytes": local.Capacity.MemoryBytes, "disk_bytes": local.Capacity.DiskBytes}
	}
	for _, key := range []string{"gpu_uuids", "gpu_profiles"} {
		if a, exists := value[key]; exists {
			list, e := stringsValue(a)
			if e != nil || len(list) != 0 {
				return fail()
			}
		}
	}
	if v, exists := value["sandbox_profiles"]; exists {
		profiles, e := stringsValue(v)
		if e != nil {
			return fail()
		}
		for _, p := range profiles {
			if p != "runsc-cpu-v1" {
				return fail()
			}
		}
	}
	for _, key := range []string{"cpu_millicores", "memory_bytes", "disk_bytes"} {
		maximum := capacity[key]
		if key == "disk_bytes" {
			maximum = (maximum - executor.StorageHeadroomBytes) / 2
			if maximum < 0 {
				maximum = 0
			}
		}
		requested, e := config.Int(value[key], 0, 1<<50)
		if e != nil || requested > maximum {
			return fail()
		}
	}
	return true, nil
}
func canonicalEndpoint(raw string, allowLocal bool) (string, error) {
	if e := config.RequireTLS(raw, allowLocal); e != nil {
		return "", e
	}
	u, e := url.Parse(raw)
	if e != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", config.Invalid()
	}
	hostname := strings.ToLower(u.Hostname())
	port := u.Port()
	authority := hostname
	if strings.Contains(hostname, ":") {
		authority = "[" + hostname + "]"
	}
	if port != "" && !(u.Scheme == "https" && port == "443") && !(u.Scheme == "http" && port == "80") {
		authority = net.JoinHostPort(hostname, port)
	}
	return strings.ToLower(u.Scheme) + "://" + authority + strings.TrimRight(u.EscapedPath(), "/"), nil
}
func ExpectedObjectStore(s config.Settings) (string, map[string]any, map[string]any, error) {
	values, e := s.Section("provisioner", true)
	if e != nil {
		return "", nil, nil, e
	}
	poolID, e := cfgID(values["exchange_storage_pool_id"])
	if e != nil {
		return "", nil, nil, e
	}
	allocation, ok := values["exchange_storage"].(map[string]any)
	if !ok {
		return "", nil, nil, config.Invalid()
	}
	if e = config.Keys(allocation, []string{"registration_id", "endpoint", "bucket", "prefix", "region", "capacity_bytes"}, nil); e != nil {
		return "", nil, nil, e
	}
	registration, e := cfgID(allocation["registration_id"])
	if e != nil {
		return "", nil, nil, e
	}
	capacity, e := config.Int(allocation["capacity_bytes"], 1, 1<<50)
	if e != nil {
		return "", nil, nil, e
	}
	endpoint, e := cfgText(allocation, "endpoint")
	if e != nil {
		return "", nil, nil, e
	}
	endpoint, e = canonicalEndpoint(endpoint, s.OIDC.AllowLocalHTTP)
	if e != nil {
		return "", nil, nil, e
	}
	bucket, e := config.Text(allocation["bucket"], 200)
	if e != nil || strings.ContainsAny(bucket, "/\\") {
		return "", nil, nil, config.Invalid()
	}
	region, e := config.Text(allocation["region"], 200)
	if e != nil {
		return "", nil, nil, e
	}
	prefix, ok := allocation["prefix"].(string)
	if !ok || len(prefix) > 1024 || strings.ContainsAny(prefix, "\\\x00") {
		return "", nil, nil, config.Invalid()
	}
	prefix = strings.Trim(prefix, "/")
	for _, part := range strings.Split(prefix, "/") {
		if part == "." || part == ".." {
			return "", nil, nil, config.Invalid()
		}
	}
	allow, e := config.GetBool(values, "allow_local_exchange_http", false)
	if e != nil {
		return "", nil, nil, e
	}
	pub, e := canonicalEndpoint(strValue(values["exchange_endpoint"]), allow)
	if e != nil {
		return "", nil, nil, e
	}
	managed, e := canonicalEndpoint(strValue(values["managed_exchange_endpoint"]), allow)
	if e != nil {
		return "", nil, nil, e
	}
	location := map[string]any{"endpoint": endpoint, "bucket": bucket, "prefix": prefix}
	identity := map[string]any{"endpoint": endpoint, "bucket": bucket, "prefix": prefix, "region": region, "registration_id": registration, "exchange_endpoint": pub, "managed_exchange_endpoint": managed}
	backendID, e := domain.Hash(identity)
	if e != nil {
		return "", nil, nil, e
	}
	locatorID, e := domain.Hash(location)
	if e != nil {
		return "", nil, nil, e
	}
	regHash := sha256.Sum256([]byte(registration))
	metadata := map[string]any{"object_store": true, "registration_id": registration, "backend_id": backendID, "locator_id": locatorID, "capacity_bound_bytes": capacity, "node_id": "object-store-" + hex.EncodeToString(regHash[:])[:32]}
	expected := map[string]any{"endpoint": endpoint, "bucket": bucket, "prefix": prefix, "region": region}
	return poolID, metadata, expected, nil
}
func qualifyObjectStore(ctx context.Context, s *Services) (string, map[string]any, error) {
	pool, metadata, expected, e := ExpectedObjectStore(s.Settings)
	if e != nil {
		return "", nil, e
	}
	backend, e := GatewayBackend(s.Settings)
	if e != nil {
		return "", nil, e
	}
	defer backend.Close()
	provisioner, e := s.Settings.Section("provisioner", true)
	if e != nil {
		return "", nil, e
	}
	token, e := config.ReadSecret(strValue(provisioner["admin_token_file"]))
	if e != nil {
		return "", nil, e
	}
	gateway, e := s.Settings.Section("gateway", true)
	if e != nil {
		return "", nil, e
	}
	cert := strValue(gateway["backend_client_certificate"])
	if cert == "" {
		cert = strValue(gateway["tls_certificate"])
	}
	if cert == "" {
		n, _ := s.Settings.Section("nodes", false)
		cert = strValue(n["client_certificate"])
	}
	if cert == "" {
		return "", nil, config.Invalid()
	}
	thumb, e := CertificateThumbprint(cert)
	if e != nil {
		return "", nil, e
	}
	actual, e := backend.CheckStorage(ctx, "Bearer "+token, thumb)
	if e != nil {
		return "", nil, e
	}
	if actual["checked"] != true || actual["versioning"] != "Enabled" || actual["protocol"] != "s3-multipart-v1" {
		return "", nil, config.Invalid()
	}
	for key, value := range expected {
		got := actual[key]
		if key == "endpoint" {
			endpoint, ok := got.(string)
			if !ok {
				return "", nil, config.Invalid()
			}
			got, e = canonicalEndpoint(endpoint, s.Settings.OIDC.AllowLocalHTTP)
			if e != nil {
				return "", nil, e
			}
		}
		if key == "prefix" {
			p, ok := got.(string)
			if !ok {
				return "", nil, config.Invalid()
			}
			got = strings.Trim(p, "/")
		}
		if got != value {
			return "", nil, config.Invalid()
		}
	}
	return pool, metadata, nil
}
func validateObjectStorePool(ctx context.Context, s *Services) (string, error) {
	poolID, metadata, _, e := ExpectedObjectStore(s.Settings)
	if e != nil {
		return "", e
	}
	pool, e := s.DB.One(ctx, "SELECT * FROM jm_pools WHERE id = ?", poolID)
	if e != nil {
		return "", e
	}
	if pool == nil || intValue(pool["cpu_millicores"]) != 0 || intValue(pool["memory_bytes"]) != 0 || pool["node_id"] != metadata["node_id"] {
		return "", config.Invalid()
	}
	for _, k := range []string{"gpu_uuids", "gpu_profiles", "sandbox_profiles"} {
		items, e := stringsValue(pool[k])
		if e != nil || len(items) > 0 {
			return "", config.Invalid()
		}
	}
	details := objMap(pool["details_json"])
	if details["manager_storage"] == true {
		return "", config.Invalid()
	}
	for key, value := range metadata {
		a, e := domain.CanonicalJSON(details[key])
		if e != nil {
			return "", e
		}
		b, e := domain.CanonicalJSON(value)
		if e != nil || string(a) != string(b) {
			return "", config.Invalid()
		}
	}
	disk := intValue(pool["disk_bytes"])
	if disk < 1 || disk > intValue(metadata["capacity_bound_bytes"]) {
		return "", config.Invalid()
	}
	return poolID, nil
}
func validateManagerStoragePool(ctx context.Context, s *Services, poolID, root string) error {
	if domain.ValidateIdentifier(poolID) != nil || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return config.Invalid()
	}
	current := "/"
	for _, part := range strings.Split(strings.TrimPrefix(root, "/"), "/") {
		current = filepath.Join(current, part)
		info, e := os.Lstat(current)
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return config.Invalid()
		}
	}
	var st syscall.Stat_t
	if syscall.Lstat(root, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFDIR || st.Uid != uint32(os.Getuid()) || st.Mode&0077 != 0 {
		return config.Invalid()
	}
	pool, e := s.DB.One(ctx, "SELECT * FROM jm_pools WHERE id = ?", poolID)
	if e != nil {
		return e
	}
	if pool == nil {
		return config.Invalid()
	}
	details := objMap(pool["details_json"])
	if details["object_store"] == true {
		return config.Invalid()
	}
	if details["manager_storage"] == true {
		if intValue(details["filesystem_device"]) != int64(st.Dev) || intValue(details["root_inode"]) != int64(st.Ino) || intValue(details["root_owner"]) != int64(st.Uid) || intValue(pool["cpu_millicores"]) != 0 || intValue(pool["memory_bytes"]) != 0 {
			return config.Invalid()
		}
		for _, key := range []string{"gpu_uuids", "gpu_profiles", "sandbox_profiles"} {
			items, e := stringsValue(pool[key])
			if e != nil || len(items) > 0 {
				return config.Invalid()
			}
		}
		return nil
	}
	n, _ := s.Settings.Section("node", false)
	ec, _ := s.Settings.Section("executor", false)
	if n["pool_id"] != poolID || n["node_id"] != pool["node_id"] {
		return config.Invalid()
	}
	eroot := strValue(ec["root"])
	var est syscall.Stat_t
	if eroot == "" || syscall.Stat(eroot, &est) != nil || est.Dev != st.Dev {
		return config.Invalid()
	}
	return nil
}
