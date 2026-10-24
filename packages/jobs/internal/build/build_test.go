//go:build linux

package build

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
)

func fixture(t *testing.T) (Config, Result) {
	t.Helper()
	raw, e := os.ReadFile("testdata/python-build-contracts.json")
	if e != nil {
		t.Fatal(e)
	}
	var values map[string]json.RawMessage
	if e = json.Unmarshal(raw, &values); e != nil {
		t.Fatal(e)
	}
	c, e := DecodeConfig(values["config"])
	if e != nil {
		t.Fatal(e)
	}
	r, e := DecodeResult(values["result"])
	if e != nil {
		t.Fatal(e)
	}
	return c, r
}
func opaqueFixture(t *testing.T) (Config, Result, []byte, []byte, []RetainedFile) {
	t.Helper()
	c, r := fixture(t)
	body := []byte("opaque wheel bytes; the manager must not load these")
	hash := sha256.Sum256(body)
	r.Wheel.SHA256 = hex.EncodeToString(hash[:])
	r.Wheel.SizeBytes = int64(len(body))
	report, e := json.Marshal(r)
	if e != nil {
		t.Fatal(e)
	}
	reportHash := sha256.Sum256(report)
	files := []RetainedFile{{Path: "artifacts/build.json", SHA256: hex.EncodeToString(reportHash[:]), SizeBytes: int64(len(report)), Locator: "owned-report"}, {Path: "artifacts/" + r.Wheel.Filename, SHA256: r.Wheel.SHA256, SizeBytes: r.Wheel.SizeBytes, Locator: "owned-wheel"}}
	return c, r, body, report, files
}
func mustErrorCode(t *testing.T, err error, status int, code string) {
	t.Helper()
	var actual *domain.Error
	if !errors.As(err, &actual) || actual.Status != status || actual.Code != code {
		t.Fatalf("want %d/%s got %v", status, code, err)
	}
}
func TestPythonBuildConfigBindingResultContract(t *testing.T) {
	c, r := fixture(t)
	if e := r.ValidateBinding(c); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile("testdata/python-build-contracts.json")
	if e != nil {
		t.Fatal(e)
	}
	values, e := domain.DecodeJSON(raw)
	if e != nil {
		t.Fatal(e)
	}
	m := values.(map[string]any)
	actual, e := domain.CanonicalJSON(c.Map())
	if e != nil {
		t.Fatal(e)
	}
	expected, e := domain.CanonicalJSON(m["config"])
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatalf("config roundtrip differs\n%s\n%s", actual, expected)
	}
	binding, e := domain.CanonicalJSON(c.DurableBinding().Map())
	if e != nil {
		t.Fatal(e)
	}
	expected, e = domain.CanonicalJSON(m["binding"])
	if e != nil || !bytes.Equal(binding, expected) {
		t.Fatalf("binding differs %s %s %v", binding, expected, e)
	}
}
func TestBuildDescriptorsRejectUnknownNullBooleansAndForeignBindings(t *testing.T) {
	c, r := fixture(t)
	raw, _ := json.Marshal(c)
	var cfg map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if e := dec.Decode(&cfg); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(map[string]any){
		func(m map[string]any) { m["epoch"] = true }, func(m map[string]any) { m["epoch"] = nil }, func(m map[string]any) { m["unknown"] = 1 },
		func(m map[string]any) { m["source_dir"] = "/job/state/source" }, func(m map[string]any) { m["source_dir"] = "/job/source/../foreign" },
		func(m map[string]any) { m["spec_digest"] = strings.Repeat("0", 64) }, func(m map[string]any) { m["component_id"] = "owner" },
		func(m map[string]any) {
			m["source_manifest"] = map[string]string{"../foreign": strings.Repeat("a", 64)}
		},
		func(m map[string]any) { m["approved_dependencies"] = map[string]string{"setuptools": "80.9.0"} },
		func(m map[string]any) {
			m["approved_dependencies"] = map[string]string{"build": "1.6.1", "My-Pkg": "1.0", "my_pkg": "1.0"}
		},
	} {
		value := domain.CloneMap(cfg)
		mutate(value)
		b, e := domain.CanonicalJSON(value)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = DecodeConfig(b); e == nil {
			t.Fatalf("invalid config accepted %s", b)
		}
	}
	r.Binding.JobID = "foreign-job"
	if e := r.ValidateBinding(c); e == nil {
		t.Fatal("foreign immutable binding accepted")
	}
	for _, body := range []string{
		`{"filename":"../other.whl","sha256":"` + strings.Repeat("a", 64) + `","size_bytes":1}`,
		`{"filename":"private.whl","sha256":"` + strings.Repeat("a", 64) + `","size_bytes":true}`,
		`{"filename":"private.whl","sha256":"` + strings.Repeat("a", 64) + `","size_bytes":null}`,
		`{"filename":"private.whl","sha256":"` + strings.Repeat("a", 64) + `","size_bytes":1,"extra":2}`,
	} {
		var a Artifact
		if e := json.Unmarshal([]byte(body), &a); e == nil {
			t.Fatalf("invalid artifact accepted %s", body)
		}
	}
}
func TestCollectProductsUsesBoundedOwnedDescriptorsAndImmutableBinding(t *testing.T) {
	c, r, body, report, files := opaqueFixture(t)
	calls := 0
	read := func(ctx context.Context, id Identity, file RetainedFile, limit int64) ([]byte, error) {
		calls++
		if id != (Identity{c.JobID, c.AttemptID, c.ComponentID, c.Epoch}) {
			t.Fatal("foreign read identity")
		}
		if file.SizeBytes > limit {
			t.Fatal("read requested above limit")
		}
		if file.Locator == "owned-report" {
			return append([]byte(nil), report...), nil
		}
		if file.Locator == "owned-wheel" {
			return append([]byte(nil), body...), nil
		}
		return nil, errors.New("unowned")
	}
	products, e := CollectProducts(context.Background(), map[string]Config{"build": c}, map[string][]RetainedFile{"build": files}, read)
	if e != nil {
		t.Fatal(e)
	}
	if calls != 2 || products.LogicalBytes != int64(len(body)) || products.Manifest[r.Wheel.Filename].SHA256 != r.Wheel.SHA256 || !bytes.Equal(products.Payloads[r.Wheel.Filename], body) {
		t.Fatal("incomplete collection")
	}
	if _, e = CollectProducts(context.Background(), map[string]Config{"build": c}, map[string][]RetainedFile{"foreign": files}, read); e == nil {
		t.Fatal("foreign component gang accepted")
	}
	altered := append([]RetainedFile(nil), files...)
	altered[1].SHA256 = strings.Repeat("f", 64)
	if _, e = CollectProducts(context.Background(), map[string]Config{"build": c}, map[string][]RetainedFile{"build": altered}, read); e == nil {
		t.Fatal("changed result descriptor accepted")
	}
	badReader := func(context.Context, Identity, RetainedFile, int64) ([]byte, error) {
		return []byte("foreign bytes"), nil
	}
	if _, e = CollectProducts(context.Background(), map[string]Config{"build": c}, map[string][]RetainedFile{"build": files}, badReader); e == nil {
		t.Fatal("changed retained bytes accepted")
	}
}
func TestCollectRejectsConflictingPackagesAndOversizedBeforeWheelRead(t *testing.T) {
	c, r, body, report, files := opaqueFixture(t)
	second := c
	second.ComponentID = "other-build"
	spec := c.Spec
	spec.Components = append(append([]domain.ComponentSpec(nil), spec.Components...), domain.ComponentSpec{ComponentID: "other-build", Role: "build", Resources: spec.Components[1].Resources})
	c.Spec = spec
	c.SpecDigest, _ = spec.Digest()
	second.Spec = spec
	second.SpecDigest = c.SpecDigest
	firstResult := r
	firstResult.Binding = c.DurableBinding()
	firstReport, _ := json.Marshal(firstResult)
	hash := sha256.Sum256(firstReport)
	files[0].SHA256 = hex.EncodeToString(hash[:])
	files[0].SizeBytes = int64(len(firstReport))
	secondResult := r
	secondResult.Binding = second.DurableBinding()
	secondResult.Wheel.SizeBytes = MaxBuildBytes + 1
	secondReport, _ := json.Marshal(secondResult)
	secondHash := sha256.Sum256(secondReport)
	secondFiles := []RetainedFile{{Path: "artifacts/build.json", SHA256: hex.EncodeToString(secondHash[:]), SizeBytes: int64(len(secondReport)), Locator: "second-report"}, {Path: "artifacts/" + r.Wheel.Filename, SHA256: r.Wheel.SHA256, SizeBytes: MaxBuildBytes + 1, Locator: "second-wheel"}}
	read := func(_ context.Context, _ Identity, file RetainedFile, _ int64) ([]byte, error) {
		switch file.Locator {
		case "owned-report":
			return firstReport, nil
		case "owned-wheel":
			return body, nil
		case "second-report":
			return secondReport, nil
		case "second-wheel":
			t.Fatal("oversized wheel read before bound")
			return nil, nil
		}
		return report, nil
	}
	if _, e := CollectProducts(context.Background(), map[string]Config{"build": c, "other-build": second}, map[string][]RetainedFile{"build": files, "other-build": secondFiles}, read); e == nil {
		t.Fatal("oversized conflicting output accepted")
	}
}
func makeProducts(t *testing.T) Products {
	t.Helper()
	_, r, body, _, _ := opaqueFixture(t)
	return Products{map[string]Descriptor{r.Wheel.Filename: {r.Wheel.SHA256, r.Wheel.SizeBytes}}, map[string][]byte{r.Wheel.Filename: body}, int64(len(body))}
}
func TestAtomicReadOnlyStagingReplayAndChangedProductRefusal(t *testing.T) {
	root := privateTemp(t)
	destination := filepath.Join(root, "build-products")
	t.Cleanup(func() { _ = os.Chmod(destination, 0700) })
	p := makeProducts(t)
	physical, e := StageProducts(destination, p)
	if e != nil {
		t.Fatal(e)
	}
	if physical < p.LogicalBytes {
		t.Fatal("physical footprint not accounted")
	}
	again, e := StageProducts(destination, p)
	if e != nil || again != physical {
		t.Fatalf("replay %d %v", again, e)
	}
	for name := range p.Manifest {
		info, e := os.Stat(filepath.Join(destination, name))
		if e != nil || info.Mode().Perm()&0222 != 0 {
			t.Fatal("wheel not readonly")
		}
	}
	changed := makeProducts(t)
	for name := range changed.Manifest {
		changed.Payloads[name] = []byte("tampered")
	}
	if _, e = StageProducts(destination, changed); e == nil {
		t.Fatal("changed payload accepted")
	}
	if e = os.Chmod(destination, 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink("/etc/passwd", filepath.Join(destination, "foreign.whl")); e != nil {
		t.Fatal(e)
	}
	if e = VerifyProducts(destination, p.Manifest); e == nil {
		t.Fatal("unowned link accepted")
	}
}
func TestParticipantManifestBoundsAndStrictDescriptors(t *testing.T) {
	good := makeProducts(t).Manifest
	if _, e := ValidateManifest(good, MaxBuildBytes); e != nil {
		t.Fatal(e)
	}
	for _, m := range []map[string]Descriptor{{"../foreign.whl": {strings.Repeat("a", 64), 1}}, {"bad!.whl": {strings.Repeat("a", 64), 1}}, {"valid.whl": {strings.Repeat("a", 64), MaxBuildBytes + 1}}} {
		if _, e := ValidateManifest(m, MaxBuildBytes); e == nil {
			t.Fatal("invalid manifest accepted")
		}
	}
	if _, e := ParseManifest(map[string]any{"safe.whl": map[string]any{"sha256": strings.Repeat("a", 64), "size_bytes": true}}, MaxBuildBytes); e == nil {
		t.Fatal("boolean size accepted")
	}
}
func TestProductVerifiesBeforeDisclosureAndRechecksEveryChunk(t *testing.T) {
	body := bytes.Repeat([]byte("a"), ChunkBytes*2+5)
	h := sha256.Sum256(body)
	d := Descriptor{hex.EncodeToString(h[:]), int64(len(body))}
	if _, e := NewProduct([]byte("foreign"), d, func(context.Context) bool { return true }); e == nil {
		t.Fatal("unverified body disclosed")
	}
	count := 0
	p, e := NewProduct(body, d, func(context.Context) bool { count++; return count < 2 })
	if e != nil {
		t.Fatal(e)
	}
	var sent bytes.Buffer
	e = p.Stream(context.Background(), &sent)
	mustErrorCode(t, e, 404, "participant_assignment_not_found")
	if sent.Len() != ChunkBytes {
		t.Fatalf("revoked stream disclosed %d bytes", sent.Len())
	}
}

type memoryStage struct {
	calls     []string
	partial   map[string]*bytes.Buffer
	published map[string][]byte
	reserved  int64
}

func newStage() *memoryStage {
	return &memoryStage{partial: map[string]*bytes.Buffer{}, published: map[string][]byte{}}
}
func (s *memoryStage) Reserve(_ context.Context, n int64) error {
	s.calls = append(s.calls, "reserve")
	s.reserved = n
	return nil
}
func (s *memoryStage) Begin(_ context.Context, name string, _ Descriptor) error {
	s.calls = append(s.calls, "begin")
	s.partial[name] = &bytes.Buffer{}
	return nil
}
func (s *memoryStage) WriteChunk(_ context.Context, name string, offset int64, b []byte) error {
	if int64(s.partial[name].Len()) != offset {
		return errors.New("offset")
	}
	s.calls = append(s.calls, "write")
	_, e := s.partial[name].Write(b)
	return e
}
func (s *memoryStage) Commit(_ context.Context, name string) error {
	s.calls = append(s.calls, "commit")
	s.published[name] = append([]byte(nil), s.partial[name].Bytes()...)
	delete(s.partial, name)
	return nil
}
func (s *memoryStage) Abort(_ context.Context, name string) error {
	s.calls = append(s.calls, "abort")
	delete(s.partial, name)
	return nil
}
func TestStageRemoteStreamsOnlyAfterReservationAndPublishesAfterHash(t *testing.T) {
	products := makeProducts(t)
	requests := 0
	var name string
	for n := range products.Manifest {
		name = n
	}
	stage := newStage()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if len(stage.calls) == 0 || stage.calls[0] != "reserve" {
			t.Error("HTTP before capacity reservation")
		}
		if r.Header.Get("Authorization") != "Bearer fixture-node-grant" || r.Header.Get("Accept-Encoding") != "identity" {
			t.Error("credential/encoding contract")
		}
		w.Write(products.Payloads[name])
	}))
	defer server.Close()
	result, e := StageRemote(context.Background(), server.Client(), server.URL+"/products", "fixture-node-grant", products.Manifest, MaxBuildBytes, stage)
	if e != nil {
		t.Fatal(e)
	}
	if requests != 1 || !reflect.DeepEqual(result, products.Manifest) || !bytes.Equal(stage.published[name], products.Payloads[name]) || stage.calls[len(stage.calls)-1] != "commit" {
		t.Fatal("incomplete staged product")
	}
}
func TestStageRemoteRejectsRedirectOversizeHashAndErrorBodies(t *testing.T) {
	for _, kind := range []string{"redirect", "oversize", "short", "hash", "encoding", "error", "large-error"} {
		t.Run(kind, func(t *testing.T) {
			products := makeProducts(t)
			var name string
			for n := range products.Manifest {
				name = n
			}
			stage := newStage()
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch kind {
				case "redirect":
					w.Header().Set("Location", "https://elsewhere.invalid/")
					w.WriteHeader(302)
				case "oversize":
					_, _ = w.Write(append(products.Payloads[name], []byte("extra")...))
				case "short":
					_, _ = w.Write(products.Payloads[name][:3])
				case "hash":
					_, _ = w.Write(bytes.Repeat([]byte("z"), len(products.Payloads[name])))
				case "encoding":
					w.Header().Set("Content-Encoding", "gzip")
					_, _ = w.Write(products.Payloads[name])
				case "error":
					w.WriteHeader(403)
					_, _ = io.WriteString(w, `{"error":{"code":"node_revoked"}}`)
				case "large-error":
					w.WriteHeader(403)
					_, _ = w.Write(bytes.Repeat([]byte("x"), ChunkBytes+1))
				}
			}))
			defer server.Close()
			_, e := StageRemote(context.Background(), server.Client(), server.URL+"/products", "fixture-node-grant", products.Manifest, MaxBuildBytes, stage)
			if e == nil {
				t.Fatal("invalid transfer succeeded")
			}
			if len(stage.published) != 0 || len(stage.partial) != 0 {
				t.Fatal("failed transfer published or retained partial")
			}
			if kind == "error" {
				mustErrorCode(t, e, 403, "node_revoked")
			}
			if kind == "large-error" {
				mustErrorCode(t, e, 502, "external_build_invalid_reply")
			}
		})
	}
}

func privateTemp(t *testing.T) string {
	t.Helper()
	path := t.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	return path
}
