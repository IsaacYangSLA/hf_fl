package lifecycle

import (
	"os"
	"path/filepath"
	"testing"
)

type failedPhysicalProof struct{}
type proofReporter struct{}

func (proofReporter) Helper()      {}
func (proofReporter) Fatal(...any) { panic(failedPhysicalProof{}) }

// The same verifier runs after actual Docker/findmnt/losetup probes in the live
// gate. A failed physical proof must abort before schema cleanup is authorized.
func TestPhysicalCleanupProofRetainsAuthorityOnFailure(t *testing.T) {
	for _, kind := range []string{"backing_image", "mount", "loop"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			key := "owned-execution"
			prefix := filepath.Join(root, key)
			if e := os.Mkdir(prefix, 0700); e != nil {
				t.Fatal(e)
			}
			mounts := ""
			loops := []any{}
			switch kind {
			case "backing_image":
				if e := os.WriteFile(filepath.Join(prefix, "state.ext4"), []byte("retained"), 0600); e != nil {
					t.Fatal(e)
				}
			case "mount":
				mounts = filepath.Join(prefix, "state")
			case "loop":
				loops = append(loops, object{"back-file": filepath.Join(prefix, "state.ext4")})
			}
			schemaClean := false
			failed := false
			func() {
				defer func() {
					if p := recover(); p != nil {
						if _, ok := p.(failedPhysicalProof); !ok {
							panic(p)
						}
						failed = true
					}
				}()
				verifyPhysicalCleanup(root, []map[string]any{{"execution_key": key}}, mounts, loops, proofReporter{})
				schemaClean = true
			}()
			if !failed || schemaClean {
				t.Fatal("unproven physical cleanup authorized schema removal")
			}
		})
	}
}
func TestPhysicalCleanupAcceptsReleasedAuditRowsAndIgnoresForeignResources(t *testing.T) {
	root := t.TempDir()
	proof := verifyPhysicalCleanup(root, []map[string]any{{"execution_key": "released-audit"}}, "/other/owned-root/state", []any{object{"back-file": "/other/owned-root/state.ext4"}}, t)
	if integer(proof["retained_audit_rows"]) != 1 || integer(proof["backing_images"]) != 0 {
		t.Fatal("released audit row treated as a live reservation")
	}
}
