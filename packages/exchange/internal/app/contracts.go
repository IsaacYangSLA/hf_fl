package app

import (
	"embed"
	"errors"
	"os"
	"path/filepath"

	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/httpapi"
)

//go:embed contractdata/exchange-errors.json contractdata/exchange-environment.md
var ancillaryContracts embed.FS

var contractNames = []string{"exchange-api.json", "exchange-errors.json", "exchange-environment.md"}

// ContractDocuments is self-contained. Export never opens a database, identity
// endpoint or object store and never invokes the Python reference application.
func ContractDocuments() (map[string][]byte, error) {
	api, err := httpapi.OpenAPI()
	if err != nil {
		return nil, err
	}
	result := map[string][]byte{"exchange-api.json": append([]byte(nil), api...)}
	for _, name := range contractNames[1:] {
		b, err := ancillaryContracts.ReadFile("contractdata/" + name)
		if err != nil {
			return nil, err
		}
		result[name] = append([]byte(nil), b...)
	}
	return result, nil
}
func ExportContracts(directory string) ([]string, error) {
	documents, err := ContractDocuments()
	if err != nil {
		return nil, errors.New("contract rendering failed")
	}
	if err = os.MkdirAll(directory, 0755); err != nil {
		return nil, errors.New("contract directory unavailable")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("contract directory must be a regular directory")
	}
	paths := make([]string, 0, len(contractNames))
	for _, name := range contractNames {
		path := filepath.Join(directory, name)
		if st, err := os.Lstat(path); err == nil && (!st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0) {
			return nil, errors.New("contract destination is not a regular file")
		}
		f, err := os.CreateTemp(directory, ".hf2l-contract-")
		if err != nil {
			return nil, errors.New("contract write failed")
		}
		temp := f.Name()
		ok := false
		func() {
			defer func() {
				_ = f.Close()
				if !ok {
					_ = os.Remove(temp)
				}
			}()
			if err = f.Chmod(0644); err != nil {
				return
			}
			if _, err = f.Write(documents[name]); err != nil {
				return
			}
			if err = f.Sync(); err != nil {
				return
			}
			if err = f.Close(); err != nil {
				return
			}
			if err = os.Rename(temp, path); err != nil {
				return
			}
			ok = true
		}()
		if !ok {
			return nil, errors.New("contract write failed")
		}
		paths = append(paths, path)
	}
	return paths, nil
}
