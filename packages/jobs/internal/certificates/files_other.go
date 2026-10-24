//go:build !linux

package certificates

// Reading trusted on-disk CA material requires the Linux descriptor-safe loader.
// Pure PEM constructors and certificate verification remain portable.
func ReadPEMFile(path string, private bool) ([]byte, error) { return nil, ErrRefused }

func ReadTrustBundleFile(path string) ([]byte, error) { return nil, ErrRefused }
