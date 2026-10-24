package app

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/config"
)

func TestCompositionDiagnosticsPreserveSafeConfigurationErrors(t *testing.T) {
	const sensitive = "operator-private-password"
	_, err := BuildServices(context.Background(), config.Settings{DatabaseURL: "invalid://operator:" + sensitive + "@example.invalid/db"}, false)
	for _, tc := range []struct {
		name, prefix string
		err          error
	}{
		{"service", "compose configuration: ", err},
		{"provisioner", "provisioner configuration: ", ComposeProvisioner(context.Background(), &Services{})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var configuration *config.Error
			if !errors.As(tc.err, &configuration) || !strings.HasPrefix(tc.err.Error(), tc.prefix) {
				t.Fatalf("missing safe composition stage or configuration classification: %v", tc.err)
			}
			var output bytes.Buffer
			writeError(&output, tc.err)
			if strings.Contains(tc.err.Error(), sensitive) || strings.Contains(output.String(), sensitive) || !strings.Contains(output.String(), "\"type\":\"ConfigurationError\"") {
				t.Fatal("composition error leaked configuration or lost CLI classification")
			}
		})
	}
}
