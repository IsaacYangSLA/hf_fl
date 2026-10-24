// Package app composes native Exchange services and command-line operations.
package app

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/auth"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/config"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/gateway"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/httpapi"
	schemaval "github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/schema"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/service"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/storage"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/store"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/transfers"
)

// CompositionError preserves its cause for programmatic inspection but never
// exposes database URLs, credentials, provider locators or file paths.
type CompositionError struct {
	Stage string
	Cause error
}

func (e *CompositionError) Error() string { return "Exchange composition failed: " + e.Stage }
func (e *CompositionError) Unwrap() error { return e.Cause }
func stage(name string, err error) error {
	if err == nil {
		return nil
	}
	return &CompositionError{Stage: name, Cause: err}
}

type Services struct {
	DB        *store.DB
	Core      *service.Service
	Transfers *transfers.Service
	Storage   storage.BlobStore
	Auth      *auth.Authenticator
	Settings  config.Settings
}

func (s *Services) Close() error {
	if s == nil || s.DB == nil {
		return nil
	}
	return s.DB.Close()
}

// OpenDatabase configures the native pool without loading identity or storage.
func OpenDatabase(ctx context.Context, s config.DatabaseSettings) (*store.DB, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	timeout, err := config.Duration(s.PoolTimeout)
	if err != nil {
		return nil, err
	}
	return store.OpenConfig(ctx, store.Config{URL: s.URL, MaxOpenConns: s.PoolSize + s.PoolOverflow, MaxIdleConns: s.PoolSize, ConnMaxLifetime: time.Duration(s.PoolRecycle) * time.Second, PoolTimeout: timeout})
}

type SchemaIssue struct {
	ID   string `json:"id"`
	Code string `json:"code"`
}
type CompatibilityReport struct {
	Checked      int           `json:"checked"`
	Compatible   int           `json:"compatible"`
	Incompatible []SchemaIssue `json:"incompatible"`
}
type CompatibilityError struct{ Report CompatibilityReport }

func (e *CompatibilityError) Error() string { return "retained schema compatibility check failed" }

// CheckCompatibility is read-only and streams schema revisions. Reports expose
// opaque IDs and stable error codes, never schema patterns or stored metadata.
func CheckCompatibility(ctx context.Context, db *store.DB) (CompatibilityReport, error) {
	report := CompatibilityReport{Incompatible: []SchemaIssue{}}
	if db == nil {
		return report, errors.New("database unavailable")
	}
	if err := db.CheckRevision(ctx); err != nil {
		return report, stage("database schema", err)
	}
	rows, err := db.Query(ctx, "SELECT id,schema FROM v2_schema_revisions ORDER BY id")
	if err != nil {
		return report, stage("schema inspection", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var raw any
		if err = rows.Scan(&id, &raw); err != nil {
			return report, stage("schema inspection", err)
		}
		var value any
		switch v := raw.(type) {
		case []byte:
			value, err = domain.DecodeJSON(v)
		case string:
			value, err = domain.DecodeJSON([]byte(v))
		default:
			err = errors.New("invalid persisted schema")
		}
		if err == nil {
			err = schemaval.ValidateSchema(value)
		}
		report.Checked++
		if err != nil {
			code := "invalid_schema"
			var de *domain.Error
			if errors.As(err, &de) && de.Code != "" {
				code = de.Code
			}
			report.Incompatible = append(report.Incompatible, SchemaIssue{ID: id, Code: code})
		} else {
			report.Compatible++
		}
	}
	if err = rows.Err(); err != nil {
		return report, stage("schema inspection", err)
	}
	return report, nil
}

// BuildServices checks retained state and builds only native Go components.
// Workers deliberately remain available to clean old blobs even when an
// application schema needs operator migration before API admission.
func BuildServices(ctx context.Context, s config.Settings, component string) (result *Services, err error) {
	if component != "server" && component != "worker" {
		return nil, errors.New("invalid service component")
	}
	if err = s.Validate(component); err != nil {
		return nil, stage("configuration", err)
	}
	db, err := OpenDatabase(ctx, s.Database)
	if err != nil {
		return nil, stage("database", err)
	}
	defer func() {
		if err != nil {
			_ = db.Close()
		}
	}()
	if err = db.Check(ctx); err != nil {
		return nil, stage("database schema", err)
	}
	if component == "server" {
		report, checkErr := CheckCompatibility(ctx, db)
		if checkErr != nil {
			return nil, checkErr
		}
		if len(report.Incompatible) > 0 {
			return nil, &CompatibilityError{Report: report}
		}
	}
	core := service.New(db, service.Options{
		Auth:         service.AuthOptions{AdminSubject: s.Auth.AdminSubject, WorkloadIssuer: s.Auth.WorkloadIssuer, ProvisioningPrincipalIDs: append([]string(nil), s.Auth.ProvisioningPrincipalIDs...), DownloadBrokerPrincipalIDs: append([]string(nil), s.Auth.DownloadBrokerPrincipalIDs...)},
		DraftSeconds: s.DraftSeconds, CoordinationSeconds: s.CoordinationSeconds, PartSize: s.Storage.PartSize,
	})
	blobs, err := storage.NewS3(ctx, s.Storage)
	if err != nil {
		return nil, stage("storage", err)
	}
	result = &Services{DB: db, Core: core, Storage: blobs, Settings: s}
	result.Transfers = transfers.New(core, blobs, s)
	if component == "server" {
		result.Auth, err = auth.New(s.Auth)
		if err != nil {
			return nil, stage("authentication", err)
		}
	}
	return result, nil
}

// Handler returns exactly one ingress surface; private backend routes are
// never mounted by the public or managed API listener.
func (s *Services) Handler(mode, transferAudience string) (http.Handler, error) {
	if s == nil || s.DB == nil || s.Core == nil || s.Transfers == nil {
		return nil, errors.New("incomplete native service composition")
	}
	switch mode {
	case "public", "managed":
		if s.Auth == nil {
			return nil, errors.New("authentication unavailable")
		}
		if mode == "managed" && !s.Settings.Auth.WorkloadsEnabled() {
			return nil, errors.New("managed workload authentication is required")
		}
		return httpapi.New(s.Core, s.Transfers, s.Auth, httpapi.Options{ManagedIngress: mode == "managed", MaxBodyBytes: s.Settings.MaxBodyBytes, AllowLocalHTTP: s.Settings.AllowLocalHTTP, DocsEnabled: s.Settings.DocsEnabled, AuthSettings: s.Settings.Auth})
	case "gateway":
		return gateway.New(s.Core, s.Transfers, s.Settings, gateway.Options{Audience: transferAudience})
	default:
		return nil, errors.New("invalid native listener mode")
	}
}
