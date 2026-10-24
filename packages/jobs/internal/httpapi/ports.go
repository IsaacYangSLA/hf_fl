// Package httpapi serves the Go job manager API and packaged browser dashboard.
package httpapi

import (
	"context"
	"io"
	"io/fs"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/artifacts"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/executor"
)

const Prefix = "/api/jobs/v1"

// ExecutionActor contains only authenticated, certificate-bound execution claims.
type ExecutionActor struct {
	ID, NodeID, PoolID, JobID, AttemptID, ComponentID, GrantID, CertificateThumbprint string
	Epoch                                                                             int64
	Scopes                                                                            []string
	Resources                                                                         map[string]any
	Subject                                                                           string
	IssuedAt, ExpiresAt                                                               int64
}
type StreamFile struct {
	Reader    io.ReadCloser
	SizeBytes int64
	SHA256    string
}
type ArtifactBroker interface {
	OpenAuthorized(context.Context, string, string, string) (*artifacts.Download, error)
}

// Options supplies trusted, in-process Go service ports. Callbacks never receive
// caller-selected method names: handlers select a fixed, validated operation.
type Options struct {
	AllowLocalHTTP         bool
	PublicOnly             bool
	PrivateOnly            bool
	MaxBodyBytes           int64
	CursorSecret           []byte
	SSEPollInterval        time.Duration
	Readiness              func(context.Context) error
	Dashboard              fs.FS
	ArtifactBroker         ArtifactBroker
	Clock                  func() time.Time
	NodeAuthenticate       func(context.Context, string, string) (ExecutionActor, error)
	CheckAssignment        func(context.Context, string, string, executor.ExecutionIdentity) (bool, error)
	NodeCommand            func(context.Context, string, executor.ExecutionIdentity, map[string]any) (bool, error)
	ManagedBootstrap       func(context.Context, string, executor.ExecutionIdentity) (map[string]any, error)
	ManagedAuthenticate    func(context.Context, string, string) (ExecutionActor, error)
	ManagedCall            func(context.Context, string, ExecutionActor, executor.ExecutionIdentity, map[string]any) (map[string]any, error)
	ParticipantEnroll      func(context.Context, string, string, string, string, int64, string) (map[string]any, error)
	ParticipantEnrollment  func(context.Context, string, string, string) (map[string]any, error)
	ParticipantCall        func(context.Context, string, ExecutionActor, executor.ExecutionIdentity, map[string]any) (map[string]any, error)
	ParticipantOpen        func(context.Context, string, ExecutionActor, string) (*StreamFile, error)
	ParticipantAccessValid func(context.Context, string, ExecutionActor) (bool, error)
}
