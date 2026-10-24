package participants

import (
	"context"
	"sync"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/exchange"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/executor"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/node"
)

type AgentRuntime interface {
	Reserve(context.Context, executor.ExecutionSpec) (executor.Reservation, error)
	Inspect(context.Context, executor.ExecutionIdentity) (executor.RuntimeObservation, error)
	Start(context.Context, executor.ExecutionIdentity) (executor.RuntimeObservation, error)
	Stop(context.Context, executor.ExecutionIdentity, int) (executor.RuntimeObservation, error)
	Release(context.Context, executor.ExecutionIdentity) (bool, error)
	RenewLease(context.Context, executor.ExecutionIdentity, float64) error
	ConfirmAbsent(context.Context, executor.ExecutionIdentity) (bool, error)
	ChargeAuxiliaryBytes(context.Context, executor.ExecutionIdentity, int64) (bool, error)
	ReadLogs(context.Context, executor.ExecutionIdentity, int64, int64) (map[string]any, error)
	ReconciliationRoot(context.Context, executor.ExecutionIdentity) (string, error)
	WithComponentResourceGuard(context.Context, executor.ExecutionIdentity, func() error) error
	WithComponentPurgeGuard(context.Context, executor.ExecutionIdentity, func() error) error
	Inventory(context.Context) ([]map[string]any, error)
	PurgeWithAuxiliary(context.Context, executor.ExecutionIdentity, bool) (bool, error)
}
type AgentMaterializer interface {
	Plan(context.Context, node.RemoteAssignment) (executor.ExecutionSpec, error)
	Reserve(context.Context, node.RemoteAssignment) (executor.ExecutionSpec, error)
	Assignment(context.Context, executor.ExecutionIdentity) (node.RemoteAssignment, error)
	AllAssignments(context.Context) ([]node.RemoteAssignment, error)
	RemoveAssignment(context.Context, executor.ExecutionIdentity) error
	Binding(context.Context, executor.ExecutionIdentity, string, string) (map[string]any, error)
	Prepare(context.Context, executor.ExecutionIdentity, map[string]any, map[string]any) (bool, error)
	ReserveBuildInputs(context.Context, executor.ExecutionIdentity, map[string]any) error
	StageBuildInput(context.Context, executor.ExecutionIdentity, map[string]any, string, int64, string) (bool, error)
}
type ParticipantRequester interface {
	Request(context.Context, executor.ExecutionIdentity, string, string, any) (map[string]any, error)
	Raw(context.Context, executor.ExecutionIdentity, string, string) ([]byte, error)
}
type AgentConfig struct {
	NodeID, NodeCertificateThumbprint, LedgerPath, Root string
	ProxyStop                                           func(context.Context, executor.ExecutionIdentity, bool) (bool, error)
	PurgePrivate                                        func(context.Context, executor.ExecutionIdentity, *CleanupAssignment) (bool, error)
}
type Agent struct {
	Config        AgentConfig
	Client        ParticipantRequester
	Materializer  AgentMaterializer
	Node          AgentRuntime
	Broker        *exchange.Broker
	Cleanup       CleanupAgent
	mu            sync.Mutex
	tokens        map[string]string
	logIdentities map[string]executor.ExecutionIdentity
	logOffsets    map[string]int64
	flowGuards    map[string]*sync.Mutex
	cancel        context.CancelFunc
	done          chan struct{}
}

func NewAgent(cfg AgentConfig, client ParticipantRequester, materializer AgentMaterializer, runtime AgentRuntime, broker *exchange.Broker) (*Agent, error) {
	if !validThumbprint(cfg.NodeCertificateThumbprint) || cfg.NodeID == "" || cfg.LedgerPath == "" || cfg.Root == "" || client == nil || materializer == nil || runtime == nil || broker == nil {
		return nil, invalidAgent()
	}
	a := &Agent{Config: cfg, Client: client, Materializer: materializer, Node: runtime, Broker: broker, tokens: map[string]string{}, logIdentities: map[string]executor.ExecutionIdentity{}, logOffsets: map[string]int64{}, flowGuards: map[string]*sync.Mutex{}}
	a.Cleanup = &agentCleanup{Agent: a}
	return a, nil
}
