package app

import (
	"context"
	"sync"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/auth"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/config"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/controller"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/exchange"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/executor"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/httpapi"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/manager"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/node"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/participants"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/provision"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/transfer"
)

type Services struct {
	Settings            config.Settings
	DB                  *store.DB
	Manager             *manager.Manager
	Auth                *auth.Service
	Broker              *exchange.Broker
	Controller          *controller.Controller
	LocalNode           *executor.NodeAgent
	Node                controller.Executor
	Remote              *node.RemoteExecutor
	ManagedNodes        *node.AssignmentService
	Provisioner         *provision.Provisioner
	PublicationObserver *controller.AuthoritativePublicationObserver
	Participants        *participants.Service
	ArtifactBroker      httpapi.ArtifactBroker
	Supervisor          *transfer.Supervisor
	Storage             controller.ArtifactStorage
	CloseCallbacks      []func() error
	closeOnce           sync.Once
	closeError          error
}

func (s *Services) Close() error {
	s.closeOnce.Do(func() {
		for i := len(s.CloseCallbacks) - 1; i >= 0; i-- {
			if err := s.CloseCallbacks[i](); err != nil && s.closeError == nil {
				s.closeError = err
			}
		}
		if s.LocalNode != nil {
			if e := s.LocalNode.Close(); e != nil && s.closeError == nil {
				s.closeError = e
			}
		}
		if s.DB != nil {
			if e := s.DB.Close(); e != nil && s.closeError == nil {
				s.closeError = e
			}
		}
	})
	return s.closeError
}
func (s *Services) Now() time.Time                  { return time.Now().UTC() }
func (s *Services) Ready(ctx context.Context) error { _, e := s.DB.CheckSchema(ctx); return e }
