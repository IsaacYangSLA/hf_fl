package app

import (
	"context"
	"fmt"
	"strings"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/artifacts"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/auth"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/config"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/controller"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/exchange"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/manager"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/scheduler"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

func BuildServices(ctx context.Context, s config.Settings, withController bool) (result *Services, err error) {
	stage := "configuration"
	defer func() {
		if err != nil {
			err = fmt.Errorf("compose %s: %w", stage, err)
		}
	}()
	if err = s.Validate("server"); err != nil {
		return nil, err
	}
	if strings.HasPrefix(s.DatabaseURL, "sqlite:") && !s.OIDC.AllowLocalHTTP {
		return nil, config.Invalid()
	}
	stage = "database"
	db, e := store.Open(ctx, s.DatabaseURL)
	if e != nil {
		return nil, e
	}
	services := &Services{Settings: s, DB: db}
	defer func() {
		if err != nil {
			_ = services.Close()
		}
	}()
	stage = "schema"
	if _, err = db.CheckSchema(ctx); err != nil {
		return nil, err
	}
	stage = "manager"
	services.Manager, err = manager.New(db, []byte(s.CursorSecret))
	if err != nil {
		return nil, err
	}
	for _, id := range s.PlatformOperatorIDs {
		services.Manager.PlatformOperatorIDs[id] = true
	}
	stage = "admin policy"
	if err = ConfigureAdminPolicy(ctx, services); err != nil {
		return nil, err
	}
	oidc := auth.OIDCConfig{Issuer: s.OIDC.Issuer, ClientID: s.OIDC.ClientID, ClientSecret: s.OIDC.ClientSecret, RedirectURI: s.OIDC.RedirectURI, Audience: s.OIDC.Audience, IntrospectionURL: s.OIDC.IntrospectionURL, JWKSURL: s.OIDC.JWKSURL, PublicKey: s.OIDC.PublicKey, EndpointOrigins: s.OIDC.EndpointOrigins, TimeoutSeconds: s.OIDC.TimeoutSeconds, JWKSCacheSeconds: s.OIDC.JWKSCacheSeconds, AllowLocalHTTP: s.OIDC.AllowLocalHTTP}
	stage = "authentication"
	services.Auth, err = auth.New(db, auth.Config{OIDC: oidc, SessionSecret: s.SessionSecret, PlatformOperatorIDs: s.PlatformOperatorIDs}, nil)
	if err != nil {
		return nil, err
	}
	stage = "workload broker"
	if s.Workload != nil {
		w := s.Workload
		services.Broker, err = exchange.NewBroker(exchange.BrokerSettings{Issuer: w.Issuer, ExchangeAudience: w.ExchangeAudience, GatewayAudience: w.GatewayAudience, NodeAudience: w.NodeAudience, KeyID: w.KeyID, PublicKeyPEM: []byte(w.PublicKey), PrivateKeyPEM: []byte(w.PrivateKey)})
		if err != nil {
			return nil, err
		}
	}
	services.Controller = controller.New(db, nil, nil)
	storage := artifacts.NewStorage(db, composeLogReader(services))
	ec, _ := s.Section("executor", false)
	storage.ExecutorRoot = strValue(ec["root"])
	services.Storage = storage
	services.Controller.Storage = storage
	stage = "nodes"
	if err = ComposeNodes(ctx, services, withController); err != nil {
		return nil, err
	}
	if values, _ := s.Section("provisioner", false); len(values) > 0 {
		stage = "provisioner"
		if err = ComposeProvisioner(ctx, services); err != nil {
			return nil, err
		}
		services.Manager.StoragePlannerTx = func(ctx context.Context, tx *store.Tx, job map[string]any) ([]scheduler.StoragePlan, error) {
			rows, e := services.Provisioner.AdmissionStorageTx(ctx, tx, job)
			if e != nil {
				return nil, e
			}
			return storagePlans(rows)
		}
	}
	stage = "managed nodes"
	if err = ComposeManagedNodes(ctx, services); err != nil {
		return nil, err
	}
	stage = "participants"
	if err = ComposeParticipants(ctx, services); err != nil {
		return nil, err
	}
	stage = "controller"
	if withController {
		if services.Node == nil || services.Provisioner == nil {
			return nil, config.Invalid()
		}
		services.Controller = controller.New(db, services.Node, services.Provisioner)
		sched := scheduler.New(db, scheduler.WithTransactionalStoragePlanner(services.Manager.StoragePlannerTx))
		services.Controller.Schedule = func(ctx context.Context) (int, error) { items, e := sched.Tick(ctx); return len(items), e }
		services.Controller.Storage = services.Storage
		if services.Participants != nil {
			services.Controller.Participants = services.Participants
		}
	}
	return services, nil
}
func storagePlans(rows []map[string]any) ([]scheduler.StoragePlan, error) {
	plans := make([]scheduler.StoragePlan, 0, len(rows))
	for _, row := range rows {
		if e := config.Keys(row, []string{"kind", "component_id", "pool_id", "external_id", "max_bytes"}, []string{"covered_by_allocation", "details"}); e != nil {
			return nil, e
		}
		max, e := config.Int(row["max_bytes"], 0, 1<<63-1)
		if e != nil {
			return nil, e
		}
		covered, e := config.GetBool(row, "covered_by_allocation", false)
		if e != nil {
			return nil, e
		}
		plans = append(plans, scheduler.StoragePlan{Kind: strValue(row["kind"]), ComponentID: strValue(row["component_id"]), PoolID: strValue(row["pool_id"]), ExternalID: strValue(row["external_id"]), MaxBytes: max, CoveredByAllocation: covered, Details: objMap(row["details"])})
	}
	return plans, nil
}
