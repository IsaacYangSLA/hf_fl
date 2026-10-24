package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/config"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/executor"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/httpapi"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/manager"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
	dashboard "github.com/IsaacYangSLA/hf_fl/packages/jobs/src/hf2l_jobs/static"
)

func Run(ctx context.Context, args []string, out, errOut io.Writer) int {
	a, help, e := Parse(args, out)
	if help {
		return 0
	}
	if e != nil {
		writeError(errOut, e)
		return 2
	}
	value, e := Dispatch(ctx, a, out, errOut)
	if e != nil {
		if errors.Is(e, context.Canceled) && ctx.Err() != nil {
			return 0
		}
		var exit *exec.ExitError
		if a.Command == "runtime" && errors.As(e, &exit) {
			return exit.ExitCode()
		}
		writeError(errOut, e)
		return 1
	}
	if value != nil {
		encoder := json.NewEncoder(out)
		encoder.SetEscapeHTML(false)
		if e = encoder.Encode(value); e != nil {
			return 1
		}
	}
	return 0
}
func writeError(out io.Writer, err error) {
	code := "command_failed"
	kind := fmt.Sprintf("%T", err)
	body := map[string]any{}
	var d *domain.Error
	var c *config.Error
	switch {
	case errors.Is(err, ErrArguments):
		code = "invalid_command_arguments"
		kind = "ArgumentError"
	case errors.As(err, &c):
		code = c.Code
		kind = "ConfigurationError"
	case errors.As(err, &d):
		code = d.Code
		body["status"] = d.Status
	}
	body["error"] = code
	body["type"] = kind
	_ = json.NewEncoder(out).Encode(body)
}
func Dispatch(ctx context.Context, args Arguments, out, errOut io.Writer) (any, error) {
	if args.Command == "runtime" {
		// This explicitly named command is the sandbox FL application boundary,
		// never a manager API/business-logic subprocess.
		if _, e := config.ReadJSON(args.Config, config.MaxConfigBytes); e != nil {
			return nil, e
		}
		cmd := exec.CommandContext(ctx, "python", "-m", "hf2l_jobs.runtime", "--config", args.Config)
		cmd.Stdout = out
		cmd.Stderr = errOut
		cmd.Stdin = nil
		return nil, cmd.Run()
	}
	component := "database"
	if args.Command == "serve" || args.Command == "node-api" {
		component = "server"
	}
	settings, e := config.Load(args.Config, component)
	if e != nil {
		return nil, e
	}
	switch args.Command {
	case "init-db", "migrate-db":
		db, e := store.Open(ctx, settings.DatabaseURL)
		if e != nil {
			return nil, e
		}
		defer db.Close()
		revision, e := db.Migrate(ctx)
		if e != nil {
			return nil, e
		}
		return map[string]any{"schema_revision": revision, "status": "ok"}, nil
	case "admin":
		db, e := store.Open(ctx, settings.DatabaseURL)
		if e != nil {
			return nil, e
		}
		defer db.Close()
		if _, e = db.CheckSchema(ctx); e != nil {
			return nil, e
		}
		m := &manager.Manager{DB: db, Clock: time.Now, PlatformOperatorIDs: map[string]bool{}}
		services := &Services{Settings: settings, DB: db, Manager: m}
		if e = ConfigureAdminPolicy(ctx, services); e != nil {
			return nil, e
		}
		values := map[string]any{}
		for k, v := range args.Values {
			values[k] = v
		}
		if file, ok := values["quota_file"].(string); ok {
			quota, e := config.ReadJSON(file, config.MaxConfigBytes)
			if e != nil {
				return nil, e
			}
			values["quota"] = quota
			delete(values, "quota_file")
		}
		if file, ok := values["file"].(string); ok {
			values, e = config.ReadJSON(file, config.MaxConfigBytes)
			if e != nil {
				return nil, e
			}
		}
		return m.TrustedAdmin(ctx, fmt.Sprintf("unix:%d", os.Getuid()), args.Operation, values)
	case "serve", "node-api", "controller":
		services, e := BuildServices(ctx, settings, args.Command == "controller")
		if e != nil {
			return nil, e
		}
		defer services.Close()
		if args.Command == "controller" {
			result, e := Poll(ctx, args.Once, args.Interval, func(ctx context.Context) (any, error) { return ControllerPass(ctx, services) })
			if !args.Once {
				return nil, e
			}
			return result, e
		}
		options := httpapi.Options{AllowLocalHTTP: settings.OIDC.AllowLocalHTTP, PublicOnly: args.Command == "serve", PrivateOnly: args.Command == "node-api", MaxBodyBytes: settings.MaxBodyBytes, CursorSecret: []byte(settings.CursorSecret), Readiness: services.Ready, Dashboard: dashboard.Files, ArtifactBroker: services.ArtifactBroker}
		if e = ConfigureNodeAPI(&options, services); e != nil {
			return nil, e
		}
		h, e := httpapi.New(services.Manager, services.Auth, options)
		if e != nil {
			return nil, e
		}
		if args.Command == "node-api" {
			if services.Broker == nil {
				return nil, config.Invalid()
			}
			boundaries, e := settings.Section("boundaries", true)
			if e != nil {
				return nil, e
			}
			values, ok := boundaries["nodes"].(map[string]any)
			if !ok {
				return nil, config.Invalid()
			}
			if e = config.Keys(values, []string{"tls_certificate", "tls_key", "client_ca_file"}, []string{"host", "port"}); e != nil {
				return nil, e
			}
			return nil, RunMTLS(ctx, settings, args, h, values)
		}
		return nil, RunHTTP(ctx, settings, args, h)
	case "node-agent":
		node, e := CreateNodeAgent(ctx, settings, nil)
		if e != nil {
			return nil, e
		}
		defer node.Close()
		result, e := Poll(ctx, args.Once, args.Interval, func(ctx context.Context) (any, error) {
			stopped, e := node.WatchdogOnce(ctx)
			if e != nil {
				return nil, e
			}
			inventory, e := node.Inventory(ctx)
			if e != nil {
				return nil, e
			}
			return map[string]any{"stopped": len(stopped), "reservations": len(inventory)}, nil
		})
		if !args.Once {
			return nil, e
		}
		return result, e
	case "managed-node":
		return nil, RunManagedNode(ctx, settings, args)
	case "participant-agent":
		return nil, RunParticipantAgent(ctx, settings, args)
	case "gateway":
		return nil, RunGateway(ctx, settings, args)
	case "exchange-edge":
		return nil, RunEdge(ctx, settings, args)
	case "proxy":
		return nil, RunProxy(ctx, settings)
	}
	return nil, config.Invalid()
}

func ControllerPass(ctx context.Context, services *Services) (any, error) {
	if watchdog, ok := services.Node.(interface {
		WatchdogOnce(context.Context) ([]executor.ExecutionIdentity, error)
	}); ok {
		if _, e := watchdog.WatchdogOnce(ctx); e != nil {
			return nil, e
		}
	}
	stats, e := services.Controller.RunOnce(ctx, 20)
	if e != nil {
		return nil, e
	}
	if services.Participants != nil {
		if _, e = services.Participants.DispatchPending(ctx); e != nil {
			return nil, e
		}
	}
	return map[string]any{"admitted": stats.Admitted, "dispatched": stats.Dispatched, "restored": stats.Restored}, nil
}
