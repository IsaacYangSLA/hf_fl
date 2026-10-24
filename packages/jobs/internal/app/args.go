package app

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"sort"
	"time"
)

type Arguments struct {
	Command, Operation, Config, Host string
	Port                             int
	PortSet                          bool
	Once                             bool
	Interval                         time.Duration
	Values                           map[string]any
}

var commandDescriptions = map[string]string{
	"init-db":           "Create a new manager database with the current schema",
	"migrate-db":        "Apply manager database schema migrations",
	"serve":             "Serve the authenticated API and packaged dashboard",
	"controller":        "Run the scheduler, provisioner, and lifecycle reconciler",
	"node-agent":        "Run the trusted reservation watchdog and execution agent",
	"node-api":          "Serve the private manager node mTLS API",
	"managed-node":      "Serve a registered managed execution node",
	"participant-agent": "Serve an approved external participant execution agent",
	"gateway":           "Serve certificate-bound artifact transfers",
	"exchange-edge":     "Serve the managed Exchange mTLS boundary",
	"proxy":             "Serve one execution's trusted operation proxy on a Unix socket",
	"runtime":           "Run the sandboxed Python FL application adapter",
	"admin":             "Trusted local deployment administration",
}
var adminDescriptions = map[string]string{
	"project-create":        "Create a project with explicit quota and retention",
	"project-update":        "Update a project's quota or retention policy",
	"project-member":        "Grant or revoke project creation permission",
	"object-store-pool-set": "Approve configured versioned object-store capacity",
	"storage-pool-set":      "Qualify configured manager filesystem capacity",
	"pool-set":              "Register or update explicitly allocatable capacity",
	"source-approve":        "Approve a project source",
	"image-approve":         "Approve a runtime image",
	"dataset-approve":       "Approve a local participant dataset binding",
	"secret-ref-approve":    "Approve a private secret reference",
}
var ErrArguments = errors.New("invalid_command_arguments")

func printHelp(w io.Writer) {
	fmt.Fprintln(w, "Usage: hf2l-jobs COMMAND [options]")
	fmt.Fprintln(w, "Manage isolated federated learning jobs with the Go manager.")
	names := []string{}
	for name := range commandDescriptions {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(w, "  %-20s %s\n", name, commandDescriptions[name])
	}
	fmt.Fprintln(w, "Use hf2l-jobs COMMAND --help for command options.")
}
func Parse(args []string, w io.Writer) (Arguments, bool, error) {
	a := Arguments{Interval: 5 * time.Second, Values: map[string]any{}}
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
		printHelp(w)
		return a, true, nil
	}
	if len(args) == 0 {
		return a, false, ErrArguments
	}
	if _, ok := commandDescriptions[args[0]]; !ok {
		return a, false, ErrArguments
	}
	a.Command = args[0]
	f := flag.NewFlagSet(a.Command, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.StringVar(&a.Config, "config", "", "Trusted operational JSON configuration file")
	if a.Command == "serve" || a.Command == "node-api" || a.Command == "managed-node" || a.Command == "participant-agent" || a.Command == "gateway" || a.Command == "exchange-edge" {
		f.StringVar(&a.Host, "host", "", "Listener host override")
		f.IntVar(&a.Port, "port", 0, "Listener port override")
	}
	interval := 5.0
	if a.Command == "controller" || a.Command == "node-agent" {
		f.BoolVar(&a.Once, "once", false, "Perform one reconciliation/watchdog pass")
		f.Float64Var(&interval, "interval", 5, "Polling interval in seconds")
	}
	f.Usage = func() {
		fmt.Fprintf(w, "Usage: hf2l-jobs %s [options]\n%s\n", a.Command, commandDescriptions[a.Command])
		f.SetOutput(w)
		f.PrintDefaults()
	}
	err := f.Parse(args[1:])
	if errors.Is(err, flag.ErrHelp) {
		f.Usage()
		return a, true, nil
	}
	if err != nil {
		return a, false, ErrArguments
	}
	f.Visit(func(v *flag.Flag) {
		if v.Name == "port" {
			a.PortSet = true
		}
	})
	if a.PortSet && (a.Port < 1 || a.Port > 65535) {
		return a, false, ErrArguments
	}
	if math.IsNaN(interval) || math.IsInf(interval, 0) || interval < .1 || interval > 60 {
		return a, false, ErrArguments
	}
	a.Interval = time.Duration(interval * float64(time.Second))
	rest := f.Args()
	if a.Command == "admin" {
		if len(rest) == 0 {
			return a, false, ErrArguments
		}
		if rest[0] == "--help" || rest[0] == "-h" {
			printAdminHelp(w)
			return a, true, nil
		}
		a.Operation = rest[0]
		if _, ok := adminDescriptions[a.Operation]; !ok {
			return a, false, ErrArguments
		}
		af := flag.NewFlagSet(a.Operation, flag.ContinueOnError)
		af.SetOutput(io.Discard)
		var id, name, quota, project, principal, role, file string
		retention := 90
		switch a.Operation {
		case "project-create", "project-update":
			af.StringVar(&id, "id", "", "Project identifier")
			af.StringVar(&name, "name", "", "Project display name")
			af.StringVar(&quota, "quota-file", "", "Trusted resource quota JSON object")
			af.IntVar(&retention, "retention-days", 90, "Artifact retention days")
		case "project-member":
			af.StringVar(&project, "project", "", "Project identifier")
			af.StringVar(&principal, "principal", "", "Stable human principal identifier")
			af.StringVar(&role, "role", "", "submitter, admin or remove")
		default:
			af.StringVar(&file, "file", "", "Trusted JSON definition")
		}
		af.Usage = func() {
			fmt.Fprintf(w, "Usage: hf2l-jobs admin [--config FILE] %s [options]\n%s\n", a.Operation, adminDescriptions[a.Operation])
			af.SetOutput(w)
			af.PrintDefaults()
		}
		err = af.Parse(rest[1:])
		if errors.Is(err, flag.ErrHelp) {
			af.Usage()
			return a, true, nil
		}
		if err != nil || len(af.Args()) > 0 {
			return a, false, ErrArguments
		}
		seen := map[string]bool{}
		af.Visit(func(v *flag.Flag) { seen[v.Name] = true })
		switch a.Operation {
		case "project-create":
			if id == "" || name == "" || quota == "" {
				return a, false, ErrArguments
			}
			a.Values["id"] = id
			a.Values["name"] = name
			a.Values["quota_file"] = quota
			a.Values["retention_days"] = int64(retention)
		case "project-update":
			if id == "" {
				return a, false, ErrArguments
			}
			a.Values["id"] = id
			if seen["name"] {
				a.Values["name"] = name
			}
			if seen["quota-file"] {
				a.Values["quota_file"] = quota
			}
			if seen["retention-days"] {
				a.Values["retention_days"] = int64(retention)
			}
		case "project-member":
			if project == "" || principal == "" || (role != "submitter" && role != "admin" && role != "remove") {
				return a, false, ErrArguments
			}
			a.Values["project"] = project
			a.Values["principal"] = principal
			a.Values["role"] = role
		default:
			if file == "" {
				return a, false, ErrArguments
			}
			a.Values["file"] = file
		}
	} else if len(rest) != 0 {
		return a, false, ErrArguments
	}
	if (a.Command == "managed-node" || a.Command == "participant-agent" || a.Command == "runtime") && a.Config == "" {
		return a, false, ErrArguments
	}
	return a, false, nil
}
func printAdminHelp(w io.Writer) {
	fmt.Fprintln(w, "Usage: hf2l-jobs admin [--config FILE] OPERATION [options]")
	names := []string{}
	for n := range adminDescriptions {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(w, "  %-24s %s\n", n, adminDescriptions[n])
	}
}
