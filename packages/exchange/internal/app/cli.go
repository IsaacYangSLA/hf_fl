package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/config"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/storage"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/transfers"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/worker"
)

type attemptsFlag []string

func (a *attemptsFlag) String() string     { return "<selected attempt IDs>" }
func (a *attemptsFlag) Set(v string) error { *a = append(*a, v); return nil }

type commandFlags struct {
	Listener         ListenerOptions
	Workers          int
	Once             bool
	OutputDir        string
	Attempts         attemptsFlag
	Apply            bool
	WritersStopped   bool
	ProviderQuiesced bool
	LogLevel         string
}

var commands = []string{"init-db", "migrate-db", "check-db", "check-storage", "check-compatibility", "serve", "serve-managed", "serve-gateway-backend", "worker", "repair-transfers", "export-contract"}

func usage(w io.Writer) {
	fmt.Fprintln(w, "Usage: hf2l-exchange COMMAND [flags]")
	fmt.Fprintln(w, "Native Go Exchange API, durable transfers, and background workers.")
	fmt.Fprintln(w, "Commands: "+strings.Join(commands, ", "))
}
func isServe(command string) bool {
	return command == "serve" || command == "serve-managed" || command == "serve-gateway-backend"
}
func parseFlags(command string, args []string, w io.Writer) (commandFlags, error) {
	var o commandFlags
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&o.OutputDir, "output-dir", "", "contract export directory (default docs/generated)")
	fs.StringVar(&o.Listener.Host, "host", "127.0.0.1", "listener host")
	fs.IntVar(&o.Listener.Port, "port", 8000, "listener port")
	fs.IntVar(&o.Workers, "workers", 1, "native Go uses concurrent goroutines; only 1 process per invocation")
	fs.BoolVar(&o.Once, "once", false, "worker: run one pass and exit")
	fs.Var(&o.Attempts, "attempt", "repair: select one attempt ID (repeat up to 100)")
	fs.BoolVar(&o.Apply, "apply", false, "repair: apply selected repairs; otherwise dry run")
	fs.BoolVar(&o.WritersStopped, "writers-stopped", false, "repair assertion: every API and worker writer is stopped")
	fs.BoolVar(&o.ProviderQuiesced, "provider-quiesced", false, "repair assertion: all provider mutations are quiesced")
	fs.StringVar(&o.LogLevel, "log-level", "INFO", "DEBUG, INFO, WARNING, or ERROR")
	fs.StringVar(&o.Listener.CertificateFile, "tls-cert", "", "server certificate PEM")
	fs.StringVar(&o.Listener.KeyFile, "tls-key", "", "private server key PEM (mode 0600)")
	fs.StringVar(&o.Listener.ClientCAFile, "client-ca", "", "client CA PEM; requires verified client certificates")
	fs.StringVar(&o.Listener.TransferAudience, "transfer-audience", "hf2l-transfer", "private gateway transfer audience")
	fs.Usage = func() {
		fmt.Fprintf(w, "Usage: hf2l-exchange %s [flags]\n", command)
		fs.SetOutput(w)
		fs.PrintDefaults()
		fs.SetOutput(io.Discard)
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return o, flag.ErrHelp
		}
		return o, errors.New("invalid command flags; use COMMAND --help")
	}
	if len(fs.Args()) != 0 {
		return o, errors.New("unexpected positional arguments")
	}
	if o.Listener.Port < 1 || o.Listener.Port > 65535 {
		return o, errors.New("port must be between 1 and 65535")
	}
	if o.Workers != 1 {
		return o, errors.New("native Go uses concurrent goroutines; --workers must be 1; supervise separate instances for multiple processes")
	}
	switch o.LogLevel {
	case "DEBUG", "INFO", "WARNING", "ERROR":
	default:
		return o, errors.New("invalid log level")
	}
	if o.OutputDir != "" && command != "export-contract" {
		return o, errors.New("--output-dir requires export-contract")
	}
	repairFlags := len(o.Attempts) > 0 || o.Apply || o.WritersStopped || o.ProviderQuiesced
	if repairFlags && command != "repair-transfers" {
		return o, errors.New("repair flags require repair-transfers")
	}
	if command == "repair-transfers" {
		if len(o.Attempts) > 100 {
			return o, errors.New("select at most 100 distinct attempt IDs")
		}
		ids := map[string]bool{}
		for _, id := range o.Attempts {
			if id == "" || utf8.RuneCountInString(id) > 64 || !utf8.ValidString(id) || ids[id] {
				return o, errors.New("select distinct attempt IDs of 1 to 64 characters")
			}
			ids[id] = true
		}
		if o.Apply && (len(o.Attempts) == 0 || !o.WritersStopped || !o.ProviderQuiesced) {
			return o, errors.New("--apply requires selected --attempt IDs, --writers-stopped and --provider-quiesced")
		}
	}
	if !isServe(command) && (o.Listener.CertificateFile != "" || o.Listener.KeyFile != "" || o.Listener.ClientCAFile != "") {
		return o, errors.New("TLS flags require a listener command")
	}
	if command != "serve-gateway-backend" && o.Listener.TransferAudience != "hf2l-transfer" {
		return o, errors.New("--transfer-audience requires serve-gateway-backend")
	}
	if o.Once && command != "worker" {
		return o, errors.New("--once requires worker")
	}
	return o, nil
}
func jsonOutput(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}
func safeError(err error) domain.Object {
	code := "operation_unavailable"
	detail := ""
	var de *domain.Error
	if errors.As(err, &de) {
		code = de.Code
		detail = de.Detail
	}
	var sf *storage.StorageFailure
	if errors.As(err, &sf) {
		code = sf.Code
		detail = sf.Code
	}
	var ce *config.Error
	if errors.As(err, &ce) {
		code = "invalid_configuration"
		detail = ce.Error()
	}
	var stageError *CompositionError
	if errors.As(err, &stageError) && detail == "" {
		detail = stageError.Error()
	}
	return domain.Object{"error": domain.Object{"code": code, "detail": detail}}
}
func databaseCommand(ctx context.Context, command string, o commandFlags, stdout, stderr io.Writer) int {
	s, err := config.DatabaseFromEnv()
	if err != nil {
		_ = jsonOutput(stderr, safeError(err))
		return 1
	}
	db, err := OpenDatabase(ctx, s)
	if err != nil {
		_ = jsonOutput(stderr, safeError(err))
		return 1
	}
	defer db.Close()
	switch command {
	case "init-db":
		err = db.Initialize(ctx)
	case "migrate-db":
		err = db.Migrate(ctx)
	case "check-db":
		err = db.Check(ctx)
	case "check-compatibility":
		var report CompatibilityReport
		report, err = CheckCompatibility(ctx, db)
		if err == nil {
			if jsonOutput(stdout, report) != nil {
				return 1
			}
			if len(report.Incompatible) > 0 {
				return 1
			}
			return 0
		}
	case "repair-transfers":
		if err = db.Check(ctx); err == nil {
			var result domain.Object
			if len(o.Attempts) > 0 {
				result, err = transfers.RepairMutations(ctx, db, []string(o.Attempts), o.Apply, o.WritersStopped, o.ProviderQuiesced)
			} else {
				result, err = transfers.InspectMutations(ctx, db, nil)
			}
			if err == nil {
				result["dry_run"] = !o.Apply
				if jsonOutput(stdout, result) != nil {
					return 1
				}
				return 0
			}
		}
	}
	if err != nil {
		if command == "repair-transfers" {
			_ = jsonOutput(stdout, safeError(err))
		} else {
			_ = jsonOutput(stderr, safeError(err))
		}
		return 1
	}
	fmt.Fprintln(stdout, "Exchange database revision is current")
	return 0
}
func workerCommand(ctx context.Context, o commandFlags, stdout, stderr io.Writer) int {
	settings, err := config.FromEnv("worker")
	if err != nil {
		_ = jsonOutput(stderr, safeError(err))
		return 1
	}
	services, err := BuildServices(ctx, settings, "worker")
	if err != nil {
		_ = jsonOutput(stderr, safeError(err))
		return 1
	}
	defer services.Close()
	logger := log.New(stderr, "hf2l-exchange ", log.Ldate|log.Ltime|log.LUTC)
	failures := 0
	for {
		counts, passErr := worker.Tick(ctx, services.Transfers, settings.Worker.BatchSize)
		if passErr == nil {
			failures = 0
			if o.LogLevel == "DEBUG" || o.LogLevel == "INFO" {
				b, _ := json.Marshal(counts)
				logger.Printf("worker pass %s", b)
			}
		} else {
			failures++
			logger.Printf("worker pass failed class=%T consecutive=%d", passErr, failures)
		}
		if o.Once {
			if passErr != nil {
				return 1
			}
			return 0
		}
		if ctx.Err() != nil {
			return 0
		}
		exponent := failures
		if exponent > 16 {
			exponent = 16
		}
		seconds := math.Min(math.Ldexp(settings.Worker.PollSeconds, exponent), 300)
		timer := time.NewTimer(time.Duration(seconds * float64(time.Second)))
		select {
		case <-ctx.Done():
			timer.Stop()
			return 0
		case <-timer.C:
		}
	}
}
func serveCommand(ctx context.Context, command string, o commandFlags, stdout, stderr io.Writer) int {
	settings, err := config.FromEnv("server")
	if err != nil {
		_ = jsonOutput(stderr, safeError(err))
		return 1
	}
	mode := "public"
	if command == "serve-managed" {
		mode = "managed"
	}
	if command == "serve-gateway-backend" {
		mode = "gateway"
	}
	tlsConfig, err := TLSConfig(mode, o.Listener, settings.AllowLocalHTTP)
	if err != nil {
		fmt.Fprintln(stderr, "Exchange listener TLS configuration is invalid")
		return 1
	}
	services, err := BuildServices(ctx, settings, "server")
	if err != nil {
		_ = jsonOutput(stderr, safeError(err))
		return 1
	}
	defer services.Close()
	handler, err := services.Handler(mode, o.Listener.TransferAudience)
	if err != nil {
		fmt.Fprintln(stderr, "Exchange listener composition is invalid")
		return 1
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(o.Listener.Host, strconv.Itoa(o.Listener.Port)))
	if err != nil {
		fmt.Fprintln(stderr, "Exchange listener could not start")
		return 1
	}
	server := &http.Server{Handler: handler, TLSConfig: tlsConfig, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 64 * 1024, ErrorLog: log.New(stderr, "hf2l-exchange ", log.Ldate|log.Ltime|log.LUTC)}
	done := make(chan error, 1)
	go func() {
		if tlsConfig != nil {
			done <- server.ServeTLS(listener, "", "")
		} else {
			done <- server.Serve(listener)
		}
	}()
	select {
	case err = <-done:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintln(stderr, "Exchange listener stopped unexpectedly")
			return 1
		}
		return 0
	case <-ctx.Done():
		stopCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err = server.Shutdown(stopCtx); err != nil {
			_ = server.Close()
		}
		<-done
		return 0
	}
}

// Run executes one native command. It does not invoke another language runtime.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	if args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		usage(stdout)
		return 0
	}
	command := args[0]
	known := false
	for _, c := range commands {
		if command == c {
			known = true
			break
		}
	}
	if !known {
		fmt.Fprintln(stderr, "Unknown Exchange command")
		usage(stderr)
		return 2
	}
	opts, err := parseFlags(command, args[1:], stdout)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		// Parser errors can contain user-supplied values. Emit only a fixed summary.
		fmt.Fprintln(stderr, err.Error())
		return 2
	}
	switch command {
	case "init-db", "migrate-db", "check-db", "check-compatibility", "repair-transfers":
		return databaseCommand(ctx, command, opts, stdout, stderr)
	case "export-contract":
		dir := opts.OutputDir
		if dir == "" {
			dir = "docs/generated"
		}
		paths, err := ExportContracts(dir)
		if err != nil {
			fmt.Fprintln(stderr, "Exchange contract export failed")
			return 1
		}
		for _, path := range paths {
			fmt.Fprintln(stdout, path)
		}
		return 0
	case "check-storage":
		settings, err := config.StorageFromEnv()
		if err != nil {
			_ = jsonOutput(stderr, safeError(err))
			return 1
		}
		blobs, err := storage.NewS3(ctx, settings)
		if err == nil {
			err = blobs.Check(ctx)
		}
		if err != nil {
			_ = jsonOutput(stderr, safeError(err))
			return 1
		}
		fmt.Fprintln(stdout, "Exchange storage is ready")
		return 0
	case "worker":
		return workerCommand(ctx, opts, stdout, stderr)
	default:
		return serveCommand(ctx, command, opts, stdout, stderr)
	}
}
