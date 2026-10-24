// Command hf2l-jobs runs the Go job manager and trusted operational services.
package main

import (
	"context"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/app"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := app.Run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	cancel()
	os.Exit(code)
}
