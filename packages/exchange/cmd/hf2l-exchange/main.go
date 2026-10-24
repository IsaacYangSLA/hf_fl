package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/app"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	os.Exit(app.Run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}
