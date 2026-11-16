// Command hf2l-jobs-qualify-io exposes only native backing-I/O qualification probes.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/executor"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "expected backing-device or adapter operation")
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ContinueOnError)
	profile := fs.String("profile", "", "trusted executor profile")
	root := fs.String("root", "", "owned qualification root")
	path := fs.String("path", "", "path whose physical backing is inspected")
	image := fs.String("image", "", "already local immutable image")
	job := fs.String("job-id", "", "fresh qualification execution identity")
	if err := fs.Parse(os.Args[2:]); err != nil {
		os.Exit(2)
	}
	if *profile == "" || *root == "" || fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "profile/root required and positional arguments forbidden")
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	ctx, deadline := context.WithTimeout(ctx, 2*time.Minute)
	defer deadline()
	var out any
	var err error
	switch os.Args[1] {
	case "backing-device":
		if *path == "" {
			fmt.Fprintln(os.Stderr, "path required")
			os.Exit(2)
		}
		out, err = executor.QualificationBackingDevice(*profile, *root, *path)
	case "adapter":
		if *image == "" || *job == "" {
			fmt.Fprintln(os.Stderr, "image and job-id required")
			os.Exit(2)
		}
		out, err = executor.QualifyBackingIOAdapter(ctx, *profile, *root, *image, *job)
	default:
		fmt.Fprintln(os.Stderr, "unknown qualification operation")
		os.Exit(2)
	}
	if encodeErr := json.NewEncoder(os.Stdout).Encode(out); encodeErr != nil {
		fmt.Fprintln(os.Stderr, encodeErr)
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
