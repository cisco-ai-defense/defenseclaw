// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
	"github.com/defenseclaw/defenseclaw/internal/substrate/scanworker"
)

// newSubstrateScanWorkerCmd is the scanner sidecar's entry point in the
// scanner image (GAP-0477). It is hidden: only the chart runs it.
func newSubstrateScanWorkerCmd() *cobra.Command {
	var (
		dir     string
		timeout time.Duration
	)
	cmd := &cobra.Command{
		Use:    "scan-worker",
		Short:  "Run the Agent Substrate skill scanner sidecar (the chart runs it)",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			w := &scanworker.Worker{Dir: dir, Timeout: timeout, Version: runtimeVersion()}
			fmt.Fprintf(cmd.ErrOrStderr(), "scan-worker: listening on %s/%s\n", dir, scanner.ScanSocketName)
			return w.Serve(ctx)
		},
	}
	cmd.Flags().StringVar(&dir, "dir", scanner.DefaultScanDir, "the shared scan folder (socket and jobs)")
	cmd.Flags().DurationVar(&timeout, "timeout", 20*time.Second, "per-scan timeout, waiting for a slot included")
	return cmd
}

// runtimeVersion asks the scanner runtime for its version once it answers;
// a failure is asked again next time (the runtime may still be starting).
func runtimeVersion() func(context.Context) (string, error) {
	var (
		mu sync.Mutex
		v  string
	)
	return func(ctx context.Context) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		if v != "" {
			return v, nil
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		var out, errb bytes.Buffer
		c := exec.CommandContext(cctx, scanworker.RuntimeLauncher, "--version")
		c.Stdout, c.Stderr = &out, &errb
		if err := c.Run(); err != nil {
			return "", fmt.Errorf("the scanner runtime %s does not run: %v %s", scanworker.RuntimeLauncher, err, strings.TrimSpace(errb.String()))
		}
		v = strings.TrimSpace(out.String())
		return v, nil
	}
}
