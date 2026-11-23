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

	"github.com/defenseclaw/defenseclaw/internal/processutil"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
	"github.com/defenseclaw/defenseclaw/internal/substrate/scanworker"
)

// newSubstrateScanWorkerCmd is the scanner sidecar's entry point in the
// scanner image (GAP-0477). It is hidden: only the chart runs it.
func newSubstrateScanWorkerCmd() *cobra.Command {
	var (
		dir          string
		timeout      time.Duration
		podContained bool
	)
	cmd := &cobra.Command{
		Use:    "scan-worker",
		Short:  "Run the Agent Substrate skill scanner sidecar (the chart runs it)",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			w := &scanworker.Worker{Dir: dir, Timeout: timeout}
			var contain func(*exec.Cmd) error
			if podContained {
				// Only the chart's flag selects it (GAP-0828), never a
				// refused namespace. The scanner writes only to the
				// container's tmp; Reset also empties the pod's /dev/shm
				// (GAP-0875).
				w.Pod = processutil.NewPodRunner(os.TempDir(), podShm)
				contain = w.Pod.Run
				if err := w.Pod.Check(); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "scan-worker: cannot contain scans, every scan is refused: %v\n", err)
				}
			}
			w.Version = runtimeVersion(contain)
			fmt.Fprintf(cmd.ErrOrStderr(), "scan-worker: listening on %s/%s\n", dir, scanner.ScanSocketName)
			return w.Serve(ctx)
		},
	}
	cmd.Flags().StringVar(&dir, "dir", scanner.DefaultScanDir, "the shared scan folder (socket and jobs)")
	cmd.Flags().DurationVar(&timeout, "timeout", 20*time.Second, "per-scan timeout, waiting for a slot included")
	cmd.Flags().BoolVar(&podContained, "pod-contained", false,
		"contain scans with the container (PID 1 of its own PID namespace, one scan at a time), for a sidecar whose seccomp profile refuses namespaces")
	return cmd
}

// podShm is the pod's shared memory folder, which pod mode empties after
// each job.
const podShm = "/dev/shm"

// runtimeVersion asks the scanner runtime for its version once it answers;
// a failure is asked again next time (the runtime may still be starting).
// contain runs the command in the pod-contained mode (nil: a plain child).
func runtimeVersion(contain func(*exec.Cmd) error) func(context.Context) (string, error) {
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
		run := c.Run
		if contain != nil {
			run = func() error { return contain(c) }
		}
		if err := run(); err != nil {
			return "", fmt.Errorf("the scanner runtime %s does not run: %v %s", scanworker.RuntimeLauncher, err, strings.TrimSpace(errb.String()))
		}
		v = strings.TrimSpace(out.String())
		return v, nil
	}
}
