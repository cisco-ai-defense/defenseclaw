// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package openshell_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// Review P2 (1.0.4 guard loop round 3): the restarted gateway fails the
// security check (it lets in a client without the registration's
// certificate while it honours bind mounts), and OpenShell meanwhile
// reports a sandbox another client started on it. The rollback never
// keeps the files that failed the check, and never leaves that gateway
// running: the previous files stay restored and the gateway is restarted
// on them. When that restart fails, the restart stays pending and the
// error names the exposure and the restart to run.
func TestApplyNeverKeepsGatewayFilesThatFailedTheSecurityCheck(t *testing.T) {
	for _, restartFails := range []bool{false, true} {
		f := newGatewayFixture(t)
		f.write(t, "gateway.toml", operatorTOML)
		plan := f.plan(t, bindMounts)
		f.probe = func() error {
			if f.restarts() > 0 {
				return fmt.Errorf("%w: accepted a TLS session", openshell.ErrGatewayExposed)
			}
			return nil
		}
		f.cfg.CheckStopped = func(context.Context) error {
			if f.restarts() > 0 {
				return fmt.Errorf("%w; OpenShell has not reported these stopped: raw-box (ready): `openshell sandbox stop raw-box`", openshell.ErrUnflushed)
			}
			return nil
		}
		if restartFails {
			f.runner.OnFunc("systemctl --user restart openshell-gateway", func(context.Context, openshell.Command) ([]byte, error) {
				if f.restarts() > 1 {
					return []byte("Job failed"), errors.New("exit status 1")
				}
				return nil, nil
			})
		}
		_, err := f.apply(plan)
		if !errors.Is(err, openshell.ErrBindMountsRefused) {
			t.Fatalf("restart fails %v: Apply = %v, want ErrBindMountsRefused", restartFails, err)
		}
		if got := f.read(t, "gateway.toml"); got != operatorTOML {
			t.Fatalf("restart fails %v: the files that failed the security check were kept:\n%s", restartFails, got)
		}
		if f.restarts() != 2 {
			t.Fatalf("restart fails %v: %d restarts, want the second one onto the previous files", restartFails, f.restarts())
		}
		st, readErr := f.cfg.Read()
		if readErr != nil {
			t.Fatal(readErr)
		}
		if restartFails {
			if st.RestartPendingSince.IsZero() || !strings.Contains(err.Error(), "may still run the configuration that failed the check") ||
				!strings.Contains(err.Error(), "systemctl --user restart openshell-gateway") {
				t.Fatalf("a failed restart keeps the restart pending and names the exposure: pending %v, %v", st.RestartPendingSince, err)
			}
			continue
		}
		if !st.RestartPendingSince.IsZero() || !strings.Contains(err.Error(), "never kept running") {
			t.Fatalf("the gateway restarted on the previous files: pending %v, %v", st.RestartPendingSince, err)
		}
	}
}
