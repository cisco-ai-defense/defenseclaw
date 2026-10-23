// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package openshell_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// refuseSecondRestart makes OpenShell report a sandbox another client
// started once the first restart was made (or tried).
func refuseSecondRestart(f *gatewayFixture) {
	f.cfg.CheckStopped = func(context.Context) error {
		if f.restarts() > 0 {
			return fmt.Errorf("%w; OpenShell has not reported these stopped: raw-box (ready): `openshell sandbox stop raw-box`", openshell.ErrUnflushed)
		}
		return nil
	}
}

// Files that enable bind mounts are kept only once the restarted gateway
// passed the security check, also when no check could be made: the restart
// onto them did not come back healthy, or the check could not read the
// gateway's configuration. Under a sandbox another client started, the
// previous files stay restored and the gateway is restarted on them, as
// for a check that failed.
func TestApplyNeverKeepsBindMountFilesNoSecurityCheckPassed(t *testing.T) {
	for name, fault := range map[string]func(f *gatewayFixture){
		"restart not healthy": func(f *gatewayFixture) {
			f.verify = errors.New("gateway not healthy")
			f.runner.OnFunc("systemctl --user restart openshell-gateway", func(context.Context, openshell.Command) ([]byte, error) {
				if f.restarts() > 1 {
					f.verify = nil
				}
				return nil, nil
			})
		},
		"configuration unreadable at the check": func(f *gatewayFixture) {
			f.runner.OnFunc("systemctl --user restart openshell-gateway", func(context.Context, openshell.Command) ([]byte, error) {
				if f.restarts() == 1 {
					// Something replaced the gateway's configuration with
					// one the check cannot read.
					path := filepath.Join(f.dir, "gateway.toml")
					if err := os.WriteFile(path, []byte("[openshell\n"), 0o600); err != nil {
						return nil, err
					}
				}
				return nil, nil
			})
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newGatewayFixture(t)
			f.write(t, "gateway.toml", operatorTOML)
			plan := f.plan(t, bindMounts)
			refuseSecondRestart(f)
			fault(f)
			_, err := f.apply(plan)
			if err == nil {
				t.Fatal("Apply succeeded")
			}
			if got := f.read(t, "gateway.toml"); got != operatorTOML {
				t.Fatalf("files that enable bind mounts were kept though no security check passed (%v):\n%s", err, got)
			}
			if f.restarts() != 2 || !strings.Contains(err.Error(), "is never kept running") {
				t.Fatalf("%d restarts, want the second one onto the previous files: %v", f.restarts(), err)
			}
		})
	}
}

// A restart onto the new files that the service manager refused leaves
// the gateway on what it ran: when OpenShell then reports a sandbox not
// stopped, the active files are kept without another restart, and the
// restart stays pending (doctor reports it), with the way to make it.
func TestApplyKeepsTheRestartPendingWhenTheServiceManagerRefusedIt(t *testing.T) {
	f := newGatewayFixture(t)
	f.write(t, "gateway.toml", operatorTOML)
	plan := f.plan(t, telemetryOff)
	refuseSecondRestart(f)
	f.runner.OnFunc("systemctl --user restart openshell-gateway", func(context.Context, openshell.Command) ([]byte, error) {
		return []byte("Job failed"), errors.New("exit status 1")
	})
	_, err := f.apply(plan)
	st, readErr := f.cfg.Read()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if st.RestartPendingSince.IsZero() {
		t.Fatalf("the restart mark was cleared, though the gateway was never restarted on the active files: %v", err)
	}
	if f.restarts() != 1 {
		t.Fatalf("%d restarts, want none after the refused rollback", f.restarts())
	}
	if !errors.Is(err, openshell.ErrUnflushed) || !strings.Contains(err.Error(), "active gateway files were kept without another restart, which stays pending") ||
		!strings.Contains(err.Error(), "systemctl --user restart openshell-gateway") {
		t.Fatalf("Apply = %v", err)
	}
}
