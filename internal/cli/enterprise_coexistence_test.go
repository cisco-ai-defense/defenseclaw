// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"io"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func stubPerUserGatewayRefusal(t *testing.T, refusal error) *int {
	t.Helper()
	calls := 0
	previous := refusePerUserGatewayBesideEnterprise
	refusePerUserGatewayBesideEnterprise = func() error {
		calls++
		return refusal
	}
	t.Cleanup(func() { refusePerUserGatewayBesideEnterprise = previous })
	return &calls
}

func assertNoPerUserGatewayState(t *testing.T, dataDir string) {
	t.Helper()
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("refused gateway command created per-user state: %v", names)
	}
}

// The refusal is exercised through Cobra, so each command runs its real
// persistent pre-run first. The per-user data directory has no config.yaml:
// a refusal that ran only after the root bootstrap would surface as a config
// load failure instead of the enterprise message.
func TestPerUserGatewayCommandsRefuseBesideEnterpriseDeployment(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", dataDir)
	t.Setenv(managed.ConfigPathEnv, "")
	refusal := errors.New("enterprise deployment present")
	stubPerUserGatewayRefusal(t, refusal)

	originalCfg, originalAuditStore, originalAuditLog := cfg, auditStore, auditLog
	originalOut, originalErr := rootCmd.OutOrStdout(), rootCmd.ErrOrStderr()
	t.Cleanup(func() {
		cfg, auditStore, auditLog = originalCfg, originalAuditStore, originalAuditLog
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(originalOut)
		rootCmd.SetErr(originalErr)
	})
	cfg, auditStore, auditLog = nil, nil, nil
	rootCmd.SetOut(io.Discard)
	rootCmd.SetErr(io.Discard)

	for name, args := range map[string][]string{
		"start":      {"start"},
		"restart":    {"restart"},
		"foreground": {},
	} {
		rootCmd.SetArgs(args)
		if _, err := rootCmd.ExecuteC(); !errors.Is(err, refusal) {
			t.Fatalf("%s error = %v, want the enterprise refusal", name, err)
		}
		if cfg != nil || auditStore != nil || auditLog != nil {
			t.Fatalf("%s loaded per-user config or audit state before refusing", name)
		}
		assertNoPerUserGatewayState(t, dataDir)
	}
}

// Only the bare root command is gated in the shared pre-run. Subcommands
// that reuse it, such as the enterprise hook commands, keep running.
func TestRootPreRunGatesOnlyTheForegroundGateway(t *testing.T) {
	refusal := errors.New("enterprise deployment present")
	calls := stubPerUserGatewayRefusal(t, refusal)
	skipBootstrap := map[string]string{"defenseclaw.skip-daemon-bootstrap": "true"}

	parent := &cobra.Command{Use: "defenseclaw-gateway"}
	child := &cobra.Command{Use: "child", Annotations: skipBootstrap}
	parent.AddCommand(child)
	if err := rootPersistentPreRunE(child, nil); err != nil {
		t.Fatalf("subcommand pre-run = %v, want nil", err)
	}
	if *calls != 0 {
		t.Fatalf("subcommand pre-run queried the enterprise gate %d times", *calls)
	}

	foreground := &cobra.Command{Use: "defenseclaw-gateway", Annotations: skipBootstrap}
	if err := rootPersistentPreRunE(foreground, nil); !errors.Is(err, refusal) {
		t.Fatalf("foreground pre-run = %v, want the enterprise refusal", err)
	}

	previousVersionJSON := versionJSON
	versionJSON = true
	t.Cleanup(func() { versionJSON = previousVersionJSON })
	*calls = 0
	if err := rootPersistentPreRunE(foreground, nil); err != nil || *calls != 0 {
		t.Fatalf("--version-json pre-run = %v with %d gate calls, want nil and 0", err, *calls)
	}
}

func TestPerUserGatewayGateIsInertWithoutEnterpriseDeployment(t *testing.T) {
	if err := hostPerUserGatewayRefusal(); err != nil {
		t.Skipf("host has an enterprise deployment: %v", err)
	}
}

// hostPerUserGatewayRefusal is the real start gate, kept for the host test
// above. isolatePerUserGatewayGateFromHost replaces both gates for the rest of
// the package.
var hostPerUserGatewayRefusal func() error

// isolatePerUserGatewayGateFromHost runs from TestMain. The start, restart,
// and foreground tests exercise checks that run after the coexistence gate,
// so they must not depend on whether the test host has the enterprise
// DefenseClawGateway service registered, as Secure Client test hosts do.
// Tests of the gates stub them themselves.
func isolatePerUserGatewayGateFromHost() {
	hostPerUserGatewayRefusal = refusePerUserGatewayBesideEnterprise
	refusePerUserGatewayBesideEnterprise = func() error { return nil }
	refuseRunningPerUserGatewayBesideEnterprise = func() error { return nil }
}

func TestGatewayCommandTestsDoNotDependOnHostEnterpriseDeployment(t *testing.T) {
	if err := refusePerUserGatewayBesideEnterprise(); err != nil {
		t.Fatalf("package tests run with the host start gate: %v", err)
	}
	if err := refuseRunningPerUserGatewayBesideEnterprise(); err != nil {
		t.Fatalf("package tests run with the host running-gateway gate: %v", err)
	}
}

func stubEnterpriseCoexistenceWatch(t *testing.T, refuse func() error) {
	t.Helper()
	previousSupported := enterpriseCoexistenceWatchSupported
	previousInterval := enterpriseCoexistencePollInterval
	previousRefuse := refuseRunningPerUserGatewayBesideEnterprise
	enterpriseCoexistenceWatchSupported = true
	enterpriseCoexistencePollInterval = time.Millisecond
	refuseRunningPerUserGatewayBesideEnterprise = refuse
	t.Cleanup(func() {
		enterpriseCoexistenceWatchSupported = previousSupported
		enterpriseCoexistencePollInterval = previousInterval
		refuseRunningPerUserGatewayBesideEnterprise = previousRefuse
	})
}

// A per-user gateway that was already running when Secure Client installed
// the enterprise service must stop itself. Otherwise it keeps the hook port
// until the user logs off, and every user's managed hooks fail closed.
func TestRunningPerUserGatewayStopsWhenEnterpriseDeploymentAppears(t *testing.T) {
	refusal := errors.New("enterprise deployment present")
	var calls atomic.Int32
	stubEnterpriseCoexistenceWatch(t, func() error {
		if calls.Add(1) < 3 {
			return nil
		}
		return refusal
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := errors.New("sidecar run error")
	// run stands in for Sidecar.Run: it serves until its context ends.
	run := func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return runErr
		case <-time.After(10 * time.Second):
			return errors.New("the per-user gateway kept running beside the enterprise deployment")
		}
	}
	err := runWithEnterpriseCoexistenceWatch(ctx, cancel, "", run)
	if !errors.Is(err, refusal) || !errors.Is(err, runErr) {
		t.Fatalf("gateway exit = %v, want the enterprise refusal and the run error", err)
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("checks = %d, want the gateway stopped at the first detection (3)", got)
	}
}

// Without an enterprise deployment, or when detection fails (the gate then
// returns nil), the per-user gateway keeps running and its exit is unchanged.
func TestRunningPerUserGatewayKeepsRunningWithoutEnterpriseDeployment(t *testing.T) {
	var calls atomic.Int32
	stubEnterpriseCoexistenceWatch(t, func() error {
		calls.Add(1)
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stopped atomic.Bool
	watch := startEnterpriseCoexistenceWatch(ctx, "", func() { stopped.Store(true) })
	for deadline := time.Now().Add(10 * time.Second); calls.Load() < 5; {
		if time.Now().After(deadline) {
			t.Fatalf("checks = %d, want the watch to keep checking", calls.Load())
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-watch.done
	if stopped.Load() {
		t.Fatal("the watch stopped a gateway without an enterprise deployment")
	}
	runErr := errors.New("sidecar run error")
	if err := watch.exitError(runErr); err != runErr {
		t.Fatalf("exit error = %v, want the unchanged run error", err)
	}
}

// The enterprise gateway service runs the same sidecar in managed_enterprise
// mode, and the deployment exists only on Windows. Neither starts the watch.
func TestEnterpriseCoexistenceWatchIsOffForEnterpriseGatewayAndOffWindows(t *testing.T) {
	for name, tc := range map[string]struct {
		supported bool
		mode      string
	}{
		"off Windows":                {supported: false},
		"managed enterprise gateway": {supported: true, mode: managed.DeploymentModeManagedEnterprise},
	} {
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int32
			stubEnterpriseCoexistenceWatch(t, func() error {
				calls.Add(1)
				return errors.New("enterprise deployment present")
			})
			enterpriseCoexistenceWatchSupported = tc.supported
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var stopped atomic.Bool
			watch := startEnterpriseCoexistenceWatch(ctx, tc.mode, func() { stopped.Store(true) })
			<-watch.done
			time.Sleep(20 * time.Millisecond)
			if calls.Load() != 0 || stopped.Load() || ctx.Err() != nil {
				t.Fatalf("watch ran: checks=%d stopped=%v", calls.Load(), stopped.Load())
			}
			if err := watch.exitError(nil); err != nil {
				t.Fatalf("exit error = %v, want nil", err)
			}
		})
	}
}
