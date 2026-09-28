// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"io"
	"os"
	"testing"

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
	if err := refusePerUserGatewayBesideEnterprise(); err != nil {
		t.Skipf("host has an enterprise deployment: %v", err)
	}
}
