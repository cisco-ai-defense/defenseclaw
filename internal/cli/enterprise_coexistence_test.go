// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"os"
	"testing"
)

func TestPerUserGatewayStartPathsRefuseBesideEnterpriseDeployment(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", dataDir)
	refusal := errors.New("enterprise deployment present")
	previous := refusePerUserGatewayBesideEnterprise
	refusePerUserGatewayBesideEnterprise = func() error { return refusal }
	t.Cleanup(func() { refusePerUserGatewayBesideEnterprise = previous })

	for name, run := range map[string]func() error{
		"start":      func() error { return runStart(startCmd, nil) },
		"restart":    func() error { return runRestart(restartCmd, nil) },
		"foreground": func() error { return rootCmd.RunE(rootCmd, nil) },
	} {
		if err := run(); !errors.Is(err, refusal) {
			t.Fatalf("%s error = %v, want the enterprise refusal", name, err)
		}
	}
	// The refusal precedes every side effect: no PID, log, or watchdog state.
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("refused start created gateway state: %v", names)
	}
}

func TestPerUserGatewayGateIsInertWithoutEnterpriseDeployment(t *testing.T) {
	if err := refusePerUserGatewayBesideEnterprise(); err != nil {
		t.Skipf("host has an enterprise deployment: %v", err)
	}
}
