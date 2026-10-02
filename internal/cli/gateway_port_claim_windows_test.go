// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-1569: a Windows start claims its API port with this account's SID,
// keeps other accounts' claims and drops its own claims on ports it left.
func TestGatewayStartClaimsItsAPIPortOnWindows(t *testing.T) {
	dir := t.TempDir()
	previous := gatewayPortClaimDir
	gatewayPortClaimDir = dir
	t.Cleanup(func() { gatewayPortClaimDir = previous })
	t.Setenv(managed.DeploymentModeEnv, "")
	own := currentAccountSID()
	if own == "" {
		t.Fatal("no account SID")
	}
	old := filepath.Join(dir, gatewayPortClaimPrefix+"18970")
	other := filepath.Join(dir, gatewayPortClaimPrefix+"18990")
	if err := os.WriteFile(old, []byte(own), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(other, []byte("S-1-5-21-1-2-3-1001"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.Gateway.APIPort = 18980
	claimGatewayAPIPort(cfg)

	if got := gatewayPortClaimSID(filepath.Join(dir, gatewayPortClaimPrefix+"18980")); got != own {
		t.Fatalf("claim on the configured port names %q, want %q", got, own)
	}
	if _, err := os.Lstat(old); !os.IsNotExist(err) {
		t.Fatalf("this account's claim on its old port was kept: %v", err)
	}
	if _, err := os.Lstat(other); err != nil {
		t.Fatalf("another account's claim was removed: %v", err)
	}
}
