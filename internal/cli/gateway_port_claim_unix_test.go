// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Keep the package's gateway start tests from leaving claims in /var/tmp. One
// fixed directory per account, so test runs do not leave one each.
func init() {
	dir := filepath.Join(os.TempDir(), "defenseclaw-test-port-claims-"+strconv.Itoa(os.Getuid()))
	if err := os.MkdirAll(dir, 0o700); err == nil {
		gatewayPortClaimDir = dir
	}
}

// GAP-1261: a start leaves a claim on its API port that init on another
// account skips, and drops this account's claims on ports it left.
func TestGatewayStartClaimsItsAPIPort(t *testing.T) {
	dir := t.TempDir()
	previous := gatewayPortClaimDir
	gatewayPortClaimDir = dir
	t.Cleanup(func() { gatewayPortClaimDir = previous })
	t.Setenv(managed.DeploymentModeEnv, "")

	old := filepath.Join(dir, gatewayPortClaimPrefix+"18970")
	if err := os.WriteFile(old, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.Gateway.APIPort = 18980
	claimGatewayAPIPort(cfg)

	if _, err := os.Lstat(filepath.Join(dir, gatewayPortClaimPrefix+"18980")); err != nil {
		t.Fatalf("no claim on the configured port: %v", err)
	}
	if _, err := os.Lstat(old); !os.IsNotExist(err) {
		t.Fatalf("this account's claim on its old port was kept: %v", err)
	}
	// A second start keeps the claim.
	claimGatewayAPIPort(cfg)
	if matches, _ := filepath.Glob(filepath.Join(dir, gatewayPortClaimPrefix+"*")); len(matches) != 1 {
		t.Fatalf("claims after a second start = %v, want one", matches)
	}
}
