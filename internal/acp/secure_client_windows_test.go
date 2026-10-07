//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acp

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

func TestSecureClientHostUsesRegisteredGatewayInsteadOfCallerEnvironment(t *testing.T) {
	programData := t.TempDir()
	t.Setenv("ProgramData", programData)
	roots, err := winpath.EnterpriseRootsFor(winpath.EnterpriseProfileSecureClient, os.Getenv("ProgramFiles"), programData)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Clean(roots.StateRoot), 0o700); err != nil {
		t.Fatal(err)
	}
	trusted, err := winpath.TrustedEnterpriseRoots(winpath.EnterpriseProfileSecureClient)
	if err != nil {
		t.Fatal(err)
	}
	previous := secureClientGatewayImage
	t.Cleanup(func() { secureClientGatewayImage = previous })
	secureClientGatewayImage = func() (string, error) { return filepath.Join(trusted.InstallRoot, "bin", "other.exe"), nil }
	if secureClientHost() {
		t.Fatal("caller-created state root selected the Secure Client ACP gate")
	}
	secureClientGatewayImage = func() (string, error) {
		return `"` + filepath.Join(trusted.InstallRoot, "bin", "defenseclaw-gateway.exe") + `" --service`, nil
	}
	t.Setenv("ProgramFiles", "")
	t.Setenv("ProgramData", "")
	if !secureClientHost() {
		t.Fatal("Secure Client registered service was hidden by caller environment")
	}
}
