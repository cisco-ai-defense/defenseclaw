// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// stubWindowsEnterpriseRecordedTrust makes the production standalone record
// report trust (after stubWindowsEnterpriseDeployments, whose cleanup
// restores the real inspector).
func stubWindowsEnterpriseRecordedTrust(t *testing.T, trust *string) {
	t.Helper()
	inner := windowsEnterpriseDeploymentInspector
	windowsEnterpriseDeploymentInspector = func(profile string) (winpath.EnterpriseDeployment, error) {
		deployment, err := inner(profile)
		if profile == "standalone" {
			deployment.TrustMode = *trust
			deployment.MetadataPath = `C:\ProgramData\Cisco\DefenseClaw\install\deployment.json`
		}
		return deployment, err
	}
}

// A certification-scope run (--state-root) takes the installed config and
// the recorded trust from its own state root, like the installer's layout,
// never from the production deployment on the same host.
func TestWindowsEnterpriseCertificationScopeUsesItsOwnInstalledTrust(t *testing.T) {
	stubWindowsEnterpriseDeployments(t, nil)
	productionTrust := "hash_pinned"
	stubWindowsEnterpriseRecordedTrust(t, &productionTrust)
	productionSigner := strings.Repeat("ab", 32)
	production := writeWindowsEnterpriseTrustConfig(t, t.TempDir(), "config.yaml",
		"  trust:\n    mode: authenticode\n    allowed_signers: ["+productionSigner+"]\n")
	windowsEnterpriseInstalledConfigPath = func() (string, error) { return production, nil }

	stateRoot := t.TempDir()
	scopeMetadata := filepath.Join(stateRoot, "install", "deployment.json")
	scopeTrust := ""
	var inspected []string
	originalScoped := windowsEnterpriseScopedDeploymentInspector
	windowsEnterpriseScopedDeploymentInspector = func(profile, path string) (winpath.EnterpriseDeployment, error) {
		inspected = append(inspected, path)
		return winpath.EnterpriseDeployment{
			Profile: profile, State: winpath.EnterpriseDeploymentInstalled, MetadataPath: path, TrustMode: scopeTrust,
		}, nil
	}
	t.Cleanup(func() { windowsEnterpriseScopedDeploymentInspector = originalScoped })
	scope := func(opts windowsEnterpriseLifecycleOptions) *windowsEnterpriseLifecycleOptions {
		opts.profile = "standalone"
		opts.installRoot = `C:\Program Files\Cisco\DefenseClaw-Cert\0123456789`
		opts.stateRoot = stateRoot
		opts.gatewayServiceName = "DefenseClawCertGateway_0123456789"
		opts.guardianServiceName = "DefenseClawCertGuardian_0123456789"
		return &opts
	}

	// With no config of its own, the scope takes neither the production
	// signer pin nor its authenticode mode.
	unsigned := scope(windowsEnterpriseLifecycleOptions{trustMode: "hash_pinned", payloadManifest: `C:\stage\payload-trust.json`})
	if err := resolveWindowsEnterpriseLifecycleProfile("ensure", unsigned); err != nil || len(unsigned.allowedSigners) != 0 {
		t.Fatalf("scope without its own config: signers %q, %v", unsigned.allowedSigners, err)
	}

	// The scope's own installed config applies, and its own metadata is the
	// recorded trust.
	scopeSigner := strings.Repeat("cd", 32)
	if err := os.MkdirAll(filepath.Join(stateRoot, "etc"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeWindowsEnterpriseTrustConfig(t, filepath.Join(stateRoot, "etc"), "config.yaml",
		"  trust:\n    mode: authenticode\n    allowed_signers: ["+scopeSigner+"]\n")
	signed := scope(windowsEnterpriseLifecycleOptions{})
	if err := resolveWindowsEnterpriseLifecycleProfile("ensure", signed); err != nil {
		t.Fatalf("scope with its own authenticode config over a hash_pinned production deployment: %v", err)
	}
	if !reflect.DeepEqual(signed.allowedSigners, []string{scopeSigner}) {
		t.Fatalf("scope signers %q, want its own %q", signed.allowedSigners, scopeSigner)
	}
	if len(inspected) == 0 || inspected[len(inspected)-1] != scopeMetadata {
		t.Fatalf("recorded trust read from %q, want %s", inspected, scopeMetadata)
	}
	scopeTrust = "hash_pinned"
	err := resolveWindowsEnterpriseLifecycleProfile("ensure", scope(windowsEnterpriseLifecycleOptions{}))
	if err == nil || !errors.Is(err, errWindowsEnterpriseInvalidArguments) || !strings.Contains(err.Error(), scopeMetadata) {
		t.Fatalf("scope with a hash_pinned record: %v", err)
	}
}
