// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

const untrustedLibraryRefusal = "refusing untrusted managed cloud auth library"

func TestEnsureCMIDProviderRefusesAnUntrustedLibraryPath(t *testing.T) {
	sidecar := &Sidecar{
		cfg: &config.Config{
			DeploymentMode: "managed_enterprise",
			CloudAuth: config.CloudAuthConfig{
				Mode:    "cmid",
				LibPath: filepath.Join(t.TempDir(), "absent", "cmidapi"),
			},
		},
	}

	prov, err := sidecar.ensureCMIDProvider(t.Context())
	if err == nil {
		t.Fatal("a library the deployment cannot vouch for must not be loaded")
	}
	// The refusal has to come from the path check, not from the provider
	// registry: on a build that does register a provider, reaching the
	// factory would already have handed it the untrusted path.
	if !strings.Contains(err.Error(), untrustedLibraryRefusal) {
		t.Fatalf("error = %v, want the trusted-path refusal", err)
	}
	if prov != nil {
		t.Fatal("a refused library must not yield a provider")
	}
}

func TestEnsureCMIDProviderLeavesAnUnsetLibraryPathToTheProvider(t *testing.T) {
	sidecar := &Sidecar{
		cfg: &config.Config{
			DeploymentMode: "managed_enterprise",
			CloudAuth:      config.CloudAuthConfig{Mode: "cmid", LibPath: "  "},
		},
	}

	// An unset path is the normal case: the provider knows where its own
	// library lives. Whatever happens next, it must not be a path refusal.
	_, err := sidecar.ensureCMIDProvider(t.Context())
	if err != nil && strings.Contains(err.Error(), untrustedLibraryRefusal) {
		t.Fatalf("an unset library path must not be treated as untrusted: %v", err)
	}
}
