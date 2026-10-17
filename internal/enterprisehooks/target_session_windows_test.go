// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWindowsTargetUnselectedProofAcceptsAbsentRootAndRejectsSelection pins
// the #894 proof split. A target discovered after install whose user never
// signed in has no installer-created <home>\.defenseclaw root, so the
// deferred pending proof (which authorizes staging machine policy for it)
// rejects it; the unselected proof, which only establishes that DefenseClaw
// holds no managed runtime for the exact SID, accepts it. A selected runtime
// is still rejected.
func TestWindowsTargetUnselectedProofAcceptsAbsentRootAndRejectsSelection(t *testing.T) {
	fixture := newWindowsManagedRuntimeGenerationMissingHooksGCFixture(t)
	enabled := true

	rootless := ManifestTarget{
		UserHome:     newWindowsTargetOwnedTestHome(t, fixture.target),
		SID:          fixture.target.String(),
		Connector:    "codex",
		AgentVersion: "0.130.0",
		Enabled:      &enabled,
		Deferred:     true,
	}
	if _, err := os.Lstat(filepath.Join(rootless.UserHome, ".defenseclaw")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rootless fixture unexpectedly has a data root: %v", err)
	}
	err := RequireWindowsEnterpriseDeferredTargetPending(rootless)
	if err == nil || !strings.Contains(err.Error(), "deferred target data directory is untrusted") {
		t.Fatalf("pending proof for an absent root = %v, want the untrusted data directory refusal", err)
	}
	if err := RequireWindowsEnterpriseTargetUnselected(rootless); err != nil {
		t.Fatalf("unselected proof rejected a rootless never-installed target: %v", err)
	}

	for _, tc := range []struct {
		name   string
		mutate func(*ManifestTarget)
	}{
		{"disabled", func(target *ManifestTarget) {
			disabled := false
			target.Enabled = &disabled
			target.Deferred = false
		}},
		{"unsupported_connector", func(target *ManifestTarget) { target.Connector = "openclaw" }},
		{"missing_home", func(target *ManifestTarget) {
			target.UserHome = filepath.Join(t.TempDir(), "absent")
		}},
	} {
		target := rootless
		tc.mutate(&target)
		if err := RequireWindowsEnterpriseTargetUnselected(target); err == nil {
			t.Errorf("%s: unselected proof accepted %+v", tc.name, target)
		}
	}

	selected := rootless
	selected.UserHome = filepath.Dir(fixture.options.DataDir)
	if err := RequireWindowsEnterpriseTargetUnselected(selected); err != nil {
		t.Fatalf("unselected proof before selection: %v", err)
	}
	selector := windowsManagedRuntimeSelector{
		SchemaVersion: windowsManagedRuntimeGenerationSchema,
		Connector:     fixture.options.Connector,
		Targets: []windowsManagedRuntimeSelectorTarget{{
			Connector:          fixture.options.Connector,
			SID:                fixture.options.TargetSID,
			DataDir:            fixture.options.DataDir,
			HookExecutable:     fixture.options.HookExecutable,
			GatewayAddr:        "127.0.0.1:18970",
			GatewayServiceName: "DefenseClawGateway",
			GenerationID:       strings.Repeat("a", 32),
			BundleSHA256:       "sha256:" + strings.Repeat("b", 64),
		}},
	}
	if err := publishWindowsManagedRuntimeSelector(selector); err != nil {
		t.Fatalf("publish selected target fixture: %v", err)
	}
	err = RequireWindowsEnterpriseTargetUnselected(selected)
	if err == nil || !strings.Contains(err.Error(), "already has a selected managed runtime") {
		t.Fatalf("unselected proof for a selected runtime = %v, want refusal", err)
	}
	// The selection is keyed by SID and connector, not by the data root.
	if err := RequireWindowsEnterpriseTargetUnselected(rootless); err == nil {
		t.Fatal("unselected proof accepted a selected SID because its home had no root")
	}
}
