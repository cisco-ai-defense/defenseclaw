//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks/guardianstate"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestConfigurationWindowsInstalledGuardianLayout(t *testing.T) {
	stateRoot := t.TempDir()
	runtimeDir := filepath.Join(stateRoot, "runtime")
	guardianDir := filepath.Join(stateRoot, guardianstate.StateDirName)
	authorizationDir := filepath.Join(stateRoot, "hook-guardian-state")
	wrongGuardianDir := filepath.Join(runtimeDir, guardianstate.StateDirName)
	for _, dir := range []string{runtimeDir, guardianDir, authorizationDir, wrongGuardianDir} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv(managed.WindowsServiceAccountEnv, `NT SERVICE\DefenseClawCertGateway_ReadinessFixture`)
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, authorizationDir)
	// A runtime-owned ready file must never override the guardian's signal.
	if err := guardianstate.WriteState(guardianstate.PathForStateRoot(wrongGuardianDir), guardianstate.StateReady); err != nil {
		t.Fatal(err)
	}
	statePath := guardianstate.PathForDataDir(runtimeDir)
	h := NewSidecarHealth()
	h.SetGuardianStateReader(func() string { return guardianstate.ReadState(statePath) })
	h.SetDaemonConfigLoaded(true)
	if got := h.Snapshot().Configuration.State; got != ConfigStateWaitingForTargets {
		t.Fatalf("missing installed guardian state = %q", got)
	}
	actualStatePath := guardianstate.PathForStateRoot(guardianDir)
	for _, tc := range []struct {
		signal string
		want   ConfigurationState
	}{
		{guardianstate.StateWaitingForTargets, ConfigStateWaitingForTargets},
		{guardianstate.StateReady, ConfigStateReady},
		{guardianstate.StateWaitingForTargets, ConfigStateWaitingForTargets},
	} {
		if err := guardianstate.WriteState(actualStatePath, tc.signal); err != nil {
			t.Fatal(err)
		}
		h.RefreshConfiguration()
		if got := h.Snapshot().Configuration.State; got != tc.want {
			t.Fatalf("guardian signal %q: health = %q, want %q", tc.signal, got, tc.want)
		}
	}
}
