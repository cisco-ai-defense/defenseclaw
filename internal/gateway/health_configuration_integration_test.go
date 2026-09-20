// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks/guardianstate"
)

// TestConfigurationEndToEndDeferredFlow exercises the full spec 003
// state machine across daemon + guardian:
//
//  1. Deferred install, both files absent  →  waiting_for_config.
//  2. UCB writes config.yaml               →  waiting_for_targets.
//  3. UCB writes targets.yaml              →  ready.
//
// The test wires a real `<StateRoot>\hook-guardian\.state` file
// through guardianstate.PathForDataDir + ReadState, matching the
// production sidecar layout at internal/cli/sidecar.go. This is the
// integration counterpart to the unit-level collapsing tests in
// health_configuration_test.go — those pin the rule; this pins the
// actual filesystem-round-trip cross-process signalling.
func TestConfigurationEndToEndDeferredFlow(t *testing.T) {
	dataDir := t.TempDir()
	guardianDir := filepath.Join(dataDir, guardianstate.StateDirName)
	if err := os.MkdirAll(guardianDir, 0o755); err != nil {
		t.Fatalf("mkdir guardian dir: %v", err)
	}
	statePath := guardianstate.PathForDataDir(dataDir)

	h := NewSidecarHealth()
	// Simulate the sidecar bootstrap under managed_enterprise
	// (internal/cli/sidecar.go). At this point config has not yet
	// loaded — the daemon is still in the fsnotify wait loop.
	h.SetGuardianStateReader(func() string {
		return guardianstate.ReadState(statePath)
	})
	h.SetDaemonConfigLoaded(false)

	if got := h.Snapshot().Configuration.State; got != ConfigStateWaitingForConfig {
		t.Fatalf("stage 0 state = %q, want waiting_for_config", got)
	}

	// Stage 1 — UCB atomically drops config.yaml. The daemon's
	// wait loop wakes, retries loadGatewayConfigV8, and calls
	// SetDaemonConfigLoaded(true). The guardian has NOT run yet
	// (or is still waiting for its own manifest), so the state
	// file is absent — ReadState returns Unknown → the collapsing
	// rule's safe default is waiting_for_targets.
	h.SetDaemonConfigLoaded(true)
	snapAfterConfig := h.Snapshot()
	if got := snapAfterConfig.Configuration.State; got != ConfigStateWaitingForTargets {
		t.Fatalf("stage 1 state = %q, want waiting_for_targets", got)
	}
	sinceStage1 := snapAfterConfig.Configuration.Since

	// Stage 2 — UCB atomically drops targets.yaml. The guardian's
	// wait loop wakes, calls LoadManifest, and writes
	// .state=ready. The sidecar's periodic RefreshConfiguration
	// tick (or a Snapshot() call in real code) re-reads the file
	// and folds it into the collapsed state.
	//
	// Simulate that ~500ms after the config transition so the
	// Since field's monotonic advance can be observed distinctly
	// from the earlier transition.
	time.Sleep(5 * time.Millisecond)
	if err := guardianstate.WriteState(statePath, guardianstate.StateReady); err != nil {
		t.Fatalf("guardian write ready state: %v", err)
	}
	h.RefreshConfiguration()

	snapAfterTargets := h.Snapshot()
	if got := snapAfterTargets.Configuration.State; got != ConfigStateReady {
		t.Fatalf("stage 2 state = %q, want ready", got)
	}
	if !snapAfterTargets.Configuration.Since.After(sinceStage1) {
		t.Fatalf("Since must advance from stage 1 (%v) to stage 2 (%v)",
			sinceStage1, snapAfterTargets.Configuration.Since)
	}
}

// TestConfigurationEndToEndTargetsArriveFirst covers AC-12: if UCB
// drops targets.yaml BEFORE config.yaml, the daemon-side of the
// collapsing rule keeps the field at waiting_for_config until config
// lands, then transitions DIRECTLY to ready (skipping a spurious
// waiting_for_targets tick).
func TestConfigurationEndToEndTargetsArriveFirst(t *testing.T) {
	dataDir := t.TempDir()
	guardianDir := filepath.Join(dataDir, guardianstate.StateDirName)
	if err := os.MkdirAll(guardianDir, 0o755); err != nil {
		t.Fatalf("mkdir guardian dir: %v", err)
	}
	statePath := guardianstate.PathForDataDir(dataDir)

	// Guardian has already run (perhaps because it started faster
	// than the gateway) and wrote its ready state. Daemon has not
	// yet loaded config.
	if err := guardianstate.WriteState(statePath, guardianstate.StateReady); err != nil {
		t.Fatalf("write ready state: %v", err)
	}

	h := NewSidecarHealth()
	h.SetGuardianStateReader(func() string {
		return guardianstate.ReadState(statePath)
	})
	h.SetDaemonConfigLoaded(false)

	// Despite guardian being ready, the daemon-side gate stays at
	// waiting_for_config — the entire deployment is not ready until
	// the gateway itself has loaded its config.
	if got := h.Snapshot().Configuration.State; got != ConfigStateWaitingForConfig {
		t.Fatalf("pre-load state = %q, want waiting_for_config", got)
	}

	// Config arrives. The state jumps directly to ready.
	h.SetDaemonConfigLoaded(true)
	if got := h.Snapshot().Configuration.State; got != ConfigStateReady {
		t.Fatalf("post-load state = %q, want ready (guardian was already ready)", got)
	}
}

// TestConfigurationEndToEndGuardianCrashesMidBoot exercises the
// safe-default rule: if the guardian crashed mid-wait (say, its
// process died before it could write .state), the sidecar's poll
// reads a nonexistent file and returns Unknown. The collapsing rule
// treats that as waiting_for_targets — the sidecar must NEVER
// publish a false "ready" just because the guardian's evidence is
// missing.
func TestConfigurationEndToEndGuardianCrashesMidBoot(t *testing.T) {
	dataDir := t.TempDir()
	statePath := guardianstate.PathForDataDir(dataDir)
	// Do NOT create the state file — this simulates the guardian
	// having crashed before writing its first state transition.

	h := NewSidecarHealth()
	h.SetGuardianStateReader(func() string {
		return guardianstate.ReadState(statePath)
	})
	h.SetDaemonConfigLoaded(true)

	if got := h.Snapshot().Configuration.State; got != ConfigStateWaitingForTargets {
		t.Fatalf("guardian-crashed state = %q, want waiting_for_targets (safe default)", got)
	}
}
