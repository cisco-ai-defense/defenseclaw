// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks/guardianstate"
)

// TestConfigurationSnapshotDefaultOmitted asserts a health snapshot
// from a SidecarHealth on which SetDaemonConfigLoaded was NEVER called
// omits the top-level "configuration" block entirely — the deployment
// is OSS / SaaS / DP / CP, spec 003 doesn't apply, and downstream
// consumers must NOT be given a spurious field to reason about.
func TestConfigurationSnapshotDefaultOmitted(t *testing.T) {
	h := NewSidecarHealth()
	snap := h.Snapshot()
	if snap.Configuration != nil {
		t.Fatalf("Configuration pointer must be nil for a deployment that never called SetDaemonConfigLoaded; got %+v", *snap.Configuration)
	}
}

// TestConfigurationCollapseWaitingForConfig — daemon has not yet
// loaded config, guardian state is irrelevant. Snapshot must report
// waiting_for_config.
func TestConfigurationCollapseWaitingForConfig(t *testing.T) {
	h := NewSidecarHealth()
	h.SetDaemonConfigLoaded(false)
	// Guardian says "ready", which must be ignored.
	h.SetGuardianStateReader(func() string { return guardianstate.StateReady })

	snap := h.Snapshot()
	if snap.Configuration == nil {
		t.Fatalf("Configuration should be non-nil after SetDaemonConfigLoaded")
	}
	if got := snap.Configuration.State; got != ConfigStateWaitingForConfig {
		t.Fatalf("state = %q, want %q", got, ConfigStateWaitingForConfig)
	}
}

// TestConfigurationCollapseWaitingForTargetsDefault — daemon loaded,
// no guardian reader wired. Safe default is waiting_for_targets.
func TestConfigurationCollapseWaitingForTargetsDefault(t *testing.T) {
	h := NewSidecarHealth()
	h.SetDaemonConfigLoaded(true)
	// No guardian reader — the sidecar must still refuse to publish "ready".

	snap := h.Snapshot()
	if snap.Configuration == nil {
		t.Fatalf("Configuration should be non-nil after SetDaemonConfigLoaded")
	}
	if got := snap.Configuration.State; got != ConfigStateWaitingForTargets {
		t.Fatalf("state = %q, want %q (safe default)", got, ConfigStateWaitingForTargets)
	}
}

// TestConfigurationCollapseReady — daemon loaded + guardian ready ⇒ ready.
func TestConfigurationCollapseReady(t *testing.T) {
	h := NewSidecarHealth()
	h.SetDaemonConfigLoaded(true)
	h.SetGuardianStateReader(func() string { return guardianstate.StateReady })

	snap := h.Snapshot()
	if got := snap.Configuration.State; got != ConfigStateReady {
		t.Fatalf("state = %q, want %q", got, ConfigStateReady)
	}
}

// TestConfigurationCollapseGuardianUnknownIsSafeDefault — spec 003
// design.md § Tradeoffs safe-default rule: an unreachable state file
// must never surface as ready.
func TestConfigurationCollapseGuardianUnknownIsSafeDefault(t *testing.T) {
	h := NewSidecarHealth()
	h.SetDaemonConfigLoaded(true)
	h.SetGuardianStateReader(func() string { return guardianstate.StateUnknown })

	snap := h.Snapshot()
	if got := snap.Configuration.State; got != ConfigStateWaitingForTargets {
		t.Fatalf("guardian Unknown must collapse to waiting_for_targets, got %q", got)
	}
}

// TestConfigurationSkipsWaitingForTargetsWhenTargetsArriveFirst —
// spec 003 AC-12: if the guardian is already Ready by the time the
// daemon completes config load, the state jumps directly from
// waiting_for_config to ready without a spurious waiting_for_targets
// tick. The `since` timestamp must also update on the transition.
func TestConfigurationSkipsWaitingForTargetsWhenTargetsArriveFirst(t *testing.T) {
	h := NewSidecarHealth()
	h.SetDaemonConfigLoaded(false)
	h.SetGuardianStateReader(func() string { return guardianstate.StateReady })

	// Sanity: still waiting_for_config despite guardian being ready.
	if got := h.Snapshot().Configuration.State; got != ConfigStateWaitingForConfig {
		t.Fatalf("pre-load state = %q, want waiting_for_config", got)
	}
	sinceBefore := h.Snapshot().Configuration.Since

	// Flip daemon to loaded; snapshot must jump directly to ready.
	time.Sleep(5 * time.Millisecond)
	h.SetDaemonConfigLoaded(true)
	snap := h.Snapshot()
	if got := snap.Configuration.State; got != ConfigStateReady {
		t.Fatalf("post-load state = %q, want ready (no intermediate waiting_for_targets)", got)
	}
	if !snap.Configuration.Since.After(sinceBefore) {
		t.Fatalf("Since must advance on state transition; before=%v after=%v", sinceBefore, snap.Configuration.Since)
	}
}

// TestConfigurationSinceStableWhileStateUnchanged — spec 003 AC-08.
// Repeated snapshots taken while the daemon sits in
// waiting_for_config MUST return the same Since; only a state
// transition advances it.
func TestConfigurationSinceStableWhileStateUnchanged(t *testing.T) {
	h := NewSidecarHealth()
	h.SetDaemonConfigLoaded(false)

	snap1 := h.Snapshot()
	time.Sleep(15 * time.Millisecond)
	snap2 := h.Snapshot()

	if snap1.Configuration.Since != snap2.Configuration.Since {
		t.Fatalf("Since drifted between snapshots without a state transition: %v vs %v",
			snap1.Configuration.Since, snap2.Configuration.Since)
	}
	if snap1.Configuration.State != snap2.Configuration.State {
		t.Fatalf("state drifted between snapshots without a state transition: %v vs %v",
			snap1.Configuration.State, snap2.Configuration.State)
	}
}

// TestConfigurationRefreshPicksUpGuardianTransition — a guardian-side
// transition (waiting_for_targets → ready) that lands between two
// snapshots must be reflected the moment RefreshConfiguration runs,
// even without any daemon-side call.
func TestConfigurationRefreshPicksUpGuardianTransition(t *testing.T) {
	h := NewSidecarHealth()
	h.SetDaemonConfigLoaded(true)

	current := guardianstate.StateWaitingForTargets
	h.SetGuardianStateReader(func() string { return current })

	if got := h.Snapshot().Configuration.State; got != ConfigStateWaitingForTargets {
		t.Fatalf("initial state = %q, want waiting_for_targets", got)
	}

	// Guardian transitions out-of-band. Sidecar hasn't observed it yet.
	current = guardianstate.StateReady
	// Refresh consults the reader and updates the collapsed state.
	h.RefreshConfiguration()

	if got := h.Snapshot().Configuration.State; got != ConfigStateReady {
		t.Fatalf("after refresh state = %q, want ready", got)
	}
}
