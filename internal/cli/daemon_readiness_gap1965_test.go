// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway"
)

// GAP-1965: a watcher that runs with some connector roots unwatched (an
// OpenCode plugin folder this account cannot open) reports Degraded, and the
// start waited for Running until its readiness deadline: `defenseclaw setup
// opencode` hung for minutes instead of naming the folder. Degraded is a
// running watcher; status and doctor name each unwatched root.
func TestGAP1965GatewaySnapshotReadyAcceptsADegradedWatcher(t *testing.T) {
	snap := readinessSnapshot(gateway.StateRunning, gateway.StateDisabled)
	snap.Watcher = gateway.SubsystemHealth{
		State:     gateway.StateDegraded,
		LastError: "admission scanning is off for one or more connector roots; the gateway log names each root",
	}
	requirements := daemonReadinessRequirements{guardrailEnabled: true, watcherEnabled: true}
	if ready, err := gatewaySnapshotReady(snap, requirements); err != nil || !ready {
		t.Fatalf("degraded watcher readiness = %v, error = %v; want ready", ready, err)
	}
	for _, state := range []gateway.SubsystemState{gateway.StateStarting, gateway.StateDisabled} {
		snap.Watcher = gateway.SubsystemHealth{State: state}
		if ready, err := gatewaySnapshotReady(snap, requirements); ready || err != nil {
			t.Fatalf("enabled watcher %s readiness = %v, error = %v; want not ready yet", state, ready, err)
		}
	}
	snap.Watcher = gateway.SubsystemHealth{State: gateway.StateDegraded}
	if ready, err := gatewaySnapshotReady(snap, daemonReadinessRequirements{guardrailEnabled: true}); ready || err != nil {
		t.Fatalf("disabled-by-config watcher reporting degraded readiness = %v, error = %v; want not ready", ready, err)
	}
}
