// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"fmt"
	"strings"
	"testing"
)

// GAP-2058: a pending change held by a sandbox that does not run (a sandbox
// in OpenShell's error state, or one the earlier sandbox setup left, which
// OpenShell does not report stopped) was reported as "1 sandbox runs" while
// the user's own status said Running 0 of 1. The change still waits for it
// (a stop of the gateway could end such a VM unflushed), but ensure, status
// and verify now say that no sandbox runs, which one holds the change, and
// how the user releases it. A sandbox that runs keeps the old wording.
func TestGAP2058PendingHeldByAStoppedSandboxSaysNoSandboxRuns(t *testing.T) {
	h := newOSHost(t, "linux")
	cfg := sandboxConfig(t, "linux", true, map[string]any{"install": "prerequisite", "driver": "docker"})
	requireOK(t, h.ensure(cfg))
	allowed := sandboxConfigWithTelemetry(t, "linux")

	// Nothing runs, but one sandbox holds compute OpenShell does not report stopped.
	h.ops.status[h.alice.UID] = SandboxStatus{Active: true, Running: 0, Live: 1}
	r := h.ensure(allowed)
	requireOK(t, r)
	if len(h.ops.stopped()) != 0 {
		t.Fatalf("a daemon held by a live sandbox was stopped: %v", h.ops.stopped())
	}
	state := h.env.loadOpenShellState()
	entry, ok := state.Pending[fmt.Sprint(h.alice.UID)]
	if !ok || entry.Sandboxes != 1 || entry.Running == nil || *entry.Running != 0 {
		t.Fatalf("pending = %+v", state.Pending)
	}
	warning := messagesOf(r.Warnings, codeSandboxPending)
	if strings.Contains(warning, "1 sandbox runs") || !strings.Contains(warning, "no sandbox runs") ||
		!strings.Contains(warning, "defenseclaw sandbox list") || !strings.Contains(warning, "defenseclaw sandbox delete NAME") {
		t.Fatalf("ensure warning for a change held by a stopped sandbox: %q", warning)
	}
	for _, action := range []string{ActionStatus, ActionVerify} {
		got := h.run(Options{Action: action})
		st, _ := rowState(got, "sandbox pending alice")
		if strings.Contains(st, "1 sandbox ran when") || !strings.Contains(st, "no sandbox ran") {
			t.Errorf("%s pending row = %q", action, st)
		}
	}

	// A sandbox that runs keeps the running wording.
	h.ops.status[h.alice.UID] = SandboxStatus{Active: true, Running: 1, Live: 1}
	r = h.ensure(allowed)
	requireOK(t, r)
	if warning := messagesOf(r.Warnings, codeSandboxPending); !strings.Contains(warning, "1 sandbox runs (or is starting") {
		t.Fatalf("running sandbox wording changed: %q", warning)
	}

	// The holding sandbox is deleted: the next ensure applies the change.
	h.ops.status[h.alice.UID] = SandboxStatus{Active: true}
	r = h.ensure(allowed)
	requireOK(t, r)
	if len(h.env.loadOpenShellState().Pending) != 0 || hasWarning(r, codeSandboxPending) {
		t.Errorf("the pending change was not cleared: %+v", h.env.loadOpenShellState().Pending)
	}
}
