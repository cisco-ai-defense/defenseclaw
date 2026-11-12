// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"errors"
	"os"
	"testing"
)

// A rollback must not chmod or chown a snapshotted directory whose mode and
// owner are unchanged. On macOS 27 /usr/local is SIP-protected: root gets
// EPERM from even a no-op chmod/lchown there, and the plan lists it since the
// launcher's shared parents are recorded (GAP-0091), so a failed ensure ended
// rollback_failed with the transaction pending.
func TestRollbackLeavesAnUnchangedSharedParentAlone(t *testing.T) {
	h := newTestHost(t, "darwin")
	shared := "/usr/local"
	if err := os.MkdirAll(h.env.P(shared), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(h.env.P(shared), 0o755); err != nil {
		t.Fatal(err)
	}
	snap, err := h.env.takeSnapshot("shared-parent", nil, []string{shared})
	if err != nil {
		t.Fatal(err)
	}
	protected := errors.New("operation not permitted")
	lchowned := false
	h.env.Lchown = func(string, int, int) error { lchowned = true; return protected }
	if err := h.env.restore(snap); err != nil {
		t.Fatalf("restore touched an unchanged shared parent: %v", err)
	}
	if lchowned {
		t.Fatal("restore chowned a directory whose owner did not change")
	}
	// A directory the transaction did change still goes back.
	if err := os.Chmod(h.env.P(shared), 0o700); err != nil {
		t.Fatal(err)
	}
	h.env.Lchown = func(string, int, int) error { return nil }
	if err := h.env.restore(snap); err != nil {
		t.Fatal(err)
	}
	if got := h.mode(shared).Perm(); got != 0o755 {
		t.Fatalf("restored mode %o, want 755", got)
	}
}
