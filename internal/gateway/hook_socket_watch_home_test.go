// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"testing"
)

// GAP-0066: a call on the managed hook socket carries the verified peer but
// no service-account mark (the socket server's base context), and both Claude
// Code answer paths still watch the caller's home and project, never the
// gateway service account's.
func TestHookSocketCallWatchesTheVerifiedPeerHome(t *testing.T) {
	callerHome := t.TempDir()
	serviceHome := t.TempDir()
	project := filepath.Join(callerHome, "work")
	t.Setenv("HOME", serviceHome)
	t.Setenv("USERPROFILE", serviceHome)
	t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(serviceHome, ".claude"))
	ctx := withManagedHookPeer(t.Context(), managedHookPeer{UID: 1001, Home: callerHome})

	evaluator := (claudeCodeHookRequest{HookEventName: "SessionStart", CWD: project}).withWatchHome(ctx)
	if !evaluator.managedWatch || evaluator.watchHome != callerHome {
		t.Fatalf("evaluator request managedWatch=%v watchHome=%q, want true %q", evaluator.managedWatch, evaluator.watchHome, callerHome)
	}
	paths := claudeCodeWatchPathsForRequest(evaluator, project)
	if containsString(paths, filepath.Join(serviceHome, ".claude", "settings.json")) {
		t.Fatalf("evaluator watch paths name the service account: %v", paths)
	}
	if !containsString(paths, filepath.Join(callerHome, ".claude", "settings.json")) {
		t.Fatalf("evaluator watch paths miss the caller: %v", paths)
	}

	unified := (agentHookRequest{ConnectorName: "claudecode", HookEventName: "SessionStart", ReportedCWD: project}).withManagedWatchHome(ctx)
	if !unified.managedWatch || unified.watchHome != callerHome || unified.managedWatchCWD() != project {
		t.Fatalf("unified request managedWatch=%v watchHome=%q cwd=%q", unified.managedWatch, unified.watchHome, unified.managedWatchCWD())
	}

	// A per-user gateway (no peer, no mark) keeps its own environment.
	own := (claudeCodeHookRequest{HookEventName: "SessionStart", CWD: project}).withWatchHome(t.Context())
	if own.managedWatch {
		t.Fatal("a per-user gateway request was treated as managed")
	}
}
