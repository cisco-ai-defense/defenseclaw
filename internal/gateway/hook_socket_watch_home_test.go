// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
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

// GAP-0066 live shape (managed RHEL, real Claude Code SessionStart on the
// hook socket): the caller's project is in its own home, which the gateway
// service account cannot resolve, so the evaluator's CWD is empty. Its
// answer still watches the caller's project, never the service account's.
func TestHookSocketEvaluatorWatchesTheUnresolvableCallerProject(t *testing.T) {
	callerHome := t.TempDir()
	serviceHome := t.TempDir()
	project := filepath.Join(callerHome, "not-resolvable", "work") // does not exist: sanitizeHookCWD returns ""
	t.Setenv("HOME", serviceHome)
	t.Setenv("USERPROFILE", serviceHome)
	t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(serviceHome, ".claude"))
	ctx := withManagedHookPeer(t.Context(), managedHookPeer{UID: 1001, Home: callerHome})
	for _, tc := range []struct {
		name  string
		event string
		body  string
		root  string
	}{
		{"session start", "SessionStart", `{"hook_event_name":"SessionStart","cwd":` + strconv.Quote(project) + `}`, project},
		{"cwd changed", "CwdChanged", `{"hook_event_name":"CwdChanged","cwd":` + strconv.Quote(callerHome) + `,"new_cwd":` + strconv.Quote(project) + `}`, project},
		{"outside the caller home", "SessionStart", `{"hook_event_name":"SessionStart","cwd":` + strconv.Quote(filepath.Join(serviceHome, "x")) + `}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var payload map[string]interface{}
			if err := json.Unmarshal([]byte(tc.body), &payload); err != nil {
				t.Fatal(err)
			}
			req := decodeClaudeCodeRequestForContext(ctx, []byte(tc.body), payload)
			out := claudeCodeOutput(req, "allow", "allow", "", "")
			var paths []string
			if specific, ok := out["hookSpecificOutput"].(map[string]interface{}); ok {
				paths, _ = specific["watchPaths"].([]string)
			} else {
				paths, _ = out["watchPaths"].([]string)
			}
			if containsString(paths, filepath.Join(serviceHome, ".claude", "settings.json")) {
				t.Fatalf("service account watch path leaked: %v", paths)
			}
			if !containsString(paths, filepath.Join(callerHome, ".claude", "settings.json")) {
				t.Fatalf("caller home watch path missing: %v", paths)
			}
			if tc.root == "" {
				for _, p := range paths {
					if strings.HasPrefix(p, serviceHome) {
						t.Fatalf("a path outside the caller home was watched: %v", paths)
					}
				}
				return
			}
			if !containsString(paths, filepath.Join(tc.root, ".mcp.json")) {
				t.Fatalf("caller project watch path missing: %v", paths)
			}
		})
	}
}
