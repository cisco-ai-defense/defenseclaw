// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"path/filepath"
	"slices"
	"testing"
)

// GAP-0066: the unified-pipeline Claude Code answer of a managed gateway
// names the verified caller's watch paths, never the gateway service
// account's; an unresolved caller keeps only its project entries. A
// per-user gateway keeps its own environment.
func TestClaudeCodeProfileWatchPathsFollowTheVerifiedCaller(t *testing.T) {
	callerHome := t.TempDir()
	serviceHome := t.TempDir()
	project := filepath.Join(callerHome, "work")
	t.Setenv("HOME", serviceHome)
	t.Setenv("USERPROFILE", serviceHome)
	t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(serviceHome, ".claude"))
	callerSettings := filepath.Join(callerHome, ".claude", "settings.json")
	serviceSettings := filepath.Join(serviceHome, ".claude", "settings.json")
	projectMCP := filepath.Join(project, ".mcp.json")
	for _, event := range []string{"SessionStart", "CwdChanged", "FileChanged"} {
		for _, tc := range []struct {
			name                      string
			managed                   bool
			home                      string
			wantCaller, wantService   bool
			wantProject, wantNonEmpty bool
		}{
			{"managed known caller", true, callerHome, true, false, true, true},
			{"managed unresolved caller", true, "", false, false, true, true},
			{"per-user gateway", false, "", false, true, true, true},
		} {
			t.Run(event+"/"+tc.name, func(t *testing.T) {
				req := HookProfileRequest{HookEventName: event, CWD: project, ManagedWatch: tc.managed, WatchHome: tc.home}
				if tc.managed && tc.home != "" {
					// The gateway resolves no CWD in another user's home; the
					// caller project comes in WatchCWD.
					req.CWD, req.WatchCWD = "", project
				}
				out := claudeCodeOutputForProfile(req, "allow", "allow", "", "")
				if event == "SessionStart" {
					out = out["hookSpecificOutput"].(map[string]interface{})
				}
				paths, ok := out["watchPaths"].([]string)
				if !ok || paths == nil {
					t.Fatalf("watchPaths = %#v, want a list", out["watchPaths"])
				}
				if got := slices.Contains(paths, callerSettings); got != tc.wantCaller {
					t.Fatalf("caller settings present=%v, want %v: %v", got, tc.wantCaller, paths)
				}
				if got := slices.Contains(paths, serviceSettings); got != tc.wantService {
					t.Fatalf("service settings present=%v, want %v: %v", got, tc.wantService, paths)
				}
				if got := slices.Contains(paths, projectMCP); got != tc.wantProject {
					t.Fatalf("project .mcp.json present=%v, want %v: %v", got, tc.wantProject, paths)
				}
				if (len(paths) > 0) != tc.wantNonEmpty {
					t.Fatalf("watchPaths = %v, want non-empty=%v", paths, tc.wantNonEmpty)
				}
			})
		}
	}
}
