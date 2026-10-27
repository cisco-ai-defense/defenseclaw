// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0066: the managed (service-account) unified-pipeline Claude Code
// answer (agentHookResponseForProfile -> profile.Respond) watches the
// verified caller's home and project, not the service account's home.
func TestManagedProfileAnswerWatchesTheVerifiedCallerHome(t *testing.T) {
	callerHome := t.TempDir()
	serviceHome := t.TempDir()
	project := filepath.Join(callerHome, "work")
	t.Setenv("HOME", serviceHome)
	t.Setenv("USERPROFILE", serviceHome)
	t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(serviceHome, ".claude"))
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	api := &APIServer{scannerCfg: cfg}
	profile := api.hookProfileForConnector("claudecode")
	if profile.Respond == nil {
		t.Fatal("claudecode profile has no Respond")
	}
	for _, tc := range []struct {
		name       string
		home       string
		cwd        string
		wantCaller bool
	}{
		{"known caller", callerHome, project, true},
		{"unresolved caller", "", project, false},
		// The service account cannot resolve a directory in the caller's
		// home, so hookCWDForContext leaves CWD empty on Linux and macOS.
		{"known caller, project the service cannot resolve", callerHome, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := withManagedHookPeer(withServiceAccountGateway(t.Context()), managedHookPeer{UID: 1001, Home: tc.home})
			req := (agentHookRequest{ConnectorName: "claudecode", HookEventName: "SessionStart", CWD: tc.cwd, ReportedCWD: project}).withManagedWatchHome(ctx)
			resp := agentHookResponseForProfile(profile, req, "allow", "allow", "NONE", "", nil, "action", false, profile.Capabilities)
			specific, _ := resp.HookOutput["hookSpecificOutput"].(map[string]interface{})
			paths, ok := specific["watchPaths"].([]string)
			if !ok {
				t.Fatalf("SessionStart answer has no watchPaths list: %#v", resp.HookOutput)
			}
			if containsString(paths, filepath.Join(serviceHome, ".claude", "settings.json")) {
				t.Fatalf("service account watch path leaked: %v", paths)
			}
			if got := containsString(paths, filepath.Join(callerHome, ".claude", "settings.json")); got != tc.wantCaller {
				t.Fatalf("caller watch path present=%v, want %v: %v", got, tc.wantCaller, paths)
			}
			if wantProject := tc.cwd != "" || tc.wantCaller; containsString(paths, filepath.Join(project, ".mcp.json")) != wantProject {
				t.Fatalf("caller project watch path present=%v, want %v: %v", !wantProject, wantProject, paths)
			}
		})
	}
}
