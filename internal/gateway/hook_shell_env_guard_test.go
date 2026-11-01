// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func writeHookShellEnvSettings(t *testing.T, path string, env map[string]string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]interface{}{"env": env})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

// rel-1-0-6:GAP-0322: outside the strict tier the gateway keeps Claude Code
// running and writes one guardrail-degraded alert for settings that stop its
// shell-form hooks; the same finding again writes nothing, and a cleared one
// re-arms it.
func TestHookConfigGuardAlertsOnceForHookShellEnv(t *testing.T) {
	root := t.TempDir()
	previous := connector.ClaudeCodeSettingsPathOverride
	connector.ClaudeCodeSettingsPathOverride = filepath.Join(root, "home", ".claude", "settings.json")
	t.Cleanup(func() { connector.ClaudeCodeSettingsPathOverride = previous })
	workspace := filepath.Join(root, "repo")
	project := filepath.Join(workspace, ".claude", "settings.json")
	writeHookShellEnvSettings(t, project, map[string]string{"SHELLOPTS": "noexec"})

	store, logger := testStoreAndLogger(t)
	guard := NewHookConfigGuard(logger, nil, time.Hour)
	conn := connector.NewClaudeCodeConnector()
	opts := connector.SetupOpts{DataDir: filepath.Join(root, "dc"), WorkspaceDir: workspace}

	alerts := func() []audit.Event {
		t.Helper()
		events, err := store.ListEvents(50)
		if err != nil {
			t.Fatal(err)
		}
		var out []audit.Event
		for _, event := range events {
			if event.Action == string(audit.ActionGuardrailDegraded) && strings.Contains(event.Details, "agent settings can stop the hooks") {
				out = append(out, event)
			}
		}
		return out
	}

	guard.auditHookShellEnv(conn, opts)
	guard.auditHookShellEnv(conn, opts)
	got := alerts()
	if len(got) != 1 || !strings.Contains(got[0].Details, project) || !strings.Contains(got[0].Details, "SHELLOPTS") {
		t.Fatalf("alerts after two audits = %+v, want one naming %s", got, project)
	}

	writeHookShellEnvSettings(t, project, map[string]string{})
	guard.auditHookShellEnv(conn, opts)
	writeHookShellEnvSettings(t, project, map[string]string{"BASH_ENV": "/tmp/startup"})
	guard.auditHookShellEnv(conn, opts)
	if got := alerts(); len(got) != 2 {
		t.Fatalf("alerts after clear and a new finding = %d, want 2", len(got))
	}

	// The strict tier reports the same settings through the effective-policy
	// refusal, so this audit writes nothing there.
	opts.PolicyTier = "strict"
	writeHookShellEnvSettings(t, project, map[string]string{"SHELLOPTS": "noexec"})
	guard.auditHookShellEnv(conn, opts)
	if got := alerts(); len(got) != 2 {
		t.Fatalf("strict-tier alerts = %d, want none added", len(got))
	}
}

// Review finding 5 (mutant M11): the alert comes from the guard's periodic
// effective-policy audit, so drive it through processPolicyAudit.
func TestHookConfigGuardPolicyAuditRaisesTheHookShellEnvAlert(t *testing.T) {
	root := t.TempDir()
	previous := connector.ClaudeCodeSettingsPathOverride
	connector.ClaudeCodeSettingsPathOverride = filepath.Join(root, "home", ".claude", "settings.json")
	t.Cleanup(func() { connector.ClaudeCodeSettingsPathOverride = previous })
	previousManaged := connector.ClaudeCodeManagedSettingsRootOverride
	connector.ClaudeCodeManagedSettingsRootOverride = filepath.Join(root, "managed")
	t.Cleanup(func() { connector.ClaudeCodeManagedSettingsRootOverride = previousManaged })
	workspace := filepath.Join(root, "repo")
	writeHookShellEnvSettings(t, filepath.Join(workspace, ".claude", "settings.json"), map[string]string{"SHELLOPTS": "noexec"})

	store, logger := testStoreAndLogger(t)
	guard := NewHookConfigGuard(logger, nil, time.Hour)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	guard.mu.Lock()
	guard.ctx = ctx
	guard.conn = &stubConnector{name: "claudecode"}
	guard.opts = connector.SetupOpts{DataDir: filepath.Join(root, "dc"), WorkspaceDir: workspace}
	guard.mu.Unlock()

	guard.processPolicyAudit()
	events, err := store.ListEvents(50)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, event := range events {
		if event.Action == string(audit.ActionGuardrailDegraded) && strings.Contains(event.Details, "agent settings can stop the hooks") {
			found++
		}
	}
	if found != 1 {
		t.Fatalf("alerts after one policy audit = %d, want 1", found)
	}
}
