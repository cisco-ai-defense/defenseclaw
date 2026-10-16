// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func TestCopilotIgnoresClaudeUserHooksOutsideTheHome(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		t.Run(goos, func(t *testing.T) {
			req := guardRequest(t, ConnectorCopilot, config.ForeignHooksRemove)
			req.GOOS = goos
			req.WorkingDir = t.TempDir()
			settings := filepath.Join(req.Home, ".claude", "settings.json")
			original := `{"hooks":{"PostToolUse":[{"matcher":"Edit","hooks":[{"type":"command","command":"prettier --write"}]}]}}`
			writeFile(t, settings, original)
			if decision := EvaluateForeignHooks(req); decision.Deny || len(decision.Findings) != 0 {
				t.Fatalf("Copilot CLI loads no Claude Code user hooks: %+v", decision)
			}
			result, err := CleanUserForeignHooks(req, time.Now())
			if err != nil || len(result.Removed) != 0 || result.BackupDir != "" {
				t.Fatalf("Copilot cleanup changed Claude Code settings: %+v, %v", result, err)
			}
			if data, err := os.ReadFile(settings); err != nil || string(data) != original {
				t.Fatalf("Claude Code settings changed: %q, %v", data, err)
			}
		})
	}
}

func TestCopilotVSCodeClaudeUserSourceStaysReportOnly(t *testing.T) {
	req := guardRequest(t, ConnectorCopilot, config.ForeignHooksRemove)
	req.WorkingDir = t.TempDir()
	req.HookSurface = connector.CopilotHookSurfaceVSCodeLocal
	settings := filepath.Join(req.Home, ".claude", "settings.json")
	for _, source := range guardSources(req) {
		if samePath(source.path, settings) {
			if source.scope != ScopeUser || !source.reportOnly {
				t.Fatalf("VS Code Local Claude settings source = %+v", source)
			}
			return
		}
	}
	t.Fatal("VS Code Local Claude settings source missing")
}

func TestCopilotIgnoresDefenseClawClaudeUserRegistration(t *testing.T) {
	req := guardRequest(t, ConnectorCopilot, config.ForeignHooksRemove)
	req.WorkingDir = t.TempDir()
	command := connector.PerUserOwnedHookCommands("claudecode", filepath.Join(req.Home, ".defenseclaw"))[0]
	req.OwnedCommands = connector.PerUserOwnedHookCommands("copilot", filepath.Join(req.Home, ".defenseclaw"))
	writeFile(t, filepath.Join(req.Home, ".claude", "settings.json"),
		`{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"`+strings.ReplaceAll(command, `"`, `\"`)+`"}]}]}}`)
	for _, route := range []string{RouteMachinePolicy, RoutePerUser} {
		req.Policy.Route = route
		if decision := EvaluateForeignHooks(req); decision.Deny || len(decision.Findings) != 0 {
			t.Fatalf("Copilot route %s treated Claude Code registration as foreign: %+v", route, decision)
		}
	}
}

func TestCopilotProjectWalkCanReachClaudeSettingsInHome(t *testing.T) {
	req := guardRequest(t, ConnectorCopilot, config.ForeignHooksRemove)
	req.WorkingDir = filepath.Join(req.Home, "work without git", "project")
	if err := os.MkdirAll(req.WorkingDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(req.Home, ".claude", "settings.json"), foreignClaudeSettings)
	decision := EvaluateForeignHooks(req)
	if !decision.Deny || len(decision.Findings) != 1 || decision.Findings[0].Scope != ScopeProject {
		t.Fatalf("home reached by project walk must be a project source: %+v", decision)
	}
	result, err := CleanUserForeignHooks(req, time.Now())
	if err != nil || len(result.Removed) != 0 || result.BackupDir != "" {
		t.Fatalf("project source was rewritten: %+v, %v", result, err)
	}
}
