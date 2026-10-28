//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

func TestGuardianWorkerLeavesCopilotClaudeUserHookUntouched(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	original := `{"theme":"dark","hooks":{"PostToolUse":[{"hooks":[{"type":"command","command":"prettier --write"}]}]}}`
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	reports := runEnterpriseHookWorkerForeignCleanup(enterpriseHookWorkerRequest{
		Home: home,
		ForeignCleanup: []enterpriseHookWorkerForeignCleanup{{
			Connector: "copilot", HookBinary: "/opt/defenseclaw/bin/defenseclaw-hook",
			Policy: enterprisepolicy.PublicConnectorPolicy{
				Route: enterprisepolicy.RouteMachinePolicy, ForeignHooks: config.ForeignHooksRemove, Guard: true,
			},
		}},
	}, time.Date(2026, 10, 13, 20, 0, 0, 0, time.UTC), nil)
	report := reports["copilot"]
	if report.Error != "" || len(report.Removed) != 0 || report.BackupDir != "" {
		t.Fatalf("worker changed Claude Code settings: %+v", report)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != original {
		t.Fatalf("Claude Code settings changed: %q, %v", data, err)
	}
}
