// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestGAP0458ManagedWindowsOverflowSelection(t *testing.T) {
	cfg := &config.Config{DeploymentMode: "managed_enterprise"}
	cfg.Enterprise.Profile = "standalone"
	ctx := withAuthenticatedHookConnector(context.Background(), "codex")
	if !managedWindowsHookOverflowHold(ctx, cfg, "codex", "windows") {
		t.Fatal("authenticated managed Windows hook did not select the hold")
	}
	for _, tc := range []struct {
		name      string
		ctx       context.Context
		cfg       *config.Config
		os        string
		connector string
	}{
		{"per-user", ctx, &config.Config{}, "windows", "codex"},
		{"unauthenticated", context.Background(), cfg, "windows", "codex"},
		{"other connector", ctx, cfg, "windows", "claudecode"},
		{"non-Windows", ctx, cfg, "darwin", "codex"},
	} {
		if managedWindowsHookOverflowHold(tc.ctx, tc.cfg, tc.connector, tc.os) {
			t.Errorf("%s selected the managed Windows hold", tc.name)
		}
	}
	cfg.Enterprise.Profile = "secure_client"
	if managedWindowsHookOverflowHold(ctx, cfg, "codex", "windows") {
		t.Fatal("Secure Client selected the hold")
	}
}

func TestGAP0458ManagedOverflowHoldAndReadTwin(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	steps := make([]string, 200)
	for i := range steps {
		steps[i] = fmt.Sprintf("Write-Host 'step %d'", i)
	}
	pad := strings.Join(steps, "\n")
	for _, tc := range []struct {
		name, command string
		want          bool
	}{
		{"alias", pad + "\nSet-Alias gc Set-Content -Force; gc -Path ~/.defenseclaw/config.yaml -Value x", true},
		{"read", pad + "\nGet-Content ~/.defenseclaw/config.yaml", false},
		{"printed path", pad + "\nWrite-Output $(Get-Date) '~/.defenseclaw/config.yaml'", false},
		{"printed literal", pad + "\nWrite-Output $('ok') '~/.defenseclaw/config.yaml'", false},
		{"nested write", pad + "\nWrite-Output $(Set-Content ~/.defenseclaw/config.yaml x)", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := actionfacts.Input{Tool: "PowerShell", Command: tc.command, CWD: cwd, ActiveHome: home,
				DialectHint: actionfacts.DialectPowerShell}
			findings := withReducedStateReading(t.Context(), trustedActionRequest{
				Input: input, Connector: "codex", EnforcementCapable: true, ManagedHookOverflowHold: true,
			}, actionfacts.Analyze(input), nil)
			if got := findingWithID(findings, "tamper.detector_state_write") != nil; got != tc.want {
				t.Fatalf("state hold = %t, want %t", got, tc.want)
			}
		})
	}
}
