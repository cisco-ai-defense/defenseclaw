//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestManagedWindowsOpenCodeStatusNamesAccountAndHeldPort(t *testing.T) {
	oldRead, oldConnectors := windowsOpenCodePortWarningRead, windowsOpenCodePortConnectorList
	t.Cleanup(func() { windowsOpenCodePortWarningRead, windowsOpenCodePortConnectorList = oldRead, oldConnectors })
	windowsOpenCodePortConnectorList = func() ([]string, error) { return []string{"opencode"}, nil }
	windowsOpenCodePortWarningRead = func() ([]windowsOpenCodePortWarning, error) {
		return []windowsOpenCodePortWarning{
			{Code: "opencode_port_account_unknown", Message: "S-1-5-21-100-200-300-1001 at C:\\Users\\first\\.config\\opencode\\service.json: repair the account file"},
			{Code: "opencode_port_contested", Message: "port 25002 held; clear with enterprise windows opencode-port-clear 25002 --yes"},
		}, nil
	}
	result := enterprisestatus.New("status", managed.ProfileStandalone, "windows", "test")
	appendWindowsOpenCodePortWarnings(result)
	if len(result.Warnings) != 2 || result.Warnings[0].Code != "opencode_port_account_unknown" ||
		!strings.Contains(result.Warnings[0].Message, "service.json") || result.Warnings[1].Code != "opencode_port_contested" ||
		!strings.Contains(result.Warnings[1].Message, "opencode-port-clear 25002 --yes") {
		t.Fatalf("status warnings: %+v", result.Warnings)
	}
	windowsOpenCodePortConnectorList = func() ([]string, error) { return []string{"codex"}, nil }
	ordinary := enterprisestatus.New("status", managed.ProfileStandalone, "windows", "test")
	appendWindowsOpenCodePortWarnings(ordinary)
	if len(ordinary.Warnings) != 0 {
		t.Fatalf("unrelated connector warnings: %+v", ordinary.Warnings)
	}
	windowsOpenCodePortConnectorList = func() ([]string, error) { return []string{"opencode"}, nil }
	windowsOpenCodePortWarningRead = func() ([]windowsOpenCodePortWarning, error) { return nil, errors.New("read denied") }
	unavailable := enterprisestatus.New("status", managed.ProfileStandalone, "windows", "test")
	appendWindowsOpenCodePortWarnings(unavailable)
	if len(unavailable.Warnings) != 1 || unavailable.Warnings[0].Code != "opencode_port_record_unchecked" {
		t.Fatalf("unavailable summary warning: %+v", unavailable.Warnings)
	}
	windowsOpenCodePortConnectorList = func() ([]string, error) { return nil, errors.New("connector list unavailable") }
	unavailable = enterprisestatus.New("status", managed.ProfileStandalone, "windows", "test")
	appendWindowsOpenCodePortWarnings(unavailable)
	if len(unavailable.Warnings) != 1 || unavailable.Warnings[0].Code != "opencode_port_record_unchecked" {
		t.Fatalf("unavailable connector list warning: %+v", unavailable.Warnings)
	}
}

// The clear hint is the renderer's PowerShell call of the installed gateway,
// never a hand-built or a bare command.
func TestManagedWindowsOpenCodePortClearHintIsARenderedPowerShellCall(t *testing.T) {
	old := managedWindowsAdminCLI
	managedWindowsAdminCLI = func() string { return `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw.exe` }
	t.Cleanup(func() { managedWindowsAdminCLI = old })
	want := `& 'C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-gateway.exe' enterprise windows opencode-port-clear 25002 --yes`
	if got := windowsOpenCodePortClearCommand(25002); got != want {
		t.Fatalf("clear hint = %q, want %q", got, want)
	}
}
