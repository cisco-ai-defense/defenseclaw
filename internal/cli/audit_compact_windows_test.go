// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// On a managed Windows computer no DefenseClaw command is on PATH: the
// refusals name the installed CLI by its full path, as PowerShell runs it.
func TestAuditCompactManagedWindowsAnswersNameTheInstalledCLI(t *testing.T) {
	t.Setenv(managed.DeploymentModeEnv, managed.DeploymentModeManagedEnterprise)
	rerun := auditCompactCommand()
	if rerun != managedWindowsCommand("audit", "compact") || strings.HasPrefix(rerun, "defenseclaw ") {
		t.Fatalf("managed Windows compact command = %q", rerun)
	}
	for _, answer := range []string{auditCompactInUse(`C:\ProgramData\Cisco\DefenseClaw\audit.db`, 0).Error(), auditCompactRepair()} {
		if strings.Contains(answer, "run defenseclaw ") || strings.Contains(answer, "Run defenseclaw ") {
			t.Errorf("managed Windows answer names a bare command: %q", answer)
		}
	}
	if !strings.Contains(auditCompactInUse("x", 0).Error(), "Stop-Service DefenseClawGateway") {
		t.Errorf("managed Windows refusal does not name the service stop")
	}
	t.Setenv(managed.DeploymentModeEnv, "")
	if got := auditCompactCommand("--dry-run"); got != "defenseclaw audit compact --dry-run" {
		t.Fatalf("per-user Windows compact command = %q", got)
	}
}
