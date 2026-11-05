// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"strings"
	"testing"
)

// cowork-1-0-8 GAP-0076, as a class: the managed answers built only on
// Windows name the commands they hand on as typed too
// (TestManagedWindowsRefusalsNameRunnableCommands has the others).
func TestManagedWindowsOnlyAnswersNameRunnableCommands(t *testing.T) {
	restoreAccount, restoreManaged := managedHostCurrentAccount, auditExportManagedHost
	t.Cleanup(func() { managedHostCurrentAccount, auditExportManagedHost = restoreAccount, restoreManaged })
	managedHostCurrentAccount = func() string { return `HOST\dcadmin` }
	auditExportManagedHost = func() bool { return true }
	live := enterprisePolicyLiveAvailable()
	if live == nil {
		t.Fatal("enterprise policy verify --live ran on a managed Windows host")
	}
	answers := map[string]string{
		"live verify":           live.Error(),
		"secret status":         windowsSecretStandardUserAnswer("status", nil),
		"secret set":            windowsSecretStandardUserAnswer("set", &enterpriseSecretOptions{name: "ai_defense_api_key"}),
		"own status next steps": strings.Join(ownStatusNextSteps(), " "),
	}
	for name, answer := range answers {
		if problems := managedWindowsCommandProblems(answer); len(problems) > 0 {
			t.Errorf("%s names commands that do not run as typed %q: %s", name, problems, answer)
		}
		if !strings.Contains(answer, "& '"+strings.TrimSuffix(managedWindowsAdminCLI(), "defenseclaw.exe")) {
			t.Errorf("%s names no command to run: %s", name, answer)
		}
	}
}
