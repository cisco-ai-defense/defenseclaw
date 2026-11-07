// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package mcpasuser

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// cowork-1-0-8 GAP-0095: the standalone profile has no Setup installed, so its
// enumerator answer names the installed CLI's repair; Secure Client keeps the
// text it always had.
func TestEnumeratorNotServingNamesTheRepairOfTheProfile(t *testing.T) {
	const secureClient = "the DefenseClaw hook enumerator service is not serving MCP as-user scans; " +
		"it starts them once it runs (Setup /repair restarts it)"
	for _, pin := range []string{"", managed.ProfileSecureClient} {
		t.Setenv(managed.EnterpriseProfileEnv, pin)
		if got := enumeratorNotServing().Error(); got != secureClient {
			t.Errorf("profile pin %q: %q, want the Secure Client text %q", pin, got, secureClient)
		}
	}
	t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
	got := enumeratorNotServing().Error()
	repair := managed.WindowsAdminCommand("enterprise", "windows", "repair", "--profile", "standalone")
	if !strings.Contains(got, "run "+repair+" from an elevated PowerShell prompt to restart it") {
		t.Errorf("standalone answer %q does not name %q", got, repair)
	}
	if strings.Contains(got, "Setup") {
		t.Errorf("standalone answer %q names Setup, which is not installed on the computer", got)
	}
}
