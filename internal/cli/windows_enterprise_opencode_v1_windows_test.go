// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// rel-1-0-6 GAP-0037 on Windows: an OpenCode V1 copy the enumerator found
// is a warning in status, verify and ensure that OpenCode is NOT protected,
// with the remedy, and coverage_complete is false; verify does not fail.
func TestWindowsOpenCodeV1IsAnIncompleteCoverageWarning(t *testing.T) {
	data, err := enterprisehooks.MarshalUnprotectedAgents([]enterprisehooks.UnprotectedAgent{{
		User: "alice", SID: "S-1-5-21-1-2-3-1001", Connector: "opencode", Version: "1.18.34",
		InstallPath: `C:\Users\alice\AppData\Roaming\npm\node_modules\opencode-ai`,
		Code:        enterprisehooks.UnprotectedCodeHookContractUnverified, Reason: "version 1.18.34 is below the lowest supported hook contract 2.0.0",
	}})
	if err != nil {
		t.Fatal(err)
	}
	agents, err := enterprisehooks.ParseUnprotectedAgents(data)
	if err != nil {
		t.Fatal(err)
	}
	stubWindowsUnprotectedAgents(t, agents, nil)
	previous := windowsManagedInstallAudit
	t.Cleanup(func() { windowsManagedInstallAudit = previous })
	audited := 0
	windowsManagedInstallAudit = func(agent enterprisehooks.UnprotectedAgent) error {
		if agent.Connector == "opencode" && agent.Version == "1.18.34" {
			audited++
		}
		return nil
	}
	for _, action := range []string{"status", "verify", "ensure"} {
		result := enterprisestatus.New(action, managed.ProfileStandalone, "windows", "1.0.6")
		result.CoverageComplete, result.SecurityComplete = true, true
		applyWindowsEnterpriseUnprotectedAgents(result)
		if result.CoverageComplete || result.SecurityComplete || len(result.Errors) != 0 || len(result.Warnings) != 1 ||
			result.Warnings[0].Code != enterprisehooks.UnprotectedCodeOpenCodeV1 ||
			!strings.Contains(result.Warnings[0].Message, "opencode 1.18.34 at C:\\Users\\alice\\AppData\\Roaming\\npm\\node_modules\\opencode-ai for user alice (S-1-5-21-1-2-3-1001) is not protected: it is OpenCode V1") ||
			!strings.Contains(result.Warnings[0].Message, "npm install -g @opencode/cli@2") {
			t.Fatalf("%s = %+v, want one OpenCode V1 warning and coverage_complete false", action, result)
		}
	}
	if audited != 2 {
		t.Fatalf("status and verify must audit the V1 copy once each, got %d", audited)
	}
}
