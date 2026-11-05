// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestClaudeManagedStatusAndVerifyReportShellOptions(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			settings := "/etc/claude-code/managed-settings.json"
			if goos == "darwin" {
				settings = "/Library/Application Support/ClaudeCode/managed-settings.json"
			}
			writeHostFile(t, h, settings, `{"env":{"SHELLOPTS":"braceexpand:noexec"}}`)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: machinePolicyConfig(t, h, "claudecode")}))
			writeFreshLedger(t, h)
			for _, action := range []string{ActionStatus, ActionVerify} {
				r := h.run(Options{Action: action})
				requireOK(t, r)
				warning := messagesOf(r.Warnings, codeClaudeShellOptions)
				if !strings.Contains(warning, filepath.Base(settings)+" sets env SHELLOPTS with noexec") || hasWarning(r, codeMachinePolicyIncomplete) {
					t.Fatalf("%s: warnings = %+v", action, r.Warnings)
				}
			}
			writeHostFile(t, h, settings, `{"env":{"SHELLOPTS":"braceexpand:hashall"}}`)
			requireOK(t, h.run(Options{Action: ActionReconcile}))
			for _, action := range []string{ActionStatus, ActionVerify} {
				r := h.run(Options{Action: action})
				requireOK(t, r)
				if warning := messagesOf(r.Warnings, codeClaudeShellOptions); warning != "" || hasWarning(r, codeMachinePolicyIncomplete) {
					t.Fatalf("%s benign settings: warnings = %+v", action, r.Warnings)
				}
			}
		})
	}
}
