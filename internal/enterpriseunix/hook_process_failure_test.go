// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"strings"
	"testing"
)

func TestManagedCodexStatusAndVerifyShowHookProcessFailure(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.4"), ConfigFile: machinePolicyConfig(t, h, "codex")}))
	for _, action := range []string{ActionStatus, ActionVerify} {
		r := h.run(Options{Action: action})
		message := messagesOf(r.Warnings, "hook_process_fail_open")
		if !strings.Contains(message, "codex") || !strings.Contains(message, "timeout") || r.SecurityComplete {
			t.Fatalf("%s warning=%q security_complete=%v", action, message, r.SecurityComplete)
		}
	}
}
