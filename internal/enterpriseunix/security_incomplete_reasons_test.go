// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/contracttest"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// A managed host upgraded from 1.0.2 or 1.0.3 read security_complete true
// before and false after, with the same config, and nothing said which check
// made it false: 1.0.4 counts the vendor fail-open limit of the Claude Code
// hook (hook_process_fail_open) and the host's kernel settings into the
// field (GAP-1863, GAP-1861). Status, verify and ensure (the package result)
// name the warning codes behind each false field.
func TestStatusVerifyAndEnsureNameWhySecurityIsIncomplete(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			file := "linux-standalone.yaml"
			if goos == "darwin" {
				file = "macos-standalone.yaml"
			}
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: writeTempConfig(t, readSampleConfig(t, file))}))
			writeFreshLedger(t, h)
			for _, action := range []string{ActionStatus, ActionVerify, ActionEnsure} {
				r := h.run(Options{Action: action})
				contracttest.Compile(t).ValidateValue(t, "lifecycle-result.schema.json", r)
				if r.SecurityComplete {
					t.Fatalf("%s: security_complete true with an enabled Claude Code (hook_process_fail_open)", action)
				}
				why := messagesOf(r.Warnings, enterprisestatus.CodeSecurityIncomplete)
				if !strings.HasPrefix(why, "security_complete is false because of: ") || !strings.Contains(why, enterprisestatus.CodeHookProcessFailOpen) {
					t.Fatalf("%s did not name why security_complete is false: %q (warnings %+v)", action, why, r.Warnings)
				}
				if strings.Count(why, "security_complete is false") != 1 {
					t.Fatalf("%s named the reasons more than once: %q", action, why)
				}
				listed := strings.SplitN(strings.TrimPrefix(why, "security_complete is false because of: "), ";", 2)[0]
				listed = strings.TrimSuffix(listed, " and the errors above")
				for _, reason := range strings.Split(listed, ", ") {
					if strings.Contains(reason, " ") {
						continue // a readiness phrase, not a code
					}
					if messagesOf(r.Warnings, reason)+messagesOf(r.Errors, reason) == "" {
						t.Fatalf("%s named %q, which no warning or error of the result carries: %q", action, reason, why)
					}
				}
			}
		})
	}
}
