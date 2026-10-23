// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// An install or upgrade owns the account's data directory while it changes
// credentials and the gateway. Neither a stopped gateway nor an unusable
// answer is an outage-open approval during that interval (GAP-0797/0798).
func TestPerUserInstallLockClosesNativeHookFailures(t *testing.T) {
	for _, tc := range []struct{ connector, event string }{
		{"amp", ""},
		{"opencode", "tool.execute.before"},
		{"claudecode", "PreToolUse"},
		{"codex", "PreToolUse"},
		{"cursor", "beforeShellExecution"},
		{"copilot", "preToolUse"},
		{"copilot", "permissionRequest"},
		{"antigravity", "PreToolUse"},
		{"hermes", "pre_tool_call"},
		{"devin", "PreToolUse"},
		{"kiro", "PreToolUse"},
	} {
		for _, failure := range []string{"gateway stopped", "HTTP 401", "invalid verdict"} {
			t.Run(tc.connector+"/"+tc.event+"/"+failure, func(t *testing.T) {
				home := t.TempDir()
				if err := os.Mkdir(filepath.Join(home, ".install.lock"), 0o700); err != nil {
					t.Fatal(err)
				}
				var stdout, stderr bytes.Buffer
				opts := Options{Connector: tc.connector, Event: tc.event, Home: home,
					FailMode: "open", Stdout: &stdout, Stderr: &stderr, Now: time.Now}
				sp := specs[tc.connector]
				var code int
				switch failure {
				case "gateway stopped":
					code = failUnreachable(opts, sp, "open", "gateway not running")
				case "HTTP 401":
					code = failResponse(opts, sp, "open", "gateway returned HTTP 401")
				case "invalid verdict":
					code = failResponse(opts, sp, "open", "invalid or missing action in gateway response")
				}
				// Connectors use different native exit contracts.
				if !strings.Contains(stdout.String(), "deny") && !strings.Contains(stdout.String(), "block") &&
					!strings.Contains(stdout.String(), "Stop") && code == 0 {
					t.Fatalf("install lock allowed %s: stdout=%q stderr=%q", failure, stdout.String(), stderr.String())
				}
			})
		}
	}
}
