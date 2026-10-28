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
	"strconv"
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

// The carry keeps the fix/r104-oss-outage-open identity rule
// (installLockStale): the lock is stale only when its installer is proven
// gone, and no clock is read. The live owner is another running process
// (this test's parent): a lock naming the reader's own pid is a reused pid.
func TestPerUserInstallLockIsBoundedByItsOwnerNotItsAge(t *testing.T) {
	live := strconv.Itoa(os.Getppid())
	for _, tc := range []struct {
		name, pid string
		age       time.Duration
		held      bool
	}{
		{"new lock without pid", "", 0, true},
		{"dead owner", "99999999", 0, false},
		{"live owner", live, 0, true},
		{"aged live owner", live, 11 * time.Minute, true},
		{"aged lock without pid", "", 11 * time.Minute, true},
		{"pid reused by the reader", strconv.Itoa(os.Getpid()), 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			lock := filepath.Join(home, ".install.lock")
			if err := os.Mkdir(lock, 0o700); err != nil {
				t.Fatal(err)
			}
			if tc.pid != "" {
				if err := os.WriteFile(filepath.Join(lock, "pid"), []byte(tc.pid+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.age != 0 {
				then := time.Now().Add(-tc.age)
				if err := os.Chtimes(lock, then, then); err != nil {
					t.Fatal(err)
				}
			}
			if got := InstallLockHeld(home); got != tc.held {
				t.Fatalf("held=%v, want %v", got, tc.held)
			}
			if got := perUserInstallWindow(Options{Home: home}); got != tc.held {
				t.Fatalf("native Copilot install window=%v, want %v", got, tc.held)
			}
		})
	}
}
