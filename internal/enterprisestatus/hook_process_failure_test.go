// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import (
	"strings"
	"testing"
)

func TestHookProcessFailureWarnings(t *testing.T) {
	for _, tc := range []struct {
		name     string
		versions []string
		warn     bool
		contains string
	}{
		{"codex", []string{"0.160.0"}, true, ""},
		{"claudecode", []string{"2.1.219"}, true, ""},
		{"devin", []string{"3000.11.3"}, true, ""},
		{"copilot", []string{"1.0.91"}, true, ""},
		{"hermes", []string{"0.19.0"}, true, "unknown-version"},
		{"hermes", []string{"0.21.5"}, true, "non-2 process exit"},
		{"hermes", []string{"2026.9.14"}, true, "non-2 process exit"},
		{"hermes", []string{"Hermes Agent v0.21.5 (2026.9.24)"}, true, "non-2 process exit"},
		{"hermes", []string{"0.21.5", "0.19.0"}, true, "unknown-version"},
		{"hermes", nil, true, "unknown-version"},
		{"opencode", []string{"1.19.0"}, false, ""},
		{"amp", nil, false, ""},
		{"antigravity", nil, true, ""},
		{"kiro", []string{"2.24.1"}, true, ""},
	} {
		t.Run(tc.name+strings.Join(tc.versions, ","), func(t *testing.T) {
			r := New("status", "standalone", "linux", "1.0.4")
			r.SecurityComplete = true
			r.Connectors = map[string]ConnectorState{tc.name: {Enabled: true, Versions: tc.versions}}
			r.AddHookProcessFailureWarnings(r.Connectors)
			if got := len(r.Warnings) > 0; got != tc.warn {
				t.Fatalf("%s versions %v: warning=%v, want %v", tc.name, tc.versions, r.Warnings, tc.warn)
			}
			if tc.warn {
				if r.Warnings[0].Code != CodeHookProcessFailOpen || !strings.Contains(r.Warnings[0].Message, tc.name) || r.SecurityComplete {
					t.Fatalf("%s: warning=%v security_complete=%v", tc.name, r.Warnings, r.SecurityComplete)
				}
				if tc.name == "hermes" && !strings.Contains(r.Warnings[0].Message, "kill") {
					t.Fatalf("Hermes warning misses killed-hook residual: %v", r.Warnings)
				}
				if tc.contains != "" && !strings.Contains(r.Warnings[0].Message, tc.contains) {
					t.Fatalf("%s versions %v: warning %q does not contain %q", tc.name, tc.versions, r.Warnings[0].Message, tc.contains)
				}
			} else if !r.SecurityComplete {
				t.Fatalf("%s: security_complete changed", tc.name)
			}
		})
	}

	r := New("verify", "standalone", "windows", "1.0.4")
	r.Connectors = map[string]ConnectorState{"codex": {Enabled: false}}
	r.AddHookProcessFailureWarnings(r.Connectors)
	if len(r.Warnings) != 0 {
		t.Fatalf("disabled connector warned: %v", r.Warnings)
	}
}

// Ensure, install and repair print no connectors block, but they describe
// the same connectors: the limit lowers their security_complete as it does
// for status and verify (it applied only to status and verify).
func TestHookProcessFailureWarningsApplyToEveryAction(t *testing.T) {
	for _, action := range []string{"ensure", "install", "repair", "upgrade", "status", "verify"} {
		r := New(action, "standalone", "darwin", "1.0.4")
		r.SecurityComplete = true
		r.AddHookProcessFailureWarnings(map[string]ConnectorState{"codex": {Enabled: true, Versions: []string{"0.160.0"}}})
		if len(r.Warnings) != 1 || r.Warnings[0].Code != CodeHookProcessFailOpen || r.SecurityComplete || r.Connectors != nil {
			t.Fatalf("%s: warnings=%v security_complete=%v connectors=%v", action, r.Warnings, r.SecurityComplete, r.Connectors)
		}
	}
	r := New("ensure", "secure_client", "windows", "1.0.4")
	r.SecurityComplete = true
	r.AddHookProcessFailureWarnings(map[string]ConnectorState{"codex": {Enabled: true}})
	if len(r.Warnings) != 0 || !r.SecurityComplete {
		t.Fatalf("Secure Client ensure changed: warnings=%v security_complete=%v", r.Warnings, r.SecurityComplete)
	}
}
