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
			r.AddHookProcessFailureWarnings()
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

	for _, action := range []string{"status", "verify", "ensure"} {
		r := New(action, "standalone", "windows", "1.0.4")
		r.SecurityComplete = true
		r.Connectors = map[string]ConnectorState{"codex": {Enabled: true}}
		r.AddHookProcessFailureWarnings()
		if len(r.Warnings) != 1 || r.SecurityComplete {
			t.Fatalf("%s warning=%v security_complete=%v", action, r.Warnings, r.SecurityComplete)
		}
		r = New(action, "standalone", "windows", "1.0.4")
		r.Connectors = map[string]ConnectorState{"codex": {Enabled: false}}
		r.AddHookProcessFailureWarnings()
		if len(r.Warnings) != 0 {
			t.Fatalf("%s disabled connector warned: %v", action, r.Warnings)
		}
	}
}
