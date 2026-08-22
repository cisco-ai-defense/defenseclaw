// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package connector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProtectedDarwinVersionProbeScrubsInheritedCredentials(t *testing.T) {
	t.Setenv("DEFENSECLAW_VERSION_PROBE_SECRET", "must-not-be-inherited")
	probe := filepath.Join(t.TempDir(), "version-probe")
	body := "#!/bin/sh\n" +
		"if [ -n \"${DEFENSECLAW_VERSION_PROBE_SECRET:-}\" ]; then exit 41; fi\n" +
		"printf 'codex-cli 0.146.0\\n'\n"
	if err := os.WriteFile(probe, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	_, digest, ok := setupSelectedAgentExecutableEvidence(probe)
	if !ok {
		t.Fatal("cannot hash version probe fixture")
	}
	raw, err := runProtectedDarwinAgentVersionProbe("codex", probe, digest)
	if err != nil {
		t.Fatalf("runProtectedDarwinAgentVersionProbe: %v", err)
	}
	if raw != "codex-cli 0.146.0" {
		t.Fatalf("probe output = %q", raw)
	}
}

func TestProtectedDarwinVersionProbeOutputIsBounded(t *testing.T) {
	if protectedDarwinVersionProbeWaitDelay <= 0 || protectedDarwinVersionProbeWaitDelay >= protectedDarwinVersionProbeTimeout {
		t.Fatalf(
			"version probe WaitDelay = %s, want positive and shorter than %s",
			protectedDarwinVersionProbeWaitDelay,
			protectedDarwinVersionProbeTimeout,
		)
	}
	buffer := &protectedDarwinVersionProbeBuffer{limit: 4}
	if _, err := buffer.Write([]byte("12345")); err == nil || !strings.Contains(err.Error(), "exceeds 4 bytes") {
		t.Fatalf("oversized write error = %v, want bounded refusal", err)
	}
}

func TestProtectedDarwinVersionValidationRequiresExactFullVersionToken(t *testing.T) {
	tests := []struct {
		name      string
		connector string
		expected  string
		probed    string
		wantError bool
	}{
		{name: "Codex wrappers", connector: "codex", expected: "0.146.0", probed: "codex-cli 0.146.0"},
		{name: "Claude wrappers", connector: "claudecode", expected: "Claude Code v2.1.219", probed: "2.1.219 (Claude Code)"},
		{name: "Codex prerelease mismatch", connector: "codex", expected: "codex-cli 0.146.0", probed: "codex-cli 0.146.0-alpha.1", wantError: true},
		{name: "Claude build mismatch", connector: "claudecode", expected: "2.1.219+build.1", probed: "2.1.219+build.2 (Claude Code)", wantError: true},
		{name: "unknown wrapper", connector: "codex", expected: "codex-cli 0.146.0", probed: "attacker 0.146.0", wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateProtectedDarwinAgentVersion(test.connector, test.expected, test.probed)
			if test.wantError && err == nil {
				t.Fatal("validation error = nil")
			}
			if !test.wantError && err != nil {
				t.Fatalf("validation error = %v", err)
			}
		})
	}
}
