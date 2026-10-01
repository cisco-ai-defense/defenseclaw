// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestWindowsGoOwnedTargetsExcludeLifecycleOwnedFiles(t *testing.T) {
	for _, name := range []string{ConnectorCopilot, ConnectorOpenCode} {
		if !IsWindowsGoOwned(name) {
			t.Fatalf("%s is not Go-owned on Windows", name)
		}
	}
	for _, name := range []string{ConnectorCodex, ConnectorClaudeCode, ConnectorCursor, "devin", "amp"} {
		if IsWindowsGoOwned(name) {
			t.Fatalf("%s must not have a second Windows writer", name)
		}
	}
	if _, err := PublishWindowsGoOwned(Options{GOOS: "linux"}, nil); err == nil {
		t.Fatal("PublishWindowsGoOwned accepted a non-Windows target")
	}
}

func TestPublicPolicyPathForWindowsIsUserReadableRuntimeDir(t *testing.T) {
	layout, err := managed.StandaloneWindowsLayoutForRoots(`C:\Program Files`, `C:\ProgramData`)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := PublicPolicyPathFor(layout), `C:\ProgramData\Cisco\DefenseClaw-HookRuntime\machine-policy.json`; got != want {
		t.Fatalf("Windows summary path = %q, want %q", got, want)
	}
	unix, err := managed.StandaloneLayoutFor("linux")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := PublicPolicyPathFor(unix), "/etc/defenseclaw/machine-policy.json"; got != want {
		t.Fatalf("Linux summary path = %q, want %q", got, want)
	}
}
