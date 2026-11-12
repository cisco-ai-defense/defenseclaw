// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"testing"
)

func writeAgentDiscoveryForTest(t *testing.T, agents string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "agent_discovery.json"), []byte(`{"version":7,"agents":{`+agents+`}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

const (
	kiroUnidentified = `"kiro":{"version":"kiro-cli 2.27.1","installed":true,"binary_path":"/opt/kiro/kiro-cli"}`
	kiroIdentified   = `"kiro":{"version":"kiro-cli 2.27.1","installed":true,"binary_path":"/opt/kiro/kiro-cli","identity":["/opt/kiro/kiro-cli",12,34,56,78,90]}`
)

// A cached Kiro version that names no executable is never admitted, and the
// refusal reads it as a version discovery has not read yet.
func TestCachedKiroVersionWithoutAnExecutableIdentityIsNotAdmitted(t *testing.T) {
	dir := writeAgentDiscoveryForTest(t, kiroUnidentified)
	if got := LoadCachedAgentVersion(dir, "kiro"); got != "" {
		t.Fatalf("LoadCachedAgentVersion = %q, want no version", got)
	}
	detail, cause := CachedAgentVersionProbeError(dir, "kiro")
	if detail == "" || cause != AgentVersionProbeNotProbed {
		t.Fatalf("CachedAgentVersionProbeError = %q, %v; want a not-probed reason", detail, cause)
	}
	if CachedAgentNotFound(dir, "kiro") {
		t.Fatal("an installed Kiro is reported as not found")
	}
}

// The benign twins: the same Kiro with its identity is admitted, a short
// identity does not count, and the rule is for Kiro alone (other connectors
// keep their cached version; Python reads those again by their executable).
func TestCachedKiroVersionWithAnExecutableIdentityIsAdmitted(t *testing.T) {
	dir := writeAgentDiscoveryForTest(t, kiroIdentified)
	if got := LoadCachedAgentVersion(dir, "kiro"); got != "kiro-cli 2.27.1" {
		t.Fatalf("LoadCachedAgentVersion = %q", got)
	}
	short := writeAgentDiscoveryForTest(t, `"kiro":{"version":"kiro-cli 2.27.1","installed":true,"identity":["/x",1]}`)
	if got := LoadCachedAgentVersion(short, "kiro"); got != "" {
		t.Fatalf("a short identity admitted %q", got)
	}
	other := writeAgentDiscoveryForTest(t, `"cursor":{"version":"3.19.13","installed":true,"binary_path":"/opt/cursor/cursor"}`)
	if got := LoadCachedAgentVersion(other, "cursor"); got != "3.19.13" {
		t.Fatalf("an unidentified cursor version = %q, want it kept", got)
	}
}
