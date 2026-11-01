// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"os"
	"path/filepath"
	"testing"
)

// GAP-1390: a VS Code extensions root that is a junction was refused and
// read as an empty folder, so an old extension behind it was omitted with no
// warning. A root that exists but is not inspected is reported incomplete;
// an absent root is still an empty, complete listing.
func TestWindowsLinkedExtensionRootIsReportedIncomplete(t *testing.T) {
	const sid = "S-1-5-21-1-2-3-1001"
	previousReadAs := windowsSurfaceReadAs
	windowsSurfaceReadAs = func(_, _ string, fn func() error) error { return fn() }
	t.Cleanup(func() { windowsSurfaceReadAs = previousReadAs })

	absent := t.TempDir()
	if observed, complete, err := discoverWindowsAgentSurfaces(sid, absent, "claudecode"); err != nil || len(observed) != 0 || len(complete) != 0 {
		t.Fatalf("a profile without extension roots: observed=%+v complete=%+v err=%v", observed, complete, err)
	}

	home, target := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(target, "anthropic.claude-code-1.0.0"), 0o755); err != nil {
		t.Fatal(err)
	}
	makeTestJunction(t, filepath.Join(home, ".vscode", "extensions"), target)
	observed, complete, err := discoverWindowsAgentSurfaces(sid, home, "claudecode")
	if err == nil || len(complete) != 0 {
		t.Fatalf("a linked extension root must make the inventory incomplete: observed=%+v complete=%+v err=%v", observed, complete, err)
	}
	var reported []UnprotectedAgent
	row := &ManifestTarget{SID: sid, UserHome: home, Connector: "claudecode"}
	ctx := windowsStandaloneRowContext{sessionActive: true, user: "alice", report: func(agent UnprotectedAgent) { reported = append(reported, agent) }}
	if version := windowsStandaloneSurfaceVersion(row, nil, ctx, ""); version != "" || len(reported) != 1 || reported[0].Code != UnprotectedCodeInstallScanIncomplete {
		t.Fatalf("linked root row: version=%q reported=%+v", version, reported)
	}
}
