// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// rel-1-0-10 GAP-1540: the rollback to 1.0.9 (retire, then the published
// 1.0.9 Setup /upgrade) ended 1603 on every standalone host. Retire left the
// Claude Code drop-in in the current form, with the GAP-0119 guard texts, and
// the 1.0.9 guardian, which recognizes its drop-in only by rendering it in
// its own form, refused it as "an unrecognized registered command": its
// startup reconcile published no state and Setup rolled back after 93 s.
// While the launch folders are retired the drop-in is the 1.0.9 form, the
// installed release still accepts it, and once the marker is gone the next
// ensure writes the current form again.
func TestGAP1540RetiredLaunchFoldersWriteThe109ClaudePolicy(t *testing.T) {
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	setStandaloneProfileForTest(t, true)
	opts := windowsManagedInstallOptions(fixture)
	opts.AgentVersion = "2.1.230 (Claude Code)"
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	current, err := os.ReadFile(fixture.policyPath)
	if err != nil {
		t.Fatal(err)
	}
	newMissing, newStart := gap1495Args(t, gap1495Missing10), gap1495Args(t, gap1495Start10)
	events := bytes.Count(current, newMissing)
	if events == 0 || bytes.Count(current, newStart) != events {
		t.Fatalf("fixture policy is not the guarded wrapper form: %d missing and %d start texts", events, bytes.Count(current, newStart))
	}
	want109 := bytes.ReplaceAll(current, newMissing, gap1495Args(t, gap1495Missing109))
	want109 = bytes.ReplaceAll(want109, newStart, gap1495Args(t, gap1495Start109))

	root := winpath.EnterpriseHookImagesRoot(filepath.Dir(fixture.hookExe))
	marker := filepath.Join(root, winpath.EnterpriseHookImagesRetiredMarker)
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, []byte(`{"schema_version":1,"state":"ok"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(filepath.Dir(fixture.policyPath), windowsClaudeManagedStateFile)
	recordedDigest := func() string {
		t.Helper()
		body, err := os.ReadFile(statePath)
		if err != nil {
			t.Fatal(err)
		}
		var record windowsClaudeManagedPolicyState
		if err := decodeWindowsClaudeManagedPolicyState(body, &record); err != nil {
			t.Fatal(err)
		}
		return record.PolicySHA256
	}

	ensure := connector.SetupOpts{APIAddr: opts.APIAddr, HookExecutable: fixture.hookExe}
	for pass := 1; pass <= 2; pass++ {
		if err := EnsureWindowsStandaloneClaudeManagedPolicy(ensure); err != nil {
			t.Fatalf("ensure %d with the launch folders retired: %v", pass, err)
		}
		got, err := os.ReadFile(fixture.policyPath)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want109) {
			t.Fatalf("ensure %d with the launch folders retired left a drop-in the 1.0.9 guardian does not render (current form: %v, %d current guard texts)",
				pass, bytes.Equal(got, current), bytes.Count(got, newMissing))
		}
		if digest := recordedDigest(); digest != windowsManagedPolicyDigest(want109) {
			t.Fatalf("ensure %d: ownership record keeps %s, not the digest of the 1.0.9 form", pass, digest)
		}
	}
	// This release still verifies and keeps its own retired drop-in.
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatalf("install with the launch folders retired: %v", err)
	}
	if got, err := os.ReadFile(fixture.policyPath); err != nil || !bytes.Equal(got, want109) {
		t.Fatalf("install with the launch folders retired rewrote the 1.0.9 form: err=%v", err)
	}

	// The next Setup of this release removes the marker: current form again.
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if err := EnsureWindowsStandaloneClaudeManagedPolicy(ensure); err != nil {
		t.Fatalf("ensure after the marker is gone: %v", err)
	}
	if got, err := os.ReadFile(fixture.policyPath); err != nil || !bytes.Equal(got, current) {
		t.Fatalf("ensure after the marker is gone left the 1.0.9 form: err=%v", err)
	}
	if digest := recordedDigest(); digest != windowsManagedPolicyDigest(current) {
		t.Fatalf("ownership record keeps %s after the marker is gone, not the current digest", digest)
	}
}
