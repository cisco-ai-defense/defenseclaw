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
	requireElevatedManagedWindows(t)
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

// rel-1-0-10 GAP-1567: the identity proof the guardian runs before it stages
// a signed-out account's deferred row took the guard texts from the caller's
// hook path. During a retire the caller names the transition image (1.0.9
// texts) while the drop-in still names a launch folder in the current form,
// so the proof refused this deployment's policy. Mirror: the marker is gone,
// the caller names a launch folder, and the record names the transition
// image with the 1.0.9 form a retire wrote.
func TestGAP1567ClaudePolicyIdentityFollowsTheRecordedHookImage(t *testing.T) {
	fixture := newWindowsManagedInstallFixture(t, nil)
	setStandaloneProfileForTest(t, true)
	transition, launch := hookImageFixtureLayout(t, fixture)
	service := os.Getenv(connector.WindowsGatewayServiceNameEnv)
	setup := hookImageClaudeSetup(launch)
	body, err := connector.NewClaudeCodeConnector().ManagedHookPolicy(setup)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := installWindowsClaudeManagedPolicy(body, setup, fixture.targetSID); err != nil {
		t.Fatalf("publish the launch image's policy: %v", err)
	}
	marker := filepath.Join(winpath.EnterpriseHookImagesRoot(filepath.Dir(transition)), winpath.EnterpriseHookImagesRetiredMarker)
	if err := os.WriteFile(marker, []byte(`{"schema_version":1,"state":"pending"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyWindowsClaudeManagedPolicyIdentity(transition, setup.APIAddr, service); err != nil {
		t.Fatalf("retire pending: identity of the launch folder's current-form policy, asked with the transition image: %v", err)
	}

	// The retire then rewrites the drop-in for the transition image in the
	// 1.0.9 form, and the next Setup removes the marker.
	retired := hookImageClaudeSetup(transition)
	if !retired.ClaudeManagedGuardTexts109 {
		t.Fatal("the transition image with the marker present does not render the 1.0.9 form")
	}
	body, err = connector.NewClaudeCodeConnector().ManagedHookPolicy(retired)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := installWindowsClaudeManagedPolicy(body, retired, nil); err != nil {
		t.Fatalf("retire: move the policy to the transition image: %v", err)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if err := VerifyWindowsClaudeManagedPolicyIdentity(launch, setup.APIAddr, service); err != nil {
		t.Fatalf("marker gone: identity of the transition image's 1.0.9-form policy, asked with a launch folder: %v", err)
	}
	other := filepath.Join(filepath.Dir(fixture.hookExe), "other-hook.exe")
	if err := VerifyWindowsClaudeManagedPolicyIdentity(other, setup.APIAddr, service); err == nil {
		t.Fatal("the policy was accepted for another hook executable")
	}
}

// GAP-1540 review: with the marker present only the standalone transition
// image is written in the 1.0.9 form; a launch-folder path and Secure Client
// keep the current one.
func TestGAP1540RetiredFormOnlyForTheStandaloneTransitionImage(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "bin")
	launchDir := filepath.Join(bin, "hooks", "0123456789abcdef")
	if err := os.MkdirAll(launchDir, 0o700); err != nil {
		t.Fatal(err)
	}
	transition := filepath.Join(bin, winpath.EnterpriseHookImageName)
	launch := filepath.Join(launchDir, winpath.EnterpriseHookImageName)
	for _, path := range []string{transition, launch} {
		if err := os.WriteFile(path, []byte("test native hook"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	setStandaloneProfileForTest(t, true)
	if form := windowsClaudeWrittenForm(transition); form != windowsClaudeFormCurrent {
		t.Fatalf("no marker: transition image form %d, want the current form", form)
	}
	marker := filepath.Join(bin, "hooks", winpath.EnterpriseHookImagesRetiredMarker)
	if err := os.WriteFile(marker, []byte(`{"schema_version":1,"state":"ok"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if form := windowsClaudeWrittenForm(transition); form != windowsClaudeFormGuard109 {
		t.Fatalf("marker present: standalone transition image form %d, want the 1.0.9 form", form)
	}
	if form := windowsClaudeWrittenForm(launch); form != windowsClaudeFormCurrent {
		t.Fatalf("marker present: launch folder form %d, want the current form", form)
	}
	setStandaloneProfileForTest(t, false)
	if form := windowsClaudeWrittenForm(transition); form != windowsClaudeFormCurrent {
		t.Fatalf("marker present: Secure Client form %d, want the current form", form)
	}
	if withWindowsClaudeManagedHooksOnly(connector.SetupOpts{HookExecutable: transition}).ClaudeManagedGuardTexts109 {
		t.Fatal("marker present: Secure Client setup carries the 1.0.9 guard texts")
	}
}
