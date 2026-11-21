// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// rel-1-0-10 GAP-0856: the runtime selectors are machine files, but only an
// account's own install publishes its entry. Retire drops the entries that
// name this install's launch folder for a signed-out account (no runtime
// selected, pending until its sign-in), and keeps every entry the guardian
// rewrites itself: a signed-in account's, one naming the transition image,
// one naming another install's launch folder, and one whose session could
// not be told (named in the failures). A selector left empty goes.
func TestDeselectWindowsStandaloneSignedOutLaunchSelections(t *testing.T) {
	stubWindowsHookRuntimeRoot(t)
	owner := currentWindowsTestSID(t)
	const (
		signedOut = "S-1-5-21-1111111111-2222222222-3333333333-1002"
		signedIn  = "S-1-5-21-1111111111-2222222222-3333333333-1001"
		unknown   = "S-1-5-21-1111111111-2222222222-3333333333-1004"
		bin       = `C:\Program Files\Cisco\DefenseClaw\bin`
		launch    = bin + `\hooks\0123456789abcdef\defenseclaw-hook.exe`
		other     = `C:\Program Files\Cisco\Other\bin\hooks\0123456789abcdef\defenseclaw-hook.exe`
	)
	base := t.TempDir()
	previousPath, previousOwner := windowsManagedRuntimeSelectorPathResolver, windowsManagedPolicyOwnerSID
	previousDirTrust, previousAncestorTrust := windowsManagedPolicyDirTrustCheck, windowsManagedPolicyAncestorTrustCheck
	previousFileTrust, previousMutation := windowsManagedPolicyFileTrustCheck, windowsManagedRuntimeSelectorMutationAuthorize
	windowsManagedRuntimeSelectorPathResolver = func(name string) (string, error) {
		return filepath.Join(base, name, windowsManagedRuntimeSelectorFile), nil
	}
	windowsManagedPolicyOwnerSID = func() (*windows.SID, error) { return owner, nil }
	windowsManagedPolicyDirTrustCheck = func(string) error { return nil }
	windowsManagedPolicyAncestorTrustCheck = func(string) error { return nil }
	windowsManagedPolicyFileTrustCheck = func(string) error { return nil }
	windowsManagedRuntimeSelectorMutationAuthorize = func() error { return nil }
	t.Cleanup(func() {
		windowsManagedRuntimeSelectorPathResolver, windowsManagedPolicyOwnerSID = previousPath, previousOwner
		windowsManagedPolicyDirTrustCheck, windowsManagedPolicyAncestorTrustCheck = previousDirTrust, previousAncestorTrust
		windowsManagedPolicyFileTrustCheck, windowsManagedRuntimeSelectorMutationAuthorize = previousFileTrust, previousMutation
	})
	entry := func(connector, sid, hook string) windowsManagedRuntimeSelectorTarget {
		return windowsManagedRuntimeSelectorTarget{
			Connector:          connector,
			SID:                sid,
			DataDir:            filepath.Join(base, "profiles", sid, ".defenseclaw"),
			HookExecutable:     hook,
			GatewayAddr:        "127.0.0.1:18970",
			GatewayServiceName: "DefenseClawGateway",
			GenerationID:       strings.Repeat("a", 32),
			BundleSHA256:       "sha256:" + strings.Repeat("b", 64),
		}
	}
	for connector, targets := range map[string][]windowsManagedRuntimeSelectorTarget{
		// sorted by SID, as the selector keeps them
		"claudecode": {entry("claudecode", signedIn, launch), entry("claudecode", signedOut, launch)},
		"codex":      {entry("codex", signedOut, bin+`\defenseclaw-hook.exe`)},
		"cursor":     {entry("cursor", signedOut, other)},
		"copilot":    {entry("copilot", signedOut, launch)},
		"hermes":     {entry("hermes", unknown, launch)},
	} {
		if err := ensureWindowsManagedPolicyDirectory(filepath.Join(base, connector)); err != nil {
			t.Fatal(err)
		}
		if err := publishWindowsManagedRuntimeSelector(windowsManagedRuntimeSelector{
			SchemaVersion: windowsManagedRuntimeGenerationSchema,
			Connector:     connector,
			Targets:       targets,
		}); err != nil {
			t.Fatalf("publish %s selector: %v", connector, err)
		}
	}
	asked := map[string]int{}
	dropped, failures := DeselectWindowsStandaloneSignedOutLaunchSelections(bin+`\`, func(sid string) (bool, error) {
		asked[sid]++
		switch sid {
		case signedOut:
			return true, nil
		case signedIn:
			return false, nil
		}
		return false, errors.New("WTS query failed")
	})
	var got []string
	for _, selection := range dropped {
		got = append(got, selection.Connector+"@"+selection.SID)
	}
	if strings.Join(got, ",") != "claudecode@"+signedOut+",copilot@"+signedOut {
		t.Fatalf("dropped %v; want only the signed-out account's launch-folder selections", got)
	}
	if asked[signedOut] != 1 {
		t.Fatalf("the signed-out account's session was asked %d times; want once per retire", asked[signedOut])
	}
	hermes := filepath.Join(base, "hermes", windowsManagedRuntimeSelectorFile)
	if len(failures) != 1 || failures[hermes] == nil || !strings.Contains(failures[hermes].Error(), "WTS query failed") {
		t.Fatalf("failures = %v; want the hermes selector named with the session error", failures)
	}
	claude, _, exists, err := readWindowsManagedRuntimeSelector("claudecode", true)
	if err != nil || !exists || len(claude.Targets) != 1 || claude.Targets[0].SID != signedIn {
		t.Fatalf("claudecode selector must keep only the signed-in account: exists=%v targets=%+v err=%v", exists, claude.Targets, err)
	}
	for _, name := range []string{"codex", "cursor", "hermes"} {
		selector, _, exists, err := readWindowsManagedRuntimeSelector(name, true)
		if err != nil || !exists || len(selector.Targets) != 1 {
			t.Fatalf("%s selector must be kept unchanged: exists=%v targets=%+v err=%v", name, exists, selector.Targets, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(base, "copilot", windowsManagedRuntimeSelectorFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the copilot selector held only the dropped entry and must be gone: %v", err)
	}
	// A second retire finds nothing more to drop.
	if again, failed := DeselectWindowsStandaloneSignedOutLaunchSelections(bin, func(sid string) (bool, error) { return sid == unknown, nil }); len(again) != 1 ||
		again[0].Connector != "hermes" || len(failed) != 0 {
		t.Fatalf("second pass = %+v, %v; only the hermes entry, now told signed out, may go", again, failed)
	}
}

// Off the standalone profile (Secure Client) retire's selector step does
// nothing.
func TestDeselectWindowsSignedOutLaunchSelectionsIsStandaloneOnly(t *testing.T) {
	previous := windowsEnterpriseStandaloneProcess
	windowsEnterpriseStandaloneProcess = func() bool { return false }
	t.Cleanup(func() { windowsEnterpriseStandaloneProcess = previous })
	dropped, failures := DeselectWindowsStandaloneSignedOutLaunchSelections(`C:\Program Files\Cisco\DefenseClaw\bin`, func(string) (bool, error) {
		t.Fatal("the session check ran off the standalone profile")
		return true, nil
	})
	if len(dropped) != 0 || len(failures) != 0 {
		t.Fatalf("dropped %v failures %v", dropped, failures)
	}
}
