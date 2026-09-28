// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// deferredPendingProofFixture is a real deferred row for a profile that
// DefenseClaw has never touched: the home exists, its canonical
// %USERPROFILE%\.defenseclaw does not, and no runtime selector is published.
func deferredPendingProofFixture(t *testing.T, standalone bool) ManifestTarget {
	t.Helper()
	targetSID := currentWindowsTestSID(t)
	home := newWindowsTargetOwnedTestHome(t, targetSID)
	// The trust check is stubbed; the proof only needs a canonical path.
	hookExe := filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
	selectorRoot := t.TempDir()

	previousStandalone := windowsEnterpriseStandaloneProcess
	previousHook := windowsEnterpriseHookExecutable
	previousTrust := windowsEnterpriseHookTrustCheck
	previousSelector := windowsManagedRuntimeSelectorPathResolver
	windowsEnterpriseStandaloneProcess = func() bool { return standalone }
	windowsEnterpriseHookExecutable = func() (string, error) { return hookExe, nil }
	windowsEnterpriseHookTrustCheck = func(string) error { return nil }
	windowsManagedRuntimeSelectorPathResolver = func(name string) (string, error) {
		return filepath.Join(selectorRoot, name, windowsManagedRuntimeSelectorFile), nil
	}
	t.Cleanup(func() {
		windowsEnterpriseStandaloneProcess = previousStandalone
		windowsEnterpriseHookExecutable = previousHook
		windowsEnterpriseHookTrustCheck = previousTrust
		windowsManagedRuntimeSelectorPathResolver = previousSelector
	})

	enabled := true
	return ManifestTarget{
		SID:          targetSID.String(),
		UserHome:     home,
		Connector:    "claudecode",
		AgentVersion: "2.1.230",
		Enabled:      &enabled,
		Deferred:     true,
	}
}

// The pending proof for a deferred row of a profile DefenseClaw never
// touched: on the standalone profile an absent data directory is accepted,
// while a file in its place or a published runtime selector is refused; the
// Secure Client profile still requires the data directory.
func TestDeferredPendingProofForAnUntouchedProfile(t *testing.T) {
	for _, tc := range []struct {
		name       string
		standalone bool
		prepare    func(t *testing.T, target ManifestTarget)
		want       string // the refusal; "" accepts unless refused is set
		refused    bool
	}{
		{name: "standalone, absent data directory", standalone: true, prepare: func(t *testing.T, target ManifestTarget) {
			if _, err := os.Lstat(filepath.Join(target.UserHome, ".defenseclaw")); !os.IsNotExist(err) {
				t.Fatalf("fixture data directory must be absent, got %v", err)
			}
		}},
		{name: "secure client", want: "deferred target data directory is untrusted"},
		{name: "standalone, file in place of the data directory", standalone: true, want: "deferred target data directory is untrusted",
			prepare: func(t *testing.T, target ManifestTarget) {
				if err := os.WriteFile(filepath.Join(target.UserHome, ".defenseclaw"), []byte("not a directory"), 0o600); err != nil {
					t.Fatal(err)
				}
			}},
		// Any published selector must be read and judged; an unreadable one
		// is an error, never proof of absence.
		{name: "standalone, selector published", standalone: true, refused: true,
			prepare: func(t *testing.T, _ ManifestTarget) {
				selector, err := windowsManagedRuntimeSelectorPathResolver("claudecode")
				if err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(filepath.Dir(selector), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(selector, []byte("{"), 0o600); err != nil {
					t.Fatal(err)
				}
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := deferredPendingProofFixture(t, tc.standalone)
			if tc.prepare != nil {
				tc.prepare(t, target)
			}
			err := RequireWindowsEnterpriseDeferredTargetPending(target)
			switch {
			case tc.refused:
				if err == nil {
					t.Fatal("pending proof accepted a profile while a runtime selector was published")
				}
			case tc.want == "":
				if err != nil {
					t.Fatalf("pending proof: %v", err)
				}
			case err == nil || !strings.Contains(err.Error(), tc.want):
				t.Fatalf("pending proof error = %v, want %q", err, tc.want)
			}
		})
	}
}
