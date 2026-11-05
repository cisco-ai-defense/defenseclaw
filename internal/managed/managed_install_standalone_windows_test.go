//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// extraReaderDACL is ACL-only drift: BUILTIN\Users may read, nobody untrusted
// may write, so the content cannot have changed through it.
const extraReaderDACL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)"

// standaloneInstallStateForTest builds a state root with the guardian's
// content files and one log, each carrying dacl.
func standaloneInstallStateForTest(t *testing.T, dacl string) (string, map[string]string) {
	t.Helper()
	t.Setenv(TrustStrictAncestorsEnv, "")
	t.Setenv(ConfigPathEnv, "")
	state := filepath.Join(t.TempDir(), "DefenseClaw")
	files := map[string]string{
		"config":     filepath.Join(state, "etc", "config.yaml"),
		"manifest":   filepath.Join(state, "hook-guardian", "targets.yaml"),
		"deployment": filepath.Join(state, "install", "deployment.json"),
		"log":        filepath.Join(state, "logs", "guardian", "hook-guardian.log"),
	}
	for _, path := range files {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("approved"), 0o600); err != nil {
			t.Fatal(err)
		}
		setTestFileDACL(t, path, testDACL(t, canonicalTestDACL), true)
		if err := ValidateTrustedFilePath(path, "fixture"); err != nil {
			t.Skipf("the process user does not own a trusted temp file here: %v", err)
		}
		setTestFileDACL(t, path, testDACL(t, dacl), true)
	}
	return state, files
}

func installResultFor(results []CanonicalResult, path string) (CanonicalResult, bool) {
	for _, result := range results {
		if strings.EqualFold(filepath.Clean(result.Path), filepath.Clean(path)) {
			return result, true
		}
	}
	return CanonicalResult{}, false
}

// GAP-0561 (v108f dc-ent-win): on standalone the guardian's layout self-heal
// never re-ACLs a content file (config.yaml, targets.yaml, the install
// records) that an untrusted principal can write. It stays refused by every
// reader until Setup /ensure writes a fresh file. A log keeps its repair.
func TestStandaloneManagedInstallRepairRefusesDriftedContentFiles(t *testing.T) {
	state, files := standaloneInstallStateForTest(t, usersWriteDACL)
	pinTrustProfileForTest(t, true)
	results := RepairWindowsManagedInstall(ManagedInstallLayout{StateRoot: state}, CanonicalOptions{Quiet: true})

	logResult, ok := installResultFor(results, files["log"])
	if !ok || logResult.Outcome != CanonicalRepaired {
		t.Skipf("this process cannot re-stamp a managed file here (log result %+v)", logResult)
	}
	if err := ValidateTrustedFilePath(files["log"], "log"); err != nil {
		t.Fatalf("the repaired log is still untrusted: %v", err)
	}
	for _, name := range []string{"config", "manifest", "deployment"} {
		result, ok := installResultFor(results, files[name])
		if !ok {
			t.Fatalf("%s: no result in %+v", name, results)
		}
		if result.Outcome != CanonicalBoundary || !strings.Contains(result.RepairError, "Setup /ensure") {
			t.Fatalf("%s: result = %+v, want a boundary refusal naming Setup /ensure", name, result)
		}
		if err := ValidateTrustedFilePath(files[name], name); err == nil {
			t.Fatalf("%s: the drifted content file was re-ACLed in place", name)
		}
	}

	// Setup /ensure: a fresh file under the admin-only descriptor replaces
	// the drifted one. The next guardian pass accepts it as it is.
	for _, name := range []string{"config", "manifest", "deployment"} {
		trustedRewriteForTest(t, files[name], []byte("approved"))
	}
	for _, result := range RepairWindowsManagedInstall(ManagedInstallLayout{StateRoot: state}, CanonicalOptions{Quiet: true}) {
		for _, name := range []string{"config", "manifest", "deployment"} {
			if strings.EqualFold(result.Path, files[name]) && result.Outcome == CanonicalBoundary {
				t.Fatalf("%s: still refused after the Setup rewrite: %+v", name, result)
			}
		}
	}
	for _, name := range []string{"config", "manifest", "deployment"} {
		if err := ValidateTrustedFilePath(files[name], name); err != nil {
			t.Fatalf("%s: untrusted after the Setup rewrite: %v", name, err)
		}
	}
}

// ACL-only drift (a reader, no untrusted writer) is still repaired on
// standalone: the bytes cannot have changed through it.
func TestStandaloneManagedInstallRepairKeepsACLOnlyRepair(t *testing.T) {
	state, files := standaloneInstallStateForTest(t, extraReaderDACL)
	pinTrustProfileForTest(t, true)
	results := RepairWindowsManagedInstall(ManagedInstallLayout{StateRoot: state}, CanonicalOptions{Quiet: true})
	if logResult, ok := installResultFor(results, files["log"]); !ok || logResult.Outcome != CanonicalRepaired {
		t.Skipf("this process cannot re-stamp a managed file here (log result %+v)", logResult)
	}
	for _, name := range []string{"config", "manifest", "deployment"} {
		result, _ := installResultFor(results, files[name])
		if result.Outcome != CanonicalRepaired {
			t.Fatalf("%s: ACL-only drift result = %+v, want repaired", name, result)
		}
	}
}

// Secure Client twin: unchanged, the content files are repaired in place.
func TestSecureClientManagedInstallRepairStillRepairsContentFiles(t *testing.T) {
	state, files := standaloneInstallStateForTest(t, usersWriteDACL)
	pinTrustProfileForTest(t, false)
	results := RepairWindowsManagedInstall(ManagedInstallLayout{StateRoot: state}, CanonicalOptions{Quiet: true})
	if logResult, ok := installResultFor(results, files["log"]); !ok || logResult.Outcome != CanonicalRepaired {
		t.Skipf("this process cannot re-stamp a managed file here (log result %+v)", logResult)
	}
	for _, name := range []string{"config", "manifest", "deployment"} {
		result, _ := installResultFor(results, files[name])
		if result.Outcome != CanonicalRepaired {
			t.Fatalf("%s: Secure Client result = %+v, want repaired as before", name, result)
		}
	}
}
