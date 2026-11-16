//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// stampWindowsTargetsManifestTestSDDL writes owner, group and protected DACL
// from sddl onto path.
func stampWindowsTargetsManifestTestSDDL(t *testing.T, path, sddl string) {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		t.Fatal(err)
	}
	group, _, err := descriptor.Group()
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	extended, err := winpath.Extended(path)
	if err != nil {
		t.Fatal(err)
	}
	info := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION | windows.GROUP_SECURITY_INFORMATION |
		windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if err := windows.SetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, info, owner, group, dacl, nil); err != nil {
		t.Skipf("this process cannot stamp the manifest fixture: %v", err)
	}
}

// driftedWindowsTargetsManifestForTest publishes a manifest into a protected
// folder and then gives it the drift in sddl.
func driftedWindowsTargetsManifestForTest(t *testing.T, sddl string) (string, []byte) {
	t.Helper()
	path := filepath.Join(prepareWindowsTargetsManifestTestDirectory(t), "targets.yaml")
	if _, err := WriteTargetsManifestAtomic(path, Manifest{Version: 1}); err != nil {
		t.Fatalf("publish the fixture manifest: %v", err)
	}
	stampWindowsTargetsManifestTestSDDL(t, path, sddl)
	if validateWindowsTargetsManifestObject(path, false) == nil {
		t.Fatal("the drift fixture still validates")
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, before
}

func pinWindowsTargetsManifestContentRule(t *testing.T, standalone bool, strict func(string) error) {
	t.Helper()
	previousRule, previousStrict := windowsTargetsManifestRefusesContentDrift, windowsTargetsManifestStrictTrust
	t.Cleanup(func() {
		windowsTargetsManifestRefusesContentDrift, windowsTargetsManifestStrictTrust = previousRule, previousStrict
	})
	windowsTargetsManifestRefusesContentDrift = func() bool { return standalone }
	if strict != nil {
		windowsTargetsManifestStrictTrust = strict
	}
}

// GAP-0561 (v108f dc-ent-win): on standalone the enumerator never re-stamps
// a targets.yaml that an untrusted principal can write. The write is refused
// with the Setup step, and the file keeps the descriptor every reader refuses.
func TestWriteTargetsManifestAtomicStandaloneRefusesDriftedManifest(t *testing.T) {
	path, before := driftedWindowsTargetsManifestForTest(t, "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FW;;;BU)")
	pinWindowsTargetsManifestContentRule(t, true, nil)
	originalProtect := windowsTargetsManifestProtect
	windowsTargetsManifestProtect = func(target string, directory bool) error {
		if !directory && filepath.Clean(target) == filepath.Clean(path) {
			t.Fatal("the drifted manifest was re-stamped in place")
		}
		return originalProtect(target, directory)
	}
	t.Cleanup(func() { windowsTargetsManifestProtect = originalProtect })

	changed, err := WriteTargetsManifestAtomic(path, Manifest{Version: 1})
	var refusal *managed.StandaloneContentDriftError
	if err == nil || changed || !errors.As(err, &refusal) {
		t.Fatalf("WriteTargetsManifestAtomic = %t, %v; want a standalone content-drift refusal", changed, err)
	}
	if validateWindowsTargetsManifestObject(path, false) == nil {
		t.Fatal("the refused manifest's descriptor changed")
	}
	after, readErr := os.ReadFile(path)
	if readErr != nil || string(after) != string(before) {
		t.Fatalf("the refused manifest's bytes changed: %v", readErr)
	}
}

// ACL-only drift (a reader, no untrusted writer) is still re-stamped on
// standalone, and Secure Client keeps re-stamping a writer grant.
func TestWriteTargetsManifestAtomicKeepsRestampWhenNotRefused(t *testing.T) {
	for _, tc := range []struct {
		name       string
		sddl       string
		standalone bool
		strict     func(string) error
	}{
		{"standalone ACL-only drift", "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)", true, func(string) error { return nil }},
		{"Secure Client writer grant", "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FW;;;BU)", false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, _ := driftedWindowsTargetsManifestForTest(t, tc.sddl)
			pinWindowsTargetsManifestContentRule(t, tc.standalone, tc.strict)
			if _, err := WriteTargetsManifestAtomic(path, Manifest{Version: 1}); err != nil {
				t.Fatalf("WriteTargetsManifestAtomic: %v", err)
			}
			if err := validateWindowsTargetsManifestObject(path, false); err != nil {
				t.Fatalf("the manifest was not re-stamped: %v", err)
			}
		})
	}
}
