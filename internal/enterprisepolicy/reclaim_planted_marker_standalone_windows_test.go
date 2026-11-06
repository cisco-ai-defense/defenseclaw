//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/windows"
)

// g582 review 4 F2: a DefenseClaw-named file a standard user planted in a
// vendor folder they created before the first install is owned by that user
// and does not count as a DefenseClaw marker, so the documented pre-install
// takeover still runs.
func TestWindowsReclaimIgnoresAPlantedUserOwnedMarkerOnStandalone(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated token (the Windows CI runners and the native test hosts run elevated)")
	}
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, t.TempDir())
	opts := windowsTestOptions(t)
	github := filepath.Join(opts.WindowsProgramData, "GitHub")
	copilot := filepath.Join(github, "Copilot")
	for _, dir := range []string{github, copilot} {
		if err := createProtectedDir(dir); err != nil {
			t.Fatal(err)
		}
	}
	dir := filepath.Join(copilot, "policy.d")
	sd, err := windows.SecurityDescriptorFromString("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200af;;;BU)")
	if err != nil {
		t.Fatal(err)
	}
	attributes := windows.SecurityAttributes{SecurityDescriptor: sd}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	name, _ := windows.UTF16PtrFromString(dir)
	if err := windows.CreateDirectory(name, &attributes); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "50-defenseclaw.json")
	if err := os.WriteFile(marker, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	stampF1(t, marker, "O:BUG:SYD:P(A;;FA;;;BU)(A;;FA;;;SY)(A;;FA;;;BA)")
	previous := reclaimRefusesContentDrift
	reclaimRefusesContentDrift = func() bool { return true }
	t.Cleanup(func() { reclaimRefusesContentDrift = previous })

	err = RepairWindowsPublicDir(dir)

	var refused *managed.StandaloneContentDriftError
	if errors.As(err, &refused) {
		t.Fatalf("a planted, user-owned marker refused the pre-install takeover: %v", err)
	}
	if err != nil {
		t.Fatalf("RepairWindowsPublicDir: %v", err)
	}
	if validateTrustedLeafDir(dir) != nil {
		t.Fatal("the pre-created folder was not taken over")
	}
}
