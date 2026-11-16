//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// GAP-0063: an elevated per-user hook (Claude Desktop runs elevated as the
// built-in Administrator) created hooks\.outage-warnings owned by
// Administrators, which the account without elevation could not remove.
func TestElevatedPerUserTokenOwnsWhatItCreatesAsItsUser(t *testing.T) {
	_, _, localSystem, user := gatewayOwnerTestSIDs(t)
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	entra, err := windows.StringToSid("S-1-12-1-1-2-3-4")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name        string
		token       *fakeOwnerToken
		managed     bool
		want        bool
		wantOwner   *windows.SID
		wantChecked bool
	}{
		{"elevated user owns as the user", &fakeOwnerToken{fakeServiceToken: fakeServiceToken{user: user}, owner: administrators}, false, true, user, true},
		{"elevated Entra ID user owns as the user", &fakeOwnerToken{fakeServiceToken: fakeServiceToken{user: entra}, owner: administrators}, false, true, entra, true},
		{"token without elevation is left alone, marker not read", &fakeOwnerToken{fakeServiceToken: fakeServiceToken{user: user}, owner: user}, false, false, user, false},
		{"managed computer is left alone", &fakeOwnerToken{fakeServiceToken: fakeServiceToken{user: user}, owner: administrators}, true, false, administrators, true},
		{"LocalSystem is left alone", &fakeOwnerToken{fakeServiceToken: fakeServiceToken{user: localSystem}, owner: administrators}, false, false, administrators, false},
		{"a refused change leaves the token", &fakeOwnerToken{fakeServiceToken: fakeServiceToken{user: user}, owner: administrators, setErr: windows.ERROR_ACCESS_DENIED}, false, false, administrators, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			checked := false
			got := useTokenUserAsDefaultOwner(test.token, func() bool { checked = true; return !test.managed })
			if got != test.want {
				t.Fatalf("changed = %v, want %v", got, test.want)
			}
			if !test.token.owner.Equals(test.wantOwner) {
				t.Fatalf("default owner = %v, want %v", test.token.owner, test.wantOwner)
			}
			if checked != test.wantChecked {
				t.Fatalf("managed marker read = %v, want %v", checked, test.wantChecked)
			}
		})
	}
}

func TestEnterpriseCommandsKeepTheTokenOwner(t *testing.T) {
	original := openWindowsProcessTokenOwner
	t.Cleanup(func() { openWindowsProcessTokenOwner = original })
	opened := 0
	openWindowsProcessTokenOwner = func() (windowsTokenOwnerSetter, func(), error) {
		opened++
		return nil, nil, errors.New("not opened in this test")
	}
	if UseCurrentUserAsWindowsDefaultOwner([]string{"enterprise", "windows", "status"}) || opened != 0 {
		t.Fatalf("an enterprise command opened its token %d times", opened)
	}
	if UseCurrentUserAsWindowsDefaultOwner([]string{"hook", "--connector", "claudecode"}) || opened != 1 {
		t.Fatalf("a hook call opened its token %d times, want 1", opened)
	}
}

func TestManagedPinKeepsTheTokenOwner(t *testing.T) {
	original := openWindowsProcessTokenOwner
	t.Cleanup(func() { openWindowsProcessTokenOwner = original })
	opened := 0
	openWindowsProcessTokenOwner = func() (windowsTokenOwnerSetter, func(), error) {
		opened++
		return nil, nil, errors.New("not opened in this test")
	}
	t.Setenv(DeploymentModeEnv, DeploymentModeManagedEnterprise)
	if UseCurrentUserAsWindowsDefaultOwner([]string{"policy", "reload"}) || opened != 0 {
		t.Fatalf("a managed-pinned process opened its token %d times", opened)
	}
}

// Only the standalone profile writes the marker: a Secure Client deployment,
// or a first standalone install before its marker, has only its install root.
func TestManagedDeploymentAbsentNeedsNoMarkerAndNoInstallRoot(t *testing.T) {
	roots := func(profile string) (winpath.EnterpriseRoots, error) {
		return winpath.EnterpriseRootsFor(profile, `C:\Program Files`, `C:\ProgramData`)
	}
	notFound := func() error { return windows.ERROR_FILE_NOT_FOUND }
	noRoot := func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	rootAt := func(want string) func(string) (os.FileInfo, error) {
		return func(path string) (os.FileInfo, error) {
			if path == want {
				return nil, nil
			}
			return nil, os.ErrNotExist
		}
	}
	for _, test := range []struct {
		name   string
		marker func() error
		roots  func(string) (winpath.EnterpriseRoots, error)
		lstat  func(string) (os.FileInfo, error)
		absent bool
	}{
		{"nothing installed", notFound, roots, noRoot, true},
		{"marker present", func() error { return nil }, roots, noRoot, false},
		{"marker read error", func() error { return windows.ERROR_ACCESS_DENIED }, roots, noRoot, false},
		{"Secure Client install root", notFound, roots, rootAt(`C:\Program Files\Cisco\Cisco Secure Client\DefenseClaw`), false},
		{"standalone install root before its marker", notFound, roots, rootAt(`C:\Program Files\Cisco\DefenseClaw`), false},
		{"install root unreadable", notFound, roots, func(string) (os.FileInfo, error) { return nil, os.ErrPermission }, false},
		{"machine roots unreadable", notFound, func(string) (winpath.EnterpriseRoots, error) {
			return winpath.EnterpriseRoots{}, errors.New("no registration")
		}, noRoot, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := managedDeploymentAbsent(test.marker, test.roots, test.lstat); got != test.absent {
				t.Fatalf("absent = %v, want %v", got, test.absent)
			}
		})
	}
}

// windowsManagedDeploymentHere is the real check: a marker or an install root.
func windowsManagedDeploymentHere(t *testing.T) bool {
	t.Helper()
	return !windowsManagedDeploymentMarkerAbsent()
}

// The live shape of the hook's outage marker: a folder made with MkdirAll
// and a file opened O_EXCL, as firstOutageWarning makes them. Elevated or
// not, both are owned by the token user afterwards. The managed marker is
// read as absent so the real token change runs on any test computer.
func TestLiveProcessCreatesTheOutageMarkerAsItsUser(t *testing.T) {
	original := windowsManagedDeploymentMarkerAbsent
	t.Cleanup(func() { windowsManagedDeploymentMarkerAbsent = original })
	windowsManagedDeploymentMarkerAbsent = func() bool { return true }
	token, closeToken, err := openWindowsProcessTokenOwner()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeToken)
	current, err := token.defaultOwner()
	if err != nil {
		t.Fatal(err)
	}
	// Cleanups run last first: the owner is restored before the token closes,
	// so later tests see the token as TestMain left it.
	t.Cleanup(func() {
		if err := token.setDefaultOwner(current); err != nil {
			t.Errorf("restore the default owner %s: %v", current, err)
		}
	})
	// TestMain made the token user the default owner; start from the owner
	// the token had at process start (BUILTIN\Administrators when elevated),
	// so the real change below is still exercised.
	previous := current
	if testStartDefaultOwner != nil {
		if err := token.setDefaultOwner(testStartDefaultOwner); err != nil {
			t.Fatalf("restore the process start default owner %s: %v", testStartDefaultOwner, err)
		}
		previous = testStartDefaultOwner
	}
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	changed := UseCurrentUserAsWindowsDefaultOwner([]string{"hook", "--connector", "claudecode"})
	t.Logf("token user %s, default owner before %s, changed %v, elevated %v",
		user.User.Sid, previous, changed, windows.GetCurrentProcessToken().IsElevated())
	if changed == previous.Equals(user.User.Sid) {
		t.Fatalf("changed = %v with default owner %s for user %s", changed, previous, user.User.Sid)
	}
	dir := filepath.Join(t.TempDir(), "hooks", ".outage-warnings")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "marker")
	file, err := os.OpenFile(marker, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	for _, path := range []string{filepath.Dir(dir), dir, marker} {
		sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		owner, _, err := sd.Owner()
		if err != nil {
			t.Fatal(err)
		}
		if !owner.Equals(user.User.Sid) {
			t.Fatalf("%s is owned by %s, want the token user %s", path, owner, user.User.Sid)
		}
	}
}

// On a computer with a managed deployment the real check (marker or install
// root) keeps the token as it is, elevated or not.
func TestLiveManagedComputerKeepsTheTokenOwner(t *testing.T) {
	if !windowsManagedDeploymentHere(t) {
		t.Skip("no managed deployment on this computer")
	}
	token, closeToken, err := openWindowsProcessTokenOwner()
	if err != nil {
		t.Fatal(err)
	}
	defer closeToken()
	before, err := token.defaultOwner()
	if err != nil {
		t.Fatal(err)
	}
	if UseCurrentUserAsWindowsDefaultOwner([]string{"hook", "--connector", "claudecode"}) {
		t.Fatal("the token owner changed on a managed computer")
	}
	after, err := token.defaultOwner()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("managed computer: default owner %s kept", after)
	if !after.Equals(before) {
		t.Fatalf("default owner %s, was %s", after, before)
	}
}
