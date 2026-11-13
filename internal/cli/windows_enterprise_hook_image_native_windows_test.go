//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

// Native checks of the premises the hook image stage and prune rest on
// (GAP-0751 review 1, P2-3). They run on the Windows Native CI runner, where
// .github/workflows/windows-native.yml requires each to PASS.

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const windowsHookImageNativeHelperEnv = "DC_HOOKIMG_NATIVE_HELPER"

// TestWindowsHookImageNativeHelperProcess is the child the native tests start
// from a launch folder (a copy of this test binary); it does nothing in a
// normal run.
func TestWindowsHookImageNativeHelperProcess(t *testing.T) {
	mode := os.Getenv(windowsHookImageNativeHelperEnv)
	if mode == "" {
		t.Skip("helper process only")
	}
	switch {
	case mode == "sleep":
		time.Sleep(2 * time.Minute)
	case strings.HasPrefix(mode, "handle:"):
		parts := strings.SplitN(strings.TrimPrefix(mode, "handle:"), ":", 2)
		value, _ := strconv.ParseUint(parts[0], 10, 64)
		want := ""
		if len(parts) == 2 {
			want = parts[1]
		}
		fmt.Println("HOOKIMG:" + windowsHookImageNativeHandleState(windows.Handle(value), want))
	case mode == "token":
		fmt.Println("HOOKIMG:" + windowsHookImageNativeTokenState())
	}
	os.Exit(0)
}

// windowsHookImageNativeHandleState says whether handle in this process is a
// file named want (the parent's inheritable handle) or not.
func windowsHookImageNativeHandleState(handle windows.Handle, want string) string {
	buffer := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), 0)
	if err != nil || n == 0 {
		return "not-inherited"
	}
	got := windows.UTF16ToString(buffer[:n])
	if strings.EqualFold(filepath.Base(got), want) {
		return "inherited"
	}
	return "not-inherited"
}

// windowsHookImageNativeTokenState reports this process's Administrators group
// state and how many privileges its token keeps.
func windowsHookImageNativeTokenState() string {
	token := windows.GetCurrentProcessToken()
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return "error:" + err.Error()
	}
	groups, err := token.GetTokenGroups()
	if err != nil {
		return "error:" + err.Error()
	}
	state := "admins-absent"
	for _, group := range groups.AllGroups() {
		if !group.Sid.Equals(administrators) {
			continue
		}
		switch {
		case group.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY != 0:
			state = "admins-deny-only"
		case group.Attributes&windows.SE_GROUP_ENABLED != 0:
			state = "admins-enabled"
		default:
			state = "admins-disabled"
		}
	}
	var needed uint32
	_ = windows.GetTokenInformation(token, windows.TokenPrivileges, nil, 0, &needed)
	privileges := -1
	if needed > 0 {
		buffer := make([]byte, needed)
		if err := windows.GetTokenInformation(token, windows.TokenPrivileges, &buffer[0], needed, &needed); err == nil {
			privileges = int((*windows.Tokenprivileges)(unsafe.Pointer(&buffer[0])).PrivilegeCount)
		}
	}
	return fmt.Sprintf("%s privileges=%d", state, privileges)
}

// windowsHookImageNativeLaunchCopy copies this test binary into
// <tmp>\bin\hooks\<16 hex>\defenseclaw-hook.exe and returns the copy and its
// folder.
func windowsHookImageNativeLaunchCopy(t *testing.T) (string, string) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	folder := filepath.Join(t.TempDir(), "bin", "hooks", "0123456789abcdef")
	if err := os.MkdirAll(folder, 0o755); err != nil {
		t.Fatal(err)
	}
	image := filepath.Join(folder, "defenseclaw-hook.exe")
	source, err := os.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	target, err := os.Create(image)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(target, source); err != nil {
		t.Fatal(err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	return image, folder
}

func windowsHookImageNativeHelperArgs() []string {
	return []string{"-test.run=^TestWindowsHookImageNativeHelperProcess$", "-test.count=1"}
}

func windowsHookImageNativeMarker(t *testing.T, output []byte) string {
	t.Helper()
	for _, line := range strings.Split(string(output), "\n") {
		if marker, ok := strings.CutPrefix(strings.TrimSpace(line), "HOOKIMG:"); ok {
			return marker
		}
	}
	t.Fatalf("the helper printed no marker: %q", output)
	return ""
}

// Prune removes a launch folder only by first renaming it, on the premise
// that Windows refuses to rename a folder while an image in it runs.
func TestWindowsHookImageNativeRenameRefusedWhileAnImageRuns(t *testing.T) {
	image, folder := windowsHookImageNativeLaunchCopy(t)
	child := exec.Command(image, windowsHookImageNativeHelperArgs()...)
	child.Env = append(os.Environ(), windowsHookImageNativeHelperEnv+"=sleep")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = child.Process.Kill()
		_, _ = child.Process.Wait()
	}()
	time.Sleep(500 * time.Millisecond)
	aside := filepath.Join(filepath.Dir(folder), ".staging-"+strings.Repeat("a", 32))
	fsys := osWindowsHookImageFS{}
	if err := fsys.Rename(folder, aside); err == nil {
		t.Fatal("Windows renamed a launch folder while an image in it ran; prune would remove a running session's launch set")
	} else if !windowsHookImageRenameBusy(err) {
		t.Fatalf("the refusal %v is not one the publish retry and prune treat as busy", err)
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_, _ = child.Process.Wait()
	var err error
	for attempt := 0; attempt < 50; attempt++ {
		if err = fsys.Rename(folder, aside); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("the folder could not be renamed after the image ended: %v", err)
	}
}

// MkdirProtected gives bin\hooks and each launch folder bin's protection.
func TestWindowsHookImageNativeFolderDACL(t *testing.T) {
	if !windowsEnterpriseIsElevated() {
		t.Skip("needs an elevated administrator (Windows Native CI runs elevated)")
	}
	restoreOwner, err := adoptWindowsAdministratorsDefaultOwner()
	if err != nil {
		t.Fatal(err)
	}
	defer restoreOwner()
	path := filepath.Join(t.TempDir(), "hooks")
	if err := (osWindowsHookImageFS{}).MkdirProtected(path); err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := descriptor.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal("the launch folder access list inherits from its parent")
	}
	want := "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
	if got := strings.Replace(descriptor.String(), "D:PAI(", "D:P(", 1); got != want {
		t.Fatalf("launch folder descriptor %s, want %s (Users read and execute only, no add-subdirectory)", got, want)
	}
	if err := (osWindowsHookImageFS{}).MkdirProtected(path); err == nil {
		t.Fatal("MkdirProtected reused an existing folder")
	}
}

// The start check ends an image that does not answer in time.
func TestWindowsHookImageNativeStarterTimesOut(t *testing.T) {
	image, _ := windowsHookImageNativeLaunchCopy(t)
	t.Setenv(windowsHookImageNativeHelperEnv, "sleep")
	began := time.Now()
	_, err := (osWindowsHookImageStarter{}).Start(windowsHookImageStart{
		Path: image, Args: windowsHookImageNativeHelperArgs(), Timeout: 3 * time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "no answer within") {
		t.Fatalf("a hanging image = %v; want a timeout", err)
	}
	if elapsed := time.Since(began); elapsed > 30*time.Second {
		t.Fatalf("the timeout took %s", elapsed)
	}
}

// The start check's image inherits no handle of Setup's process.
func TestWindowsHookImageNativeStarterInheritsNoHandles(t *testing.T) {
	image, _ := windowsHookImageNativeLaunchCopy(t)
	marker := filepath.Join(t.TempDir(), "inheritable.txt")
	name, err := windows.UTF16PtrFromString(marker)
	if err != nil {
		t.Fatal(err)
	}
	attributes := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), InheritHandle: 1}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ,
		attributes, windows.CREATE_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(handle)
	t.Setenv(windowsHookImageNativeHelperEnv, fmt.Sprintf("handle:%d:%s", uintptr(handle), filepath.Base(marker)))
	result, err := (osWindowsHookImageStarter{}).Start(windowsHookImageStart{
		Path: image, Args: windowsHookImageNativeHelperArgs(), Timeout: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := windowsHookImageNativeMarker(t, result.Stdout); got != "not-inherited" {
		t.Fatalf("the started image %s Setup's handle", got)
	}
}

// The start check's image runs without Administrators and without
// privileges, as an agent user's hook does.
func TestWindowsHookImageNativeStarterUsesTheFilteredToken(t *testing.T) {
	image, _ := windowsHookImageNativeLaunchCopy(t)
	t.Setenv(windowsHookImageNativeHelperEnv, "token")
	result, err := (osWindowsHookImageStarter{}).Start(windowsHookImageStart{
		Path: image, Args: windowsHookImageNativeHelperArgs(), Timeout: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Restricted {
		t.Fatalf("the filtered token could not be made: %s", result.TokenProblem)
	}
	state := windowsHookImageNativeMarker(t, result.Stdout)
	if strings.HasPrefix(state, "admins-enabled") || strings.HasPrefix(state, "error:") {
		t.Fatalf("the started image ran with %s", state)
	}
	fields := strings.Fields(state)
	if len(fields) != 2 {
		t.Fatalf("token state %q", state)
	}
	count, err := strconv.Atoi(strings.TrimPrefix(fields[1], "privileges="))
	if err != nil || count < 0 || count > 1 {
		t.Fatalf("the started image kept %s (only SeChangeNotify may stay)", fields[1])
	}
}
