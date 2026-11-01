// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// p0-round:GAP-1365: an object a killed first install created under the
// canonical install root, before it was given its own protected DACL, carries
// only the ACEs it inherited from that root. The forced uninstall purge
// accepts that shape below the root, and nothing looser.
func TestWindowsNamespacePurgeAcceptsOnlyTheInheritedShapeBelowTheRoot(t *testing.T) {
	descriptors, err := windowsNamespacePurgeCanonicalDescriptors("S-1-5-80-1-2-3-4-5")
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "DefenseClaw")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	set := func(path, sddl string, protected bool) {
		t.Helper()
		sd, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			t.Fatalf("%s: %v", sddl, err)
		}
		owner, _, _ := sd.Owner()
		group, _, _ := sd.Group()
		dacl, _, _ := sd.DACL()
		info := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION | windows.GROUP_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION)
		if protected {
			info |= windows.PROTECTED_DACL_SECURITY_INFORMATION
		} else {
			info |= windows.UNPROTECTED_DACL_SECURITY_INFORMATION
		}
		extended, err := winpath.Extended(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := windows.SetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, info, owner, group, dacl, nil); err != nil {
			t.Fatalf("set %s on %s: %v", sddl, path, err)
		}
	}
	set(root, "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)", true)
	bin := filepath.Join(root, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(bin, "defenseclaw.exe")
	if err := os.WriteFile(exe, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// What the killed install left: owned by LocalSystem, inherited only.
	set(bin, "O:SYG:SYD:", false)
	set(exe, "O:SYG:SYD:", false)
	matches := func(path string, allowed []*windows.SECURITY_DESCRIPTOR) bool {
		t.Helper()
		ptr, err := windows.UTF16PtrFromString(path)
		if err != nil {
			t.Fatal(err)
		}
		handle, err := windows.CreateFile(ptr, windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
			nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer windows.CloseHandle(handle)
		matched, err := windowsNamespacePurgeHandleMatches(handle, allowed)
		if err != nil {
			t.Fatal(err)
		}
		return matched
	}
	if matches(bin, descriptors.directories) || matches(exe, descriptors.files) {
		t.Fatal("the inherited shape matched a canonical protected descriptor")
	}
	if !matches(bin, descriptors.inheritedDirectories) {
		t.Fatalf("inherited folder refused: %s", ownerRewrittenTestSDDL(t, bin))
	}
	if !matches(exe, descriptors.inheritedFiles) {
		t.Fatalf("inherited file refused: %s", ownerRewrittenTestSDDL(t, exe))
	}
	// An explicit extra writer on the child, a foreign owner, or a protected
	// copy with an extra ACE stay foreign.
	set(exe, "O:SYG:SYD:(A;;0x1301bf;;;BU)", false)
	if matches(exe, descriptors.inheritedFiles) || matches(exe, descriptors.files) {
		t.Fatal("inherited file with an explicit Users write ACE accepted")
	}
	set(exe, "O:BUG:BUD:", false)
	if matches(exe, descriptors.inheritedFiles) {
		t.Fatal("inherited file owned by Users accepted")
	}
	set(bin, "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;OICI;0x1301bf;;;BU)", true)
	if matches(bin, descriptors.inheritedDirectories) || matches(bin, descriptors.directories) {
		t.Fatal("protected folder with a Users write ACE accepted")
	}
}
