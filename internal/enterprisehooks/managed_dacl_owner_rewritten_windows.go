// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// windowsDACLEntriesOf reads every ACE of dacl. An ACE that is neither an
// access-allowed nor an access-denied ACE keeps an empty SID.
func windowsDACLEntriesOf(dacl *windows.ACL) ([]windowsDACLEntry, error) {
	if dacl == nil {
		return nil, errors.New("enterprise hooks: null Windows DACL")
	}
	entries := make([]windowsDACLEntry, 0, dacl.AceCount)
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			return nil, err
		}
		if ace == nil {
			return nil, fmt.Errorf("enterprise hooks: unreadable Windows ACE %d", index)
		}
		entry := windowsDACLEntry{aceType: ace.Header.AceType, flags: ace.Header.AceFlags, mask: uint32(ace.Mask)}
		switch ace.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE, windows.ACCESS_DENIED_ACE_TYPE:
			entry.sid = (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// windowsUserPathCanonicalExpected is the canonical managed DACL of target
// for a file or a folder, as Windows stores it.
func windowsUserPathCanonicalExpected(target *windows.SID, directory bool) ([]windowsDACLExpectedEntry, error) {
	applied, err := windowsUserPathAppliedCanonicalACEs(target, directory)
	if err != nil {
		return nil, err
	}
	expected := make([]windowsDACLExpectedEntry, 0, len(applied))
	for _, want := range applied {
		expected = append(expected, windowsDACLExpectedEntry{sid: want.sid.String(), mask: uint32(want.mask), flags: want.flags})
	}
	return expected, nil
}

// windowsUserPathOwnerRewrittenDescriptor reports whether sd is owned by
// target and carries the protected canonical managed DACL of path as an
// owner write leaves it (windowsOwnerRewrittenDACL), with the read-only
// extra grants the strict check of path tolerates.
func windowsUserPathOwnerRewrittenDescriptor(path string, sd *windows.SECURITY_DESCRIPTOR, target *windows.SID, directory bool) bool {
	if sd == nil || target == nil {
		return false
	}
	owner, ownerDefaulted, err := sd.Owner()
	if err != nil || ownerDefaulted || owner == nil || !owner.Equals(target) {
		return false
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return false
	}
	dacl, daclDefaulted, err := sd.DACL()
	if err != nil || daclDefaulted || dacl == nil {
		return false
	}
	entries, err := windowsDACLEntriesOf(dacl)
	if err != nil {
		return false
	}
	expected, err := windowsUserPathCanonicalExpected(target, directory)
	if err != nil {
		return false
	}
	return windowsOwnerRewrittenDACL(entries, expected, target.String(), windowsReadOnlyExtraACEsTolerated(path, directory))
}

// windowsManagedFileOwnerRewrittenDescriptor is
// windowsUserPathOwnerRewrittenDescriptor for a managed file.
func windowsManagedFileOwnerRewrittenDescriptor(sd *windows.SECURITY_DESCRIPTOR, target *windows.SID) bool {
	return windowsUserPathOwnerRewrittenDescriptor("", sd, target, false)
}

// windowsUserPathOwnerRewritten reports whether path is a folder (directory)
// or a single-link regular file, reached without a reparse point at its
// last element, whose security is the owner-rewritten managed shape.
func windowsUserPathOwnerRewritten(path string, target *windows.SID, directory bool) bool {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	if directory != info.IsDir() || (!directory && !info.Mode().IsRegular()) {
		return false
	}
	ptr, err := winpath.UTF16Ptr(path)
	if err != nil {
		return false
	}
	attributes, err := windows.GetFileAttributes(ptr)
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return false
	}
	if !directory && validateWindowsRegularFileSingleLink(path) != nil {
		return false
	}
	extended, err := winpath.Extended(path)
	if err != nil {
		return false
	}
	sd, err := windows.GetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	return windowsUserPathOwnerRewrittenDescriptor(path, sd, target, directory)
}

// validateWindowsUserPathElementOrOwnerRewritten is the strict managed check
// of a target-owned folder or file, or exactly the canonical DACL an owner
// write left without its OWNER RIGHTS entry (rel-1-0-6:GAP-0303).
func validateWindowsUserPathElementOrOwnerRewritten(path string, target *windows.SID, directory bool) error {
	err := validateWindowsUserPathElement(path, target, directory, directory, true)
	if err == nil || errors.Is(err, os.ErrNotExist) {
		return err
	}
	if windowsUserPathOwnerRewritten(path, target, directory) {
		return nil
	}
	return err
}

// validateWindowsManagedRuntimeBundleElement is the trust check of an
// immutable managed runtime generation bundle. The digest the protected
// selector pins still authenticates the bytes of a selected bundle.
func validateWindowsManagedRuntimeBundleElement(path string, target *windows.SID) error {
	return validateWindowsUserPathElementOrOwnerRewritten(path, target, false)
}

// validateWindowsManagedRuntimeGenerationCollectionRoots is
// validateWindowsManagedRuntimeGenerationRoots for collection and deletion:
// each of <data dir> and <data dir>\hooks may also be in the owner-rewritten
// shape. Publication and verification keep the strict check.
func validateWindowsManagedRuntimeGenerationCollectionRoots(dataDir string, target *windows.SID) error {
	for _, path := range []string{dataDir, filepath.Join(dataDir, "hooks")} {
		if err := validateWindowsUserPathElementOrOwnerRewritten(path, target, true); err != nil {
			return err
		}
	}
	return nil
}

// windowsManagedRuntimeBundleRestoreOwnerRights is a seam for tests.
var windowsManagedRuntimeBundleRestoreOwnerRights = restoreWindowsManagedFileOwnerRights

func restoreWindowsManagedFileOwnerRights(path string, target *windows.SID) (bool, error) {
	return restoreWindowsUserPathOwnerRights(path, target, false)
}

// restoreWindowsUserPathOwnerRights puts the OWNER RIGHTS entry back on a
// managed folder or file in the exact owner-rewritten shape and reports
// whether it changed it. Every other entry, a tolerated read-only grant of
// another product included, is kept as it is; an inherit-only OWNER RIGHTS
// entry is dropped. Any other shape, a link, a file with another name and an
// object the caller cannot open for WRITE_DAC are left as they are for the
// trust check to judge. LocalSystem holds full control in that shape, and so
// does the owner, which no OWNER RIGHTS entry limits there.
func restoreWindowsUserPathOwnerRights(path string, target *windows.SID, directory bool) (bool, error) {
	if target == nil {
		return false, errors.New("enterprise hooks: target SID is unavailable for the OWNER RIGHTS restore")
	}
	extended, err := winpath.Extended(path)
	if err != nil {
		return false, err
	}
	ptr, err := windows.UTF16PtrFromString(extended)
	if err != nil {
		return false, err
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if directory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	handle, err := windows.CreateFile(
		ptr,
		windows.READ_CONTROL|windows.WRITE_DAC|windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		flags,
		0,
	)
	switch {
	case errors.Is(err, windows.ERROR_FILE_NOT_FOUND), errors.Is(err, windows.ERROR_PATH_NOT_FOUND),
		errors.Is(err, windows.ERROR_ACCESS_DENIED):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("enterprise hooks: open %s for the OWNER RIGHTS restore: %w", path, err)
	}
	defer windows.CloseHandle(handle)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return false, err
	}
	isDirectory := info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || isDirectory != directory ||
		(!directory && info.NumberOfLinks != 1) {
		return false, nil
	}
	current, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, fmt.Errorf("enterprise hooks: read the security of %s: %w", path, err)
	}
	if !windowsUserPathOwnerRewrittenDescriptor(path, current, target, directory) {
		return false, nil
	}
	dacl, _, err := current.DACL()
	if err != nil || dacl == nil {
		return false, fmt.Errorf("enterprise hooks: read the DACL of %s: %w", path, err)
	}
	entries, err := windowsDACLEntriesOf(dacl)
	if err != nil {
		return false, err
	}
	var sddl strings.Builder
	sddl.WriteString("D:P(A;;RC;;;OW)")
	for _, entry := range entries {
		if strings.EqualFold(entry.sid, windowsSIDOwnerRights) {
			continue
		}
		fmt.Fprintf(&sddl, "(A;%s;0x%x;;;%s)", windowsSDDLACEFlags(entry.flags), entry.mask, entry.sid)
	}
	restoredDescriptor, err := windows.SecurityDescriptorFromString(sddl.String())
	if err != nil {
		return false, fmt.Errorf("enterprise hooks: build the restored DACL of %s: %w", path, err)
	}
	restoredDACL, _, err := restoredDescriptor.DACL()
	if err != nil || restoredDACL == nil {
		return false, fmt.Errorf("enterprise hooks: build the restored DACL of %s: %w", path, err)
	}
	if err := setWindowsObjectDACLNoPropagation(handle, restoredDACL, directory); err != nil {
		return false, fmt.Errorf("enterprise hooks: restore the OWNER RIGHTS entry on %s: %w", path, err)
	}
	after, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return true, fmt.Errorf("enterprise hooks: reread the security of %s: %w", path, err)
	}
	owner, _, err := after.Owner()
	if err != nil || owner == nil || !owner.Equals(target) {
		return true, fmt.Errorf("enterprise hooks: owner of %s changed during the OWNER RIGHTS restore", path)
	}
	afterDACL, _, err := after.DACL()
	if err != nil || afterDACL == nil {
		return true, fmt.Errorf("enterprise hooks: DACL of %s is unreadable after the OWNER RIGHTS restore", path)
	}
	if err := validateWindowsUserPathProtectionACL(path, after, afterDACL, target, directory); err != nil {
		return true, err
	}
	return true, nil
}

// restoreWindowsManagedRuntimeRootsOwnerRights restores <data dir> and its
// hooks child when an owner write left them without OWNER RIGHTS; a failure
// is reported and left to the trust check, which accepts that shape here.
func restoreWindowsManagedRuntimeRootsOwnerRights(dataDir string, target *windows.SID) {
	for _, path := range []string{dataDir, filepath.Join(dataDir, "hooks")} {
		reportWindowsOwnerRightsRestore(path, func() (bool, error) {
			return restoreWindowsUserPathOwnerRights(path, target, true)
		})
	}
}

func reportWindowsOwnerRightsRestore(path string, restore func() (bool, error)) {
	restored, err := restore()
	switch {
	case err != nil:
		fmt.Fprintf(os.Stderr, "[enterprise-hooks] could not restore the OWNER RIGHTS entry of %s: %v\n", path, err)
	case restored:
		fmt.Fprintf(os.Stderr, "[enterprise-hooks] restored the OWNER RIGHTS entry an owner change removed from %s\n", path)
	}
}

// RestoreWindowsManagedUserStateOwnerRights restores, for one enrolled
// account, the OWNER RIGHTS entry an owner write took out of its managed
// .defenseclaw folder, its hooks child and the files directly in them
// (generation bundles, hook scripts, tokens, configs), and returns how many
// it restored. Only objects owned by the account and in the exact
// owner-rewritten shape change; no folder is walked deeper, and neither
// folder may be or lie behind a reparse point. A standalone Setup runs it
// with its own gateway before the installed helper of an older release
// collects or purges that state (rel-1-0-6:GAP-0303), so a host that release
// left half-uninstalled reaches a clean end.
func RestoreWindowsManagedUserStateOwnerRights(sid, dataDir string) (int, error) {
	target, err := validateWindowsEnterpriseTargetSID(sid)
	if err != nil {
		return 0, err
	}
	if err := validateWindowsManagedRuntimeGenerationPath(dataDir, ".defenseclaw"); err != nil {
		return 0, err
	}
	restored := 0
	var failures []error
	for _, dir := range []string{dataDir, filepath.Join(dataDir, "hooks")} {
		if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			failures = append(failures, err)
			continue
		}
		if err := winpath.RejectReparseChain(dir); err != nil {
			failures = append(failures, err)
			continue
		}
		changed, err := restoreWindowsUserPathOwnerRights(dir, target, true)
		if changed {
			restored++
		}
		if err != nil {
			failures = append(failures, err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if len(entries) > 4*windowsManagedRuntimeGenerationGCMaxCandidates {
			failures = append(failures, fmt.Errorf("enterprise hooks: %s has too many entries for the OWNER RIGHTS restore", dir))
			continue
		}
		for _, entry := range entries {
			if !entry.Type().IsRegular() {
				continue
			}
			changed, err := restoreWindowsUserPathOwnerRights(filepath.Join(dir, entry.Name()), target, false)
			if changed {
				restored++
			}
			if err != nil {
				failures = append(failures, err)
			}
		}
	}
	return restored, errors.Join(failures...)
}
