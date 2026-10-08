//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Protected descriptors: SYSTEM and Administrators own and write; standard
// users read policy (agents must load it) but never records.
const (
	publicFileSDDL   = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)"
	privateFileSDDL  = "D:P(A;;FA;;;SY)(A;;FA;;;BA)"
	publicDirSDDL    = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
	privateDirSDDL   = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	adminOwnerSIDStr = "S-1-5-32-544"

	// openCodePluginFileSDDL is publicFileSDDL plus FILE_WRITE_ATTRIBUTES
	// (0x100) for BUILTIN\Users, on the managed OpenCode plugin only.
	// OpenCode's runtime (Bun) opens every source module with
	// READ_CONTROL|FILE_WRITE_ATTRIBUTES|SYNCHRONIZE|GENERIC_READ, even to
	// read it, so with read and execute alone a standard account's import
	// fails ("EPERM reading") and OpenCode runs without the plugin. The
	// right changes only timestamps and basic attributes; the content, the
	// DACL, the owner and the name stay administrator-only.
	openCodePluginFileSDDL   = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1201a9;;;BU)"
	openCodePluginReadAccess = windows.ACCESS_MASK(0x1200a9)
	openCodePluginLoadAccess = openCodePluginReadAccess | windows.FILE_WRITE_ATTRIBUTES
)

var trustedOwner = func(uint32) bool { return true }

func platformPath(_ Options, path string) string { return path }

// validateTrustedDir validates an existing directory, and every ancestor,
// as a parent of machine policy. Tests replace it: a Windows temp tree is
// owned by the test user.
var validateTrustedDir = func(dir string) error {
	return managed.ValidateTrustedDirectoryAncestor(dir, "machine policy directory")
}

// validateTrustedLeafDir validates the policy directory itself with the
// leaf rules (no unprivileged principal may add, change or delete its
// entries) and its ancestors with the ancestor rules. A vendor policy
// directory an administrator made in Explorer inherits ProgramData's
// "Users may create files" entry, which the ancestor rules accept, so a
// standard user could add policy files that apply to every user. Tests
// replace it.
var validateTrustedLeafDir = func(dir string) error {
	return managed.ValidateTrustedRuntimeDir(dir, "machine policy directory")
}

// validatePolicyLeafDir reports a policy directory that unprivileged users
// may write (verify_only inspection; reconcile takes such a directory
// back).
func validatePolicyLeafDir(opts Options, dir string) error {
	if opts.SkipTrustChecks {
		return nil
	}
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return validateTrustedLeafDir(dir)
}

// reclaimDirHandle takes a directory back through its handle; tests replace
// it to run without LocalSystem's restore privilege.
var reclaimDirHandle = func(path string, reclaim func() error) error {
	return enterprisehooks.RunWithWindowsOwnerRestorePrivilege(reclaim)
}

func validateTrustedAncestors(opts Options, path string) error {
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		if _, err := os.Lstat(dir); err == nil {
			return validateTrustedDir(dir)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if dir == filepath.Dir(dir) {
			return fmt.Errorf("%s has no existing ancestor", path)
		}
	}
}

// validateTrustedFile validates an existing policy file and its ancestors;
// tests replace it with validateTrustedDir.
var validateTrustedFile = func(path string) error {
	return managed.ValidateTrustedFilePath(path, "machine policy file")
}

func validateTrustedPolicyFile(_ Options, path string) error {
	return validateTrustedFile(path)
}

// validateOpenCodePluginFile applies the machine policy trust rules to the
// managed OpenCode plugin, with its own rule for the file (see
// openCodePluginLoadable): ancestors as for every policy file.
func validateOpenCodePluginFile(_ Options, path string) error {
	if err := validateTrustedDir(filepath.Dir(path)); err != nil {
		return err
	}
	_, err := openCodePluginLoadable(Options{}, path)
	return err
}

func atomicWriteOpenCodePlugin(_ Options, path string, data []byte) error {
	return atomicWriteSDDL(path, data, openCodePluginFileSDDL)
}

// releaseOpenCodePluginName undoes, before the plugin is rewritten or
// removed, what a standard account can do with the FILE_WRITE_ATTRIBUTES
// right it holds on the installed copy: a read-only attribute (no rename
// replaces the file) and a reparse point set on it (no reader can open it,
// and it is no longer a regular file to replace). It works through a handle
// that does not follow reparse points, changes nothing unless the plugin's
// folder passes the trust rules, and leaves a directory for the writer to
// refuse.
func releaseOpenCodePluginName(_ Options, path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) || (err == nil && info.IsDir()) {
		return nil
	}
	if err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	share := uint32(windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE)
	handle, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES|windows.FILE_WRITE_ATTRIBUTES|windows.SYNCHRONIZE,
		share, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	var basic struct {
		CreationTime, LastAccessTime, LastWriteTime, ChangeTime int64
		FileAttributes                                          uint32
		_                                                       uint32
	}
	if err := windows.GetFileInformationByHandleEx(handle, windows.FileBasicInfo, (*byte)(unsafe.Pointer(&basic)), uint32(unsafe.Sizeof(basic))); err != nil {
		return err
	}
	attributes := basic.FileAttributes
	if attributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 ||
		attributes&(windows.FILE_ATTRIBUTE_READONLY|windows.FILE_ATTRIBUTE_REPARSE_POINT) == 0 {
		return nil
	}
	if err := validateTrustedDir(filepath.Dir(path)); err != nil {
		return err
	}
	if attributes&windows.FILE_ATTRIBUTE_READONLY != 0 {
		basic.CreationTime, basic.LastAccessTime, basic.LastWriteTime, basic.ChangeTime = 0, 0, 0, 0
		basic.FileAttributes = attributes &^ (windows.FILE_ATTRIBUTE_READONLY | windows.FILE_ATTRIBUTE_REPARSE_POINT)
		if basic.FileAttributes == 0 {
			basic.FileAttributes = windows.FILE_ATTRIBUTE_NORMAL
		}
		if err := windows.SetFileInformationByHandle(handle, windows.FileBasicInfo, (*byte)(unsafe.Pointer(&basic)), uint32(unsafe.Sizeof(basic))); err != nil {
			return fmt.Errorf("clear the read-only attribute of %s: %w", path, err)
		}
	}
	if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0 {
		return nil
	}
	// Delete the reparse object itself; the writer then creates the plugin.
	target, err := windows.CreateFile(name, windows.DELETE|windows.SYNCHRONIZE, share, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return fmt.Errorf("remove the reparse point at %s: %w", path, err)
	}
	defer windows.CloseHandle(target)
	deleteFile := byte(1)
	if err := windows.SetFileInformationByHandle(target, windows.FileDispositionInfo, &deleteFile, 1); err != nil {
		return fmt.Errorf("remove the reparse point at %s: %w", path, err)
	}
	return nil
}

// openCodePluginReadOnly reports whether a standard account marked the
// installed plugin read-only with the FILE_WRITE_ATTRIBUTES right Users hold
// on it. OpenCode still loads it, but no rename replaces it, so the guardian
// and repair rewrite it (releaseOpenCodePluginName clears the attribute).
func openCodePluginReadOnly(path string) bool {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	attributes, err := windows.GetFileAttributes(name)
	return err == nil && attributes&windows.FILE_ATTRIBUTE_READONLY != 0
}

// openCodePluginLoadable inspects the installed plugin's own descriptor. It
// is trusted when it is a regular file, not a reparse point, owned by
// Administrators or LocalSystem, and every other principal holds at most
// read and execute plus FILE_WRITE_ATTRIBUTES. It reports loadable when
// BUILTIN\Users holds that access and nothing denies it; a copy written by
// 1.0.52 or earlier (read and execute only) is trusted but not loadable by a
// standard account's OpenCode.
func openCodePluginLoadable(_ Options, path string) (bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("%s is not a regular file", path)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false, err
	}
	attributes, err := windows.GetFileAttributes(name)
	if err != nil {
		return false, err
	}
	if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return false, fmt.Errorf("%s is a reparse point", path)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, fmt.Errorf("inspect %s: %w", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return false, err
	}
	if owner == nil || !(owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) || owner.IsWellKnown(windows.WinLocalSystemSid)) {
		return false, fmt.Errorf("%s is not owned by Administrators or LocalSystem", path)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return false, fmt.Errorf("%s has no DACL", path)
	}
	usersLoad, denied := false, false
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
			return false, err
		}
		if ace == nil || ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		switch ace.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		case windows.ACCESS_DENIED_ACE_TYPE, 0x6, 0xA, 0xC: // denied, denied object, denied callback (object)
			denied = true
			continue
		default:
			return false, fmt.Errorf("%s has an unsupported ACE type 0x%x", path, ace.Header.AceType)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
			continue
		}
		if ace.Mask&^openCodePluginLoadAccess != 0 {
			return false, fmt.Errorf("%s grants %s access 0x%x beyond read", path, sid, uint32(ace.Mask))
		}
		if sid.IsWellKnown(windows.WinBuiltinUsersSid) && ace.Mask&openCodePluginLoadAccess == openCodePluginLoadAccess {
			usersLoad = true
		}
	}
	return usersLoad && !denied, nil
}

func openNoFollow(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeIrregular != 0 {
		return nil, fmt.Errorf("%s is a reparse point", path)
	}
	return os.Open(path)
}

func applySDDL(path, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	owner, err := windows.StringToSid(adminOwnerSIDStr)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, dacl, nil,
	)
}

// ensurePolicyDir creates the missing directories of dir. Each one is
// created with DefenseClaw's owner and protected DACL in the same call, so
// no other principal ever owns it; an object that appears at a missing
// path first is refused, never adopted and re-ACLed (a vendor target's next
// reconcile takes it back through reclaimPolicyDirs, by handle). Existing
// directories are only validated here: DefenseClaw's own directories, such
// as the hook runtime root that holds the public summary, keep the ACLs
// their lifecycle sets.
func ensurePolicyDir(opts Options, dir string) ([]string, error) {
	var missing []string
	for cur := dir; ; cur = filepath.Dir(cur) {
		if _, err := os.Lstat(cur); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		missing = append([]string{cur}, missing...)
		if cur == filepath.Dir(cur) {
			break
		}
	}
	if !opts.SkipTrustChecks {
		if err := validateTrustedAncestors(opts, filepath.Join(dir, "x")); err != nil {
			return nil, err
		}
	}
	created := []string{}
	for _, cur := range missing {
		if err := createProtectedDir(cur); err != nil {
			return created, err
		}
		created = append(created, cur)
	}
	return created, nil
}

// protectedDirDescriptor is the owner and protected DACL of every machine
// policy directory DefenseClaw creates or takes back.
func protectedDirDescriptor() (*windows.SECURITY_DESCRIPTOR, error) {
	return windows.SecurityDescriptorFromString("O:" + adminOwnerSIDStr + publicDirSDDL)
}

func createProtectedDir(path string) error {
	sd, err := protectedDirDescriptor()
	if err != nil {
		return err
	}
	attributes := windows.SecurityAttributes{SecurityDescriptor: sd}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	if err := windows.CreateDirectory(name, &attributes); err != nil {
		if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return fmt.Errorf("%s appeared while DefenseClaw was creating it; refusing to adopt a directory it did not create: %w", path, err)
		}
		return fmt.Errorf("create %s: %w", path, err)
	}
	handle, err := openDirNoFollow(path, windows.READ_CONTROL)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	if err := requirePlainDirectory(handle, path); err != nil {
		return err
	}
	return requireTrustedOwner(handle, path)
}

// openDirNoFollow opens path itself, never the target of a reparse point.
func openDirNoFollow(path string, access uint32) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	handle, err := windows.CreateFile(name, access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return windows.InvalidHandle, fmt.Errorf("open %s: %w", path, err)
	}
	return handle, nil
}

func requirePlainDirectory(handle windows.Handle, path string) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return fmt.Errorf("inspect %s: %w", path, err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%s is a reparse point", path)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return fmt.Errorf("%s is not a directory", path)
	}
	return nil
}

func requireTrustedOwner(handle windows.Handle, path string) error {
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("inspect owner of %s: %w", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("inspect owner of %s: %w", path, err)
	}
	if owner == nil || !(owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) || owner.IsWellKnown(windows.WinLocalSystemSid)) {
		return fmt.Errorf("%s is not owned by Administrators or LocalSystem", path)
	}
	return nil
}

// programDataRelative returns the trusted ProgramData root and path
// relative to it when path lies strictly below that root.
func programDataRelative(opts Options, path string) (string, string, bool) {
	root := filepath.Clean(opts.WindowsProgramData)
	if !windowsAbsolute(root) {
		return "", "", false
	}
	rel, err := filepath.Rel(root, filepath.Clean(path))
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, `..\`) || filepath.IsAbs(rel) {
		return "", "", false
	}
	return root, rel, true
}

func plainDirectory(info os.FileInfo) bool {
	return info.IsDir() && info.Mode()&(os.ModeSymlink|os.ModeIrregular) == 0
}

// reclaimPolicyDirs takes back the vendor directories between the trusted
// ProgramData root and dir that an unprivileged user created first, and
// the policy directory itself when unprivileged users may write it.
// BUILTIN\Users may create folders directly in ProgramData and owns what it
// creates, so a single mkdir would otherwise make every reconcile fail and
// leave the connector's machine policy unpublished for every user. Each
// existing, untrusted component is opened without following reparse
// points; a plain directory receives DefenseClaw's owner and protected DACL
// through that handle. Nothing propagates to its children: the target's
// inspection reports foreign entries inside instead. A file, junction or
// symbolic link an unprivileged user put at a component is removed or moved
// aside (displacePlanted), never followed, and the directory is created in
// its place at once. Directories outside ProgramData are left alone, and an
// object an administrator owns is refused.
func reclaimPolicyDirs(opts Options, dir string) (policyTakeBack, error) {
	var result policyTakeBack
	root, rel, ok := programDataRelative(opts, dir)
	if !ok {
		return result, nil
	}
	if err := validateTrustedDir(root); err != nil {
		return result, err
	}
	cur := root
	parts := strings.Split(rel, `\`)
	for index, part := range parts {
		cur = filepath.Join(cur, part)
		info, err := os.Lstat(cur)
		if errors.Is(err, os.ErrNotExist) {
			return result, nil
		}
		if err != nil {
			return result, err
		}
		validate := validateTrustedDir
		if index == len(parts)-1 {
			validate = validateTrustedLeafDir
		}
		trustErr := validate(cur)
		if trustErr == nil {
			continue
		}
		if !plainDirectory(info) {
			if err := replacePlantedWithDir(opts, cur, &result); err != nil {
				return result, fmt.Errorf("%w; it is not a plain directory, and DefenseClaw could not replace it: %v", trustErr, err)
			}
			continue
		}
		if err := reclaimDir(cur); err != nil {
			return result, fmt.Errorf("%w; taking it back failed: %v", trustErr, err)
		}
		if err := validate(cur); err != nil {
			return result, err
		}
		result.reclaimed = append(result.reclaimed, cur)
	}
	return result, nil
}

// plantedAttempts bounds how often one reconcile clears an object that
// reappears at a vendor path before DefenseClaw can create the directory.
const plantedAttempts = 3

// plantedCleared runs between clearing a planted object and creating the
// directory in its place; tests replace it to plant the object again.
var plantedCleared = func(string) {}

// replacePlantedWithDir clears the planted object at path and creates the
// protected directory in the same step, so the name is DefenseClaw's before
// anyone can plant it again.
func replacePlantedWithDir(opts Options, path string, result *policyTakeBack) error {
	for attempt := 1; ; attempt++ {
		note, err := displacePlanted(opts, path)
		if err != nil {
			return err
		}
		result.notes = append(result.notes, note)
		plantedCleared(path)
		err = createProtectedDir(path)
		if err == nil {
			result.created = append(result.created, path)
			return nil
		}
		if !errors.Is(err, windows.ERROR_ALREADY_EXISTS) || attempt == plantedAttempts {
			return err
		}
	}
}

// clearPolicyFileName clears a non-regular object an unprivileged user put
// at a policy file path under ProgramData (a directory, junction or symbolic
// link where DefenseClaw's drop-in belongs), so it cannot keep the drop-in
// from being written. A regular file there is the reader's to judge.
func clearPolicyFileName(opts Options, path string) (string, error) {
	if _, _, ok := programDataRelative(opts, path); !ok {
		return "", nil
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if info.Mode().IsRegular() {
		return "", nil
	}
	note, err := displacePlanted(opts, path)
	if err != nil {
		return "", fmt.Errorf("%s is not a regular file, and DefenseClaw could not remove it: %w", path, err)
	}
	return note, nil
}

// displaceUntrustedPolicyFiles moves aside the *.json entries of a vendor
// policy directory under ProgramData that an unprivileged principal owns,
// once DefenseClaw holds the directory itself. Such a file was planted
// before the directory was taken back; its owner could keep editing it, and
// Copilot may load it as a machine-wide hook for every user. Files an
// administrator owns are left for inspection to report, and keep (the
// DefenseClaw drop-in) is handled by its writer.
func displaceUntrustedPolicyFiles(opts Options, dir, keep string, state *State) {
	displaceUntrusted(opts, dir, state, false, func(name string) bool {
		return strings.HasSuffix(strings.ToLower(name), ".json") && !strings.EqualFold(name, keep)
	})
}

// displaceUntrustedEntries moves aside every entry of a vendor folder
// DefenseClaw holds (files of any kind and folders) that an unprivileged
// principal owns or can change.
func displaceUntrustedEntries(opts Options, dir string, state *State) {
	displaceUntrusted(opts, dir, state, true, func(string) bool { return true })
}

func displaceUntrusted(opts Options, dir string, state *State, dirs bool, match func(string) bool) {
	if opts.SkipTrustChecks {
		return
	}
	if _, _, ok := programDataRelative(opts, dir); !ok || validateTrustedLeafDir(dir) != nil {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		name := entry.Name()
		if !match(name) {
			continue
		}
		path := filepath.Join(dir, name)
		info, err := os.Lstat(path)
		if err != nil || (plainDirectory(info) && (!dirs || validateTrustedDir(path) == nil)) {
			continue
		}
		if info.Mode().IsRegular() && validateTrustedPolicyFile(opts, path) == nil {
			continue
		}
		note, err := displacePlanted(opts, path)
		switch {
		case errors.Is(err, errOwnedByAdministrator):
		case err != nil:
			state.detail("could not move %s aside: %v", path, err)
		default:
			state.detail("%s", note)
		}
	}
}

// displaceUntrustedPolicyFile moves aside the regular file at path, in a
// vendor policy directory under ProgramData that DefenseClaw holds, when an
// unprivileged principal owns it or may change it: it was planted before
// DefenseClaw took the directory back, its owner could keep editing it, and
// the vendor loads it for every user. A file an administrator owns is left
// for the reader to judge. It reports whether the file was moved.
func displaceUntrustedPolicyFile(opts Options, path string, state *State) bool {
	if opts.SkipTrustChecks {
		return false
	}
	dir := filepath.Dir(path)
	if _, _, ok := programDataRelative(opts, dir); !ok || validateTrustedLeafDir(dir) != nil {
		return false
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || validateTrustedPolicyFile(opts, path) == nil {
		return false
	}
	note, err := displacePlanted(opts, path)
	switch {
	case errors.Is(err, errOwnedByAdministrator):
		return false
	case err != nil:
		state.detail("could not move %s aside: %v", path, err)
		return false
	}
	state.detail("%s", note)
	return true
}

// errOwnedByAdministrator marks an object Administrators, LocalSystem or
// TrustedInstaller owns: an administrator made it, so it is theirs to fix,
// never DefenseClaw's to remove.
var errOwnedByAdministrator = errors.New("it is owned by Administrators, LocalSystem or TrustedInstaller; an administrator must remove or fix it")

const trustedInstallerSID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

// displacePlanted clears path of an object an unprivileged principal put
// where DefenseClaw's machine policy belongs. It works on the object
// itself, through a handle that does not follow reparse points: a junction
// or symbolic link is deleted, never its target; an extra name of a
// hard-linked file is deleted and the file keeps its other names; an empty
// directory is deleted; a regular file or a non-empty directory is renamed
// aside in the same directory, under a hidden name with no vendor
// extension, and gets DefenseClaw's owner and a private DACL, so its former
// owner can no longer change it and an administrator can review it. It
// returns what it did.
func displacePlanted(opts Options, path string) (string, error) {
	var note string
	err := reclaimDirHandle(path, func() error {
		handle, err := openDirNoFollow(path, windows.DELETE|windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER|windows.FILE_READ_ATTRIBUTES)
		if err != nil {
			return err
		}
		defer windows.CloseHandle(handle)
		var info windows.ByHandleFileInformation
		if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
			return fmt.Errorf("inspect %s: %w", path, err)
		}
		privileged, err := ownedByPrivilegedPrincipal(handle, path)
		if err != nil {
			return err
		}
		if privileged {
			return fmt.Errorf("%s: %w", path, errOwnedByAdministrator)
		}
		directory := info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
		switch {
		case info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0:
			if err := deleteByHandle(handle); err != nil {
				return fmt.Errorf("remove %s: %w", path, err)
			}
			note = fmt.Sprintf("removed %s: a link an unprivileged user created where machine policy belongs (its target is untouched)", path)
			return nil
		case !directory && info.NumberOfLinks > 1:
			if err := deleteByHandle(handle); err != nil {
				return fmt.Errorf("remove %s: %w", path, err)
			}
			note = fmt.Sprintf("removed %s: a second name an unprivileged user gave another file where machine policy belongs (the file keeps its other names)", path)
			return nil
		case directory:
			err := deleteByHandle(handle)
			if err == nil {
				note = fmt.Sprintf("removed %s: an empty directory an unprivileged user created where machine policy belongs", path)
				return nil
			}
			if !errors.Is(err, windows.ERROR_DIR_NOT_EMPTY) {
				return fmt.Errorf("remove %s: %w", path, err)
			}
		}
		aside, err := displacedPath(opts, path)
		if err != nil {
			return err
		}
		if err := renameByHandle(handle, aside); err != nil {
			return fmt.Errorf("move %s aside: %w", path, err)
		}
		sddl := privateFileSDDL
		if directory {
			sddl = privateDirSDDL
		}
		if err := setObjectDescriptor(handle, sddl); err != nil {
			note = fmt.Sprintf("moved %s aside to %s: an unprivileged user created it where machine policy belongs; taking its owner and DACL failed: %v", path, aside, err)
			return nil
		}
		note = fmt.Sprintf("moved %s aside to %s: an unprivileged user created it where machine policy belongs; it now has DefenseClaw's owner and a private DACL, for an administrator to review", path, aside)
		return nil
	})
	return note, err
}

func ownedByPrivilegedPrincipal(handle windows.Handle, path string) (bool, error) {
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return false, fmt.Errorf("inspect owner of %s: %w", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return false, fmt.Errorf("inspect owner of %s: %v", path, err)
	}
	return owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) || owner.IsWellKnown(windows.WinLocalSystemSid) ||
		owner.String() == trustedInstallerSID, nil
}

// deleteByHandle deletes the object behind handle itself. POSIX semantics
// free the name as soon as the handle closes, even while another handle
// that allows deletion stays open.
func deleteByHandle(handle windows.Handle) error {
	flags := uint32(windows.FILE_DISPOSITION_DELETE | windows.FILE_DISPOSITION_POSIX_SEMANTICS | windows.FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE)
	exErr := windows.SetFileInformationByHandle(handle, windows.FileDispositionInfoEx, (*byte)(unsafe.Pointer(&flags)), uint32(unsafe.Sizeof(flags)))
	if exErr == nil || errors.Is(exErr, windows.ERROR_DIR_NOT_EMPTY) {
		return exErr
	}
	deleteFile := byte(1)
	if err := windows.SetFileInformationByHandle(handle, windows.FileDispositionInfo, &deleteFile, uint32(unsafe.Sizeof(deleteFile))); err != nil {
		return errors.Join(exErr, err)
	}
	return nil
}

// displacedPath is a fresh hidden name beside path that ends in no vendor
// policy extension, so no agent loads what is moved there.
func displacedPath(opts Options, path string) (string, error) {
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		return "", err
	}
	name := "." + filepath.Base(path) + ".defenseclaw-displaced-" + opts.now().Format("20060102T150405Z") + "-" + hex.EncodeToString(suffix)
	return filepath.Join(filepath.Dir(path), name), nil
}

// renameByHandle renames the object behind handle to target, failing if
// target exists.
func renameByHandle(handle windows.Handle, target string) error {
	name, err := windows.UTF16FromString(target)
	if err != nil {
		return err
	}
	type fileRenameInfo struct {
		ReplaceIfExists uint32
		RootDirectory   windows.Handle
		FileNameLength  uint32
		FileName        [1]uint16
	}
	size := unsafe.Offsetof(fileRenameInfo{}.FileName) + uintptr(len(name))*2
	buffer := make([]uint64, (size+7)/8)
	info := (*fileRenameInfo)(unsafe.Pointer(&buffer[0]))
	info.FileNameLength = uint32((len(name) - 1) * 2)
	copy(unsafe.Slice(&info.FileName[0], len(name)), name)
	return windows.SetFileInformationByHandle(handle, windows.FileRenameInfo, (*byte)(unsafe.Pointer(&buffer[0])), uint32(size))
}

// setObjectDescriptor gives the object behind handle DefenseClaw's owner and
// the protected DACL in sddl; like reclaimDir it never walks children.
func setObjectDescriptor(handle windows.Handle, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString("O:" + adminOwnerSIDStr + sddl)
	if err != nil {
		return err
	}
	return windows.SetKernelObjectSecurity(handle,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, sd)
}

func reclaimDir(path string) error {
	return reclaimDirHandle(path, func() error {
		handle, err := openDirNoFollow(path, windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER)
		if err != nil {
			return err
		}
		defer windows.CloseHandle(handle)
		if err := requirePlainDirectory(handle, path); err != nil {
			return err
		}
		sd, err := protectedDirDescriptor()
		if err != nil {
			return err
		}
		// SetKernelObjectSecurity sets exactly this object's descriptor;
		// unlike SetNamedSecurityInfo it never walks the children.
		return windows.SetKernelObjectSecurity(handle,
			windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, sd)
	})
}

func atomicWrite(_ Options, path string, data []byte, public bool) error {
	sddl := privateFileSDDL
	if public {
		sddl = publicFileSDDL
	}
	return atomicWriteSDDL(path, data, sddl)
}

// atomicWriteSDDL writes data beside path, applies sddl and renames it
// into place.
func atomicWriteSDDL(path string, data []byte, sddl string) error {
	dir := filepath.Dir(path)
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return err
	}
	tmp := filepath.Join(dir, "."+filepath.Base(path)+".defenseclaw-"+hex.EncodeToString(suffix))
	file, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	cleanup := func() { _ = os.Remove(tmp) }
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		cleanup()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		cleanup()
		return err
	}
	if err := file.Close(); err != nil {
		cleanup()
		return err
	}
	if err := applySDDL(tmp, sddl); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		cleanup()
		return err
	}
	return nil
}

func ensurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return applySDDL(dir, privateDirSDDL)
}

// openGuardFile opens a user or project file for the foreign-hook guard
// without following a reparse point.
func openGuardFile(path string) (*os.File, error) {
	return openNoFollow(path)
}

// openGuardDir opens a user or project directory for listing without
// following a reparse point.
func openGuardDir(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeIrregular != 0 {
		return nil, fmt.Errorf("%s is a reparse point", path)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", path)
	}
	return os.Open(path)
}

// openGuardFileFollow opens a file a hook command names, following links
// as the agent would.
func openGuardFileFollow(path string) (*os.File, error) {
	return os.Open(path)
}

// adminOwnedFile is not derived on Windows: every referenced file is bound
// by content.
func adminOwnedFile(os.FileInfo) bool { return false }

// systemBoundFile is never true on Windows (adminOwnedFile).
func systemBoundFile(string, os.FileInfo) bool { return false }

// publishedFileProblem is "" on Windows: atomicWrite gives a policy file its
// protected DACL on every write, and mode bits do not apply.
func publishedFileProblem(Options, string) string { return "" }

// publishedDirProblem and restorePublishedDirs are unix only: a vendor
// directory's protected DACL already lets every user read it.
func publishedDirProblem(Options, string) string { return "" }

func restorePublishedDirs(Options, string) ([]string, error) { return nil, nil }

// adminOwnedLink is never true on Windows, where no file is bound by kind
// only (adminOwnedFile).
func adminOwnedLink(os.FileInfo) bool { return false }

// guardPathCannotExist reports a stat error that means nothing can be at
// the path: a name no Windows file can have (a command word such as *.tmp
// or a:b), a component that is a file, or a name past the length limit.
func guardPathCannotExist(err error) bool {
	return errors.Is(err, windows.ERROR_INVALID_NAME) ||
		errors.Is(err, windows.ERROR_BAD_PATHNAME) ||
		errors.Is(err, windows.ERROR_DIRECTORY) ||
		errors.Is(err, windows.ERROR_FILENAME_EXCED_RANGE)
}

// openGuardAppend opens a user-owned record file for appending without
// following a reparse point.
func openGuardAppend(path string) (*os.File, error) {
	if info, err := os.Lstat(path); err == nil && (info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeIrregular != 0) {
		return nil, fmt.Errorf("%s is a reparse point", path)
	}
	return os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
}
