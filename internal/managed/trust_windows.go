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

package managed

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// UntrustedPrincipalError is a path element whose owner, or one of whose
// write-like allow entries, names a principal the trust check does not
// accept. Error keeps the text the Secure Client profile pins; the
// standalone lifecycle reads the fields to name the account and the fix
// (GAP-0528, GAP-0562).
type UntrustedPrincipalError struct {
	// Path is the file or folder that failed the check.
	Path string
	// SID is the untrusted principal.
	SID string
	// Owner is true for an untrusted owner and false for a write-like entry.
	Owner bool
	text  string
}

func (e *UntrustedPrincipalError) Error() string { return e.text }

func ValidateTrustedConfigPath(path string) error {
	return ValidateTrustedFilePath(path, "managed config")
}

// ValidateTrustedFilePath is the Windows counterpart of the unix
// trust_unix.go implementation and is INTENTIONALLY NOT byte-for-byte
// equivalent. The leaf (clean, windowsTrustLeaf) is checked with the
// full strict write mask — same as unix — but ancestor directories are
// checked with the narrower WindowsAncestorReplaceAccess mask (see its
// docstring). That relaxation is load-bearing on Windows: stock OS
// defaults grant BUILTIN\Users add-file and write-EA/attributes on
// roots like `C:\ProgramData`, none of which lets a standard user
// replace an existing protected leaf. Applying the leaf mask to
// ancestors would reject every legitimate Windows install.
//
// Callers that need a strictly-strict ancestor check (no relaxation)
// must build their own walk with windowsTrustLeaf at every element; no
// caller currently does. When adding one, do NOT quietly extend this
// function — introduce a distinct entry point so the semantic split
// stays visible at the call site.
//
// Since AIFW-34262 the ancestor pass is advisory as well as narrower: an
// untrusted ancestor owner, a null ancestor DACL, or a write-like ancestor
// ACE emits a TrustAdvisoryMarker warning and the walk continues, because
// the permissions on the shared Cisco Secure Client tree above the managed
// roots belong to the platform installer, not to DefenseClaw. Structural
// failures (missing element, symlink, reparse point, wrong type, non-NTFS
// mount, security-descriptor API errors) stay fatal at every element, and
// the named leaf keeps every verdict fatal. Pin TrustStrictAncestorsEnv to
// make the ancestor verdicts fatal again.
func ValidateTrustedFilePath(path, label string) error {
	if label == "" {
		label = "managed file"
	}
	if path == "" {
		return fmt.Errorf("%s path is empty", label)
	}
	clean, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve %s path: %w", label, err)
	}
	if _, err := winpath.ValidateFixedNTFSMountedPath(clean); err != nil {
		return fmt.Errorf("%s is not on a trusted mount-manager NTFS drive: %w", label, err)
	}
	if err := validateTrustedWindowsPathElementWithWriter(clean, false, label, nil, windowsTrustLeaf); err != nil {
		return err
	}
	for dir := filepath.Dir(clean); dir != filepath.Dir(dir); dir = filepath.Dir(dir) {
		if err := validateTrustedWindowsPathElementWithWriter(dir, true, label, nil, windowsAncestorScope(dir)); err != nil {
			return err
		}
	}
	root := filepath.VolumeName(clean) + string(filepath.Separator)
	return validateTrustedWindowsPathElementWithWriter(
		root,
		true,
		label,
		nil,
		windowsAncestorScope(root),
	)
}

// ValidateTrustedFilePathStrictAncestors is ValidateTrustedFilePath with no
// advisory verdict: every folder above the file, the installer-owned Cisco
// folders included, gets the narrow ancestor mask with fatal verdicts. It is
// for an image an elevated process runs. A standard user who can delete the
// children of a folder above it, or rename or re-ACL that folder, can swap
// the image between the check and the launch, so drift on the Cisco tree
// must refuse here, not warn.
func ValidateTrustedFilePathStrictAncestors(path, label string) error {
	if label == "" {
		label = "managed file"
	}
	if path == "" {
		return fmt.Errorf("%s path is empty", label)
	}
	clean, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve %s path: %w", label, err)
	}
	if _, err := winpath.ValidateFixedNTFSMountedPath(clean); err != nil {
		return fmt.Errorf("%s is not on a trusted mount-manager NTFS drive: %w", label, err)
	}
	if err := validateTrustedWindowsPathElementWithWriter(clean, false, label, nil, windowsTrustLeaf); err != nil {
		return err
	}
	for dir := filepath.Dir(clean); ; dir = filepath.Dir(dir) {
		if err := validateTrustedWindowsPathElementWithWriter(dir, true, label, nil, windowsTrustForeignAncestor); err != nil {
			return err
		}
		if dir == filepath.Dir(dir) {
			return nil
		}
	}
}

func ValidateTrustedRuntimeDir(path, label string) error {
	return validateTrustedWindowsRuntimeDir(path, label, nil)
}

// ValidateTrustedInstallMarkerDir requires a SYSTEM-owned marker whose only
// writers are SYSTEM and Administrators. Every verdict is fatal on ancestors;
// their stock create-child grants keep the narrow replacement mask.
func ValidateTrustedInstallMarkerDir(path, label string) error {
	if err := validateTrustedWindowsRuntimeDirWithAncestors(path, label, nil, windowsStrictAncestorScope); err != nil {
		return err
	}
	return validateTrustedWindowsPathElementWithWriter(path, true, label, nil, windowsTrustSystemOwned)
}

// ValidateTrustedRuntimeImage checks an executable that an elevated process
// or a service runs from a protected runtime folder (the scanner runtime and
// the Python under it): root and image keep every verdict fatal, and every
// folder above root, the installer-owned Cisco folders included, gets the
// narrow ancestor mask with fatal verdicts. Folders within root get the full
// write mask: an added module there can run as the service. Under the
// advisory walk a standard user who could delete the children of
// C:\ProgramData\Cisco, or rename or re-ACL it, or add a file to the runtime
// folder, got a warning, and could swap the runtime between the check and
// the launch (review loop round 4). image must be below root.
func ValidateTrustedRuntimeImage(root, image, label string) error {
	if label == "" {
		label = "managed runtime image"
	}
	if root == "" || image == "" {
		return fmt.Errorf("%s path is empty", label)
	}
	cleanRoot, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("resolve %s path: %w", label, err)
	}
	cleanImage, err := filepath.Abs(image)
	if err != nil {
		return fmt.Errorf("resolve %s path: %w", label, err)
	}
	if rel, err := filepath.Rel(cleanRoot, cleanImage); err != nil || rel == "." || filepath.IsAbs(rel) ||
		rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%s %s is not inside its runtime folder %s", label, cleanImage, cleanRoot)
	}
	if err := validateTrustedWindowsRuntimeDirWithAncestors(cleanRoot, label, nil, windowsStrictAncestorScope); err != nil {
		return err
	}
	if err := validateTrustedWindowsPathElementWithWriter(cleanRoot, true, label, nil, windowsTrustSystemAdminOnly); err != nil {
		return err
	}
	if err := ValidateTrustedFilePathStrictAncestors(cleanImage, label); err != nil {
		return err
	}
	if err := validateTrustedWindowsPathElementWithWriter(cleanImage, false, label, nil, windowsTrustSystemAdminOnly); err != nil {
		return err
	}
	for dir := filepath.Dir(cleanImage); !strings.EqualFold(dir, cleanRoot); dir = filepath.Dir(dir) {
		if err := validateTrustedWindowsPathElementWithWriter(dir, true, label, nil, windowsTrustSystemAdminOnly); err != nil {
			return err
		}
	}
	return nil
}

// ValidateTrustedRuntimeCodeTree checks every file and folder beneath the
// scanner runtime root before a SYSTEM or service launch. The embedded
// interpreter lives at <root>/<digest>/python, and its ._pth includes both
// that directory and site-packages. A writable .pth, module, or folder can
// execute code even if python.exe itself is protected. Unknown entries and
// unreadable ACLs refuse the run.
func ValidateTrustedRuntimeCodeTree(root, label string) error {
	if root == "" {
		return fmt.Errorf("%s path is empty", label)
	}
	cleanRoot, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("resolve %s path: %w", label, err)
	}
	root = cleanRoot
	if err := validateTrustedWindowsRuntimeDirWithAncestors(root, label, nil, windowsStrictAncestorScope); err != nil {
		return err
	}
	const maxEntries = 200000
	entries := 0
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		// Failed removals are moved aside under these names and never used
		// as code. A locked stale folder must not prevent the newly unpacked
		// runtime from passing repair (GAP-0262).
		if filepath.Dir(path) == root && entry.IsDir() {
			for _, prefix := range []string{".stale-", ".prune-", ".unpack-"} {
				if strings.HasPrefix(entry.Name(), prefix) {
					return filepath.SkipDir
				}
			}
		}
		if entries++; entries > maxEntries {
			return fmt.Errorf("%s has more than %d entries", root, maxEntries)
		}
		return validateTrustedWindowsPathElementWithWriter(path, entry.IsDir(), label, nil, windowsTrustSystemAdminOnly)
	})
}

// ValidateTrustedDirectoryAncestor validates an existing directory that will
// contain a new protected child. Unlike ValidateTrustedRuntimeDir, the named
// directory is evaluated with the narrow ancestor-replacement mask as well as
// its parents. This accepts stock Windows known-folder create-child grants,
// while still rejecting DELETE_CHILD, DELETE, WRITE_DAC, WRITE_OWNER, generic
// write, reparse points, non-NTFS mounts, and untrusted owners.
//
// The named directory keeps every verdict FATAL. Callers use this as a
// pre-write and pre-delete guard on directories DefenseClaw itself creates and
// ACLs below the state root (hook-guardian manifests, managed policy, namespace
// purge), so an untrusted write ACE there is real breakage, not AVC's drift on
// the shared tree. Only its parents are advisory, which is what AIFW-34262
// needed: the untrusted grant lands on ...\Cisco Secure Client\DefenseClaw, one
// level above every directory named here.
func ValidateTrustedDirectoryAncestor(path, label string) error {
	if label == "" {
		label = "managed directory ancestor"
	}
	if path == "" {
		return fmt.Errorf("%s path is empty", label)
	}
	clean, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve %s path: %w", label, err)
	}
	if _, err := winpath.ValidateFixedNTFSMountedPath(clean); err != nil {
		return fmt.Errorf("%s is not on a trusted mount-manager NTFS drive: %w", label, err)
	}
	for cur := clean; ; cur = filepath.Dir(cur) {
		scope := windowsAncestorScope(cur)
		if cur == clean {
			scope = windowsTrustNamedDir
		}
		if err := validateTrustedWindowsPathElementWithWriter(cur, true, label, nil, scope); err != nil {
			return err
		}
		if cur == filepath.Dir(cur) {
			break
		}
	}
	return nil
}

// ValidateTrustedServiceRuntimeDir permits the exact NT SERVICE virtual
// account installed for the gateway to write the managed runtime tree. That
// exception is deliberately opt-in and is never used for config, binaries,
// guardian manifests, or the protected authorization ledger.
func ValidateTrustedServiceRuntimeDir(path, label, serviceAccount string) error {
	serviceSID, err := windowsVirtualServiceSID(serviceAccount)
	if err != nil {
		return err
	}
	return validateTrustedWindowsRuntimeDir(path, label, serviceSID)
}

// ValidateTrustedServiceRuntimeFilePath applies the same narrow service-SID
// writer exception to a regular runtime file such as a scoped token.
func ValidateTrustedServiceRuntimeFilePath(path, label, serviceAccount string) error {
	if label == "" {
		label = "managed runtime file"
	}
	serviceSID, err := windowsVirtualServiceSID(serviceAccount)
	if err != nil {
		return err
	}
	if path == "" {
		return fmt.Errorf("%s path is empty", label)
	}
	clean, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve %s path: %w", label, err)
	}
	if _, err := winpath.ValidateFixedNTFSMountedPath(clean); err != nil {
		return fmt.Errorf("%s is not on a trusted mount-manager NTFS drive: %w", label, err)
	}
	if err := validateTrustedWindowsPathElementWithWriter(clean, false, label, serviceSID, windowsTrustLeaf); err != nil {
		return err
	}
	for dir := filepath.Dir(clean); dir != filepath.Dir(dir); dir = filepath.Dir(dir) {
		if err := validateTrustedWindowsPathElementWithWriter(dir, true, label, serviceSID, windowsAncestorScope(dir)); err != nil {
			return err
		}
	}
	root := filepath.VolumeName(clean) + string(filepath.Separator)
	return validateTrustedWindowsPathElementWithWriter(
		root,
		true,
		label,
		serviceSID,
		windowsAncestorScope(root),
	)
}

// ValidateStrictServiceRuntimeFilePath is ValidateTrustedServiceRuntimeFilePath
// without an advisory verdict: the file and the namedDirs folders nearest
// to it, which DefenseClaw creates with a protected DACL, get the strict
// leaf check, and every folder above them the narrow ancestor mask with
// fatal verdicts, inside the platform installer's roots too. It is for a
// record whose loss only blocks (the protected foreign-hook session record,
// GAP-0352), where a drifted Cisco folder must refuse the record rather
// than warn: whoever can replace a folder above it can bring back a record
// that was revoked.
func ValidateStrictServiceRuntimeFilePath(path, label, serviceAccount string, namedDirs int) error {
	if label == "" {
		label = "managed runtime file"
	}
	serviceSID, err := windowsVirtualServiceSID(serviceAccount)
	if err != nil {
		return err
	}
	return validateStrictServiceRuntimeFilePath(path, label, serviceSID, namedDirs)
}

// ValidateStrictServiceRuntimeDirPath is ValidateStrictServiceRuntimeFilePath
// for a folder: the folder and the namedDirs folders nearest above it get
// the strict leaf check, every folder above them the narrow ancestor mask,
// all fatal. The Windows lifecycle and status use it to tell whether the
// protected foreign-hook session record folder is one the hook trusts
// (GAP-0352 review).
func ValidateStrictServiceRuntimeDirPath(path, label, serviceAccount string, namedDirs int) error {
	if label == "" {
		label = "managed runtime folder"
	}
	serviceSID, err := windowsVirtualServiceSID(serviceAccount)
	if err != nil {
		return err
	}
	return validateStrictServiceRuntimePath(path, true, label, serviceSID, namedDirs)
}

func validateStrictServiceRuntimeFilePath(path, label string, serviceSID *windows.SID, namedDirs int) error {
	return validateStrictServiceRuntimePath(path, false, label, serviceSID, namedDirs)
}

func validateStrictServiceRuntimePath(path string, isDir bool, label string, serviceSID *windows.SID, namedDirs int) error {
	if path == "" {
		return fmt.Errorf("%s path is empty", label)
	}
	clean, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve %s path: %w", label, err)
	}
	if _, err := winpath.ValidateFixedNTFSMountedPath(clean); err != nil {
		return fmt.Errorf("%s is not on a trusted mount-manager NTFS drive: %w", label, err)
	}
	if err := validateTrustedWindowsPathElementWithWriter(clean, isDir, label, serviceSID, windowsTrustLeaf); err != nil {
		return err
	}
	for level, dir := 0, filepath.Dir(clean); ; level, dir = level+1, filepath.Dir(dir) {
		if err := validateTrustedWindowsPathElementWithWriter(dir, true, label, serviceSID, windowsStrictServiceAncestorScope(level, namedDirs)); err != nil {
			return err
		}
		if dir == filepath.Dir(dir) {
			return nil
		}
	}
}

// windowsStrictServiceAncestorScope is the scope of the folder level steps above
// the file in ValidateStrictServiceRuntimeFilePath: the leaf rule for the
// namedDirs nearest, else the narrow mask, never advisory.
func windowsStrictServiceAncestorScope(level, namedDirs int) windowsTrustScope {
	if level < namedDirs {
		return windowsTrustLeaf
	}
	return windowsTrustForeignAncestor
}

// windowsRulePackTreeMaxEntries bounds the walk of an administrator rule pack.
const windowsRulePackTreeMaxEntries = 20000

var errWindowsRulePackTreeTooLarge = errors.New("too many entries")

// ValidateTrustedRulePackTree is the standalone lifecycle check of an
// administrator rule pack. The pack folder and the folders above it get the
// check the gateway makes of a managed rule pack (ValidateTrustedServiceRuntimeDir),
// and then every folder and file in the pack, without following links: no
// reparse point, owned by Administrators, LocalSystem, TrustedInstaller or
// the gateway service, and no write-like entry for anyone else. The gateway
// checks only the folder, so a standard user with Modify on the pack manifest
// or a rules file changed what the agents of every user are held to and,
// against a digest pin, kept the gateway from starting at the next restart
// (GAP-0672). A service account that does not resolve yet (before the first
// install) is held to the administrator-only rule.
func ValidateTrustedRulePackTree(dir, label, serviceAccount string) error {
	writer, err := windowsVirtualServiceSID(serviceAccount)
	if err != nil {
		writer = nil
	}
	if err := validateTrustedWindowsRuntimeDir(dir, label, writer); err != nil {
		return err
	}
	root, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("resolve %s path: %w", label, err)
	}
	return walkWindowsRulePackTree(root, func(path string, isDir bool) error {
		return validateTrustedWindowsPathElementWithWriter(path, isDir, label, writer, windowsTrustLeaf)
	})
}

// ValidateTrustedServiceRuntimeTree checks a managed policy folder and
// everything in it as ValidateTrustedRulePackTree checks a rule pack: the
// folder check alone (and the readability check of
// ValidateServiceCanReadTree) passed a policy_dir whose Rego modules a
// standard user could modify (GAP-1499).
func ValidateTrustedServiceRuntimeTree(path, label, serviceAccount string) error {
	return ValidateTrustedRulePackTree(path, label, serviceAccount)
}

// walkWindowsRulePackTree calls check for every folder and file below root
// (root itself excluded: the caller checks it with its parents) without
// following links, and stops at the first refusal.
func walkWindowsRulePackTree(root string, check func(path string, isDir bool) error) error {
	entries := 0
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		if entries++; entries > windowsRulePackTreeMaxEntries {
			return errWindowsRulePackTreeTooLarge
		}
		return check(path, entry.IsDir())
	})
	if errors.Is(err, errWindowsRulePackTreeTooLarge) {
		return fmt.Errorf("%s has more than %d entries", root, windowsRulePackTreeMaxEntries)
	}
	return err
}

func validateTrustedWindowsRuntimeDir(path, label string, allowedWriter *windows.SID) error {
	return validateTrustedWindowsRuntimeDirWithAncestors(path, label, allowedWriter, windowsAncestorScope)
}

// windowsStrictAncestorScope gives every ancestor the narrow mask with fatal
// verdicts, the installer-owned Cisco folders included.
func windowsStrictAncestorScope(string) windowsTrustScope { return windowsTrustForeignAncestor }

// validateTrustedWindowsRuntimeDirWithAncestors checks the named folder with
// the leaf rule and each folder above it with the scope ancestors picks.
func validateTrustedWindowsRuntimeDirWithAncestors(path, label string, allowedWriter *windows.SID, ancestors func(string) windowsTrustScope) error {
	if label == "" {
		label = "managed runtime dir"
	}
	if path == "" {
		return fmt.Errorf("%s path is empty", label)
	}
	clean, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve %s path: %w", label, err)
	}
	if _, err := winpath.ValidateFixedNTFSMountedPath(clean); err != nil {
		return fmt.Errorf("%s is not on a trusted mount-manager NTFS drive: %w", label, err)
	}
	for cur := clean; ; cur = filepath.Dir(cur) {
		scope := ancestors(cur)
		if cur == clean {
			scope = windowsTrustLeaf
		}
		if err := validateTrustedWindowsPathElementWithWriter(cur, true, label, allowedWriter, scope); err != nil {
			return err
		}
		if cur == filepath.Dir(cur) {
			break
		}
	}
	return nil
}

// windowsTrustScope carries two independent ancestor relaxations and the
// stricter code/marker owner rule. The relaxations used to be one `ancestor
// bool`, which silently coupled the narrower mask to advisory verdicts.
// Keep them separate so each call site states exactly what it wants.
//
//   - narrowMask evaluates allow ACEs with WindowsAncestorReplaceAccess instead
//     of the full write-like mask. Required for stock Windows known-folder
//     grants (BUILTIN\Users add-file and write-EA/attributes on roots such as
//     C:\ProgramData), none of which can replace an existing protected child.
//   - advisory downgrades owner/DACL *verdicts* to a TrustAdvisoryMarker warning
//     and continues the walk (AIFW-34262). Structural and API failures are never
//     downgraded, and TrustStrictAncestorsEnv restores fatality.
//   - systemAdminOnly allows only LocalSystem and Administrators to own or
//     change a code path, never TrustedInstaller.
//   - ownerSystemOnly requires LocalSystem to own a Secure Client marker.
type windowsTrustScope struct {
	narrowMask      bool
	advisory        bool
	systemAdminOnly bool
	ownerSystemOnly bool
}

var (
	// windowsTrustLeaf is the named artifact a caller asked about: strictest
	// mask, every verdict fatal.
	windowsTrustLeaf = windowsTrustScope{}
	// Code run as SYSTEM accepts only SYSTEM and Administrators as owners
	// and write-capable principals.
	windowsTrustSystemAdminOnly = windowsTrustScope{systemAdminOnly: true}
	// The install marker alone must be SYSTEM-owned; Administrators may write.
	windowsTrustSystemOwned = windowsTrustScope{systemAdminOnly: true, ownerSystemOnly: true}
	// windowsTrustNamedDir is a named directory that legitimately carries stock
	// create-child grants but is still DefenseClaw-owned, so its verdicts stay
	// fatal. Used for the directory ValidateTrustedDirectoryAncestor was asked
	// about, which callers rely on as a pre-write / pre-delete guard.
	windowsTrustNamedDir = windowsTrustScope{narrowMask: true}
	// windowsTrustAncestor is a parent directory inside the platform installer's
	// roots. Those live in the shared Cisco Secure Client tree that AVC owns and
	// re-ACLs, so their verdicts are advisory.
	windowsTrustAncestor = windowsTrustScope{narrowMask: true, advisory: true}
	// windowsTrustForeignAncestor is a parent directory OUTSIDE the platform
	// installer's roots: C:\, C:\ProgramData itself, or any temp/home prefix a
	// test or a per-user install walks through. It keeps the narrow mask, because
	// stock known-folder create-child grants are still legitimate there, but its
	// verdicts stay fatal — no other installer has a claim on those permissions,
	// so an untrusted owner or a replace-capable ACE means the artifact below can
	// be swapped.
	windowsTrustForeignAncestor = windowsTrustScope{narrowMask: true}
)

// windowsAncestorScope picks the ancestor scope from the ancestor's position:
// advisory only inside PlatformInstallerOwnedRoots (AIFW-34262), fatal
// everywhere else. Every ancestor walk in this file routes through here so the
// allowlist cannot be forgotten at one call site.
func windowsAncestorScope(path string) windowsTrustScope {
	if PlatformInstallerOwnedPath(path) {
		return windowsTrustAncestor
	}
	return windowsTrustForeignAncestor
}

func validateTrustedWindowsPathElementWithWriter(
	path string,
	wantDir bool,
	label string,
	allowedWriter *windows.SID,
	scope windowsTrustScope,
) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s: symlinks are not allowed in %s path", path, label)
	}
	if err := rejectWindowsReparsePoint(path, label); err != nil {
		return err
	}
	if wantDir && !info.IsDir() {
		return fmt.Errorf("%s: expected directory in %s path", path, label)
	}
	if !wantDir && !info.Mode().IsRegular() {
		return fmt.Errorf("%s: expected regular %s file", path, label)
	}
	extendedPath, err := winpath.Extended(path)
	if err != nil {
		return fmt.Errorf("%s: encode extended Windows path: %w", path, err)
	}
	sd, err := windows.GetNamedSecurityInfo(
		extendedPath,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("%s: inspect Windows security descriptor: %w", path, err)
	}
	if sd == nil {
		return fmt.Errorf("%s: missing Windows security descriptor", path)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("%s: inspect Windows owner: %w", path, err)
	}
	trustedOwner := windowsTrustedPathOwner(owner, allowedWriter)
	if scope.systemAdminOnly {
		trustedOwner = windowsSystemOrAdmin(owner)
	}
	if scope.ownerSystemOnly {
		trustedOwner = owner != nil && owner.IsWellKnown(windows.WinLocalSystemSid)
	}
	if !trustedOwner {
		expected := "Administrators, LocalSystem, or TrustedInstaller"
		if scope.systemAdminOnly {
			expected = "Administrators or LocalSystem"
		}
		if scope.ownerSystemOnly {
			expected = "LocalSystem"
		}
		if allowedWriter != nil {
			expected = fmt.Sprintf("%s, or the pinned service SID %s", expected, sidString(allowedWriter))
		}
		if err := relaxAncestorTrustVerdict(scope.advisory, path, label, &UntrustedPrincipalError{
			Path:  path,
			SID:   sidString(owner),
			Owner: true,
			text:  fmt.Sprintf("%s: owner %s is not trusted for %s; expected %s", path, sidString(owner), label, expected),
		}); err != nil {
			return err
		}
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("%s: inspect Windows DACL: %w", path, err)
	}
	if dacl == nil {
		return relaxAncestorTrustVerdict(scope.advisory, path, label, fmt.Errorf(
			"%s: null Windows DACL is not trusted", path,
		))
	}
	return rejectUntrustedWindowsWriteACEsWithWriter(path, label, dacl, allowedWriter, scope)
}

func rejectUntrustedWindowsWriteACEs(path string, dacl *windows.ACL) error {
	return rejectUntrustedWindowsWriteACEsWithWriter(path, "managed path", dacl, nil, windowsTrustLeaf)
}

func rejectUntrustedWindowsWriteACEsWithWriter(
	path string,
	label string,
	dacl *windows.ACL,
	allowedWriter *windows.SID,
	scope windowsTrustScope,
) error {
	const (
		accessAllowedObjectACEType         = 0x5
		accessAllowedCallbackACEType       = 0x9
		accessAllowedCallbackObjectACEType = 0xB
	)
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
			return fmt.Errorf("%s: inspect Windows ACE %d: %w", path, i, err)
		}
		if ace == nil || ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		switch ace.Header.AceType {
		case accessAllowedObjectACEType, accessAllowedCallbackACEType, accessAllowedCallbackObjectACEType:
			// Not a permission verdict: the ACE layout differs from
			// ACCESS_ALLOWED_ACE, so ace.Mask and ace.SidStart cannot be read
			// and this walk has no idea who was granted what. Advisory mode
			// must not turn "cannot evaluate" into "trusted" — stock NTFS never
			// carries these types, and AIFW-34262's grant was a plain
			// ACCESS_ALLOWED_ACE, so keeping them fatal costs no install.
			return fmt.Errorf(
				"%s: unsupported allow ACE type 0x%x; refusing managed trust", path, ace.Header.AceType,
			)
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		default:
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		writeLike := windowsWriteLikeAccess(ace.Mask)
		if scope.narrowMask && !windowsWorldSID(sid) {
			writeLike = WindowsAncestorReplaceAccess(ace.Mask)
		}
		if !writeLike {
			continue
		}
		trustedWriter := windowsTrustedOwner(sid) || sameWindowsSID(sid, allowedWriter)
		if scope.systemAdminOnly {
			trustedWriter = windowsSystemOrAdmin(sid)
		}
		if !trustedWriter {
			if err := relaxAncestorTrustVerdict(scope.advisory, path, label, &UntrustedPrincipalError{
				Path: path,
				SID:  sidString(sid),
				text: fmt.Sprintf("%s: untrusted Windows principal %s has write-like access mask 0x%x", path, sidString(sid), uint32(ace.Mask)),
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

// WindowsAncestorReplaceAccess reports whether mask lets a principal replace a
// protected child. Narrower than the leaf rule: stock Windows grants Users
// add-file and write-EA/attributes on roots like C:\ProgramData, none of which
// can replace an existing child.
func WindowsAncestorReplaceAccess(mask windows.ACCESS_MASK) bool {
	const fileDeleteChild windows.ACCESS_MASK = 0x00000040
	dangerous := windows.ACCESS_MASK(
		windows.GENERIC_ALL |
			windows.GENERIC_WRITE |
			windows.DELETE |
			windows.WRITE_DAC |
			windows.WRITE_OWNER,
	)
	return mask&(dangerous|fileDeleteChild) != 0
}

func rejectWindowsReparsePoint(path, label string) error {
	extendedPath, err := winpath.Extended(path)
	if err != nil {
		return fmt.Errorf("%s: encode extended Windows path: %w", path, err)
	}
	pathPtr, err := windows.UTF16PtrFromString(extendedPath)
	if err != nil {
		return fmt.Errorf("%s: encode Windows path: %w", path, err)
	}
	attributes, err := windows.GetFileAttributes(pathPtr)
	if err != nil {
		return fmt.Errorf("%s: inspect Windows file attributes: %w", path, err)
	}
	if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%s: reparse points are not allowed in %s path", path, label)
	}
	return nil
}

func windowsVirtualServiceSID(account string) (*windows.SID, error) {
	account = strings.TrimSpace(account)
	if account == "" {
		// Empty account falls through to (nil, nil): callers get a nil
		// `allowedWriter` and the trust check reverts to strict-admin
		// (Administrators / LocalSystem / TrustedInstaller only). This
		// is the safe path when no service exception is configured.
		//
		// T3.5 finding proposed erroring here, but the fallback is
		// actually correct behaviour — real callers of
		// WindowsServiceAccountSID (audit, hook-token) already guard
		// for empty input and refuse to proceed; internal
		// ValidateTrustedService* callers legitimately want the
		// strict-admin trust when the env is not pinned (dev boxes,
		// non-managed integration tests). Erroring here surfaces a
		// misleading "not set" error at every managed-mode reload on
		// a QA host that never authored the pin, and broke sidecar
		// v8 bootstrap tests that exercise reload paths without
		// populating the env.
		return nil, nil
	}
	name, err := ntServiceName(account)
	if err != nil {
		return nil, err
	}
	derived, err := windowsDerivedServiceSID(name)
	if err != nil {
		return nil, fmt.Errorf("derive Windows service SID for %q: %w", account, err)
	}
	sid, _, _, err := windows.LookupSID("", account)
	if errors.Is(err, windows.ERROR_NONE_MAPPED) {
		// A virtual account that logged on stays resolvable after its
		// service is deleted. The LocalSystem gateway never logs on as
		// NT SERVICE\<name>, so once Uninstall deletes the service the name
		// no longer maps, and the managed data_dir check during teardown
		// finalize failed (Setup /uninstall exit 1603). The service SID is
		// a pure function of the name, as `sc.exe showsid` computes it.
		return derived, nil
	}
	if err != nil {
		return nil, fmt.Errorf("resolve Windows virtual service account %q: %w", account, err)
	}
	if !sid.Equals(derived) {
		return nil, fmt.Errorf(
			"resolved Windows virtual service account %q is %s, not its service SID %s",
			account, sidString(sid), sidString(derived),
		)
	}
	// LookupSID resolved the `NT SERVICE\<name>` string, but a compromised
	// registrar could point the lookup at any SID. Bind trust to the NT
	// SERVICE authority (S-1-5-80-...) before returning: reject any SID
	// that is not under NT AUTHORITY (Value 5) with SubAuthority(0) == 80.
	if !sidIsNTService(sid) {
		return nil, fmt.Errorf(
			"resolved Windows virtual service account %q is not under NT SERVICE (S-1-5-80): %s",
			account, sidString(sid),
		)
	}
	return sid, nil
}

// windowsDerivedServiceSID is the service SID SCM assigns to a service name
// (WindowsServiceSIDString), as a SID. Callers pass a name ntServiceName
// already checked.
func windowsDerivedServiceSID(name string) (*windows.SID, error) {
	return windows.StringToSid(WindowsServiceSIDString(name))
}

// ntServiceName is the service name of account once it is checked to be an
// NT SERVICE virtual account with a valid service name.
func ntServiceName(account string) (string, error) {
	const prefix = `NT SERVICE\`
	if len(account) <= len(prefix) || !strings.EqualFold(account[:len(prefix)], prefix) {
		return "", fmt.Errorf(
			"%s must identify an NT SERVICE virtual account, got %q",
			WindowsServiceAccountEnv,
			account,
		)
	}
	name := account[len(prefix):]
	for _, char := range name {
		if (char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '_' || char == '.' || char == '-' {
			continue
		}
		return "", fmt.Errorf("%s contains an invalid service name: %q", WindowsServiceAccountEnv, account)
	}
	if len(name) > 128 {
		return "", fmt.Errorf("%s service name is too long", WindowsServiceAccountEnv)
	}
	return name, nil
}

func sidIsNTService(sid *windows.SID) bool {
	if sid == nil || !sid.IsValid() {
		return false
	}
	authority := sid.IdentifierAuthority()
	// NT authority: {0, 0, 0, 0, 0, 5}. Only the last byte varies for known
	// authorities on modern Windows, so a byte-exact comparison is safe.
	if authority.Value != [6]byte{0, 0, 0, 0, 0, 5} {
		return false
	}
	if sid.SubAuthorityCount() < 1 {
		return false
	}
	const ntServiceSubAuthority uint32 = 80
	return sid.SubAuthority(0) == ntServiceSubAuthority
}

// WindowsServiceAccountSID resolves a narrowly validated NT SERVICE virtual
// account for Windows-only ACL construction. Callers must still choose the
// service-runtime versus strict administrator trust API for each path.
func WindowsServiceAccountSID(account string) (*windows.SID, error) {
	return windowsVirtualServiceSID(account)
}

// windowsTokenIdentity is the subset of windows.Token the service identity
// check reads; tests substitute it to model LocalSystem service tokens.
type windowsTokenIdentity interface {
	GetTokenUser() (*windows.Tokenuser, error)
	GetTokenGroups() (*windows.Tokengroups, error)
}

// WindowsTokenRunsAsService reports whether token belongs to a process
// started by SCM for the service whose service SID is serviceSID.
//
// The gateway logs on as LocalSystem with a restricted service SID, so its
// TokenUser is S-1-5-18 and the service SID is an enabled, non-deny-only
// group. Earlier releases logged the gateway on as the virtual account
// itself, where the service SID is the TokenUser. Both forms are accepted so
// a host keeps working while it moves between them.
func WindowsTokenRunsAsService(token windows.Token, serviceSID *windows.SID) (bool, error) {
	return windowsTokenRunsAsService(token, serviceSID)
}

// WindowsCurrentProcessIsGatewayService reports whether the current
// process is the managed gateway service. The gateway logs on as LocalSystem,
// so code that grants LocalSystem administrator authority (policy writes,
// hook mutations) calls this to keep that authority with the guardian and the
// installer. The gateway's write-restricted token is the enforced boundary;
// this keeps the same rule visible in code. An unset or unresolvable gateway
// pin reports false so it cannot block the guardian.
func WindowsCurrentProcessIsGatewayService() bool {
	account := strings.TrimSpace(os.Getenv(WindowsServiceAccountEnv))
	if account == "" {
		return false
	}
	serviceSID, err := windowsVirtualServiceSID(account)
	if err != nil || serviceSID == nil {
		return false
	}
	isGateway, err := windowsTokenRunsAsService(windows.GetCurrentProcessToken(), serviceSID)
	return err == nil && isGateway
}

func windowsTokenRunsAsService(token windowsTokenIdentity, serviceSID *windows.SID) (bool, error) {
	if serviceSID == nil || !serviceSID.IsValid() {
		return false, fmt.Errorf("windows service identity: service SID is unavailable")
	}
	user, err := token.GetTokenUser()
	if err != nil {
		return false, fmt.Errorf("windows service identity: read token user: %w", err)
	}
	if user == nil || user.User.Sid == nil {
		return false, fmt.Errorf("windows service identity: token has no user SID")
	}
	if user.User.Sid.Equals(serviceSID) {
		return true, nil
	}
	if !user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return false, nil
	}
	groups, err := token.GetTokenGroups()
	if err != nil {
		return false, fmt.Errorf("windows service identity: read token groups: %w", err)
	}
	if groups == nil {
		return false, nil
	}
	for _, group := range groups.AllGroups() {
		if group.Sid == nil || !group.Sid.Equals(serviceSID) {
			continue
		}
		return group.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY == 0 &&
			group.Attributes&windows.SE_GROUP_ENABLED != 0, nil
	}
	return false, nil
}

func sameWindowsSID(left, right *windows.SID) bool {
	return left != nil && right != nil && left.Equals(right)
}

func windowsWriteLikeAccess(mask windows.ACCESS_MASK) bool {
	const fileDeleteChild windows.ACCESS_MASK = 0x00000040
	writeLike := windows.ACCESS_MASK(
		windows.GENERIC_ALL |
			windows.GENERIC_WRITE |
			windows.DELETE |
			windows.WRITE_DAC |
			windows.WRITE_OWNER |
			windows.FILE_WRITE_DATA |
			windows.FILE_APPEND_DATA |
			windows.FILE_WRITE_EA |
			windows.FILE_WRITE_ATTRIBUTES,
	)
	return mask&(writeLike|fileDeleteChild) != 0
}

// windowsWorldSID reports whether sid is Everyone. The relaxed ancestor rule
// covers what stock Windows grants on roots like C:\ProgramData, which goes to
// BUILTIN\Users and Authenticated Users. Everyone gets nothing there, so a write
// right for it is deliberate and answers to the leaf rule.
func windowsWorldSID(sid *windows.SID) bool {
	return sid != nil && sid.IsWellKnown(windows.WinWorldSid)
}

func windowsTrustedOwner(sid *windows.SID) bool {
	return IsWindowsTrustedAdminOwner(sid)
}

func windowsSystemOrAdmin(sid *windows.SID) bool {
	return sid != nil && (sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) || sid.IsWellKnown(windows.WinLocalSystemSid))
}

// IsWindowsTrustedAdminOwner reports whether the given SID identifies a
// platform-installer-trusted administrator principal: SYSTEM, BUILTIN\
// Administrators, or NT SERVICE\TrustedInstaller. Callers outside this
// package (connector filelock + hook-API token validators, enterprise-
// hooks DACL repair) use this to decide whether an admin-owned leaf is
// safe to adopt during install reconcile. Centralized here so the
// well-known SID string lives in exactly one place.
func IsWindowsTrustedAdminOwner(sid *windows.SID) bool {
	if sid == nil {
		return false
	}
	if sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) || sid.IsWellKnown(windows.WinLocalSystemSid) {
		return true
	}
	trustedInstaller, err := windows.StringToSid("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")
	if err != nil {
		return false
	}
	return sid.Equals(trustedInstaller)
}

func windowsTrustedPathOwner(owner, allowedServiceOwner *windows.SID) bool {
	return windowsTrustedOwner(owner) || sameWindowsSID(owner, allowedServiceOwner)
}

func sidString(sid *windows.SID) string {
	if sid == nil {
		return "<nil>"
	}
	return sid.String()
}
