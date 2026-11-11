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
	"sync"
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

// ValidateTrustedConfigPath validates config.yaml. On Secure Client drift on
// its owner or DACL is repaired first when the caller can (a LocalSystem
// service or an elevated administrator; never the gateway, whose token cannot
// re-ACL it), the strict check runs again, and what survives is accepted and
// logged by ValidateTrustedPolicyFilePath. On standalone a drifted
// config.yaml is refused with the strict verdict and never repaired in place
// (StandaloneRefusesContentDrift, GAP-0561). Structural failures stay fatal.
func ValidateTrustedConfigPath(path string) error {
	const label = "managed config"
	err := ValidateTrustedFilePath(path, label)
	if err != nil && StandaloneRefusesContentDrift() {
		return RefuseStandaloneContentDrift(err)
	}
	if err == nil || trustStrictAncestors() {
		return err
	}
	// Only the service-pinned managed config is ever re-stamped, never an
	// arbitrary path a caller passed in.
	if pinned := strings.TrimSpace(os.Getenv(ConfigPathEnv)); pinned != "" &&
		strings.EqualFold(filepath.Clean(pinned), filepath.Clean(path)) {
		result, ensureErr := windowsConfigEnsureCanonical(path, ObjectConfigFile, CanonicalOptions{})
		if ensureErr != nil {
			return errors.Join(err, ensureErr)
		}
		if result.Outcome == CanonicalRepaired && ValidateTrustedFilePath(path, label) == nil {
			return nil
		}
	}
	return ValidateTrustedPolicyFilePath(path, label)
}

// windowsConfigEnsureCanonical is the config.yaml repair; tests replace it to
// model a repair that cannot fix the drift.
var windowsConfigEnsureCanonical = EnsureCanonical

// ValidateTrustedPolicyFilePath validates a managed policy or data file that
// DefenseClaw reads but a service cannot always repair (config.yaml,
// targets.yaml, deployment.json, env_config.json). It runs the strict
// ValidateTrustedFilePath check, so a caller that repaired the file first
// gets a fresh verdict.
//
// On Secure Client a permission verdict on the file or an ancestor is then
// accepted and logged instead of refusing the file, and an untrusted owner or
// writer on the file itself is logged once as a MarkerBoundary finding naming
// the principal; the installer re-stamps the canonical descriptor on its next
// Install, Upgrade or Repair. The shared Cisco Secure Client tree is re-ACLed
// by other installers, which is why that profile tolerates the drift.
//
// A standalone process (windowsStandaloneTrustScope) keeps the strict verdict,
// as every drift-tolerant walk does there (windowsTrustScope.driftTolerated),
// as before 26.8.4: there DefenseClaw owns the whole tree, and a standard
// user who gained write access to config.yaml or the guardian manifest could
// otherwise change the fail mode or drop an account from enforcement
// (GAP-0561). Structural failures (missing element, symlink, reparse point,
// wrong type, non-NTFS mount) stay fatal on both profiles. Pin
// TrustStrictAncestorsEnv to make every verdict fatal again.
func ValidateTrustedPolicyFilePath(path, label string) error {
	err := ValidateTrustedFilePath(path, label)
	if err == nil || trustStrictAncestors() || windowsStandaloneTrustScope() {
		return err
	}
	leaf := windowsTrustLeaf.tolerant()
	leaf.code = true
	return validateTrustedFilePathTolerant(path, label, leaf)
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
	return validateTrustedWindowsFilePath(path, label, nil, windowsTrustLeaf, windowsAncestorScope)
}

// validateTrustedWindowsFilePath checks a regular file with the leaf scope
// and every folder above it, the volume root included, with the scope
// ancestors picks.
func validateTrustedWindowsFilePath(
	path, label string,
	allowedWriter *windows.SID,
	leaf windowsTrustScope,
	ancestors func(string) windowsTrustScope,
) error {
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
	if err := validateTrustedWindowsPathElementWithWriter(clean, false, label, allowedWriter, leaf); err != nil {
		return err
	}
	for dir := filepath.Dir(clean); dir != filepath.Dir(dir); dir = filepath.Dir(dir) {
		if err := validateTrustedWindowsPathElementWithWriter(dir, true, label, allowedWriter, ancestors(dir)); err != nil {
			return err
		}
	}
	root := filepath.VolumeName(clean) + string(filepath.Separator)
	return validateTrustedWindowsPathElementWithWriter(
		root,
		true,
		label,
		allowedWriter,
		ancestors(root),
	)
}

// ValidateTrustedFilePathStrictAncestors is ValidateTrustedFilePath with no
// advisory verdict: every folder above the file, the installer-owned Cisco
// folders included, gets the narrow ancestor mask with fatal verdicts, and
// neither the file nor a folder above it takes the principal drift
// acceptances of the ordinary walk. It is for an image an elevated process
// runs. A standard user who can delete the children of a folder above it, or
// rename or re-ACL that folder, can swap the image between the check and the
// launch, so drift on the Cisco tree must refuse here, not warn.
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
	if err := validateTrustedWindowsPathElementWithWriter(clean, false, label, nil, windowsTrustStrictLeaf); err != nil {
		return err
	}
	for dir := filepath.Dir(clean); ; dir = filepath.Dir(dir) {
		if err := validateTrustedWindowsPathElementWithWriter(dir, true, label, nil, windowsTrustStrictAncestor); err != nil {
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
// writers are SYSTEM and Administrators. Its ancestors take the same scope as
// the install root and gateway executable checked beside it: drift on the
// operating system roots and the shared Cisco Secure Client folders is
// advisory, because Windows and the platform installer own those permissions,
// while every other ancestor stays fatal. A fatal verdict there would demote
// a verified Secure Client host to the standalone rules (fixed agent versions,
// no best-effort hook contract) for as long as the drift lasts.
func ValidateTrustedInstallMarkerDir(path, label string) error {
	if err := validateTrustedWindowsRuntimeDirWithAncestors(path, label, nil, installMarkerAncestorScope); err != nil {
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

// ValidateTrustedFilePathTolerant walks exactly like ValidateTrustedFilePath,
// with the same per-element masks, but downgrades every permission verdict —
// on the named file as well as on each ancestor — to a
// TrustDriftAdvisoryMarker warning and continues. Structural failures
// (missing element, symlink, reparse point, wrong type, non-NTFS mount,
// security-descriptor API errors) stay fatal.
//
// It exists for the CMID broker's own objects (its executable, the CMID
// library; the auth key uses ValidateTrustedFileStructureTolerant), whose ACLs the platform installer and Cloud Management
// re-stamp on their own schedule. A permission drift there must not stop the
// broker, and with it the gateway that depends on it. Pin
// TrustStrictAncestorsEnv to make every verdict fatal again.
//
// Do not use this for paths whose permissions DefenseClaw alone owns; keep
// ValidateTrustedFilePath for those.
func ValidateTrustedFilePathTolerant(path, label string) error {
	return ValidateExecutableFilePath(path, label)
}

// ValidateExecutableFilePath validates a binary or library that DefenseClaw or
// LocalSystem executes or loads (the CMID broker executable, cmidapi.dll, a
// gateway or hook executable). Code integrity is advisory: structural failures
// (missing element, symlink, reparse point, wrong type, non-NTFS mount) stay
// fatal, every permission verdict is accepted, and an untrusted writer or
// owner on the file itself is additionally logged once as a critical
// MarkerBoundary finding naming the path and principal. The caller keeps
// running and loading the file; a privileged component re-stamps the ACL and
// Install, Upgrade and Repair re-copy the binary. Pin TrustStrictAncestorsEnv
// to make every verdict fatal again. A standalone process gets every verdict
// fatal too (windowsTrustScope.driftTolerated, GAP-0561); no caller repairs
// an executable before this check, so there is no repaired-content case.
func ValidateExecutableFilePath(path, label string) error {
	leaf := windowsTrustLeaf.tolerant()
	leaf.code = true
	return validateTrustedFilePathTolerant(path, label, leaf)
}

// ValidateTrustedFileStructureTolerant is ValidateTrustedFilePathTolerant for
// a caller that validates the named file's owner and DACL itself, on its own
// open handle, with a stricter rule than this walk applies (the CMID broker
// auth key). The named file gets the structural checks only — symlink,
// reparse point, regular file — so its permission drift is reported once, by
// the caller; every ancestor is walked drift-tolerantly as usual.
//
// The named file's owner and DACL are never checked here, even with
// TrustStrictAncestorsEnv pinned; the pin only affects the ancestors. A caller
// that needs strict leaf checks under the pin must switch to
// ValidateTrustedFilePath itself, as the CMID broker key loader does.
func ValidateTrustedFileStructureTolerant(path, label string) error {
	return validateTrustedFilePathTolerant(path, label, windowsTrustScope{structureOnly: true})
}

func validateTrustedFilePathTolerant(path, label string, leaf windowsTrustScope) error {
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
	if err := validateTrustedWindowsPathElementWithWriter(clean, false, label, nil, leaf); err != nil {
		return err
	}
	for dir := filepath.Dir(clean); dir != filepath.Dir(dir); dir = filepath.Dir(dir) {
		if err := validateTrustedWindowsPathElementWithWriter(dir, true, label, nil, windowsAncestorScope(dir).tolerant()); err != nil {
			return err
		}
	}
	root := filepath.VolumeName(clean) + string(filepath.Separator)
	return validateTrustedWindowsPathElementWithWriter(
		root,
		true,
		label,
		nil,
		windowsAncestorScope(root).tolerant(),
	)
}

// ValidateTrustedRuntimeDirTolerant is ValidateTrustedRuntimeDir with every
// permission verdict downgraded to a drift advisory, for the same reason as
// ValidateTrustedFilePathTolerant. Structural failures stay fatal.
func ValidateTrustedRuntimeDirTolerant(path, label string) error {
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
		scope := windowsAncestorScope(cur)
		if cur == clean {
			scope = windowsTrustLeaf
		}
		if err := validateTrustedWindowsPathElementWithWriter(cur, true, label, nil, scope.tolerant()); err != nil {
			return err
		}
		if cur == filepath.Dir(cur) {
			break
		}
	}
	return nil
}

// ValidateTrustedDirectoryAncestor validates an existing directory that will
// contain a new protected child. Unlike ValidateTrustedRuntimeDir, the named
// directory is evaluated with the narrow ancestor-replacement mask as well as
// its parents. This accepts stock Windows known-folder create-child grants,
// while still rejecting DELETE_CHILD, DELETE, WRITE_DAC, WRITE_OWNER, generic
// write, reparse points, non-NTFS mounts, and untrusted owners.
//
// A named directory DefenseClaw itself creates and ACLs below the state root
// (hook-guardian manifests, managed policy, namespace purge) keeps every
// verdict FATAL: an untrusted write ACE there is real breakage, not AVC's drift
// on the shared tree. Callers also name folders DefenseClaw does not own — the
// first existing ancestor of a not-yet-created policy root (C:\Program Files,
// C:\ProgramData) or the purge root's parent (...\Cisco Secure Client). Those
// get the advisory ancestor scope (windowsNamedDirectoryScope), because
// DefenseClaw never repairs their permissions. Structural checks stay fatal
// everywhere, and TrustStrictAncestorsEnv keeps every verdict fatal.
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
			scope = windowsNamedDirectoryScope(cur)
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
	return validateTrustedWindowsFilePath(path, label, serviceSID, windowsTrustLeaf, windowsAncestorScope)
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
	return validateTrustedWindowsRulePackTree(dir, label, serviceAccount, windowsTrustLeaf, windowsAncestorScope)
}

// validateTrustedWindowsRulePackTree checks dir as a runtime folder and every
// folder and file below it with the leaf scope.
func validateTrustedWindowsRulePackTree(
	dir, label, serviceAccount string,
	leaf windowsTrustScope,
	ancestors func(string) windowsTrustScope,
) error {
	writer, err := windowsVirtualServiceSID(serviceAccount)
	if err != nil {
		writer = nil
	}
	if err := validateTrustedWindowsRuntimeDirWith(dir, label, writer, leaf, ancestors); err != nil {
		return err
	}
	root, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("resolve %s path: %w", label, err)
	}
	return walkWindowsRulePackTree(root, func(path string, isDir bool) error {
		return validateTrustedWindowsPathElementWithWriter(path, isDir, label, writer, leaf)
	})
}

// UnreadableServiceFolder returns cause unchanged on Windows: the service
// read checks there (ValidateServiceCanReadTree) name the folder and the
// access the service account lacks.
func UnreadableServiceFolder(_, _ string, cause error) error { return cause }

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

// installMarkerAncestorScope is the ancestor scope of the Secure Client
// install marker check (ValidateTrustedInstallMarkerDir).
func installMarkerAncestorScope(path string) windowsTrustScope { return windowsAncestorScope(path) }

// windowsStrictAncestorScope gives every ancestor the narrow mask with fatal
// verdicts and the exact principal rule, the installer-owned Cisco folders
// included.
func windowsStrictAncestorScope(string) windowsTrustScope { return windowsTrustStrictAncestor }

// validateTrustedWindowsRuntimeDirWithAncestors checks the named folder with
// the leaf rule and each folder above it with the scope ancestors picks.
func validateTrustedWindowsRuntimeDirWithAncestors(path, label string, allowedWriter *windows.SID, ancestors func(string) windowsTrustScope) error {
	return validateTrustedWindowsRuntimeDirWith(path, label, allowedWriter, windowsTrustLeaf, ancestors)
}

// validateTrustedWindowsRuntimeDirWith checks the named folder with leaf and
// each folder above it with the scope ancestors picks.
func validateTrustedWindowsRuntimeDirWith(
	path, label string,
	allowedWriter *windows.SID,
	leaf windowsTrustScope,
	ancestors func(string) windowsTrustScope,
) error {
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
			scope = leaf
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
//   - strictPrincipals keeps the exact owner and writer rule on an element of
//     an elevated-image or marker walk: the principal drift acceptances (an
//     administrator-equivalent owner or writer, an inherited create-child
//     entry) do not apply. systemAdminOnly and ownerSystemOnly imply it.
//   - drift downgrades every permission verdict on the element, the named leaf
//     included, to a TrustDriftAdvisoryMarker warning. Unlike advisory it also
//     downgrades an allow ACE whose type the walk cannot evaluate. Only the
//     *Tolerant entry points set it. Structural and API failures are never
//     downgraded, and TrustStrictAncestorsEnv restores fatality.
//   - structureOnly skips the owner and DACL checks on the element entirely,
//     for a named file whose caller checks its permissions on its own handle.
//     Never set on an ancestor.
//   - code marks the named file as executable code: an untrusted writer or
//     owner is also logged as a MarkerBoundary finding. Only meaningful with
//     drift, and never set on an ancestor.
type windowsTrustScope struct {
	narrowMask       bool
	advisory         bool
	systemAdminOnly  bool
	ownerSystemOnly  bool
	strictPrincipals bool
	drift            bool
	structureOnly    bool
	code             bool
}

// acceptsPrincipalDrift reports whether the principal drift acceptances (an
// administrator-equivalent owner or writer, an inherited create-child entry)
// may apply to the element. The code and marker walks keep their exact rule,
// and a structure-only element never reaches a principal verdict.
func (scope windowsTrustScope) acceptsPrincipalDrift() bool {
	return !scope.structureOnly && !scope.systemAdminOnly && !scope.ownerSystemOnly && !scope.strictPrincipals
}

// tolerant returns the scope with the same mask and drift tolerance set.
func (scope windowsTrustScope) tolerant() windowsTrustScope {
	scope.drift = true
	return scope
}

// driftTolerated reports whether this drift-tolerant scope may accept a
// permission verdict: the scope is tolerant, strict mode is off, and the
// process is not on the standalone profile (windowsStandaloneTrustScope).
// The drift acceptances exist for the Secure Client tree, which other Cisco
// installers re-ACL; a standalone install owns its whole tree, so there a
// tolerant walk gives the strict verdict, as before 26.8.4 (GAP-0561).
func (scope windowsTrustScope) driftTolerated() bool {
	return scope.drift && !trustStrictAncestors() && !windowsStandaloneTrustScope()
}

// relaxVerdict is the single exit for a permission verdict on one element.
// Drift wins over advisory so a tolerant walk tags its warnings with the drift
// marker; strict mode, and the standalone profile for drift, make both fall
// through to the verdict.
func (scope windowsTrustScope) relaxVerdict(path, label string, verdict error) error {
	if verdict == nil {
		return nil
	}
	if scope.driftTolerated() {
		reportTrustDrift(path, label, verdict.Error())
		return nil
	}
	return relaxAncestorTrustVerdict(scope.advisory, path, label, verdict)
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
	// windowsTrustStrictLeaf and windowsTrustStrictAncestor are the leaf and
	// foreign-ancestor rules for an image an elevated process runs and for a
	// Secure Client marker: verdicts fatal, and no administrator-equivalent or
	// inherited create-child acceptance.
	windowsTrustStrictLeaf     = windowsTrustScope{strictPrincipals: true}
	windowsTrustStrictAncestor = windowsTrustScope{narrowMask: true, strictPrincipals: true}
)

// windowsAncestorScope picks the ancestor scope from the ancestor's position:
// advisory only inside PlatformInstallerOwnedRoots (AIFW-34262), fatal
// everywhere else. Every ancestor walk in this file routes through here so the
// allowlist cannot be forgotten at one call site.
func windowsAncestorScope(path string) windowsTrustScope {
	if AdvisoryAncestorPath(path) {
		return windowsTrustAncestor
	}
	return windowsTrustForeignAncestor
}

// osRootAncestor reports whether path is one of the fixed operating
// system roots every managed path sits under: the system drive root, the
// Windows and System32 directories, ProgramData and Program Files. Their
// permissions belong to Windows and to whatever hardening the host applies,
// not to DefenseClaw, so drift there is advisory like the platform
// installer's roots. Temp, profile and other prefixes stay fatal.
func osRootAncestor(path string) bool {
	clean := filepath.Clean(path)
	var roots []string
	if dir, err := windows.GetWindowsDirectory(); err == nil && dir != "" {
		roots = append(roots, dir, filepath.VolumeName(dir)+`\`)
	}
	if dir, err := windows.GetSystemDirectory(); err == nil && dir != "" {
		roots = append(roots, dir)
	}
	// Every root comes from Windows or the HKLM machine registration, never
	// the process environment, which the invoking user controls.
	roots = append(roots, trustedMachineInstallBases()...)
	for _, root := range roots {
		if strings.EqualFold(clean, filepath.Clean(root)) {
			return true
		}
	}
	return false
}

// windowsNamedDirectoryScope picks the scope for the directory named to
// ValidateTrustedDirectoryAncestor. An OS root, or a platform installer root
// and the shared folders between it and DefenseClaw's own tree (...\Cisco,
// ...\Cisco\Cisco Secure Client), gets the advisory ancestor scope; everything
// else, including every folder at or below a DefenseClaw folder, stays
// windowsTrustNamedDir. Strict mode keeps the named directory fatal.
func windowsNamedDirectoryScope(path string) windowsTrustScope {
	if !trustStrictAncestors() && (osRootAncestor(path) || installerSharedFolder(path)) {
		return windowsTrustAncestor
	}
	return windowsTrustNamedDir
}

// installerSharedFolder reports whether path is at or below a platform
// installer root without crossing a DefenseClaw-named folder, i.e. a folder
// whose permissions belong to AVC rather than to DefenseClaw.
func installerSharedFolder(path string) bool {
	clean := filepath.Clean(path)
	for _, root := range PlatformInstallerOwnedRoots() {
		root = filepath.Clean(root)
		if !pathAtOrUnder(clean, root) {
			continue
		}
		rel, err := filepath.Rel(root, clean)
		if err != nil {
			return false
		}
		for _, element := range strings.Split(rel, string(filepath.Separator)) {
			if strings.HasPrefix(strings.ToLower(element), "defenseclaw") {
				return false
			}
		}
		return true
	}
	return false
}

// trustedMachineInstallBases returns ProgramData, Program Files and Program
// Files (x86) from the HKLM machine registration. A base that cannot be
// resolved is left out.
func trustedMachineInstallBases() []string {
	var bases []string
	for _, resolve := range []func() (string, error){
		winpath.TrustedProgramData, winpath.TrustedProgramFiles, winpath.TrustedProgramFilesX86,
	} {
		if dir, err := resolve(); err == nil && dir != "" {
			bases = append(bases, dir)
		}
	}
	testMachineInstallBases.Lock()
	defer testMachineInstallBases.Unlock()
	return append(bases, testMachineInstallBases.bases...)
}

var testMachineInstallBases struct {
	sync.Mutex
	bases []string
}

// AddTrustedMachineInstallBaseForTest makes base count as a registered machine
// base (ProgramData, Program Files) for PlatformInstallerOwnedRoots and the
// OS-root ancestor scope, so a test can stand a temporary folder in for one:
// the process environment no longer adds a base. Production code never calls
// it. restore removes base again.
func AddTrustedMachineInstallBaseForTest(base string) (restore func()) {
	testMachineInstallBases.Lock()
	defer testMachineInstallBases.Unlock()
	previous := testMachineInstallBases.bases
	testMachineInstallBases.bases = append(append([]string(nil), previous...), base)
	return func() {
		testMachineInstallBases.Lock()
		defer testMachineInstallBases.Unlock()
		testMachineInstallBases.bases = previous
	}
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
	if scope.structureOnly {
		return nil
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
		if acceptUnreadableDescriptor(scope, err) {
			// The element's DACL no longer grants this caller READ_CONTROL.
			// Its type and reparse state were checked above through
			// attributes, which is all an ancestor or a drift-tolerant
			// element needs; the permissions belong to whoever re-ACLed it.
			reportTrustDrift(path, label, "security descriptor is not readable: "+err.Error())
			return nil
		}
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
	if !trustedOwner && acceptAdminEquivalent(scope, path, label, "owner", owner) {
		// An administrator account or domain admin group owns the element:
		// accepted and logged, never fatal.
	} else if !trustedOwner {
		if scope.code {
			reportCodeIntegrityFinding(path, label, sidString(owner), "untrusted owner")
		}
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
		if err := scope.relaxVerdict(path, label, &UntrustedPrincipalError{
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
		if scope.code {
			reportCodeIntegrityFinding(path, label, "Everyone", "null DACL")
		}
		return scope.relaxVerdict(path, label, fmt.Errorf(
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
		case accessAllowedObjectACEType, accessAllowedCallbackObjectACEType:
			// Not a permission verdict: the ACE layout differs from
			// ACCESS_ALLOWED_ACE, so ace.Mask and ace.SidStart cannot be read
			// and this walk has no idea who was granted what. Advisory mode
			// must not turn "cannot evaluate" into "trusted" — stock NTFS never
			// carries these types, and AIFW-34262's grant was a plain
			// ACCESS_ALLOWED_ACE, so keeping them fatal costs no install.
			// Only a drift scope (the broker's own objects) accepts them,
			// because there the product decision is to never stop on
			// permissions alone.
			verdict := fmt.Errorf(
				"%s: unsupported allow ACE type 0x%x; refusing managed trust", path, ace.Header.AceType,
			)
			if !scope.driftTolerated() {
				return verdict
			}
			if err := scope.relaxVerdict(path, label, verdict); err != nil {
				return err
			}
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE, accessAllowedCallbackACEType:
			// A callback (conditional) allow entry has the ACCESS_ALLOWED_ACE
			// layout followed by its condition, so its trustee and mask are
			// judged like a plain entry: the condition can only narrow it.
		default:
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		writeLike := windowsWriteLikeAccess(ace.Mask)
		// The narrower ancestor rule ignores create-child bits, which an
		// object-inheritable entry would hand to every new file as write
		// data and append data; those entries keep the full rule.
		if scope.narrowMask && !windowsWorldSID(sid) &&
			ace.Header.AceFlags&windows.OBJECT_INHERIT_ACE == 0 {
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
			if acceptAdminEquivalent(scope, path, label, fmt.Sprintf("writer mask 0x%x", uint32(ace.Mask)), sid) {
				continue
			}
			if scope.acceptsPrincipalDrift() && acceptInheritedCreateChild(path, label, ace.Header.AceFlags, ace.Mask, sid) {
				continue
			}
			if scope.code {
				reportCodeIntegrityFinding(path, label, sidString(sid), fmt.Sprintf("write-like access mask 0x%x", uint32(ace.Mask)))
			}
			if err := scope.relaxVerdict(path, label, &UntrustedPrincipalError{
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

// acceptUnreadableDescriptor reports whether an error reading an element's
// security descriptor is drift rather than a structural failure: access denied
// on an ancestor inside the platform installer's roots, or on any element of
// a drift-tolerant walk. Strict mode and the exact principal rule keep it
// fatal.
func acceptUnreadableDescriptor(scope windowsTrustScope, err error) bool {
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) || trustStrictAncestors() || scope.strictPrincipals {
		return false
	}
	return scope.advisory || scope.driftTolerated()
}

// acceptAdminEquivalent accepts and logs an owner or writer that is an
// administrator principal outside the core trusted set (the built-in
// Administrator account, Domain Admins, Enterprise Admins, a local
// Administrators member). It reports false, leaving the verdict to the caller,
// in strict mode or when sid is not administrator-equivalent.
func acceptAdminEquivalent(scope windowsTrustScope, path, label, what string, sid *windows.SID) bool {
	if !scope.acceptsPrincipalDrift() || trustStrictAncestors() || !windowsAdminEquivalentOwner(sid) {
		return false
	}
	reportTrustDrift(path, label, fmt.Sprintf("%s %s is an administrator principal, not a canonical owner or writer", what, sidString(sid)))
	return true
}

// reportCodeIntegrityFinding logs an untrusted writer or owner on executable
// code once per (path, principal, reason) as a critical, non-fatal boundary
// finding.
func reportCodeIntegrityFinding(path, label, principal, reason string) {
	fields := map[string]string{
		"path":      path,
		"object":    label,
		"principal": principal,
		"reason":    reason,
	}
	if !advisoryLogDedupe.shouldEmit(path, MarkerBoundary, FormatResilienceEvent(MarkerBoundary, fields)) {
		return
	}
	EmitResilienceEvent(MarkerBoundary, fields)
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
	// Return the SID computed from the validated name instead of asking LSA.
	// Before the service exists LSA does not know the name and forwards it
	// to a domain controller; a domain-joined host off the corporate network
	// then fails the lookup (ERROR_TRUSTED_RELATIONSHIP_FAILURE) even though
	// the SID depends only on the name.
	return derived, nil
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

// windowsCreateChildOnlyMask is what an inherited ProgramData entry grants
// BUILTIN\Users on a folder (0x116 plus read and traverse): list, read, add
// files and subfolders, and set the folder's own attributes. None of it can
// change, rename or delete anything already in the folder.
const windowsCreateChildOnlyMask windows.ACCESS_MASK = 0x001201bf

var acceptedCreateChild sync.Map

// AcceptInheritedCreateChild is acceptInheritedCreateChild for the gateway's
// own trust walks (audit store, judge-body store, hook token folders), so a
// folder reset to inherit from C:\ProgramData is judged the same way
// everywhere. It reports whether the entry is accepted, logging it once.
func AcceptInheritedCreateChild(path, label string, flags uint8, mask windows.ACCESS_MASK, sid *windows.SID) bool {
	return acceptInheritedCreateChild(path, label, flags, mask, sid)
}

// acceptInheritedCreateChild accepts, and logs once per path, an inherited
// create-child-only entry for Users or Authenticated Users on a directory:
// the shape a folder takes after its protection is reset to inherit from
// C:\ProgramData. Strict mode keeps it fatal.
func acceptInheritedCreateChild(path, label string, flags uint8, mask windows.ACCESS_MASK, sid *windows.SID) bool {
	// An object-inheritable entry would pass these bits to new files, where
	// add-file and add-subfolder mean write data and append data.
	if trustStrictAncestors() || flags&windows.INHERITED_ACE == 0 || flags&windows.OBJECT_INHERIT_ACE != 0 ||
		mask&^windowsCreateChildOnlyMask != 0 {
		return false
	}
	if sid == nil || !(sid.IsWellKnown(windows.WinBuiltinUsersSid) || sid.IsWellKnown(windows.WinAuthenticatedUserSid)) {
		return false
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	key := strings.ToLower(filepath.Clean(path)) + "\x00" + sidString(sid)
	if _, seen := acceptedCreateChild.LoadOrStore(key, struct{}{}); !seen {
		EmitResilienceEvent(MarkerAccept, map[string]string{
			"path":      path,
			"label":     label,
			"principal": sidString(sid),
			"reason":    fmt.Sprintf("inherited create-child-only access mask 0x%x on a folder", uint32(mask)),
		})
	}
	return true
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
