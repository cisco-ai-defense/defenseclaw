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
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

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

func ValidateTrustedRuntimeDir(path, label string) error {
	return validateTrustedWindowsRuntimeDir(path, label, nil)
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
	return validateTrustedFilePathTolerant(path, label, windowsTrustLeaf.tolerant())
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

func validateTrustedWindowsRuntimeDir(path, label string, allowedWriter *windows.SID) error {
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
		if err := validateTrustedWindowsPathElementWithWriter(cur, true, label, allowedWriter, scope); err != nil {
			return err
		}
		if cur == filepath.Dir(cur) {
			break
		}
	}
	return nil
}

// windowsTrustScope carries the two INDEPENDENT relaxations that apply when a
// managed path is walked. They used to be one `ancestor bool`, which silently
// coupled them: any element that needed the narrower mask also lost the ability
// to fail. Keep them separate so each call site states exactly what it wants.
//
//   - narrowMask evaluates allow ACEs with WindowsAncestorReplaceAccess instead
//     of the full write-like mask. Required for stock Windows known-folder
//     grants (BUILTIN\Users add-file and write-EA/attributes on roots such as
//     C:\ProgramData), none of which can replace an existing protected child.
//   - advisory downgrades owner/DACL *verdicts* to a TrustAdvisoryMarker warning
//     and continues the walk (AIFW-34262). Structural and API failures are never
//     downgraded, and TrustStrictAncestorsEnv restores fatality.
//   - drift downgrades every permission verdict on the element, the named leaf
//     included, to a TrustDriftAdvisoryMarker warning. Unlike advisory it also
//     downgrades an allow ACE whose type the walk cannot evaluate. Only the
//     *Tolerant entry points set it. Structural and API failures are never
//     downgraded, and TrustStrictAncestorsEnv restores fatality.
//   - structureOnly skips the owner and DACL checks on the element entirely,
//     for a named file whose caller checks its permissions on its own handle.
//     Never set on an ancestor.
type windowsTrustScope struct {
	narrowMask    bool
	advisory      bool
	drift         bool
	structureOnly bool
}

// tolerant returns the scope with the same mask and drift tolerance set.
func (scope windowsTrustScope) tolerant() windowsTrustScope {
	scope.drift = true
	return scope
}

// relaxVerdict is the single exit for a permission verdict on one element.
// Drift wins over advisory so a tolerant walk tags its warnings with the drift
// marker; strict mode makes both fall through to the verdict.
func (scope windowsTrustScope) relaxVerdict(path, label string, verdict error) error {
	if verdict == nil {
		return nil
	}
	if scope.drift && !trustStrictAncestors() {
		reportTrustDrift(path, label, verdict.Error())
		return nil
	}
	return relaxAncestorTrustVerdict(scope.advisory, path, label, verdict)
}

var (
	// windowsTrustLeaf is the named artifact a caller asked about: strictest
	// mask, every verdict fatal.
	windowsTrustLeaf = windowsTrustScope{}
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

func validateTrustedWindowsPathElement(path string, wantDir bool, label string) error {
	return validateTrustedWindowsPathElementWithWriter(path, wantDir, label, nil, windowsTrustLeaf)
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
		return fmt.Errorf("%s: inspect Windows security descriptor: %w", path, err)
	}
	if sd == nil {
		return fmt.Errorf("%s: missing Windows security descriptor", path)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("%s: inspect Windows owner: %w", path, err)
	}
	if !windowsTrustedPathOwner(owner, allowedWriter) {
		expected := "Administrators, LocalSystem, or TrustedInstaller"
		if allowedWriter != nil {
			expected = fmt.Sprintf("%s, or the pinned service SID %s", expected, sidString(allowedWriter))
		}
		if err := scope.relaxVerdict(path, label, fmt.Errorf(
			"%s: owner %s is not trusted for %s; expected %s", path, sidString(owner), label, expected,
		)); err != nil {
			return err
		}
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("%s: inspect Windows DACL: %w", path, err)
	}
	if dacl == nil {
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
		case accessAllowedObjectACEType, accessAllowedCallbackACEType, accessAllowedCallbackObjectACEType:
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
			if !scope.drift {
				return verdict
			}
			if err := scope.relaxVerdict(path, label, verdict); err != nil {
				return err
			}
			continue
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
		if !windowsTrustedOwner(sid) && !sameWindowsSID(sid, allowedWriter) {
			if err := scope.relaxVerdict(path, label, fmt.Errorf(
				"%s: untrusted Windows principal %s has write-like access mask 0x%x",
				path, sidString(sid), uint32(ace.Mask),
			)); err != nil {
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
	const prefix = `NT SERVICE\`
	if len(account) <= len(prefix) || !strings.EqualFold(account[:len(prefix)], prefix) {
		return nil, fmt.Errorf(
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
		return nil, fmt.Errorf("%s contains an invalid service name: %q", WindowsServiceAccountEnv, account)
	}
	if len(name) > 128 {
		return nil, fmt.Errorf("%s service name is too long", WindowsServiceAccountEnv)
	}
	sid, _, _, err := windows.LookupSID("", account)
	if errors.Is(err, windows.ERROR_NONE_MAPPED) {
		// SCM removes the virtual account mapping when an uninstall deletes
		// the service. Committed managed-hook teardown still has to validate
		// the retained runtime before it can retire its authenticated journal.
		// Match the installer's recovery path: sc.exe showsid computes the
		// service SID from the exact validated name without an SCM row.
		sid, err = windowsDeterministicServiceSID(name)
	}
	if err != nil {
		return nil, fmt.Errorf("resolve Windows virtual service account %q: %w", account, err)
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

var windowsServiceSIDOutput = regexp.MustCompile(
	`S-1-5-80-(?:[0-9]{1,10}-){4}[0-9]{1,10}`,
)

func windowsDeterministicServiceSID(name string) (*windows.SID, error) {
	systemDir, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, fmt.Errorf("resolve Windows system directory: %w", err)
	}
	scExe := filepath.Join(systemDir, "sc.exe")
	if err := ValidateTrustedFilePath(scExe, "Windows service SID calculator"); err != nil {
		return nil, fmt.Errorf("validate Windows service SID calculator: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, scExe, "showsid", name)
	command.Dir = systemDir
	output, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("compute Windows virtual service SID: %w", err)
	}
	if len(output) > 4096 {
		return nil, errors.New("Windows service SID calculator output exceeds 4096 bytes")
	}
	return parseWindowsServiceSIDOutput(string(output))
}

func parseWindowsServiceSIDOutput(output string) (*windows.SID, error) {
	matches := windowsServiceSIDOutput.FindAllStringIndex(output, -1)
	if len(matches) != 1 {
		return nil, errors.New("Windows service SID calculator did not return exactly one service SID")
	}
	start, end := matches[0][0], matches[0][1]
	if start > 0 && isWindowsSIDChar(output[start-1]) ||
		end < len(output) && isWindowsSIDChar(output[end]) {
		return nil, errors.New("Windows service SID calculator returned a partial service SID")
	}
	sid, err := windows.StringToSid(output[start:end])
	if err != nil || !sidIsNTService(sid) || sid.SubAuthorityCount() != 6 {
		return nil, errors.New("Windows service SID calculator returned an invalid service SID")
	}
	return sid, nil
}

func isWindowsSIDChar(char byte) bool {
	return char == '-' || char >= '0' && char <= '9'
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

// windowsTokenOwner mirrors the Win32 TOKEN_OWNER structure.
type windowsTokenOwner struct {
	Owner *windows.SID
}

// AdoptWindowsGatewayServiceDefaultOwner makes the gateway's service SID the
// default owner of objects the gateway process creates.
//
// The gateway logs on as LocalSystem with a write-restricted token. Without
// this, its new files are owned by LocalSystem, which is not one of the
// token's restricting SIDs, so the owner's implicit WRITE_DAC fails the
// restricted access check and the gateway cannot apply the protected DACL to
// files it just created (for example SQLite's -wal sidecar). With the service
// SID as owner, new files are owned as they were when the gateway logged on as
// the virtual account. It reports whether the owner was changed; it is a no-op
// for any process that is not the pinned gateway service, and for a gateway
// still logged on as its virtual account.
func AdoptWindowsGatewayServiceDefaultOwner() (bool, error) {
	account := strings.TrimSpace(os.Getenv(WindowsServiceAccountEnv))
	if account == "" {
		return false, nil
	}
	var token windows.Token
	if err := windows.OpenProcessToken(
		windows.CurrentProcess(),
		windows.TOKEN_QUERY|windows.TOKEN_ADJUST_DEFAULT,
		&token,
	); err != nil {
		return false, fmt.Errorf("windows gateway default owner: open process token: %w", err)
	}
	defer func() { _ = token.Close() }()
	resolveServiceSID := func() (*windows.SID, error) { return windowsVirtualServiceSID(account) }
	return adoptWindowsGatewayServiceDefaultOwner(token, resolveServiceSID, func(owner *windows.SID) error {
		value := windowsTokenOwner{Owner: owner}
		return windows.SetTokenInformation(
			token,
			windows.TokenOwner,
			(*byte)(unsafe.Pointer(&value)),
			uint32(unsafe.Sizeof(value)),
		)
	})
}

// adoptWindowsGatewayServiceDefaultOwner reads the token user before it
// resolves the pinned service SID, so a pin that does not resolve only fails a
// LocalSystem process and never a gateway still on its virtual account.
func adoptWindowsGatewayServiceDefaultOwner(
	token windowsTokenIdentity,
	resolveServiceSID func() (*windows.SID, error),
	setOwner func(*windows.SID) error,
) (bool, error) {
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return false, fmt.Errorf("windows gateway default owner: read token user: %w", err)
	}
	if !user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		// Virtual-account logon already owns new objects as the service SID.
		return false, nil
	}
	serviceSID, err := resolveServiceSID()
	if err != nil {
		return false, err
	}
	isGateway, err := windowsTokenRunsAsService(token, serviceSID)
	if err != nil {
		return false, err
	}
	if !isGateway {
		return false, nil
	}
	if err := setOwner(serviceSID); err != nil {
		return false, fmt.Errorf(
			"windows gateway default owner: set token owner to service SID %s: %w",
			sidString(serviceSID), err,
		)
	}
	return true, nil
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
