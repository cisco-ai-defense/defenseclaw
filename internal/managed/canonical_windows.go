// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package managed

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// EnsureCanonical makes path carry kind's canonical security descriptor.
//
// It opens the object by handle without following a reparse point, checks
// its structure (reparse point, hard links, object type, NTFS fixed volume:
// fatal, returned as an error), and judges the descriptor by effective write
// authority. Drift is repaired by stamping the canonical owner, group and
// protected DACL on the same handle, with SeRestorePrivilege,
// SeTakeOwnershipPrivilege and SeBackupPrivilege enabled when the caller
// holds them, and the result is re-judged.
//
// An object owned by a principal outside the trusted and
// administrator-equivalent set is not adopted unless
// opts.AllowUntrustedOwnerTransfer is set; it is reported as a boundary.
// Inside the gateway service, whose write-restricted token cannot change these
// descriptors, EnsureCanonical never writes and behaves like AssessCanonical.
func EnsureCanonical(path string, kind ObjectKind, opts CanonicalOptions) (CanonicalResult, error) {
	return canonicalize(path, kind, opts, !WindowsCurrentProcessIsGatewayService())
}

// AssessCanonical is the read-only form of EnsureCanonical: it reports
// accepted or boundary drift without writing anything.
func AssessCanonical(path string, kind ObjectKind, opts CanonicalOptions) (CanonicalResult, error) {
	return canonicalize(path, kind, opts, false)
}

func canonicalize(path string, kind ObjectKind, opts CanonicalOptions, repair bool) (CanonicalResult, error) {
	result := CanonicalResult{Path: path, Kind: kind}
	fail := func(err error) (CanonicalResult, error) {
		result.Outcome = CanonicalStructural
		result.Err = err
		reportCanonicalResult(result, opts)
		return result, err
	}
	if !kind.valid() {
		return fail(fmt.Errorf("unknown managed object kind %q", kind))
	}
	if strings.TrimSpace(path) == "" {
		return fail(errors.New("managed object path is empty"))
	}
	clean, err := filepath.Abs(path)
	if err != nil {
		return fail(fmt.Errorf("resolve %s: %w", path, err))
	}
	result.Path = clean
	if _, err := os.Lstat(clean); os.IsNotExist(err) {
		result.Outcome = CanonicalMissing
		return result, nil
	}
	if _, err := winpath.ValidateFixedNTFSMountedPath(clean); err != nil {
		return fail(fmt.Errorf("%s is not on a fixed local NTFS volume: %w", clean, err))
	}
	if err := winpath.RejectReparseChain(filepath.Dir(clean)); err != nil {
		return fail(fmt.Errorf("%s: %w", clean, err))
	}

	gatewaySID := ""
	if sid, err := windowsVirtualServiceSID(canonicalGatewayAccount(opts)); err == nil && sid != nil {
		gatewaySID = sid.String()
	}

	handle, err := openCanonicalObject(clean, uint32(windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES))
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		result.Outcome = CanonicalMissing
		return result, nil
	}
	descriptorUnreadable := false
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		// The DACL no longer lets this caller read it. Structure is still
		// checked through an attribute-only open; a privileged repair then
		// reads the descriptor with backup semantics.
		descriptorUnreadable = true
		handle, err = openCanonicalObject(clean, uint32(windows.FILE_READ_ATTRIBUTES))
	}
	if err != nil {
		return fail(fmt.Errorf("open %s: %w", clean, err))
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	if err := checkCanonicalStructure(handle, clean, kind); err != nil {
		return fail(err)
	}

	var desc objectDescriptor
	if descriptorUnreadable && repair {
		// Backup semantics with SeBackupPrivilege grant READ_CONTROL whatever
		// the DACL says, so the owner is known before anything is adopted.
		if err := RunWithWindowsRepairPrivileges(func() error {
			privileged, openErr := openCanonicalObject(clean, uint32(windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES))
			if openErr != nil {
				return openErr
			}
			defer func() { _ = windows.CloseHandle(privileged) }()
			if same, sameErr := sameWindowsFile(handle, privileged); sameErr != nil || !same {
				return errors.New("object changed during inspection")
			}
			var readErr error
			desc, readErr = readObjectDescriptor(privileged)
			return readErr
		}); err == nil {
			descriptorUnreadable = false
		}
	}
	var assessment canonicalAssessment
	if descriptorUnreadable {
		// Neither this caller nor its privileges can read the descriptor:
		// accept and report it, never adopt it blind.
		assessment = canonicalAssessment{Owner: ownerTrusted, Drift: []string{"security descriptor is not readable"}}
		repair = false
	} else {
		if desc.Owner == "" && desc.ACEs == nil && !desc.NullDACL {
			var err error
			if desc, err = readObjectDescriptor(handle); err != nil {
				return fail(fmt.Errorf("%s: read security descriptor: %w", clean, err))
			}
		}
		assessment = assessCanonicalDescriptor(desc, kind, gatewaySID, windowsLocalAdministratorsMember)
	}
	result.Drift = assessment.Drift
	result.UntrustedWriters = assessment.UntrustedWriters
	result.GatewayAccessMissing = assessment.GatewayAccessMissing
	result.Outcome = assessment.outcome()
	if result.Outcome == CanonicalOK || !repair {
		reportCanonicalResult(result, opts)
		return result, nil
	}
	if assessment.Owner == ownerUntrusted && !descriptorUnreadable && !opts.AllowUntrustedOwnerTransfer {
		result.Outcome = CanonicalBoundary
		result.RepairError = "owner is not trusted; not adopted"
		reportCanonicalResult(result, opts)
		return result, nil
	}
	spec := canonicalSpecFor(kind, gatewaySID)
	if gatewaySID == "" && kind != ObjectConfigFile && kind != ObjectConfigDirectory {
		// Every runtime form names the gateway service; stamping without it
		// would lock the gateway out.
		result.RepairError = "gateway service identity is unavailable"
		reportCanonicalResult(result, opts)
		return result, nil
	}
	if repairErr := stampCanonicalDescriptor(handle, clean, kind, spec.canonicalSDDL()); repairErr != nil {
		result.RepairError = repairErr.Error()
		reportCanonicalResult(result, opts)
		return result, nil
	}
	desc, err = readObjectDescriptor(handle)
	if err != nil {
		result.RepairError = "re-read repaired descriptor: " + err.Error()
		reportCanonicalResult(result, opts)
		return result, nil
	}
	after := assessCanonicalDescriptor(desc, kind, gatewaySID, windowsLocalAdministratorsMember)
	switch {
	case after.Canonical:
		result.Outcome = CanonicalRepaired
	case after.boundary():
		result.Outcome = CanonicalBoundary
		result.RepairError = "descriptor still drifted after repair: " + strings.Join(after.Drift, "; ")
	default:
		result.Outcome = CanonicalAccepted
		result.RepairError = "descriptor still drifted after repair: " + strings.Join(after.Drift, "; ")
	}
	reportCanonicalResult(result, opts)
	return result, nil
}

func canonicalGatewayAccount(opts CanonicalOptions) string {
	if account := strings.TrimSpace(opts.GatewayServiceAccount); account != "" {
		return account
	}
	return os.Getenv(WindowsServiceAccountEnv)
}

// Transient-open retry budget: a backup agent, an antivirus scan or the
// installer can hold the object briefly. Access denied and not found are
// never retried.
var (
	canonicalOpenAttempts = 6
	canonicalOpenBackoff  = 50 * time.Millisecond
)

// openCanonicalObject opens path without following a reparse point and with
// backup semantics, so a directory opens and a privileged caller's backup and
// restore privileges apply. Sharing and lock violations are retried with a
// bounded backoff.
func openCanonicalObject(path string, access uint32) (windows.Handle, error) {
	pointer, err := winpath.UTF16Ptr(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return retryTransientOpen(func() (windows.Handle, error) {
		return windows.CreateFile(
			pointer,
			access,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
			nil,
			windows.OPEN_EXISTING,
			windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
			0,
		)
	})
}

// RetryTransientOpen runs open until it succeeds or fails with something other
// than a sharing or lock violation, within the package's bounded retry budget.
// Access denied and not found are returned at once.
func RetryTransientOpen(open func() (windows.Handle, error)) (windows.Handle, error) {
	return retryTransientOpen(open)
}

func retryTransientOpen(open func() (windows.Handle, error)) (windows.Handle, error) {
	delay := canonicalOpenBackoff
	var lastErr error
	for attempt := 0; attempt < canonicalOpenAttempts; attempt++ {
		handle, err := open()
		if err == nil {
			return handle, nil
		}
		lastErr = err
		if !IsTransientWindowsError(err) {
			return windows.InvalidHandle, err
		}
		time.Sleep(delay)
		delay *= 2
	}
	return windows.InvalidHandle, lastErr
}

// IsTransientWindowsError reports a sharing or lock violation: another
// process holds the object for a moment. Never access denied or not found.
func IsTransientWindowsError(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_LOCK_VIOLATION)
}

func checkCanonicalStructure(handle windows.Handle, path string, kind ObjectKind) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return fmt.Errorf("%s: inspect object: %w", path, err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%s: reparse points are not allowed for managed objects", path)
	}
	isDir := info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if isDir != kind.Directory() {
		if kind.Directory() {
			return fmt.Errorf("%s: expected a directory", path)
		}
		return fmt.Errorf("%s: expected a regular file", path)
	}
	if !isDir && info.NumberOfLinks != 1 {
		return fmt.Errorf("%s: file has %d hard links, expected exactly 1", path, info.NumberOfLinks)
	}
	return nil
}

func readObjectDescriptor(handle windows.Handle) (objectDescriptor, error) {
	sd, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return objectDescriptor{}, err
	}
	return objectDescriptorFromSD(sd)
}

func objectDescriptorFromSD(sd *windows.SECURITY_DESCRIPTOR) (objectDescriptor, error) {
	var desc objectDescriptor
	if sd == nil {
		return desc, errors.New("missing security descriptor")
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return desc, err
	}
	if owner != nil {
		desc.Owner = owner.String()
	}
	control, _, err := sd.Control()
	if err != nil {
		return desc, err
	}
	desc.Protected = control&windows.SE_DACL_PROTECTED != 0
	dacl, _, err := sd.DACL()
	if err != nil {
		return desc, err
	}
	if dacl == nil {
		desc.NullDACL = true
		return desc, nil
	}
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil || ace == nil {
			return desc, fmt.Errorf("inspect ACE %d: %w", index, err)
		}
		entry := descriptorACE{Type: ace.Header.AceType, Flags: ace.Header.AceFlags, Mask: uint32(ace.Mask)}
		switch ace.Header.AceType {
		case aceTypeAllowed, aceTypeDenied, aceTypeAllowedCallback:
			// Same mask and SID offset as ACCESS_ALLOWED_ACE.
			entry.SID = (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		}
		desc.ACEs = append(desc.ACEs, entry)
	}
	return desc, nil
}

// stampCanonicalDescriptor writes sddl's owner, group and protected DACL to
// the object open as readHandle, through a second handle proven to be the same
// file. With the restore privilege enabled the second open is granted
// WRITE_DAC and WRITE_OWNER whatever the current DACL says; without it, an
// owner change is dropped and only the DACL is written, which the owner's
// implicit rights allow for an administrator-owned object.
func stampCanonicalDescriptor(readHandle windows.Handle, path string, kind ObjectKind, sddl string) error {
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("build canonical descriptor: %w", err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return fmt.Errorf("read canonical owner: %w", err)
	}
	group, _, err := descriptor.Group()
	if err != nil {
		return fmt.Errorf("read canonical group: %w", err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf("read canonical DACL: %w", err)
	}
	return RunWithWindowsRepairPrivileges(func() error {
		full := uint32(windows.READ_CONTROL | windows.WRITE_DAC | windows.WRITE_OWNER | windows.FILE_READ_ATTRIBUTES)
		handle, openErr := openCanonicalObject(path, full)
		ownerToo := openErr == nil
		if openErr != nil {
			handle, openErr = openCanonicalObject(path, uint32(windows.READ_CONTROL|windows.WRITE_DAC|windows.FILE_READ_ATTRIBUTES))
		}
		if openErr != nil {
			return fmt.Errorf("open for repair: %w", openErr)
		}
		defer func() { _ = windows.CloseHandle(handle) }()
		if err := checkCanonicalStructure(handle, path, kind); err != nil {
			return err
		}
		same, err := sameWindowsFile(readHandle, handle)
		if err != nil {
			return fmt.Errorf("compare handles: %w", err)
		}
		if !same {
			return errors.New("object changed between inspection and repair")
		}
		dataInfo := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
		if ownerToo {
			info := dataInfo | windows.OWNER_SECURITY_INFORMATION | windows.GROUP_SECURITY_INFORMATION
			if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, info, owner, group, dacl, nil); err == nil {
				return nil
			}
			// The owner may be refused (no restore privilege for an owner
			// other than the caller); keep the DACL repair.
		}
		if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, dataInfo, nil, nil, dacl, nil); err != nil {
			return fmt.Errorf("apply canonical DACL: %w", err)
		}
		return nil
	})
}

func sameWindowsFile(left, right windows.Handle) (bool, error) {
	var a, b windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(left, &a); err != nil {
		return false, err
	}
	if err := windows.GetFileInformationByHandle(right, &b); err != nil {
		return false, err
	}
	return a.VolumeSerialNumber == b.VolumeSerialNumber &&
		a.FileIndexHigh == b.FileIndexHigh &&
		a.FileIndexLow == b.FileIndexLow, nil
}

// windowsRepairPrivileges are enabled, each when held, for a privileged
// descriptor repair.
var windowsRepairPrivileges = []string{"SeRestorePrivilege", "SeTakeOwnershipPrivilege", "SeBackupPrivilege"}

// RunWithWindowsRepairPrivileges runs fn on a locked OS thread that
// impersonates the process token with SeRestorePrivilege,
// SeTakeOwnershipPrivilege and SeBackupPrivilege enabled where the token holds
// them. A privilege a policy removed is reported once with MarkerPrereq and
// skipped, so the repair degrades to what the remaining rights allow instead
// of failing. The thread is reverted before it is returned to the runtime.
func RunWithWindowsRepairPrivileges(fn func() error) error {
	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if err := windows.ImpersonateSelf(windows.SecurityImpersonation); err != nil {
			runtime.UnlockOSThread()
			// No dedicated token: run with the process token as it is.
			result <- fn()
			return
		}
		var token windows.Token
		if err := windows.OpenThreadToken(
			windows.CurrentThread(),
			windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY,
			false,
			&token,
		); err == nil {
			for _, name := range windowsRepairPrivileges {
				if enableErr := enableWindowsPrivilege(token, name); enableErr != nil {
					reportMissingRepairPrivilege(name, enableErr)
				}
			}
			_ = token.Close()
		}
		callErr := fn()
		if revertErr := windows.RevertToSelf(); revertErr != nil {
			// Never hand a privileged thread back to the scheduler: keep it
			// locked so the runtime retires it with this goroutine.
			if callErr == nil {
				callErr = fmt.Errorf("revert repair privileges: %w", revertErr)
			}
			result <- callErr
			return
		}
		runtime.UnlockOSThread()
		result <- callErr
	}()
	return <-result
}

func enableWindowsPrivilege(token windows.Token, name string) error {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, namePtr, &luid); err != nil {
		return err
	}
	state := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges:     [1]windows.LUIDAndAttributes{{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}},
	}
	if err := windows.AdjustTokenPrivileges(token, false, &state, 0, nil, nil); err != nil {
		return err
	}
	if err := windows.GetLastError(); errors.Is(err, windows.ERROR_NOT_ALL_ASSIGNED) {
		return errors.New("privilege is not held")
	}
	return nil
}

var missingRepairPrivilegeOnce sync.Map

func reportMissingRepairPrivilege(name string, err error) {
	if _, loaded := missingRepairPrivilegeOnce.LoadOrStore(name, struct{}{}); loaded {
		return
	}
	EmitResilienceEvent(MarkerPrereq, map[string]string{
		"privilege": name,
		"reason":    err.Error(),
		"remedy":    "grant the privilege to Administrators and LocalSystem; repairs that need it are skipped",
	})
}

// Local Administrators membership, for owner and writer SIDs that are not
// otherwise recognised. Cached briefly: the guardian asks on every tick.
var (
	modNetapi32                 = windows.NewLazySystemDLL("netapi32.dll")
	procNetLocalGroupGetMembers = modNetapi32.NewProc("NetLocalGroupGetMembers")
	procNetApiBufferFree        = modNetapi32.NewProc("NetApiBufferFree")

	localAdminsMu      sync.Mutex
	localAdminsCache   map[string]bool
	localAdminsExpires time.Time
)

const localAdminsCacheTTL = time.Minute

func windowsLocalAdministratorsMember(sid string) bool {
	localAdminsMu.Lock()
	defer localAdminsMu.Unlock()
	if localAdminsCache == nil || time.Now().After(localAdminsExpires) {
		members, err := listLocalAdministrators()
		if err != nil {
			members = map[string]bool{}
		}
		localAdminsCache = members
		localAdminsExpires = time.Now().Add(localAdminsCacheTTL)
	}
	return localAdminsCache[sid]
}

type localGroupMembersInfo0 struct {
	SID *windows.SID
}

func listLocalAdministrators() (map[string]bool, error) {
	if err := procNetLocalGroupGetMembers.Find(); err != nil {
		return nil, err
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, err
	}
	// The group name is localized; resolve it from the well-known SID.
	name, _, _, err := administrators.LookupAccount("")
	if err != nil {
		return nil, err
	}
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	members := map[string]bool{}
	var resume uintptr
	for {
		var buffer *byte
		var read, total uint32
		const maxPreferredLength = 0xFFFFFFFF
		ret, _, _ := procNetLocalGroupGetMembers.Call(
			0,
			uintptr(unsafe.Pointer(namePtr)),
			0,
			uintptr(unsafe.Pointer(&buffer)),
			uintptr(maxPreferredLength),
			uintptr(unsafe.Pointer(&read)),
			uintptr(unsafe.Pointer(&total)),
			uintptr(unsafe.Pointer(&resume)),
		)
		const errorMoreData = 234
		if ret != 0 && ret != errorMoreData {
			if buffer != nil {
				_, _, _ = procNetApiBufferFree.Call(uintptr(unsafe.Pointer(buffer)))
			}
			return nil, windows.Errno(ret)
		}
		if buffer != nil {
			entries := unsafe.Slice((*localGroupMembersInfo0)(unsafe.Pointer(buffer)), read)
			for _, entry := range entries {
				if entry.SID != nil && entry.SID.IsValid() {
					members[entry.SID.String()] = true
				}
			}
			_, _, _ = procNetApiBufferFree.Call(uintptr(unsafe.Pointer(buffer)))
		}
		if ret != errorMoreData {
			return members, nil
		}
	}
}

// windowsAdminEquivalentOwner reports whether sid is an administrator
// principal outside the core trusted set: the built-in Administrator account,
// Domain Admins, Enterprise Admins, or a direct member of local
// Administrators. Owner drift to one of these is accepted and logged, never
// fatal: an administrator can already do anything the owner can.
func windowsAdminEquivalentOwner(sid *windows.SID) bool {
	if sid == nil || !sid.IsValid() {
		return false
	}
	text := sid.String()
	return adminEquivalentSID(text) || windowsLocalAdministratorsMember(text)
}

// WindowsAdminEquivalentPrincipal reports whether sid is an administrator
// principal outside SYSTEM, Administrators and TrustedInstaller: the built-in
// Administrator account, Domain Admins, Enterprise Admins or a direct member
// of local Administrators. Validators accept such an owner or writer as drift.
func WindowsAdminEquivalentPrincipal(sid *windows.SID) bool {
	return windowsAdminEquivalentOwner(sid)
}

// AcceptServiceRuntimeFileDrift is the gateway's read-only judgement of a
// managed runtime file it reads, such as a hook or OTLP token: it never
// writes. Structure is fatal (reparse point anywhere in the chain, hard
// links, wrong type, non-NTFS volume), and so is a boundary: an untrusted
// principal that can write or owns the file. Everything else (an
// administrator or TrustedInstaller owner, extra read entries, inherited
// trusted entries, inheritance re-enabled, a missing gateway entry) is
// accepted and logged once with MarkerAccept; the hook guardian repairs it.
// Ancestor directories are walked drift-tolerantly for structure.
func AcceptServiceRuntimeFileDrift(path, label, serviceAccount string) error {
	if label == "" {
		label = "managed runtime file"
	}
	if err := ValidateTrustedRuntimeDirTolerant(filepath.Dir(path), label+" directory"); err != nil {
		return err
	}
	result, err := AssessCanonical(path, ObjectRuntimeFile, CanonicalOptions{GatewayServiceAccount: serviceAccount})
	if err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	switch result.Outcome {
	case CanonicalMissing:
		return fmt.Errorf("%s %s: %w", label, result.Path, os.ErrNotExist)
	case CanonicalBoundary:
		return fmt.Errorf("%s %s: %s", label, result.Path, strings.Join(result.Drift, "; "))
	}
	return nil
}
