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

// canonicalRunWithRepairPrivileges is RunWithWindowsRepairPrivileges; tests
// replace it to stand for a caller whose privileges cannot read the
// descriptor either.
var canonicalRunWithRepairPrivileges = RunWithWindowsRepairPrivileges

// valid reports whether kind is one of the managed object kinds; only
// canonicalize, on Windows, needs it.
func (kind ObjectKind) valid() bool {
	switch kind {
	case ObjectRuntimeDirectory, ObjectRuntimeFile, ObjectRuntimeSecretFile,
		ObjectConfigFile, ObjectConfigDirectory, ObjectInstallDirectory,
		ObjectInstallFile, ObjectServiceInstallDirectory, ObjectServiceInstallFile,
		ObjectStateDirectory, ObjectAdminDirectory, ObjectAdminFile,
		ObjectAuthorizationDirectory, ObjectLogDirectory, ObjectManagedIPCDirectory:
		return true
	}
	return false
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
	attributeOnlyHandle := false
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		// The DACL no longer lets this caller read it. Structure is still
		// checked through an attribute-only open; a privileged repair then
		// reads the descriptor with backup semantics.
		descriptorUnreadable = true
		attributeOnlyHandle = true
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
	if descriptorUnreadable && (repair || StandaloneRefusesContentDrift()) {
		// Backup semantics with SeBackupPrivilege grant READ_CONTROL whatever
		// the DACL says, so the owner is known before anything is adopted.
		// On standalone the read-only assessment reads it the same way: an
		// account that owns the object or holds WRITE_DAC on it can hide the
		// descriptor from SYSTEM and Administrators, and every standalone
		// refusal that asks AssessCanonical must judge the real owner and
		// writers, not accept what it cannot see (g582 review 4 F1). Secure
		// Client's assessment never takes the privileges, with or without
		// the strict pin, so its verdicts and events are the base ones: an
		// unreadable descriptor is Accepted, or Boundary under the strict
		// pin (g582 review 5 M1, review 6 M1).
		if err := canonicalRunWithRepairPrivileges(func() error {
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
	if descriptorUnreadable && (TrustStrictAncestors() || StandaloneRefusesContentDrift()) {
		// Strict mode keeps an unverifiable owner and writer set fatal, and
		// so does standalone: an object whose descriptor even backup
		// semantics cannot read is never taken for trusted drift, so no
		// standalone refusal lets it be re-stamped in place (g582 review 4
		// F1).
		result.Outcome = CanonicalBoundary
		result.RepairError = "security descriptor is not readable"
	}
	if result.Outcome == CanonicalOK || !repair {
		reportCanonicalResult(result, opts)
		return result, nil
	}
	// On standalone the repair itself refuses an object an untrusted
	// principal can write or owns, whatever AllowUntrustedOwnerTransfer
	// says, and judges it again on the handle it stamps (see
	// stampCanonicalDescriptor). A caller's earlier read-only check can be
	// raced: a hard link removed or an object deleted and recreated between
	// that check and this repair (g582 review 6 S1, review 5 L1).
	refuseUntrusted := StandaloneRefusesContentDrift() && !opts.inPlaceOutOfClass
	if refuseUntrusted && assessment.boundary() {
		result.Outcome = CanonicalBoundary
		result.RepairError = standaloneInPlaceRepairRefused
		reportCanonicalResult(result, opts)
		return result, nil
	}
	if assessment.Owner == ownerUntrusted && !descriptorUnreadable && !opts.AllowUntrustedOwnerTransfer {
		result.Outcome = CanonicalBoundary
		result.RepairError = "owner is not trusted; not adopted"
		reportCanonicalResult(result, opts)
		return result, nil
	}
	if assessment.Owner == ownerUntrusted && !descriptorUnreadable {
		// The caller vouched that DefenseClaw created and holds this object,
		// so the foreign owner is drift. Name it once as a boundary finding
		// before the canonical owner replaces it.
		reportUntrustedOwnerTransfer(clean, kind, desc.Owner, opts)
	}
	spec := canonicalSpecFor(kind, gatewaySID)
	if canonicalIdentityMissing(kind, spec, gatewaySID) {
		// Every runtime form names the gateway service; stamping without it
		// would lock the gateway out.
		result.RepairError = ErrCanonicalIdentityUnavailable.Error()
		reportCanonicalResult(result, opts)
		return result, nil
	}
	if repairErr := stampCanonicalDescriptor(handle, clean, kind, spec.canonicalSDDL(), refuseUntrusted, gatewaySID); repairErr != nil {
		var refused *standaloneStampRefusal
		if errors.As(repairErr, &refused) {
			result.Outcome = CanonicalBoundary
			result.Drift = refused.drift
			result.UntrustedWriters = refused.writers
			result.RepairError = standaloneInPlaceRepairRefused
			reportCanonicalResult(result, opts)
			return result, nil
		}
		result.RepairError = repairErr.Error()
		reportCanonicalResult(result, opts)
		return result, nil
	}
	if attributeOnlyHandle {
		// handle was opened without READ_CONTROL because the descriptor was
		// unreadable; handle rights are fixed at open, so re-read through a
		// privileged reopen of the same object.
		err = RunWithWindowsRepairPrivileges(func() error {
			verify, openErr := openCanonicalObject(clean, uint32(windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES))
			if openErr != nil {
				return openErr
			}
			defer func() { _ = windows.CloseHandle(verify) }()
			if same, sameErr := sameWindowsFile(handle, verify); sameErr != nil || !same {
				return errors.New("object changed during repair verification")
			}
			var readErr error
			desc, readErr = readObjectDescriptor(verify)
			return readErr
		})
	} else {
		desc, err = readObjectDescriptor(handle)
	}
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

// ErrCanonicalIdentityUnavailable reports that the gateway service identity
// kind names could not be resolved, so no descriptor is stamped or created.
var ErrCanonicalIdentityUnavailable = errors.New("gateway service identity is unavailable")

// canonicalIdentityMissing reports whether spec names the gateway service but
// its SID could not be resolved. Config objects only need it to read.
func canonicalIdentityMissing(kind ObjectKind, spec canonicalSpec, gatewaySID string) bool {
	return gatewaySID == "" && spec.GatewayNeedsAccess && kind != ObjectConfigFile && kind != ObjectConfigDirectory
}

// ErrCanonicalOwnerUnavailable reports that an object created by this process
// could not be given the canonical owner, so it was removed again rather than
// left as drift for the Guardian to repair.
var ErrCanonicalOwnerUnavailable = errors.New("the canonical owner could not be assigned at creation")

// CreateCanonicalDirectory creates path as a new directory that carries the
// canonical protected descriptor of kind from its first instant: the same
// owner, group and explicit protected DACL EnsureCanonical stamps, built from
// the same spec. A directory made with a plain mkdir inherits its parent
// entries unprotected, which the Guardian then logs as drift on its next
// pass, so every DefenseClaw-created managed directory is created through
// this. Success means the directory reads canonical:
// ErrCanonicalIdentityUnavailable is returned, and nothing is created, when
// the gateway service SID cannot be resolved, and
// ErrCanonicalOwnerUnavailable when the canonical owner could not be assigned
// (the new directory is removed again). An existing path fails like os.Mkdir
// (errors.Is os.ErrExist); the parent must exist.
func CreateCanonicalDirectory(path string, kind ObjectKind, opts CanonicalOptions) error {
	if !kind.valid() || !kind.Directory() {
		return fmt.Errorf("managed object kind %q is not a directory kind", kind)
	}
	return createCanonicalObject(path, kind, opts, func(pointer *uint16, attributes *windows.SecurityAttributes) error {
		return windows.CreateDirectory(pointer, attributes)
	})
}

// CreateCanonicalFile is CreateCanonicalDirectory for a new, empty file of a
// file kind (a lock file). An existing path fails with errors.Is os.ErrExist.
func CreateCanonicalFile(path string, kind ObjectKind, opts CanonicalOptions) error {
	if !kind.valid() || kind.Directory() {
		return fmt.Errorf("managed object kind %q is not a file kind", kind)
	}
	return createCanonicalObject(path, kind, opts, func(pointer *uint16, attributes *windows.SecurityAttributes) error {
		handle, err := windows.CreateFile(pointer, windows.GENERIC_WRITE,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, attributes,
			windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if err != nil {
			return err
		}
		return windows.CloseHandle(handle)
	})
}

// EnsureCanonicalLockFile makes sure the lock file at path exists, created in
// the canonical protection of kind, when this process is pinned to a
// standalone managed deployment and path lies in its tree
// (StandaloneManagedTreeAccount). Anywhere else it does nothing and the
// caller creates the file as before. A file that already exists is left to
// the Guardian and to Setup repair, which list every lock file.
func EnsureCanonicalLockFile(path string, kind ObjectKind) error {
	account, ok := StandaloneManagedTreeAccount(path)
	if !ok {
		return nil
	}
	err := CreateCanonicalFile(path, kind, CanonicalOptions{GatewayServiceAccount: account, Quiet: true})
	if err == nil || errors.Is(err, os.ErrExist) {
		return nil
	}
	return err
}

// createCanonicalObject creates path through create with the canonical
// descriptor of kind and returns nil only when the result reads canonical.
func createCanonicalObject(
	path string, kind ObjectKind, opts CanonicalOptions,
	create func(*uint16, *windows.SecurityAttributes) error,
) error {
	gatewaySID := ""
	if sid, err := windowsVirtualServiceSID(canonicalGatewayAccount(opts)); err == nil && sid != nil {
		gatewaySID = sid.String()
	}
	spec := canonicalSpecFor(kind, gatewaySID)
	if canonicalIdentityMissing(kind, spec, gatewaySID) {
		return ErrCanonicalIdentityUnavailable
	}
	pointer, err := winpath.UTF16Ptr(path)
	if err != nil {
		return err
	}
	sddl := spec.canonicalSDDL()
	attributes, err := setupSecurityAttributes(sddl)
	if err != nil {
		return err
	}
	err = create(pointer, attributes)
	if !errors.Is(err, windows.ERROR_INVALID_OWNER) {
		return err
	}
	// The token cannot assign the canonical owner at creation: create with
	// the default owner and the same protected DACL, then take the owner
	// through the shared repair. Anything short of a canonical result is
	// removed again and reported, never left as owner drift.
	attributes, err = setupSecurityAttributes(strings.TrimPrefix(sddl, "O:"+spec.Forms[0].Owner))
	if err != nil {
		return err
	}
	if err := create(pointer, attributes); err != nil {
		return err
	}
	quiet := opts
	quiet.Quiet = true
	result, _ := canonicalize(path, kind, quiet, !WindowsCurrentProcessIsGatewayService())
	if result.Outcome == CanonicalOK || result.Outcome == CanonicalRepaired {
		return nil
	}
	_ = os.Remove(path)
	return fmt.Errorf("%w (%s): %s", ErrCanonicalOwnerUnavailable, result.Outcome,
		strings.Join(append(append([]string(nil), result.Drift...), result.RepairError), "; "))
}

// reportUntrustedOwnerTransfer logs, as a MarkerBoundary finding, that a
// privileged repair is taking ownership of path from a principal outside the
// trusted and administrator-equivalent set.
func reportUntrustedOwnerTransfer(path string, kind ObjectKind, previousOwner string, opts CanonicalOptions) {
	if opts.Quiet {
		return
	}
	fields := map[string]string{
		"path":      path,
		"object":    string(kind),
		"principal": ownerText(previousOwner),
		"reason":    "untrusted owner taken over by the canonical repair",
	}
	// A repair that keeps failing retries on every guardian tick; name the
	// owner once per process.
	if !advisoryLogDedupe.shouldEmit(path, MarkerBoundary, FormatResilienceEvent(MarkerBoundary, fields)) {
		return
	}
	EmitResilienceEvent(MarkerBoundary, fields)
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
	return openCanonicalObjectShared(path, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)
}

// openCanonicalObjectShared is openCanonicalObject with the share mode given.
// The standalone repair handle leaves out FILE_SHARE_DELETE, so while it is
// open no name of the object can be removed or renamed: the object judged
// on it is the object stamped through it.
func openCanonicalObjectShared(path string, access, share uint32) (windows.Handle, error) {
	pointer, err := winpath.UTF16Ptr(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return retryTransientOpen(func() (windows.Handle, error) {
		return windows.CreateFile(
			pointer,
			access,
			share,
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
		if attempt == canonicalOpenAttempts-1 {
			break
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
	isDir := info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 &&
		(isDir || kind.Directory() || !acceptBenignFileReparseTag(handle, path)) {
		return fmt.Errorf("%s: reparse points are not allowed for managed objects", path)
	}
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

// canonicalAttributeTagInfo mirrors FILE_ATTRIBUTE_TAG_INFO.
type canonicalAttributeTagInfo struct {
	FileAttributes uint32
	ReparseTag     uint32
}

// acceptBenignFileReparseTag reports whether the regular file open as handle
// carries a storage reparse tag that keeps its content local (WOF
// compression, deduplication), logging the acceptance once. Cloud-files
// placeholders, AF_UNIX sockets, symbolic links, mount points and unknown
// tags stay fatal, and the strict pin makes every tag fatal again.
func acceptBenignFileReparseTag(handle windows.Handle, path string) bool {
	if trustStrictAncestors() {
		return false
	}
	var info canonicalAttributeTagInfo
	if err := windows.GetFileInformationByHandleEx(
		handle,
		windows.FileAttributeTagInfo,
		(*byte)(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	); err != nil {
		return false
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 || !isLocalContentFileReparseTag(info.ReparseTag) {
		return false
	}
	fields := map[string]string{
		"path":   path,
		"reason": fmt.Sprintf("regular file carries a storage reparse tag 0x%08x that redirects nothing", info.ReparseTag),
	}
	if advisoryLogDedupe.shouldEmit(path, MarkerAccept, FormatResilienceEvent(MarkerAccept, fields)) {
		EmitResilienceEvent(MarkerAccept, fields)
	}
	return true
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

// standaloneInPlaceRepairRefused is the RepairError of an object the
// standalone repair refused to re-stamp in place.
const standaloneInPlaceRepairRefused = "not repaired in place on a standalone install, because an untrusted " +
	"principal can write or owns it: from an elevated prompt remove that entry (icacls \"<path>\" /remove:g *<SID>; for an inherited entry first run icacls \"<path>\" /inheritance:d, which keeps copies of the inherited entries), " +
	"or give it back to Administrators (icacls \"<path>\" /setowner *S-1-5-32-544), check it, then run Setup " +
	"/ensure and Setup /verify (GAP-0561)"

// standaloneStampRefusal is the refusal stampCanonicalDescriptor returns when
// the descriptor read on its own repair handle lets an untrusted principal
// write or own the object.
type standaloneStampRefusal struct {
	drift   []string
	writers []string
}

func (r *standaloneStampRefusal) Error() string {
	return "an untrusted principal can write or owns the object: " + strings.Join(r.drift, "; ")
}

// canonicalBeforeStamp runs after the assessment and before the repair handle
// is opened; tests replace it to change the object in between.
var canonicalBeforeStamp = func(string) {}

// canonicalOpenForStamp opens the object a standalone repair stamps; tests
// replace it to answer as if another program held the object open.
var canonicalOpenForStamp = openCanonicalObjectForStamp

// openCanonicalObjectForStamp is openCanonicalObjectShared for a stamp that
// asks for read access (standaloneHoldFor): the open is plain first. With
// backup semantics Windows does not refuse a read open on a handle that
// denies read sharing, so a file opened that way hides such a holder; the
// backup open is only the fallback for a file whose access list does not let
// the caller read it. A stamp that asks for no data access is not checked
// against share modes at all and keeps the one open it had.
func openCanonicalObjectForStamp(path string, access, share uint32) (windows.Handle, error) {
	if access&windows.FILE_READ_DATA == 0 {
		return openCanonicalObjectShared(path, access, share)
	}
	pointer, err := winpath.UTF16Ptr(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	handle, err := retryTransientOpen(func() (windows.Handle, error) {
		return windows.CreateFile(pointer, access, share, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	})
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return openCanonicalObjectShared(path, access, share)
	}
	return handle, err
}

// heldFileRefusal starts the refusal of an in-place re-stamp of a file that
// another program holds open (GAP-0763). The stamp is one transaction on one
// handle: open it so that nothing else can write or delete the object, check
// holders and links, judge the descriptor, then write; a holder stops it
// before anything is written, and the file is named.
const heldFileRefusal = "refusing to re-stamp a managed file while another program holds it open " +
	"with write or delete access, or without sharing read access, and nothing was changed"

func heldFileError(path string) error {
	return fmt.Errorf("%s (close the program that holds it, then run Setup /ensure again): %s", heldFileRefusal, path)
}

func isSharingViolation(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_LOCK_VIOLATION)
}

// heldAgainstWriters reports the kinds whose standalone in-place stamp is
// made under a handle that no other program may write under: the recorded
// content files (config.yaml, targets.yaml, deployment.json, the Codex
// records), which only administrators write and which are only ever written
// by DefenseClaw's own short transactions. The database and log files the
// gateway holds open for write (RuntimeFile) keep the delete-only check, and
// the credential file keeps its own, so a live gateway never blocks the
// guardian's repair of them.
func (kind ObjectKind) heldAgainstWriters() bool {
	return kind == ObjectConfigFile || kind == ObjectAdminFile
}

// standaloneHoldFor widens the repair handle of a recorded content file: it
// asks for read access and shares read only, so another handle with write or
// delete access, or one that does not share read, makes the open fail. Opens
// that ask for no data access (READ_CONTROL, WRITE_DAC) are not checked
// against a share mode, and readers that share read do not conflict.
func standaloneHoldFor(kind ObjectKind, share uint32) (uint32, uint32) {
	switch {
	case kind.heldAgainstWriters():
		return windows.FILE_SHARE_READ, windows.FILE_READ_DATA
	case kind == ObjectRuntimeFile:
		// The gateway keeps these open for write, so they share writing; the
		// read access is what makes a handle with delete access conflict
		// with the repair handle's missing delete sharing.
		return windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE, windows.FILE_READ_DATA
	}
	return share, 0
}

// stampCanonicalDescriptor writes sddl's owner, group and protected DACL to
// the object open as readHandle, through a second handle proven to be the same
// file. With refuseUntrusted (standalone) that handle is opened without
// delete sharing, and the structure (no reparse point, one link) and the
// descriptor are judged again on it: an untrusted owner or writer is refused
// with a standaloneStampRefusal and nothing is written. With the restore privilege enabled the second open is granted
// WRITE_DAC and WRITE_OWNER whatever the current DACL says; without it, an
// owner change is dropped and only the DACL is written, which the owner's
// implicit rights allow for an administrator-owned object.
func stampCanonicalDescriptor(readHandle windows.Handle, path string, kind ObjectKind, sddl string, refuseUntrusted bool, gatewaySID string) error {
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
	canonicalBeforeStamp(path)
	share := uint32(windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE)
	extraAccess := uint32(0)
	if refuseUntrusted {
		share = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE
		share, extraAccess = standaloneHoldFor(kind, share)
	}
	return RunWithWindowsRepairPrivileges(func() error {
		full := uint32(windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER|windows.FILE_READ_ATTRIBUTES) | extraAccess
		handle, openErr := canonicalOpenForStamp(path, full, share)
		ownerToo := openErr == nil
		if openErr != nil && (!refuseUntrusted || !isSharingViolation(openErr)) {
			handle, openErr = canonicalOpenForStamp(path, uint32(windows.READ_CONTROL|windows.WRITE_DAC|windows.FILE_READ_ATTRIBUTES)|extraAccess, share)
		}
		if openErr != nil {
			if refuseUntrusted && isSharingViolation(openErr) {
				return heldFileError(path)
			}
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
		if refuseUntrusted {
			// The decision is made on this handle: no name of the object can
			// go away while it is open, and the descriptor stamped below
			// replaces the one judged here.
			current, err := readObjectDescriptor(handle)
			if err != nil {
				return fmt.Errorf("read descriptor on the repair handle: %w", err)
			}
			if judged := assessCanonicalDescriptor(current, kind, gatewaySID, windowsLocalAdministratorsMember); judged.boundary() {
				return &standaloneStampRefusal{drift: judged.Drift, writers: judged.UntrustedWriters}
			}
		}
		dataInfo := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
		if kind.Directory() && !kind.propagatesRepair() {
			// SetKernelObjectSecurity writes only this folder's descriptor.
			// SetSecurityInfo would also push the inheritable entries into
			// every existing child, rewriting files DefenseClaw stamps on
			// their own or does not own, and fail on the first child it
			// cannot open.
			if ownerToo {
				info := dataInfo | windows.OWNER_SECURITY_INFORMATION | windows.GROUP_SECURITY_INFORMATION
				if err := windows.SetKernelObjectSecurity(handle, info, descriptor); err == nil {
					return nil
				}
			}
			if err := windows.SetKernelObjectSecurity(handle, dataInfo, descriptor); err != nil {
				return fmt.Errorf("apply canonical DACL: %w", err)
			}
			return nil
		}
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

// StampStandaloneTrustedObject is the standalone in-place stamp of a managed
// folder or file whose writer stamps its own descriptor (the hook guardian
// manifest folder, the secrets folder). It writes sddl's owner and protected
// DACL through one handle opened without delete sharing, after it has judged,
// on that same handle, the object's type and shape (no reparse point, one
// link) and its descriptor as kind. An untrusted owner or writer is refused
// with a StandaloneContentDriftError that names the path and the way out, and
// nothing is written, so a read-only check made earlier cannot be raced
// (g582 review 6 S1). Inheritable entries reach existing children as with
// SetNamedSecurityInfo.
func StampStandaloneTrustedObject(path string, kind ObjectKind, sddl string) error {
	if !kind.valid() {
		return fmt.Errorf("unknown managed object kind %q", kind)
	}
	recovery := standaloneInPlaceFileRecovery
	if kind.Directory() {
		recovery = standaloneInPlaceFolderRecovery
	}
	clean, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", path, err)
	}
	if err := winpath.RejectReparseChain(filepath.Dir(clean)); err != nil {
		return fmt.Errorf("%s: %w", clean, err)
	}
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("build descriptor: %w", err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return fmt.Errorf("read descriptor owner: %w", err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("read descriptor DACL: %v", err)
	}
	canonicalBeforeStamp(clean)
	return RunWithWindowsRepairPrivileges(func() error {
		share, extraAccess := standaloneHoldFor(kind, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE)
		handle, err := canonicalOpenForStamp(clean,
			uint32(windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER|windows.FILE_READ_ATTRIBUTES)|extraAccess,
			share)
		if err != nil {
			if isSharingViolation(err) {
				return heldFileError(clean)
			}
			return fmt.Errorf("open %s for repair: %w", clean, err)
		}
		defer func() { _ = windows.CloseHandle(handle) }()
		if err := checkCanonicalStructure(handle, clean, kind); err != nil {
			return &StandaloneContentDriftError{Err: err, Recovery: recovery}
		}
		current, err := readObjectDescriptor(handle)
		if err != nil {
			return &StandaloneContentDriftError{
				Err:      fmt.Errorf("cannot judge who can write or owns %s: %w", clean, err),
				Recovery: recovery,
			}
		}
		if judged := assessCanonicalDescriptor(current, kind, "", windowsLocalAdministratorsMember); judged.boundary() {
			return &StandaloneContentDriftError{
				Err:      fmt.Errorf("an untrusted principal can write or owns %s: %s", clean, strings.Join(judged.Drift, "; ")),
				Recovery: recovery,
			}
		}
		info := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION |
			windows.PROTECTED_DACL_SECURITY_INFORMATION)
		return windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, info, owner, nil, dacl, nil)
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
//
// A standalone process (windowsStandaloneTrustScope) keeps the strict
// service runtime file check it used before 26.8.4, which allows the gateway
// service as a writer and refuses every other drift (GAP-0561).
func AcceptServiceRuntimeFileDrift(path, label, serviceAccount string) error {
	if label == "" {
		label = "managed runtime file"
	}
	if windowsStandaloneTrustScope() {
		return ValidateTrustedServiceRuntimeFilePath(path, label, serviceAccount)
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
