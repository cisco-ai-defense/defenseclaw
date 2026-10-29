// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"time"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// errWindowsManagedRepairUnprivileged means the process cannot repair a
// managed object: only the installer (an elevated administrator) and the
// LocalSystem guardian re-stamp descriptors. The gateway service never does,
// because its write-restricted token cannot change these DACLs.
var errWindowsManagedRepairUnprivileged = errors.New(
	"managed object repair requires an elevated administrator or LocalSystem process",
)

// windowsManagedCanRepair is a test seam for windowsManagedProcessCanRepair.
var windowsManagedCanRepair = windowsManagedProcessCanRepair

// windowsManagedProcessCanRepair reports whether the process token, not the
// possibly impersonated thread token, belongs to a component allowed to
// repair managed objects.
func windowsManagedProcessCanRepair() bool {
	if managed.WindowsCurrentProcessIsGatewayService() {
		return false
	}
	token := windows.GetCurrentProcessToken()
	if token.IsElevated() {
		return true
	}
	user, err := token.GetTokenUser()
	return err == nil && user != nil && user.User.Sid != nil &&
		user.User.Sid.IsWellKnown(windows.WinLocalSystemSid)
}

// runWindowsManagedPrivilegedRepair runs fn on a dedicated locked OS thread
// that impersonates a copy of the process token with backup, restore and
// take-ownership privileges enabled. The calling thread may be impersonating
// a target user; that impersonation is untouched. A privilege that hardening
// removed is skipped, and fn then runs with whatever the token still holds.
func runWindowsManagedPrivilegedRepair(fn func() error) error {
	if fn == nil {
		return errors.New("managed repair callback is required")
	}
	if !windowsManagedCanRepair() {
		return errWindowsManagedRepairUnprivileged
	}
	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if err := windows.ImpersonateSelf(windows.SecurityImpersonation); err != nil {
			runtime.UnlockOSThread()
			result <- fmt.Errorf("create managed repair token: %w", err)
			return
		}
		var token windows.Token
		if err := windows.OpenThreadToken(
			windows.CurrentThread(),
			windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY,
			false,
			&token,
		); err != nil {
			if revertErr := windows.RevertToSelf(); revertErr != nil {
				// Never return a thread with an unknown identity to the pool.
				result <- fmt.Errorf("open managed repair token: %v (revert failed: %v)", err, revertErr)
				return
			}
			runtime.UnlockOSThread()
			result <- fmt.Errorf("open managed repair token: %w", err)
			return
		}
		for _, name := range []string{"SeBackupPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege"} {
			_ = enableWindowsManagedRepairPrivilege(token, name)
		}
		callErr := fn()
		token.Close()
		if revertErr := windows.RevertToSelf(); revertErr != nil {
			// Leave the thread locked: the runtime destroys it on goroutine exit.
			if callErr == nil {
				callErr = fmt.Errorf("revert managed repair token: %w", revertErr)
			} else {
				callErr = fmt.Errorf("%v (revert managed repair token failed: %v)", callErr, revertErr)
			}
			result <- callErr
			return
		}
		runtime.UnlockOSThread()
		result <- callErr
	}()
	return <-result
}

func enableWindowsManagedRepairPrivilege(token windows.Token, name string) error {
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
		Privileges: [1]windows.LUIDAndAttributes{{
			Luid:       luid,
			Attributes: windows.SE_PRIVILEGE_ENABLED,
		}},
	}
	if err := windows.AdjustTokenPrivileges(token, false, &state, 0, nil, nil); err != nil {
		return err
	}
	// AdjustTokenPrivileges succeeds with ERROR_NOT_ALL_ASSIGNED when the token
	// does not hold the privilege; GetLastError carries that.
	if lastErr := windows.GetLastError(); errors.Is(lastErr, windows.ERROR_NOT_ALL_ASSIGNED) {
		return lastErr
	}
	return nil
}

// windowsManagedDescriptorModel converts a live security descriptor into the
// platform-neutral model. An entry type this code cannot parse is returned as
// an error: it is structural, never a permission verdict.
func windowsManagedDescriptorModel(sd *windows.SECURITY_DESCRIPTOR) (managedDescriptor, error) {
	var model managedDescriptor
	if sd == nil {
		return model, errors.New("missing Windows security descriptor")
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return model, fmt.Errorf("inspect Windows owner: %w", err)
	}
	if owner != nil {
		model.Owner = owner.String()
	}
	control, _, err := sd.Control()
	if err != nil {
		return model, fmt.Errorf("inspect Windows DACL control: %w", err)
	}
	model.Protected = control&windows.SE_DACL_PROTECTED != 0
	dacl, _, err := sd.DACL()
	if err != nil {
		return model, fmt.Errorf("inspect Windows DACL: %w", err)
	}
	if dacl == nil {
		model.NullDACL = true
		return model, nil
	}
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			return model, fmt.Errorf("inspect Windows ACE %d: %w", index, err)
		}
		if ace == nil {
			continue
		}
		switch ace.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE, windows.ACCESS_DENIED_ACE_TYPE:
		default:
			if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
				// A template for children only; it grants nothing here.
				continue
			}
			return model, fmt.Errorf("unsupported Windows ACE type 0x%x", ace.Header.AceType)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		model.ACEs = append(model.ACEs, managedACE{
			SID:   sid.String(),
			Type:  ace.Header.AceType,
			Flags: ace.Header.AceFlags,
			Mask:  uint32(ace.Mask),
		})
	}
	runtime.KeepAlive(sd)
	return model, nil
}

// windowsManagedHandleDescriptorModel reads the owner and DACL of an open
// handle (READ_CONTROL is enough) into the neutral model.
func windowsManagedHandleDescriptorModel(handle windows.Handle) (managedDescriptor, error) {
	sd, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return managedDescriptor{}, fmt.Errorf("inspect Windows security descriptor: %w", err)
	}
	return windowsManagedDescriptorModel(sd)
}

// windowsManagedPathDescriptorModel reads the descriptor of a path without
// following a final reparse point.
func windowsManagedPathDescriptorModel(path string, directory bool) (managedDescriptor, error) {
	handle, err := openWindowsManagedRepairHandle(path, directory, windows.READ_CONTROL)
	if err != nil {
		return managedDescriptor{}, err
	}
	defer windows.CloseHandle(handle)
	return windowsManagedHandleDescriptorModel(handle)
}

// openWindowsManagedRepairHandle opens path without following a final
// reparse point, with backup semantics so a thread holding the backup and
// restore privileges is granted access regardless of the DACL. It refuses
// reparse points, the wrong object type and, for files, more than one link:
// those stay structural failures that no repair may touch.
func openWindowsManagedRepairHandle(path string, directory bool, access uint32) (windows.Handle, error) {
	extended, err := winpath.Extended(path)
	if err != nil {
		return 0, err
	}
	ptr, err := windows.UTF16PtrFromString(extended)
	if err != nil {
		return 0, err
	}
	handle, err := windows.CreateFile(
		ptr,
		access|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return 0, err
	}
	if err := validateWindowsManagedRepairHandleShape(handle, directory); err != nil {
		_ = windows.CloseHandle(handle)
		return 0, fmt.Errorf("%s: %w", path, err)
	}
	return handle, nil
}

func validateWindowsManagedRepairHandleShape(handle windows.Handle, directory bool) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return fmt.Errorf("inspect object identity: %w", err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("reparse points are not repaired")
	}
	if (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory {
		return errors.New("object has an unexpected type")
	}
	if !directory && info.NumberOfLinks != 1 {
		return fmt.Errorf("file has %d hard links, want exactly 1", info.NumberOfLinks)
	}
	return nil
}

// stampWindowsManagedDescriptor writes owner and a protected DACL onto path.
// It must run inside runWindowsManagedPrivilegedRepair: assigning an owner
// other than the caller needs the restore privilege, and a drifted DACL may
// grant the caller nothing. The owner is set first so that, even where only
// take-ownership survives hardening, the DACL write runs as the new owner.
func stampWindowsManagedDescriptor(
	path string,
	directory bool,
	owner *windows.SID,
	dacl *windows.ACL,
) error {
	if owner == nil || dacl == nil {
		return errors.New("managed descriptor repair needs an owner and a DACL")
	}
	handle, err := openWindowsManagedRepairHandle(
		path, directory, windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER,
	)
	if err != nil {
		return fmt.Errorf("open for descriptor repair: %w", err)
	}
	defer windows.CloseHandle(handle)
	if err := windows.SetSecurityInfo(
		handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION,
		owner, nil, nil, nil,
	); err != nil {
		return fmt.Errorf("set owner: %w", err)
	}
	if err := windows.SetSecurityInfo(
		handle, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	); err != nil {
		return fmt.Errorf("set DACL: %w", err)
	}
	return nil
}

// repairWindowsManagedDescriptor re-stamps descriptor's owner and DACL on
// path from a privileged thread.
func repairWindowsManagedDescriptor(
	path string,
	directory bool,
	descriptor *windows.SECURITY_DESCRIPTOR,
) error {
	if descriptor == nil {
		return errors.New("managed descriptor repair needs a canonical descriptor")
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	err = runWindowsManagedPrivilegedRepair(func() error {
		return stampWindowsManagedDescriptor(path, directory, owner, dacl)
	})
	runtime.KeepAlive(descriptor)
	return err
}

// clearWindowsManagedReadOnly clears the ReadOnly attribute on an existing
// no-follow regular file so a write or replace can proceed, and returns a
// function that sets it again on whatever regular file then holds the name.
// A missing file, a directory or a reparse point is left alone.
func clearWindowsManagedReadOnly(path string) (func() error, error) {
	noop := func() error { return nil }
	ptr, err := winpath.UTF16Ptr(path)
	if err != nil {
		return noop, err
	}
	attributes, err := windows.GetFileAttributes(ptr)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return noop, nil
		}
		return noop, err
	}
	clear, restore := managedReadOnlyPlan(attributes)
	if clear == 0 {
		return noop, nil
	}
	if err := setWindowsManagedFileAttributes(path, func(current uint32) uint32 {
		return current &^ clear
	}); err != nil {
		return noop, fmt.Errorf("clear ReadOnly attribute on %s: %w", path, err)
	}
	emitManagedResilience(managed.MarkerRepair, path, "cleared ReadOnly attribute for update", nil)
	return func() error {
		err := setWindowsManagedFileAttributes(path, func(current uint32) uint32 {
			return current | restore
		})
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}, nil
}

// setWindowsManagedFileAttributes rewrites the attributes of a no-follow
// regular file through a handle, never through the path.
func setWindowsManagedFileAttributes(path string, update func(uint32) uint32) error {
	extended, err := winpath.Extended(path)
	if err != nil {
		return err
	}
	ptr, err := windows.UTF16PtrFromString(extended)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(
		ptr,
		windows.FILE_READ_ATTRIBUTES|windows.FILE_WRITE_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return os.ErrNotExist
	}
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	return setWindowsManagedHandleAttributes(handle, update)
}

func setWindowsManagedHandleAttributes(handle windows.Handle, update func(uint32) uint32) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		return errors.New("attributes are only updated on regular files")
	}
	next := update(info.FileAttributes)
	if next == info.FileAttributes {
		return nil
	}
	if next == 0 {
		next = windows.FILE_ATTRIBUTE_NORMAL
	}
	basic := windowsManagedFileBasicInfo{FileAttributes: next}
	return windows.SetFileInformationByHandle(
		handle,
		windows.FileBasicInfo,
		(*byte)(unsafe.Pointer(&basic)),
		uint32(unsafe.Sizeof(basic)),
	)
}

// windowsManagedFileBasicInfo is FILE_BASIC_INFO. Zero timestamps leave the
// existing times unchanged.
type windowsManagedFileBasicInfo struct {
	CreationTime   int64
	LastAccessTime int64
	LastWriteTime  int64
	ChangeTime     int64
	FileAttributes uint32
	_              uint32
}

// windowsManagedTransientError reports whether err is a sharing or lock
// violation that a short wait can clear.
func windowsManagedTransientError(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION) ||
		errors.Is(err, windows.ERROR_LOCK_VIOLATION) ||
		errors.Is(err, windows.STATUS_SHARING_VIOLATION) ||
		errors.Is(err, windows.STATUS_FILE_LOCK_CONFLICT) ||
		errors.Is(err, windows.STATUS_LOCK_NOT_GRANTED)
}

// windowsManagedRetrySleep is a test seam for the transient-retry backoff.
var windowsManagedRetrySleep = time.Sleep

// windowsManagedHandleIdentity is the volume and file ID of an open handle.
func windowsManagedHandleIdentity(handle windows.Handle) (atomicTransformWindowsFileIDInfo, error) {
	var info atomicTransformWindowsFileIDInfo
	err := windows.GetFileInformationByHandleEx(
		handle,
		windows.FileIdInfo,
		(*byte)(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	)
	return info, err
}

// windowsManagedLockRepair describes one data-free lock file whose protection
// may be repaired in place: the lock carries no content, so re-stamping its
// descriptor on the very inode a caller holds cannot lose anything, and
// recreating it would break mutual exclusion with current holders.
type windowsManagedLockRepair struct {
	Label     string
	Path      string
	Handle    windows.Handle
	Validate  func(windows.Handle) error
	Canonical func() (*windows.SECURITY_DESCRIPTOR, error)
	Policy    managedDriftPolicy
	// SelfRepair lets a caller that owns the lock rewrite its DACL on its own
	// token when no privileged component is available.
	SelfRepair bool
	// PolicyOrCode marks an object whose untrusted writer is a boundary
	// finding even after a repair (generated hook scripts).
	PolicyOrCode bool
}

// ensureWindowsManagedLockProtection validates the held lock and, on
// permission drift, repairs it (privileged caller) or rewrites its DACL as
// the owner; drift that remains is accepted and logged. Structural failures
// and non-drift validation errors are returned unchanged.
func ensureWindowsManagedLockProtection(lock windowsManagedLockRepair) error {
	err := lock.Validate(lock.Handle)
	if err == nil || !isManagedPermissionDrift(err) {
		return err
	}
	var drift managedDrift
	if model, modelErr := windowsManagedHandleDescriptorModel(lock.Handle); modelErr == nil {
		drift = classifyManagedDrift(model, lock.Policy)
	}
	reason := err.Error()
	if !drift.Canonical && len(drift.Reason()) > 0 {
		reason = drift.Reason() + ": " + reason
	}
	repairErr := repairWindowsManagedHeldLock(lock)
	if repairErr == nil {
		if recheck := lock.Validate(lock.Handle); recheck == nil {
			emitManagedResilience(managedDriftMarker(drift, true, lock.PolicyOrCode), lock.Path,
				"re-stamped canonical lock protection: "+reason, map[string]string{"label": lock.Label})
			return nil
		} else {
			reason += "; still noncanonical after repair: " + recheck.Error()
		}
	} else if !errors.Is(repairErr, errWindowsManagedRepairUnprivileged) {
		reason += "; repair failed: " + repairErr.Error()
	}
	if managed.TrustStrictAncestors() {
		return err
	}
	emitManagedResilience(managedDriftMarker(drift, false, drift.Boundary()), lock.Path,
		"accepted lock permission drift: "+reason, map[string]string{"label": lock.Label})
	return nil
}

func repairWindowsManagedHeldLock(lock windowsManagedLockRepair) error {
	want, err := windowsManagedHandleIdentity(lock.Handle)
	if err != nil {
		return fmt.Errorf("read held lock identity: %w", err)
	}
	descriptor, err := lock.Canonical()
	if err != nil {
		return fmt.Errorf("build canonical lock descriptor: %w", err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("canonical lock descriptor has no DACL: %v", err)
	}
	stamp := func(setOwner bool, backup bool) error {
		access := uint32(windows.READ_CONTROL | windows.WRITE_DAC)
		if setOwner {
			access |= windows.WRITE_OWNER
		}
		var handle windows.Handle
		var openErr error
		if backup {
			handle, openErr = openWindowsManagedRepairHandle(lock.Path, false, access)
		} else {
			handle, openErr = openWindowsManagedOwnerHandle(lock.Path, access)
		}
		if openErr != nil {
			return openErr
		}
		defer windows.CloseHandle(handle)
		got, idErr := windowsManagedHandleIdentity(handle)
		if idErr != nil {
			return idErr
		}
		if got != want {
			return errors.New("lock path no longer names the held lock")
		}
		if setOwner {
			if err := windows.SetSecurityInfo(
				handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION,
				owner, nil, nil, nil,
			); err != nil {
				return fmt.Errorf("set lock owner: %w", err)
			}
		}
		if err := windows.SetSecurityInfo(
			handle, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
			nil, nil, dacl, nil,
		); err != nil {
			return fmt.Errorf("set lock DACL: %w", err)
		}
		return nil
	}
	if windowsManagedCanRepair() {
		err = runWindowsManagedPrivilegedRepair(func() error { return stamp(true, true) })
		runtime.KeepAlive(descriptor)
		return err
	}
	if !lock.SelfRepair {
		return errWindowsManagedRepairUnprivileged
	}
	err = stamp(false, false)
	runtime.KeepAlive(descriptor)
	return err
}

// openWindowsManagedOwnerHandle opens an existing no-follow single-link file on
// the caller's own token, for an owner rewriting its own DACL.
func openWindowsManagedOwnerHandle(path string, access uint32) (windows.Handle, error) {
	extended, err := winpath.Extended(path)
	if err != nil {
		return 0, err
	}
	ptr, err := windows.UTF16PtrFromString(extended)
	if err != nil {
		return 0, err
	}
	handle, err := windows.CreateFile(
		ptr,
		access|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return 0, err
	}
	if err := validateWindowsManagedRepairHandleShape(handle, false); err != nil {
		_ = windows.CloseHandle(handle)
		return 0, err
	}
	return handle, nil
}
