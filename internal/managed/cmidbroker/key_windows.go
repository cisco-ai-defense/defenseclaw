// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cmidbroker

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

const authKeyObject = "broker authentication key"

// Key drift actions reported through KeyDriftPolicy.Report.
const (
	KeyDriftRepaired = "repaired"
	KeyDriftAccepted = "accepted"
)

// KeyDriftReport describes one permission drift LoadAuthKey found on the key
// and what it did about it. RepairError is set when a repair was attempted and
// failed; the load continued anyway.
type KeyDriftReport struct {
	Action      string
	Object      string
	Path        string
	Reason      string
	RepairError string
}

// KeyDriftPolicy decides what LoadAuthKey does when the key's owner or DACL no
// longer matches the descriptor the installer stamped. Only the broker sets
// Repair: it runs as LocalSystem and starts before the gateway, which runs
// with a write-restricted token and must never re-ACL the key. Report is
// required.
type KeyDriftPolicy struct {
	Repair bool
	Report func(KeyDriftReport)
}

// canonicalAuthKeySDDL is the descriptor the installer stamps on the key
// (Set-DefenseClawCMIDBrokerAuthKey in DefenseClawEnterprise.psm1). Keep the
// two in step.
const canonicalAuthKeySDDL = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;%s)"

// LoadAuthKey reads the 32-byte broker authentication key.
//
// Structural checks are fatal: path shape, reparse points and symlinks
// anywhere in the chain, file type, hard links, sparse files, length, and any
// failure to open, read or inspect the key. Permission drift on the key or its
// parent folders is not: the broker repairs the key's descriptor when policy
// allows it, and otherwise the drift is reported and the key is still
// returned. The pipe server's caller check (the gateway service SID in the
// client token) stays the trust boundary, so a key readable by an extra
// principal does not let that principal get a token. Pin
// managed.TrustStrictAncestorsEnv to make every permission drift fatal again.
func LoadAuthKey(path, gatewayServiceName string, policy KeyDriftPolicy) ([AuthKeyBytes]byte, error) {
	var key [AuthKeyBytes]byte
	if policy.Report == nil {
		return key, errors.New("broker authentication key drift reporter is required")
	}
	if err := validateLocalAbsolutePath(path, authKeyObject); err != nil {
		return key, err
	}
	if err := ValidateIdentityBinding(
		brokerServiceForGateway(gatewayServiceName),
		gatewayServiceName,
		localPipePrefix+brokerServiceForGateway(gatewayServiceName),
	); err != nil {
		return key, err
	}
	strict := managed.TrustStrictAncestors()

	directories, err := pinDirectoryChain(filepath.Dir(path))
	if err != nil {
		return key, fmt.Errorf("broker authentication key path is unavailable")
	}
	defer closeHandles(directories)

	// Validate the path while every ancestor is held without delete sharing.
	// The key itself gets structural checks only here; its owner and DACL are
	// judged below, on the open handle, by the stricter key rule.
	if strict {
		if err := managed.ValidateTrustedFilePath(path, authKeyObject); err != nil {
			return key, fmt.Errorf("broker authentication key trust validation failed: %w", err)
		}
	} else if err := managed.ValidateTrustedFileStructureTolerant(path, authKeyObject); err != nil {
		return key, fmt.Errorf("broker authentication key trust validation failed: %w", err)
	}

	gatewaySID, err := managed.WindowsServiceAccountSID(`NT SERVICE\` + gatewayServiceName)
	if err != nil || gatewaySID == nil {
		if strict {
			return key, fmt.Errorf("gateway service identity is unavailable")
		}
		// Carried into the key's single drift report below; repair is
		// skipped because the canonical descriptor names this SID.
		gatewaySID = nil
	}

	extended, err := winpath.Extended(path)
	if err != nil {
		return key, fmt.Errorf("broker authentication key path is invalid")
	}
	pathPtr, err := windows.UTF16PtrFromString(extended)
	if err != nil {
		return key, fmt.Errorf("broker authentication key path is invalid")
	}
	handle, err := openKeyForRead(pathPtr)
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) && !strict && policy.Repair && gatewaySID != nil {
		// SYSTEM lost read on the key itself. Re-stamp the canonical
		// descriptor through a privileged, backup-semantics open first, then
		// read it as usual.
		reason := "SYSTEM read access denied"
		if repairErr := repairUnreadableKey(pathPtr, gatewaySID); repairErr != nil {
			policy.Report(KeyDriftReport{
				Action: KeyDriftAccepted, Object: authKeyObject, Path: path, Reason: reason, RepairError: repairErr.Error(),
			})
		} else {
			policy.Report(KeyDriftReport{Action: KeyDriftRepaired, Object: authKeyObject, Path: path, Reason: reason})
			handle, err = openKeyForRead(pathPtr)
		}
	}
	if err != nil {
		return key, fmt.Errorf("broker authentication key is unavailable")
	}
	file := os.NewFile(uintptr(handle), "broker-auth.key")
	if file == nil {
		_ = windows.CloseHandle(handle)
		return key, fmt.Errorf("broker authentication key is unavailable")
	}
	defer func() { _ = file.Close() }()

	if err := validateKeyStructure(handle); err != nil {
		return key, err
	}
	drift, err := keyDriftWithIdentity(handle, gatewaySID)
	if err != nil {
		return key, err
	}
	if len(drift) > 0 {
		if strict {
			return key, fmt.Errorf("broker authentication key %s", drift[0])
		}
		drift = settleKeyDrift(handle, pathPtr, path, gatewaySID, drift, policy)
	}

	if _, err := io.ReadFull(file, key[:]); err != nil {
		zeroKey(&key)
		return key, fmt.Errorf("broker authentication key has an invalid length")
	}
	var extra [1]byte
	if count, readErr := file.Read(extra[:]); count != 0 || !errors.Is(readErr, io.EOF) {
		zeroKey(&key)
		return key, fmt.Errorf("broker authentication key has an invalid length")
	}
	if err := validateKeyStructure(handle); err != nil {
		zeroKey(&key)
		return key, err
	}
	// Re-check after the read. Drift that appeared meanwhile is reported, not
	// repaired a second time.
	after, err := keyDriftWithIdentity(handle, gatewaySID)
	if err != nil {
		zeroKey(&key)
		return key, err
	}
	if len(after) > 0 {
		if strict {
			zeroKey(&key)
			return key, fmt.Errorf("broker authentication key %s", after[0])
		}
		if joined := strings.Join(after, "; "); joined != strings.Join(drift, "; ") {
			policy.Report(KeyDriftReport{Action: KeyDriftAccepted, Object: authKeyObject, Path: path, Reason: joined})
		}
	}
	return key, nil
}

// keyDriftWithIdentity is keyPermissionDrift plus a leading note when the
// gateway SID could not be resolved, so the key gets one report per load.
func keyDriftWithIdentity(handle windows.Handle, gatewaySID *windows.SID) ([]string, error) {
	drift, err := keyPermissionDrift(handle, gatewaySID)
	if err != nil || gatewaySID != nil {
		return drift, err
	}
	return append([]string{"gateway service SID unavailable"}, drift...), nil
}

// settleKeyDrift repairs or accepts the drift found on the open key and
// returns whatever drift remains. It never fails the load: every error here
// becomes an accepted report.
func settleKeyDrift(
	handle windows.Handle,
	pathPtr *uint16,
	path string,
	gatewaySID *windows.SID,
	drift []string,
	policy KeyDriftPolicy,
) []string {
	reason := strings.Join(drift, "; ")
	if !policy.Repair || gatewaySID == nil {
		policy.Report(KeyDriftReport{Action: KeyDriftAccepted, Object: authKeyObject, Path: path, Reason: reason})
		return drift
	}
	if err := repairKeyDescriptor(handle, pathPtr, gatewaySID); err != nil {
		policy.Report(KeyDriftReport{
			Action:      KeyDriftAccepted,
			Object:      authKeyObject,
			Path:        path,
			Reason:      reason,
			RepairError: err.Error(),
		})
		return drift
	}
	remaining, err := keyPermissionDrift(handle, gatewaySID)
	if err != nil {
		policy.Report(KeyDriftReport{
			Action:      KeyDriftAccepted,
			Object:      authKeyObject,
			Path:        path,
			Reason:      reason,
			RepairError: "re-inspect repaired key: " + err.Error(),
		})
		return drift
	}
	if len(remaining) > 0 {
		policy.Report(KeyDriftReport{
			Action:      KeyDriftAccepted,
			Object:      authKeyObject,
			Path:        path,
			Reason:      strings.Join(remaining, "; "),
			RepairError: "descriptor still drifted after repair",
		})
		return remaining
	}
	policy.Report(KeyDriftReport{Action: KeyDriftRepaired, Object: authKeyObject, Path: path, Reason: reason})
	return nil
}

// openKeyForRead opens the key for its single read. The share mode refuses a
// concurrent writer; a writer that holds the key for a moment (the installer
// rewriting it, a backup or antivirus scan) is retried within a bounded
// budget. Access denied is returned at once.
var openKeyForRead = func(pathPtr *uint16) (windows.Handle, error) {
	return managed.RetryTransientOpen(func() (windows.Handle, error) {
		return windows.CreateFile(
			pathPtr,
			windows.GENERIC_READ|windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL,
			windows.FILE_SHARE_READ,
			nil,
			windows.OPEN_EXISTING,
			windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
			0,
		)
	})
}

// repairUnreadableKey stamps the canonical descriptor on a key whose DACL no
// longer lets SYSTEM read it. The open uses backup semantics with the restore
// and backup privileges enabled, which grant READ_CONTROL, WRITE_DAC and
// WRITE_OWNER whatever the DACL says, and requests no data access. The
// structural checks run on that handle before anything is written; the
// ancestor chain is pinned by the caller.
func repairUnreadableKey(pathPtr *uint16, gatewaySID *windows.SID) error {
	descriptor, err := windows.SecurityDescriptorFromString(fmt.Sprintf(canonicalAuthKeySDDL, gatewaySID.String()))
	if err != nil {
		return fmt.Errorf("build canonical key descriptor: %w", err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return fmt.Errorf("read canonical key owner: %w", err)
	}
	group, _, err := descriptor.Group()
	if err != nil {
		return fmt.Errorf("read canonical key group: %w", err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf("read canonical key DACL: %w", err)
	}
	return managed.RunWithWindowsRepairPrivileges(func() error {
		handle, err := managed.RetryTransientOpen(func() (windows.Handle, error) {
			return windows.CreateFile(
				pathPtr,
				windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER|windows.FILE_READ_ATTRIBUTES,
				windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
				nil,
				windows.OPEN_EXISTING,
				windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
				0,
			)
		})
		if err != nil {
			return fmt.Errorf("open key for repair: %w", err)
		}
		defer func() { _ = windows.CloseHandle(handle) }()
		if err := validateKeyStructure(handle); err != nil {
			return err
		}
		info := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION | windows.GROUP_SECURITY_INFORMATION |
			windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
		if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, info, owner, group, dacl, nil); err != nil {
			return fmt.Errorf("apply canonical key descriptor: %w", err)
		}
		return nil
	})
}

// openKeyForRepair opens the key a second time with the given rights so its
// descriptor can be re-stamped. A variable so tests can observe the requested
// rights and simulate a denied open. No data access is requested, so the read
// handle's share mode does not conflict, and FILE_FLAG_OPEN_REPARSE_POINT keeps
// a swapped-in reparse point from being followed.
var openKeyForRepair = func(pathPtr *uint16, access uint32) (windows.Handle, error) {
	return windows.CreateFile(
		pathPtr,
		access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
}

// repairKeyDescriptor stamps the installer's canonical descriptor on the key
// through a second handle that is proven to be the same file as the one being
// read, so a path swapped between the two opens is never stamped.
//
// A trusted owner (SYSTEM or Administrators) is left as it is: only the
// protected DACL is re-stamped, and the repair handle asks for WRITE_DAC alone.
// The owner and group are rewritten, which needs WRITE_OWNER, only when the
// owner itself is not trusted.
func repairKeyDescriptor(readHandle windows.Handle, pathPtr *uint16, gatewaySID *windows.SID) error {
	ownerTrusted, err := keyOwnerTrusted(readHandle)
	if err != nil {
		return err
	}
	access := uint32(windows.READ_CONTROL | windows.WRITE_DAC | windows.FILE_READ_ATTRIBUTES)
	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if !ownerTrusted {
		access |= windows.WRITE_OWNER
		info |= windows.OWNER_SECURITY_INFORMATION | windows.GROUP_SECURITY_INFORMATION
	}
	handle, err := openKeyForRepair(pathPtr, access)
	if err != nil {
		return fmt.Errorf("open key for repair: %w", err)
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	if err := validateKeyStructure(handle); err != nil {
		return err
	}
	same, err := sameFile(readHandle, handle)
	if err != nil {
		return fmt.Errorf("compare key handles: %w", err)
	}
	if !same {
		return errors.New("key path changed between open and repair")
	}
	descriptor, err := windows.SecurityDescriptorFromString(fmt.Sprintf(canonicalAuthKeySDDL, gatewaySID.String()))
	if err != nil {
		return fmt.Errorf("build canonical key descriptor: %w", err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf("read canonical key DACL: %w", err)
	}
	var owner, group *windows.SID
	if !ownerTrusted {
		if owner, _, err = descriptor.Owner(); err != nil {
			return fmt.Errorf("read canonical key owner: %w", err)
		}
		if group, _, err = descriptor.Group(); err != nil {
			return fmt.Errorf("read canonical key group: %w", err)
		}
	}
	if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, info, owner, group, dacl, nil); err != nil {
		return fmt.Errorf("apply canonical key descriptor: %w", err)
	}
	return nil
}

// keyOwnerTrusted reports whether the open key is owned by SYSTEM or
// Administrators, the two owners keyDescriptorDrift accepts.
func keyOwnerTrusted(handle windows.Handle) (bool, error) {
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil || descriptor == nil {
		return false, fmt.Errorf("read key owner: %w", err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return false, fmt.Errorf("read key owner: %w", err)
	}
	return trustedKeyOwner(owner), nil
}

func trustedKeyOwner(owner *windows.SID) bool {
	return owner != nil &&
		(owner.IsWellKnown(windows.WinLocalSystemSid) || owner.IsWellKnown(windows.WinBuiltinAdministratorsSid))
}

func sameFile(left, right windows.Handle) (bool, error) {
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

func validateLocalAbsolutePath(path, label string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("%s must be a clean absolute path", label)
	}
	volume := filepath.VolumeName(path)
	if len(volume) != 2 || volume[1] != ':' ||
		(volume[0] < 'A' || volume[0] > 'Z') && (volume[0] < 'a' || volume[0] > 'z') {
		return fmt.Errorf("%s must be on a local drive", label)
	}
	if strings.Contains(path[len(volume):], ":") {
		return fmt.Errorf("%s must not contain alternate-data-stream syntax", label)
	}
	if _, err := winpath.ValidateFixedNTFSMountedPath(path); err != nil {
		return fmt.Errorf("%s is not on a trusted local NTFS volume: %w", label, err)
	}
	return nil
}

func pinDirectoryChain(path string) ([]windows.Handle, error) {
	volume := filepath.VolumeName(path)
	root := volume + string(filepath.Separator)
	relative := strings.TrimPrefix(path, root)
	elements := []string{root}
	current := root
	for _, element := range strings.Split(relative, string(filepath.Separator)) {
		if element == "" {
			continue
		}
		current = filepath.Join(current, element)
		elements = append(elements, current)
	}
	handles := make([]windows.Handle, 0, len(elements))
	for _, element := range elements {
		pointer, err := winpath.UTF16Ptr(element)
		if err != nil {
			closeHandles(handles)
			return nil, err
		}
		handle, err := pinDirectory(pointer)
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			// A re-ACLed ancestor that no longer grants SYSTEM read is
			// permission drift, not a structural failure: the backup
			// privilege opens it whatever its DACL says. The handle stays
			// valid after the privileged thread reverts.
			_ = managed.RunWithWindowsRepairPrivileges(func() error {
				handle, err = pinDirectory(pointer)
				return err
			})
		}
		if err != nil {
			closeHandles(handles)
			return nil, err
		}
		var details windows.ByHandleFileInformation
		if err := windows.GetFileInformationByHandle(handle, &details); err != nil ||
			details.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 ||
			details.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			_ = windows.CloseHandle(handle)
			closeHandles(handles)
			return nil, errors.New("unsafe directory in key path")
		}
		handles = append(handles, handle)
	}
	return handles, nil
}

// pinDirectory holds one ancestor open without delete sharing, so it cannot be
// renamed or replaced while the key is validated and read. Traverse is the
// one data right the pin asks for: an attribute-only open would skip the
// share-access check that makes the pin effective, while list or READ_CONTROL
// access fails on an ancestor whose DACL was tightened. A transient sharing
// violation (an installer or Explorer holding the folder for delete) is
// retried.
func pinDirectory(pointer *uint16) (windows.Handle, error) {
	return managed.RetryTransientOpen(func() (windows.Handle, error) {
		return windows.CreateFile(
			pointer,
			windows.FILE_TRAVERSE|windows.FILE_READ_ATTRIBUTES,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
			nil,
			windows.OPEN_EXISTING,
			windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
			0,
		)
	})
}

func closeHandles(handles []windows.Handle) {
	for index := len(handles) - 1; index >= 0; index-- {
		_ = windows.CloseHandle(handles[index])
	}
}

// validateKeyStructure holds the key checks that guard against redirection
// and substitution rather than permissions. Every failure is fatal.
func validateKeyStructure(handle windows.Handle) error {
	var details windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &details); err != nil {
		return fmt.Errorf("broker authentication key metadata is unavailable")
	}
	if details.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|
		windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_SPARSE_FILE) != 0 ||
		details.NumberOfLinks != 1 {
		return fmt.Errorf("broker authentication key has an unsafe file type")
	}
	size := int64(details.FileSizeHigh)<<32 | int64(details.FileSizeLow)
	if size != AuthKeyBytes {
		return fmt.Errorf("broker authentication key has an invalid length")
	}
	return nil
}

// keyPermissionDrift compares the key's owner and DACL with the installer's
// canonical descriptor and returns every mismatch, not just the first. err is
// reserved for a descriptor that cannot be read at all, which is fatal: drift
// cannot be told apart from failure then. A nil gatewaySID skips the gateway
// ACE rule; a read-only NT SERVICE ACE is then presumed to be the gateway's
// and not reported.
func keyPermissionDrift(handle windows.Handle, gatewaySID *windows.SID) ([]string, error) {
	descriptor, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || descriptor == nil {
		return nil, fmt.Errorf("broker authentication key security is unavailable")
	}
	return keyDescriptorDrift(descriptor, gatewaySID)
}

func keyDescriptorDrift(descriptor *windows.SECURITY_DESCRIPTOR, gatewaySID *windows.SID) ([]string, error) {
	var drift []string
	owner, _, err := descriptor.Owner()
	if err != nil {
		return nil, fmt.Errorf("broker authentication key owner is unavailable")
	}
	if !trustedKeyOwner(owner) {
		drift = append(drift, fmt.Sprintf("owner %s is not trusted", sidText(owner)))
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return nil, fmt.Errorf("broker authentication key security control is unavailable")
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		drift = append(drift, "DACL is not protected")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return nil, fmt.Errorf("broker authentication key DACL is unavailable")
	}
	if dacl == nil {
		return append(drift, "DACL is null"), nil
	}
	aclDrift, err := keyACLDrift(dacl, gatewaySID)
	if err != nil {
		return nil, err
	}
	return append(drift, aclDrift...), nil
}

func keyACLDrift(dacl *windows.ACL, gatewaySID *windows.SID) ([]string, error) {
	var drift []string
	seenSystem, seenAdmins, seenGateway := false, false, false
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil || ace == nil {
			return nil, fmt.Errorf("broker authentication key DACL is malformed")
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
			ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			drift = append(drift, fmt.Sprintf("ACE %d has unsupported type 0x%x or flags 0x%x",
				index, ace.Header.AceType, ace.Header.AceFlags))
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		switch {
		case sid.IsWellKnown(windows.WinLocalSystemSid):
			if seenSystem {
				drift = append(drift, "duplicate SYSTEM ACE")
			}
			seenSystem = true
			if !fullControlMask(ace.Mask) {
				drift = append(drift, "SYSTEM access is incomplete")
			}
		case sid.IsWellKnown(windows.WinBuiltinAdministratorsSid):
			if seenAdmins {
				drift = append(drift, "duplicate Administrators ACE")
			}
			seenAdmins = true
			if !fullControlMask(ace.Mask) {
				drift = append(drift, "Administrators access is incomplete")
			}
		case gatewaySID != nil && sid.Equals(gatewaySID),
			gatewaySID == nil && ntServiceSID(sid) && readOnlyMask(ace.Mask) && !seenGateway:
			if seenGateway {
				drift = append(drift, "duplicate gateway ACE")
			}
			seenGateway = true
			if !readOnlyMask(ace.Mask) {
				drift = append(drift, fmt.Sprintf("gateway access mask 0x%x is not read-only", uint32(ace.Mask)))
			}
		default:
			drift = append(drift, fmt.Sprintf("unexpected principal %s with access mask 0x%x",
				sidText(sid), uint32(ace.Mask)))
		}
	}
	if !seenSystem {
		drift = append(drift, "SYSTEM ACE is missing")
	}
	if !seenAdmins {
		drift = append(drift, "Administrators ACE is missing")
	}
	if !seenGateway && gatewaySID != nil {
		drift = append(drift, "gateway ACE is missing")
	}
	return drift, nil
}

// readOnlyMask reports whether mask grants read and nothing write-like.
func readOnlyMask(mask windows.ACCESS_MASK) bool {
	const fileGenericRead windows.ACCESS_MASK = 0x00120089
	if mask&(windows.GENERIC_WRITE|windows.GENERIC_ALL|windows.DELETE|windows.WRITE_DAC|windows.WRITE_OWNER|
		windows.FILE_WRITE_DATA|windows.FILE_APPEND_DATA|windows.FILE_WRITE_EA|windows.FILE_WRITE_ATTRIBUTES) != 0 {
		return false
	}
	return mask&windows.GENERIC_READ != 0 || mask&fileGenericRead == fileGenericRead
}

// ntServiceSID reports whether sid is under NT SERVICE (S-1-5-80-...).
func ntServiceSID(sid *windows.SID) bool {
	if sid == nil || !sid.IsValid() || sid.SubAuthorityCount() < 1 {
		return false
	}
	return sid.IdentifierAuthority().Value == [6]byte{0, 0, 0, 0, 0, 5} && sid.SubAuthority(0) == 80
}

func sidText(sid *windows.SID) string {
	if sid == nil {
		return "<nil>"
	}
	return sid.String()
}

func fullControlMask(mask windows.ACCESS_MASK) bool {
	const fileAllAccess windows.ACCESS_MASK = 0x001F01FF
	return mask&windows.GENERIC_ALL != 0 || mask&fileAllAccess == fileAllAccess
}

func zeroKey(key *[AuthKeyBytes]byte) {
	if key == nil {
		return
	}
	for index := range key {
		key[index] = 0
	}
}

func brokerServiceForGateway(gatewayServiceName string) string {
	if gatewayServiceName == defaultGatewayService {
		return defaultBrokerService
	}
	match := certificationGatewayPattern.FindStringSubmatch(gatewayServiceName)
	if len(match) == 2 {
		return defaultBrokerService + "_" + match[1]
	}
	return ""
}
