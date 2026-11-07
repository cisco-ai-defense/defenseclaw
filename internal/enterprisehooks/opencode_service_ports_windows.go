//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

const (
	WindowsOpenCodeServicePortsFileName = "opencode-service-ports.json"
	windowsOpenCodeServicePortsMaxBytes = 1 << 20
	windowsOpenCodeServicePortsSDDL     = "O:SYG:SYD:P(A;;FA;;;SY)"
)

type windowsOpenCodeServicePortsFile struct {
	Version    int                             `json:"version"`
	Ports      []windowsOpenCodeServicePort    `json:"ports"`
	Unknown    []WindowsOpenCodePortUnknown    `json:"unknown,omitempty"`
	Contested  []WindowsOpenCodeContestedPort  `json:"contested,omitempty"`
	Cleared    []WindowsOpenCodeContestCleared `json:"contested_cleared,omitempty"`
	ImportDone bool                            `json:"import_done,omitempty"`
}

type WindowsOpenCodePortUnknown struct {
	SID    string `json:"sid"`
	Path   string `json:"path"`
	Reason string `json:"reason"`
	Fix    string `json:"fix"`
}

type WindowsOpenCodeContestedPort struct {
	Port int      `json:"port"`
	SIDs []string `json:"sids"`
}

type WindowsOpenCodeContestCleared struct {
	Port int      `json:"port"`
	SIDs []string `json:"sids"`
	At   string   `json:"at"`
	By   string   `json:"by,omitempty"`
}

type WindowsOpenCodeServicePortsState struct {
	Exists     bool
	ImportDone bool
	Ports      map[string]int
	Unknown    []WindowsOpenCodePortUnknown
	Contested  []WindowsOpenCodeContestedPort
	Cleared    []WindowsOpenCodeContestCleared
}

type windowsOpenCodeServicePort struct {
	SID  string `json:"sid"`
	Port int    `json:"port"`
}

func WindowsOpenCodeServicePortsPath(manifestPath string) string {
	return filepath.Join(filepath.Dir(manifestPath), WindowsOpenCodeServicePortsFileName)
}

// LoadWindowsOpenCodeServicePorts reads the guardian's SYSTEM-only record.
// A missing record is empty; an untrusted or malformed record is an error.
func LoadWindowsOpenCodeServicePorts(path string) (map[string]int, error) {
	state, err := LoadWindowsOpenCodeServicePortsFull(path)
	return state.Ports, err
}

// LoadWindowsOpenCodeServicePortsFull reads bindings and the last pass's
// warnings. A missing record selects the one import pass after install or
// administrator rebuild; a record from an earlier build counts as done.
func LoadWindowsOpenCodeServicePortsFull(path string) (WindowsOpenCodeServicePortsState, error) {
	state := WindowsOpenCodeServicePortsState{Ports: map[string]int{}}
	if err := windowsOpenCodeServicePortsParent(path); err != nil {
		return state, err
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return state, nil
	} else if err != nil {
		return state, err
	}
	state.Exists = true
	state.ImportDone = true
	if err := validateWindowsOpenCodeServicePortsFile(path); err != nil {
		return state, err
	}
	data, err := readWindowsOpenCodePortRecord(path)
	if err != nil {
		return state, err
	}
	var record windowsOpenCodeServicePortsFile
	if err := json.Unmarshal(data, &record); err != nil {
		return state, fmt.Errorf("enterprise hooks: parse OpenCode service ports: %w", err)
	}
	if record.Version != 1 {
		return state, fmt.Errorf("enterprise hooks: OpenCode service ports version %d is not supported", record.Version)
	}
	holders := map[int]string{}
	for _, entry := range record.Ports {
		sid, err := windows.StringToSid(entry.SID)
		if err != nil || !WindowsInteractiveUserSID(entry.SID) || sid.String() != entry.SID || entry.Port <= 0 || entry.Port > 65535 {
			return state, fmt.Errorf("enterprise hooks: OpenCode service ports record has an invalid account or port")
		}
		if _, exists := state.Ports[entry.SID]; exists {
			return state, fmt.Errorf("enterprise hooks: OpenCode service ports record repeats an account")
		}
		if other := holders[entry.Port]; other != "" {
			return state, fmt.Errorf("enterprise hooks: OpenCode service ports record repeats a port for %s and %s", other, entry.SID)
		}
		holders[entry.Port] = entry.SID
		state.Ports[entry.SID] = entry.Port
	}
	state.Unknown, state.Contested, state.Cleared = record.Unknown, record.Contested, record.Cleared
	if err := validateWindowsOpenCodeContests(state.Contested, holders); err != nil {
		return state, err
	}
	return state, nil
}

// WriteWindowsOpenCodeServicePorts publishes only complete, validated
// assignments. The staging file gets the SYSTEM-only ACL before replacement.
func WriteWindowsOpenCodeServicePorts(path string, ports map[string]int) error {
	return WriteWindowsOpenCodeServicePortsFull(path, WindowsOpenCodeServicePortsState{Ports: ports})
}

func WriteWindowsOpenCodeServicePortsFull(path string, state WindowsOpenCodeServicePortsState) error {
	if err := windowsOpenCodeServicePortsParent(path); err != nil {
		return err
	}
	record := windowsOpenCodeServicePortsFile{Version: 1, Ports: make([]windowsOpenCodeServicePort, 0, len(state.Ports))}
	holders := map[int]string{}
	for sid, port := range state.Ports {
		parsed, err := windows.StringToSid(sid)
		if err != nil || !WindowsInteractiveUserSID(sid) || parsed.String() != sid || port <= 0 || port > 65535 {
			return fmt.Errorf("enterprise hooks: OpenCode service ports assignment has an invalid account or port")
		}
		if other := holders[port]; other != "" {
			return fmt.Errorf("enterprise hooks: OpenCode service ports assignment repeats a port for %s and %s", other, sid)
		}
		holders[port] = sid
		record.Ports = append(record.Ports, windowsOpenCodeServicePort{SID: sid, Port: port})
	}
	sort.Slice(record.Ports, func(i, j int) bool { return record.Ports[i].SID < record.Ports[j].SID })
	if err := validateWindowsOpenCodeContests(state.Contested, holders); err != nil {
		return err
	}
	record.Unknown = append(record.Unknown, state.Unknown...)
	sort.Slice(record.Unknown, func(i, j int) bool { return record.Unknown[i].SID < record.Unknown[j].SID })
	record.Contested = append(record.Contested, state.Contested...)
	sort.Slice(record.Contested, func(i, j int) bool { return record.Contested[i].Port < record.Contested[j].Port })
	record.Cleared = append(record.Cleared, state.Cleared...)
	record.ImportDone = state.ImportDone
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if len(data) > windowsOpenCodeServicePortsMaxBytes {
		return fmt.Errorf("enterprise hooks: OpenCode service ports record is too large")
	}
	if _, err := os.Lstat(path); err == nil {
		if err := validateWindowsOpenCodeServicePortsFile(path); err != nil {
			return err
		}
		current, err := readWindowsOpenCodePortRecord(path)
		if err != nil {
			return err
		}
		if string(current) == string(data) {
			return nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	staged, err := os.CreateTemp(filepath.Dir(path), ".defenseclaw-opencode-ports-*.new")
	if err != nil {
		return err
	}
	stagedPath := staged.Name()
	defer func() { _ = os.Remove(stagedPath) }()
	if err := staged.Close(); err != nil {
		return err
	}
	if err := protectWindowsOpenCodeServicePortsFile(stagedPath); err != nil {
		return err
	}
	handle, err := openWindowsTargetsManifestObjectWithBackup(stagedPath, false, windows.GENERIC_WRITE, true)
	if err != nil {
		return err
	}
	staged = os.NewFile(uintptr(handle), stagedPath)
	if _, err := staged.Write(data); err != nil {
		_ = staged.Close()
		return err
	}
	if err := staged.Sync(); err != nil {
		_ = staged.Close()
		return err
	}
	if err := staged.Close(); err != nil {
		return err
	}
	if err := validateWindowsOpenCodeServicePortsFile(stagedPath); err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		if err := validateWindowsOpenCodeServicePortsFile(path); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := replaceWindowsOpenCodePortRecord(stagedPath, path); err != nil {
		return err
	}
	return validateWindowsOpenCodeServicePortsFile(path)
}

// The write-through move publishes the flushed, SYSTEM-only staging file.
// An elevated administrator may need backup-intent replacement for an
// existing SYSTEM-only destination; that path flushes the renamed handle.
func replaceWindowsOpenCodePortRecord(stagedPath, path string) error {
	from, err := windows.UTF16PtrFromString(stagedPath)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err == nil {
		return nil
	} else if !errors.Is(err, windows.ERROR_ACCESS_DENIED) &&
		!errors.Is(err, windows.ERROR_SHARING_VIOLATION) && !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return err
	}
	handle, err := openWindowsTargetsManifestObjectWithBackup(stagedPath, false, windows.DELETE|windows.SYNCHRONIZE, true)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	utf16Name, err := windows.UTF16FromString(path)
	if err != nil {
		return err
	}
	type fileRenameInfo struct {
		Flags          uint32
		RootDirectory  windows.Handle
		FileNameLength uint32
		FileName       [1]uint16
	}
	size := unsafe.Offsetof(fileRenameInfo{}.FileName) + uintptr(len(utf16Name))*2
	buffer := make([]uint64, (size+7)/8)
	info := (*fileRenameInfo)(unsafe.Pointer(&buffer[0]))
	info.FileNameLength = uint32((len(utf16Name) - 1) * 2)
	copy(unsafe.Slice(&info.FileName[0], len(utf16Name)), utf16Name)
	const replaceIfExists, posixSemantics = 0x1, 0x2
	for attempt := 0; attempt < 3000; attempt++ {
		info.Flags = replaceIfExists | posixSemantics
		err = windows.SetFileInformationByHandle(handle, windows.FileRenameInfoEx, (*byte)(unsafe.Pointer(&buffer[0])), uint32(size))
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) || errors.Is(err, windows.ERROR_NOT_SUPPORTED) || errors.Is(err, windows.ERROR_INVALID_FUNCTION) {
			info.Flags = replaceIfExists
			err = windows.SetFileInformationByHandle(handle, windows.FileRenameInfo, (*byte)(unsafe.Pointer(&buffer[0])), uint32(size))
		}
		if err == nil {
			flush, openErr := openWindowsTargetsManifestObjectWithBackup(path, false, windows.GENERIC_WRITE, true)
			if openErr != nil {
				return openErr
			}
			flushErr := windows.FlushFileBuffers(flush)
			closeErr := windows.CloseHandle(flush)
			return errors.Join(flushErr, closeErr)
		}
		if !errors.Is(err, windows.ERROR_ACCESS_DENIED) && !errors.Is(err, windows.ERROR_SHARING_VIOLATION) && !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return err
		}
		time.Sleep(time.Millisecond)
	}
	return fmt.Errorf("enterprise hooks: replace OpenCode service ports record: %w", err)
}

const (
	windowsOpenCodeReconcileLockWait = 2 * time.Minute
	windowsOpenCodeReconcileLockPoll = 25 * time.Millisecond
	// WindowsOpenCodeReconcileLockFileName lives beside the record, in the
	// SYSTEM/Administrators-only folder Setup protects, so an ordinary account
	// can neither create nor open it.
	WindowsOpenCodeReconcileLockFileName = "opencode-service-ports.lock"
	windowsOpenCodeReconcileLockSDDL     = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
)

var windowsOpenCodeReconcileLocal sync.Mutex

// LockWindowsOpenCodeServicePorts holds one machine-wide reconcile lock for
// the guardian read, plan, commit and account rewrites, or for administrator
// clear. The lock is a byte-range lock (LockFileEx) on a file inside the
// protected record folder, opened only after that folder passes the same
// SYSTEM/Administrators-only check as the record. The file carries an
// Administrators owner and a protected SYSTEM/Administrators DACL, so no
// other account can create, open or hold it, or rewrite its DACL as owner
// (a named kernel object cannot give that guarantee: any account
// can create it first). The local mutex serializes goroutines in this process.
func LockWindowsOpenCodeServicePorts(recordPath string) (func(), error) {
	windowsOpenCodeReconcileLocal.Lock()
	handle, err := openWindowsOpenCodeReconcileLockFile(recordPath)
	if err != nil {
		windowsOpenCodeReconcileLocal.Unlock()
		return nil, fmt.Errorf("enterprise hooks: open OpenCode port reconcile lock: %w", err)
	}
	deadline := time.Now().Add(windowsOpenCodeReconcileLockWait)
	for {
		overlapped := new(windows.Overlapped)
		err = windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, overlapped)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) || time.Now().After(deadline) {
			_ = windows.CloseHandle(handle)
			windowsOpenCodeReconcileLocal.Unlock()
			return nil, fmt.Errorf("enterprise hooks: acquire OpenCode port reconcile lock: %w", err)
		}
		time.Sleep(windowsOpenCodeReconcileLockPoll)
	}
	return func() {
		_ = windows.UnlockFileEx(handle, 0, 1, 0, new(windows.Overlapped))
		_ = windows.CloseHandle(handle)
		windowsOpenCodeReconcileLocal.Unlock()
	}, nil
}

func openWindowsOpenCodeReconcileLockFile(recordPath string) (windows.Handle, error) {
	if err := windowsOpenCodeServicePortsParent(recordPath); err != nil {
		return 0, err
	}
	lockPath := filepath.Join(filepath.Dir(recordPath), WindowsOpenCodeReconcileLockFileName)
	for attempt := 0; attempt < 3; attempt++ {
		handle, err := openWindowsTargetsManifestObjectWithBackup(lockPath, false, windows.GENERIC_READ|windows.GENERIC_WRITE, false)
		if err == nil {
			if err := validateWindowsOpenCodeReconcileLockHandle(handle, lockPath); err != nil {
				_ = windows.CloseHandle(handle)
				return 0, err
			}
			return handle, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return 0, err
		}
		handle, err = createWindowsOpenCodeReconcileLockFile(lockPath)
		if err == nil {
			if err := validateWindowsOpenCodeReconcileLockHandle(handle, lockPath); err != nil {
				_ = windows.CloseHandle(handle)
				return 0, err
			}
			return handle, nil
		}
		if !errors.Is(err, windows.ERROR_FILE_EXISTS) && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return 0, err
		}
	}
	return 0, fmt.Errorf("enterprise hooks: OpenCode port reconcile lock file kept changing: %s", lockPath)
}

func createWindowsOpenCodeReconcileLockFile(lockPath string) (windows.Handle, error) {
	descriptor, err := windows.SecurityDescriptorFromString(windowsOpenCodeReconcileLockSDDL)
	if err != nil {
		return 0, err
	}
	attributes := &windows.SecurityAttributes{
		Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor,
	}
	pointer, err := winpath.UTF16Ptr(lockPath)
	if err != nil {
		return 0, err
	}
	return windows.CreateFile(pointer, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		attributes, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
}

// validateWindowsOpenCodeReconcileLockHandle requires a SYSTEM or
// Administrators owner and a protected DACL that allows only SYSTEM and
// Administrators, checked on the handle that will be locked. The owner counts
// as much as the DACL: an object owner holds implicit WRITE_DAC, so a file
// created by an ordinary account (before Setup protected the folder) could be
// reopened and have its DACL changed after this check passed.
func validateWindowsOpenCodeReconcileLockHandle(handle windows.Handle, lockPath string) error {
	actual, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	owner, _, err := actual.Owner()
	if err != nil || owner == nil || (!owner.Equals(system) && !owner.Equals(admins)) {
		return fmt.Errorf("enterprise hooks: OpenCode port reconcile lock is not owned by SYSTEM or Administrators: %s", lockPath)
	}
	control, _, err := actual.Control()
	if err != nil {
		return err
	}
	dacl, _, err := actual.DACL()
	if err != nil || dacl == nil || control&windows.SE_DACL_PROTECTED == 0 || dacl.AceCount == 0 {
		return fmt.Errorf("enterprise hooks: OpenCode port reconcile lock is not administrator-only: %s", lockPath)
	}
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			return err
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || (!sid.Equals(system) && !sid.Equals(admins)) {
			return fmt.Errorf("enterprise hooks: OpenCode port reconcile lock is not administrator-only: %s", lockPath)
		}
	}
	return nil
}

func validateWindowsOpenCodeContests(contested []WindowsOpenCodeContestedPort, holders map[int]string) error {
	seen := map[int]bool{}
	for _, mark := range contested {
		if mark.Port <= 0 || mark.Port > 65535 || seen[mark.Port] || holders[mark.Port] != "" || len(mark.SIDs) < 1 {
			return fmt.Errorf("enterprise hooks: OpenCode service ports record has an invalid contested port")
		}
		seen[mark.Port] = true
		claimants := map[string]bool{}
		for _, raw := range mark.SIDs {
			sid, err := windows.StringToSid(raw)
			if err != nil || !WindowsInteractiveUserSID(raw) || sid.String() != raw || claimants[raw] {
				return fmt.Errorf("enterprise hooks: OpenCode service ports record has an invalid contested account")
			}
			claimants[raw] = true
		}
	}
	return nil
}

// ClearWindowsOpenCodeContestedPort clears only the named mark and keeps all
// bindings. The operation is recorded in the SYSTEM-only record.
func ClearWindowsOpenCodeContestedPort(path string, port int, by string, now time.Time) ([]string, error) {
	unlock, err := LockWindowsOpenCodeServicePorts(path)
	if err != nil {
		return nil, err
	}
	defer unlock()
	var claimants []string
	err = RunWithWindowsOwnerRestorePrivilege(func() error {
		var clearErr error
		claimants, clearErr = clearWindowsOpenCodeContestedPort(path, port, by, now)
		return clearErr
	})
	return claimants, err
}

func clearWindowsOpenCodeContestedPort(path string, port int, by string, now time.Time) ([]string, error) {
	state, err := LoadWindowsOpenCodeServicePortsFull(path)
	if err != nil {
		return nil, err
	}
	if !state.Exists {
		return nil, fmt.Errorf("no OpenCode service ports record at %s", path)
	}
	var claimants []string
	kept := state.Contested[:0]
	for _, mark := range state.Contested {
		if mark.Port == port {
			claimants = mark.SIDs
		} else {
			kept = append(kept, mark)
		}
	}
	if claimants == nil {
		return nil, fmt.Errorf("port %d is not marked contested in %s", port, path)
	}
	state.Contested = kept
	state.Cleared = append(state.Cleared, WindowsOpenCodeContestCleared{Port: port, SIDs: claimants, At: now.UTC().Format(time.RFC3339), By: by})
	return claimants, WriteWindowsOpenCodeServicePortsFull(path, state)
}

func readWindowsOpenCodePortRecord(path string) ([]byte, error) {
	handle, err := openWindowsTargetsManifestObjectWithBackup(path, false, windows.GENERIC_READ, true)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, windowsOpenCodeServicePortsMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > windowsOpenCodeServicePortsMaxBytes {
		return nil, fmt.Errorf("enterprise hooks: %s exceeds the OpenCode port record limit", path)
	}
	return data, nil
}

func windowsOpenCodeServicePortsParent(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("enterprise hooks: OpenCode service ports path must be absolute and clean")
	}
	dir := filepath.Dir(path)
	if err := windowsTargetsManifestAncestorTrust(dir); err != nil {
		return err
	}
	return validateWindowsTargetsManifestObject(dir, true)
}

func protectWindowsOpenCodeServicePortsFile(path string) error {
	if err := validateWindowsTargetsManifestObjectShape(path, false); err != nil {
		return err
	}
	descriptor, err := windows.SecurityDescriptorFromString(windowsOpenCodeServicePortsSDDL)
	if err != nil {
		return err
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return err
	}
	group, _, err := descriptor.Group()
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	extended, err := winpath.Extended(path)
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, group, dacl, nil); err != nil {
		return err
	}
	return validateWindowsOpenCodeServicePortsFile(path)
}

func validateWindowsOpenCodeServicePortsFile(path string) error {
	handle, err := openWindowsTargetsManifestObjectWithBackup(path, false, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, true)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	actual, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	expected, err := windows.SecurityDescriptorFromString(windowsOpenCodeServicePortsSDDL)
	if err != nil {
		return err
	}
	actualOwner, _, ownerErr := actual.Owner()
	expectedOwner, _, expectedOwnerErr := expected.Owner()
	actualGroup, _, groupErr := actual.Group()
	expectedGroup, _, expectedGroupErr := expected.Group()
	control, _, controlErr := actual.Control()
	actualDACL, _, aclErr := actual.DACL()
	expectedDACL, _, expectedACLErr := expected.DACL()
	if ownerErr != nil || expectedOwnerErr != nil || groupErr != nil || expectedGroupErr != nil ||
		controlErr != nil || aclErr != nil || expectedACLErr != nil || actualOwner == nil || expectedOwner == nil ||
		actualGroup == nil || expectedGroup == nil || actualDACL == nil || expectedDACL == nil ||
		!actualOwner.Equals(expectedOwner) || !actualGroup.Equals(expectedGroup) || control&windows.SE_DACL_PROTECTED == 0 ||
		actualDACL.AceCount != 1 || expectedDACL.AceCount != 1 {
		return fmt.Errorf("enterprise hooks: OpenCode service ports record is not SYSTEM-only: %s", path)
	}
	var actualACE, expectedACE *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(actualDACL, 0, &actualACE); err != nil {
		return err
	}
	if err := windows.GetAce(expectedDACL, 0, &expectedACE); err != nil {
		return err
	}
	if actualACE == nil || expectedACE == nil || actualACE.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
		actualACE.Header.AceFlags != expectedACE.Header.AceFlags || actualACE.Header.AceSize != expectedACE.Header.AceSize ||
		actualACE.Mask != expectedACE.Mask ||
		!(*windows.SID)(unsafe.Pointer(&actualACE.SidStart)).Equals((*windows.SID)(unsafe.Pointer(&expectedACE.SidStart))) {
		return fmt.Errorf("enterprise hooks: OpenCode service ports record is not SYSTEM-only: %s", path)
	}
	return nil
}
