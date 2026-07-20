// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"debug/pe"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/hookruntime"
	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/winfolders"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var queryProcessMachines = windows.IsWow64Process2

func requireNativeWindowsX64() error {
	var processMachine uint16
	var nativeMachine uint16
	if err := queryProcessMachines(windows.CurrentProcess(), &processMachine, &nativeMachine); err != nil {
		return fmt.Errorf("cannot verify native Windows x64 architecture: %w", err)
	}
	if nativeMachine != pe.IMAGE_FILE_MACHINE_AMD64 {
		return fmt.Errorf(
			"DefenseClawSetup-x64.exe requires native Windows x64; x64 emulation on machine type %#x is not certified",
			nativeMachine,
		)
	}
	return nil
}

func publishStableHookRuntime(source, gatewayPath, dataRoot, transactionID string) error {
	if err := hookruntime.Publish(source, gatewayPath, dataRoot, transactionID); err != nil {
		return err
	}
	paths, err := hookruntime.CurrentUserPaths()
	if err != nil {
		return err
	}
	return verifyPublishedStableHookRuntime(source, paths.Launcher)
}

func disableStableHookRuntime(transactionID string) error {
	return hookruntime.Disable(transactionID)
}

type pidState struct {
	PID           int    `json:"pid"`
	Executable    string `json:"executable"`
	StartIdentity string `json:"start_identity"`
}

func acquireSetupLock() (func() error, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("resolve setup lock identity: %w", err)
	}
	name, err := windows.UTF16PtrFromString(`Global\Cisco.DefenseClaw.Setup.` + user.User.Sid.String())
	if err != nil {
		return nil, fmt.Errorf("encode setup lock name: %w", err)
	}
	handle, err := windows.CreateMutex(nil, true, name)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("another DefenseClaw setup operation is already in progress")
	}
	if err != nil {
		if handle != 0 {
			_ = windows.CloseHandle(handle)
		}
		return nil, fmt.Errorf("acquire setup lock: %w", err)
	}
	return func() error {
		releaseErr := windows.ReleaseMutex(handle)
		closeErr := windows.CloseHandle(handle)
		if releaseErr != nil {
			return releaseErr
		}
		return closeErr
	}, nil
}

func managedProcessOwnedBy(gatewayPath, dataRoot, pidFile string) (bool, error) {
	proof, owned, err := managedProcessProofFor(gatewayPath, dataRoot, pidFile)
	closeErr := closeManagedProcessProof(proof)
	if err == nil {
		err = closeErr
	}
	return owned, err
}

func managedProcessProofFor(gatewayPath, dataRoot, pidFile string) (managedProcessProof, bool, error) {
	pidPath := filepath.Join(dataRoot, pidFile)
	info, err := os.Lstat(pidPath)
	if errors.Is(err, os.ErrNotExist) {
		return managedProcessProof{}, false, nil
	}
	if err != nil {
		return managedProcessProof{}, false, err
	}
	if info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return managedProcessProof{}, false, fmt.Errorf("managed gateway PID path is not a regular file: %s", pidPath)
	}
	if reparse, err := isReparsePoint(pidPath); err != nil {
		return managedProcessProof{}, false, err
	} else if reparse {
		return managedProcessProof{}, false, fmt.Errorf("managed gateway PID path is a reparse point: %s", pidPath)
	}
	data, err := os.ReadFile(pidPath)
	if err != nil {
		return managedProcessProof{}, false, err
	}
	var state pidState
	if err := json.Unmarshal(data, &state); err != nil {
		return managedProcessProof{}, false, fmt.Errorf("invalid managed gateway PID file %s: %w", pidPath, err)
	}
	if state.PID <= 0 || strings.TrimSpace(state.Executable) == "" {
		return managedProcessProof{}, false, fmt.Errorf("managed gateway PID file lacks a complete process identity: %s", pidPath)
	}
	if !pathidentity.Same(state.Executable, gatewayPath) {
		return managedProcessProof{}, false, nil
	}
	handle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE,
		false,
		uint32(state.PID),
	)
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return managedProcessProof{}, false, nil
	}
	if err != nil {
		return managedProcessProof{}, false, err
	}
	livePath, identity, err := processIdentityFromHandle(handle)
	if errors.Is(err, os.ErrProcessDone) {
		_ = windows.CloseHandle(handle)
		return managedProcessProof{}, false, nil
	}
	if err != nil {
		_ = windows.CloseHandle(handle)
		return managedProcessProof{}, false, err
	}
	if !pathidentity.Same(livePath, gatewayPath) {
		_ = windows.CloseHandle(handle)
		return managedProcessProof{}, false, nil
	}
	if state.StartIdentity != "" && state.StartIdentity != identity {
		_ = windows.CloseHandle(handle)
		return managedProcessProof{}, false, nil
	}
	return managedProcessProof{
		PID:           uint32(state.PID),
		Executable:    livePath,
		StartIdentity: identity,
		ProcessHandle: uintptr(handle),
	}, true, nil
}

func closeManagedProcessProof(proof managedProcessProof) error {
	if proof.ProcessHandle == 0 {
		return nil
	}
	return windows.CloseHandle(windows.Handle(proof.ProcessHandle))
}

func waitForManagedProcessExitContext(
	ctx context.Context,
	proof managedProcessProof,
	timeout time.Duration,
) error {
	if proof.PID == 0 || strings.TrimSpace(proof.Executable) == "" || proof.StartIdentity == "" ||
		proof.ProcessHandle == 0 {
		return errors.New("managed process exit proof is incomplete")
	}
	handle := windows.Handle(proof.ProcessHandle)
	deadline := time.Now().Add(timeout)
	for {
		result, err := windows.WaitForSingleObject(handle, 25)
		if err != nil {
			return err
		}
		if result == uint32(windows.WAIT_OBJECT_0) {
			return nil
		}
		if result != uint32(windows.WAIT_TIMEOUT) {
			return fmt.Errorf("unexpected authenticated process wait result %#x", result)
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("timed out waiting for authenticated process %d to exit", proof.PID)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}
}

func waitForExecutableRelease(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		err := probeExecutableRelease(path)
		if err == nil || errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) &&
			!errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return err
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("timed out waiting for executable handle release: %w", err)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func probeExecutableRelease(path string) error {
	if err := rejectReparseAncestors(path); err != nil {
		return err
	}
	before, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return os.ErrNotExist
	}
	if err != nil {
		return err
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("executable release path is not a regular file: %s", path)
	}
	if reparse, err := isReparsePoint(path); err != nil {
		return err
	} else if reparse {
		return fmt.Errorf("executable release path is a reparse point: %s", path)
	}
	pathPtr, err := winpath.UTF16Ptr(path)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(
		pathPtr,
		// Stable-hook publication immediately opens this executable read/write
		// before tightening its DACL. A read/delete-only probe can succeed while
		// a legacy gateway or watchdog image still denies write sharing, creating
		// a false release proof followed by ERROR_SHARING_VIOLATION. Request the
		// same write authority here without mutating the file so recovery waits
		// for every executable image handle to drain first.
		windows.GENERIC_READ|windows.GENERIC_WRITE|windows.DELETE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return os.ErrNotExist
		}
		return err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return fmt.Errorf("wrap executable release handle: %s", path)
	}
	opened, statErr := file.Stat()
	closeErr := file.Close()
	if statErr != nil || closeErr != nil {
		return errors.Join(statErr, closeErr)
	}
	if !os.SameFile(before, opened) {
		return fmt.Errorf("executable release path changed while opening: %s", path)
	}
	return nil
}

func defaultInstallRoot() (string, error) {
	programs, err := winfolders.UserProgramFiles()
	if err != nil {
		return "", err
	}
	return filepath.Join(programs, "DefenseClaw"), nil
}

func defaultDataRoot() (string, error) {
	profile, err := defaultProfileRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(profile, ".defenseclaw"), nil
}

func defaultProfileRoot() (string, error) {
	return winpath.CurrentUserKnownFolderPath(windows.FOLDERID_Profile)
}

func defaultOpenClawRoot() (string, error) {
	profile, err := defaultProfileRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(profile, ".openclaw"), nil
}

func defaultMaintenancePath() (string, error) {
	local, err := winpath.CurrentUserKnownFolderPath(windows.FOLDERID_LocalAppData)
	if err != nil {
		return "", err
	}
	return filepath.Join(local, "DefenseClaw", "InstallerCache", setupArtifactName), nil
}

func defaultTransactionRoot() (string, error) {
	local, err := winpath.CurrentUserKnownFolderPath(windows.FOLDERID_LocalAppData)
	if err != nil {
		return "", err
	}
	return filepath.Join(local, "DefenseClaw", "InstallerState"), nil
}

func defaultPayloadTempRoot() (string, error) {
	local, err := winpath.CurrentUserKnownFolderPath(windows.FOLDERID_LocalAppData)
	if err != nil {
		return "", err
	}
	return filepath.Join(local, "DefenseClaw", "InstallerTemp"), nil
}

func createExclusiveUnpublishedFile(path string) (*os.File, error) {
	encoded, err := winpath.UTF16Ptr(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		encoded,
		windows.GENERIC_WRITE,
		0,
		nil,
		windows.CREATE_NEW,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_SEQUENTIAL_SCAN,
		0,
	)
	if err != nil {
		return nil, &os.PathError{Op: "create", Path: path, Err: err}
	}
	return os.NewFile(uintptr(handle), path), nil
}

func renameDurableFile(source, destination string) error {
	from, err := winpath.UTF16Ptr(source)
	if err != nil {
		return err
	}
	to, err := winpath.UTF16Ptr(destination)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH)
}

func replaceDurableFile(source, destination string) error {
	return safefile.ReplaceFile(source, destination)
}

func validatePrivateTransactionPath(path string, wantDirectory bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || (wantDirectory && !info.IsDir()) || (!wantDirectory && !info.Mode().IsRegular()) {
		return fmt.Errorf("installer transaction path has an unexpected type: %s", path)
	}
	if reparse, err := isReparsePoint(path); err != nil {
		return err
	} else if reparse {
		return fmt.Errorf("installer transaction path is a reparse point: %s", path)
	}
	extendedPath, err := winpath.Extended(path)
	if err != nil {
		return err
	}
	sd, err := windows.GetNamedSecurityInfo(
		extendedPath,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("inspect installer transaction security descriptor: %w", err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return fmt.Errorf("resolve installer transaction owner: %w", err)
	}
	if owner == nil || !owner.Equals(user.User.Sid) {
		return fmt.Errorf("installer transaction path is not owned by the current user: %s", path)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("installer transaction path has no verifiable DACL: %s", path)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			return err
		}
		if ace == nil || ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
				continue
			}
			return fmt.Errorf("installer transaction path has an unsupported ACE type 0x%x: %s", ace.Header.AceType, path)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid.Equals(user.User.Sid) || sid.Equals(system) || sid.IsWellKnown(windows.WinCreatorOwnerRightsSid) {
			continue
		}
		writeLike := windows.ACCESS_MASK(
			windows.GENERIC_ALL |
				windows.GENERIC_WRITE |
				windows.DELETE |
				windows.WRITE_DAC |
				windows.WRITE_OWNER |
				windows.FILE_WRITE_DATA |
				windows.FILE_APPEND_DATA |
				windows.FILE_WRITE_EA |
				windows.FILE_WRITE_ATTRIBUTES |
				0x00000040,
		)
		if ace.Mask&writeLike != 0 {
			return fmt.Errorf("untrusted principal has write access to installer transaction path: %s", path)
		}
	}
	return nil
}

func waitForProcessExit(pid uint32, timeout time.Duration) error {
	if pid == 0 {
		return nil
	}
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, pid)
	if err != nil {
		if err == windows.ERROR_INVALID_PARAMETER {
			return nil
		}
		return fmt.Errorf("open handoff parent process %d: %w", pid, err)
	}
	defer windows.CloseHandle(handle)
	result, err := windows.WaitForSingleObject(handle, uint32(timeout/time.Millisecond))
	if err != nil {
		return fmt.Errorf("wait for handoff parent process %d: %w", pid, err)
	}
	if result == uint32(windows.WAIT_TIMEOUT) {
		return fmt.Errorf("timed out waiting for handoff parent process %d to exit", pid)
	}
	return nil
}

const deferredCleanupWaitTimeout = 2 * time.Minute

func removeDirectoryAfterExit(path, journalPath string, parentPID int, transactionID string) error {
	powerShell, err := systemPowerShellPath()
	if err != nil {
		return err
	}
	cmd := directoryCleanupCommand(
		powerShell,
		path,
		journalPath,
		parentPID,
		transactionID,
		deferredCleanupWaitTimeout,
	)
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

func directoryCleanupCommand(
	powerShell, path, journalPath string,
	parentPID int,
	transactionID string,
	waitTimeout time.Duration,
) *exec.Cmd {
	const script = `
$target=$env:DEFENSECLAW_CLEANUP_TARGET
$journal=$env:DEFENSECLAW_CLEANUP_JOURNAL
$expectedID=$env:DEFENSECLAW_CLEANUP_TRANSACTION_ID
$parent=[int]$env:DEFENSECLAW_CLEANUP_PARENT_PID
$waitMilliseconds=[int]$env:DEFENSECLAW_CLEANUP_WAIT_MS

function Test-CleanupOwnership([object]$marker) {
    if ($null -eq $marker -or $null -eq $marker.transaction) { return $false }
    $maintenancePath=[string]$marker.transaction.maintenance_path
    if ([string]::IsNullOrWhiteSpace($maintenancePath)) { return $false }
    try {
        $markerTarget=[IO.Path]::GetFullPath([IO.Path]::GetDirectoryName($maintenancePath)).TrimEnd([char[]]@('\','/'))
        $expectedTarget=[IO.Path]::GetFullPath($target).TrimEnd([char[]]@('\','/'))
    } catch {
        return $false
    }
    return $marker.phase -ceq 'converged' -and
        $marker.transaction.action -ceq 'uninstall' -and
        $marker.transaction.id -ceq $expectedID -and
        [string]::Equals($markerTarget, $expectedTarget, [StringComparison]::OrdinalIgnoreCase)
}

$parentExited=$false
$parentProcess=$null
try {
    $parentProcess=[Diagnostics.Process]::GetProcessById($parent)
    $parentExited=$parentProcess.WaitForExit($waitMilliseconds)
} catch {
    $parentExited=$_.Exception -is [ArgumentException] -or
        $_.Exception.InnerException -is [ArgumentException]
} finally {
    if ($null -ne $parentProcess) { $parentProcess.Dispose() }
}
if (-not $parentExited) { exit 0 }

# Validate once immediately after the parent exits.
try {
    $marker=([IO.File]::ReadAllText($journal) | ConvertFrom-Json)
    if (-not (Test-CleanupOwnership $marker)) { exit 0 }
} catch {
    exit 0
}

# Re-read under a handle that denies write/delete sharing. Keeping that handle
# open through Remove-Item prevents a new setup transaction from replacing the
# ownership marker between the final identity check and deletion.
$markerLock=$null
$reader=$null
try {
    $markerLock=[IO.File]::Open(
        $journal,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    $reader=[IO.StreamReader]::new($markerLock, [Text.Encoding]::UTF8, $true, 4096, $true)
    $marker=($reader.ReadToEnd() | ConvertFrom-Json)
    if (-not (Test-CleanupOwnership $marker)) { exit 0 }
    if (Test-Path -LiteralPath $target -PathType Container) {
        Remove-Item -LiteralPath $target -Recurse -Force -ErrorAction Stop
    }
} catch {
    exit 0
} finally {
    if ($null -ne $reader) { $reader.Dispose() }
    if ($null -ne $markerLock) { $markerLock.Dispose() }
}
`
	cmd := newCapturedSetupCommand(context.Background(), powerShell, "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", script)
	// The cached maintenance executable can be launched with its own directory
	// as CWD. Run the detached helper from the trusted system PowerShell
	// directory so Windows permits it to remove the cache after Setup exits.
	cmd.Dir = filepath.Dir(powerShell)
	// PowerShell treats tokens following -Command as more command text rather
	// than reliably exposing them through $args. Environment variables keep the
	// cleanup path byte-for-byte intact without shell interpolation.
	cmd.Env = append(os.Environ(),
		"DEFENSECLAW_CLEANUP_TARGET="+path,
		"DEFENSECLAW_CLEANUP_JOURNAL="+journalPath,
		"DEFENSECLAW_CLEANUP_TRANSACTION_ID="+transactionID,
		"DEFENSECLAW_CLEANUP_PARENT_PID="+strconv.Itoa(parentPID),
		"DEFENSECLAW_CLEANUP_WAIT_MS="+strconv.FormatInt(waitTimeout.Milliseconds(), 10),
	)
	return cmd
}

func processIdentity(pid uint32) (string, string, error) {
	handle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE,
		false,
		pid,
	)
	if err != nil {
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
			return "", "", os.ErrProcessDone
		}
		return "", "", err
	}
	defer windows.CloseHandle(handle)
	return processIdentityFromHandle(handle)
}

func processIdentityFromHandle(handle windows.Handle) (string, string, error) {
	waitResult, err := windows.WaitForSingleObject(handle, 0)
	if err != nil {
		return "", "", err
	}
	if waitResult == uint32(windows.WAIT_OBJECT_0) {
		return "", "", os.ErrProcessDone
	}
	if waitResult != uint32(windows.WAIT_TIMEOUT) {
		return "", "", fmt.Errorf("unexpected process wait result %#x", waitResult)
	}

	// QueryFullProcessImageNameW accepts the full NT path limit. A fixed
	// MAX_PATH buffer breaks service ownership checks when the per-user install
	// root or profile is long even though Go itself is long-path aware.
	buffer := make([]uint16, 32768)
	size := uint32(len(buffer))
	if err := windows.QueryFullProcessImageName(handle, 0, &buffer[0], &size); err != nil {
		return "", "", err
	}
	if size == 0 || size > uint32(len(buffer)) {
		return "", "", errors.New("process image path exceeds the Windows long-path limit")
	}
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(handle, &creation, &exit, &kernel, &user); err != nil {
		return "", "", err
	}
	return windows.UTF16ToString(buffer[:size]), strconv.FormatInt(creation.Nanoseconds(), 10), nil
}

func liveProcessWithinInstallRoot(installRoot string, ignoredImages ...string) (uint32, string, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, "", fmt.Errorf("snapshot processes: %w", err)
	}
	defer windows.CloseHandle(snapshot)

	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	if err := windows.Process32First(snapshot, &entry); err != nil {
		if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
			return 0, "", nil
		}
		return 0, "", fmt.Errorf("read process snapshot: %w", err)
	}
	for {
		if entry.ProcessID != 0 {
			imagePath, _, queryErr := processIdentity(entry.ProcessID)
			// Processes may exit or deny inspection while the snapshot is being
			// walked. A query failure does not prove that the process executes from
			// this ACL-protected per-user install tree, so only an observed image
			// path can block activation.
			if queryErr == nil && pathWithinRoot(imagePath, installRoot) &&
				!pathMatchesAny(imagePath, ignoredImages) {
				return entry.ProcessID, imagePath, nil
			}
		}
		entry.Size = uint32(unsafe.Sizeof(windows.ProcessEntry32{}))
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
				return 0, "", nil
			}
			return 0, "", fmt.Errorf("advance process snapshot: %w", err)
		}
	}
}

func pathMatchesAny(path string, candidates []string) bool {
	for _, candidate := range candidates {
		if pathidentity.Same(path, candidate) {
			return true
		}
	}
	return false
}

func pathWithinRoot(path, root string) bool {
	for directory := filepath.Dir(filepath.Clean(path)); ; directory = filepath.Dir(directory) {
		if pathidentity.Same(directory, root) {
			return true
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return false
		}
	}
}

func rejectReparseAncestors(path string) error {
	full, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	volume := filepath.VolumeName(full)
	rest := strings.TrimPrefix(full, volume)
	rest = strings.Trim(rest, `\/`)
	cursor := volume + `\`
	if volume == "" {
		cursor = string(filepath.Separator)
	}
	for _, part := range strings.Split(rest, string(filepath.Separator)) {
		if part == "" {
			continue
		}
		cursor = filepath.Join(cursor, part)
		if reparse, err := isReparsePoint(cursor); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return err
		} else if reparse {
			return fmt.Errorf("managed path traverses a reparse point: %s", cursor)
		}
	}
	return nil
}

func rejectReparseExisting(path string) error {
	reparse, err := isReparsePoint(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if reparse {
		return fmt.Errorf("refusing to overwrite reparse point: %s", path)
	}
	return nil
}

func isReparsePoint(path string) (bool, error) {
	ptr, err := winpath.UTF16Ptr(path)
	if err != nil {
		return false, err
	}
	attrs, err := windows.GetFileAttributes(ptr)
	if err != nil {
		if err == windows.ERROR_FILE_NOT_FOUND || err == windows.ERROR_PATH_NOT_FOUND {
			return false, os.ErrNotExist
		}
		return false, err
	}
	return attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0, nil
}

const (
	userPathMutationMaxAttempts      = 8
	userPathTransactionTimeoutMillis = 5000
)

var (
	userPathKTM                    = windows.NewLazySystemDLL("KtmW32.dll")
	userPathRegistry               = windows.NewLazySystemDLL("advapi32.dll")
	procCreateUserPathTransaction  = userPathKTM.NewProc("CreateTransaction")
	procCommitUserPathTransaction  = userPathKTM.NewProc("CommitTransaction")
	procOpenUserPathKeyTransactedW = userPathRegistry.NewProc("RegOpenKeyTransactedW")
)

type userPathMutation struct {
	Next            userPathSnapshot
	Changed         bool
	ReusedSeparator bool
	ValueCreated    bool
}

type userPathCompareAndSwap func(
	func(userPathSnapshot) (userPathMutation, error),
) (userPathMutation, error)

func addUserPath(commandDir string) (bool, bool, bool, error) {
	mutation, err := mutateRegistryUserPath(
		registry.CURRENT_USER,
		`Environment`,
		addUserPathMutation(commandDir),
	)
	if err != nil {
		return mutation.Changed, mutation.ReusedSeparator, mutation.ValueCreated, err
	}
	updateCurrentProcessPath(commandDir, true)
	if err := broadcastEnvironmentChange(); err != nil {
		// A committed registry transaction is already owned even when another
		// desktop process does not acknowledge the environment broadcast.
		return mutation.Changed, mutation.ReusedSeparator, mutation.ValueCreated, err
	}
	return mutation.Changed, mutation.ReusedSeparator, mutation.ValueCreated, nil
}

func addUserPathMutation(commandDir string) func(userPathSnapshot) (userPathMutation, error) {
	return func(current userPathSnapshot) (userPathMutation, error) {
		if pathContains(strings.Split(current.Value, ";"), commandDir) {
			return userPathMutation{Next: current}, nil
		}
		next, reusedSeparator := prependUserPathEntry(current.Value, commandDir)
		valueCreated := !current.Existed
		current.Existed = true
		current.Value = next
		if current.ValueType == 0 {
			current.ValueType = registry.SZ
		}
		return userPathMutation{
			Next:            current,
			Changed:         true,
			ReusedSeparator: reusedSeparator,
			ValueCreated:    valueCreated,
		}, nil
	}
}

func captureUserPath() (userPathSnapshot, error) {
	snapshot := userPathSnapshot{}
	key, err := registry.OpenKey(registry.CURRENT_USER, `Environment`, registry.QUERY_VALUE)
	if err == registry.ErrNotExist {
		return snapshot, nil
	}
	if err != nil {
		return userPathSnapshot{}, err
	}
	defer key.Close()
	return readUserPathSnapshot(key)
}

func prependUserPathEntry(current, commandDir string) (string, bool) {
	// Put the managed launcher before legacy user-scoped DefenseClaw installs.
	// Reuse a leading separator instead of adding a second separator; removal
	// can then restore the operator's original PATH byte for byte.
	reusedSeparator := strings.HasPrefix(current, ";")
	separator := ";"
	if current == "" || reusedSeparator {
		separator = ""
	}
	return commandDir + separator + current, reusedSeparator
}

func removeUserPath(commandDir string, reusedSeparator, valueCreated bool) error {
	_, err := mutateRegistryUserPath(
		registry.CURRENT_USER,
		`Environment`,
		removeUserPathMutation(commandDir, reusedSeparator, valueCreated),
	)
	if err != nil {
		return err
	}
	updateCurrentProcessPath(commandDir, false)
	return broadcastEnvironmentChange()
}

func removeUserPathMutation(
	commandDir string,
	reusedSeparator, valueCreated bool,
) func(userPathSnapshot) (userPathMutation, error) {
	return func(current userPathSnapshot) (userPathMutation, error) {
		if !current.Existed {
			return userPathMutation{Next: current}, nil
		}
		next, deleteValue, err := planOwnedUserPathRemoval(
			current.Value,
			commandDir,
			reusedSeparator,
			valueCreated,
		)
		if err != nil {
			return userPathMutation{}, err
		}
		// A missing value was created as REG_SZ. If the user changed its type,
		// preserve the now-empty value rather than claiming ownership of it.
		if deleteValue && current.ValueType == registry.SZ {
			return userPathMutation{Changed: true}, nil
		}
		if next == current.Value {
			return userPathMutation{Next: current}, nil
		}
		current.Value = next
		return userPathMutation{Next: current, Changed: true}, nil
	}
}

func mutateRegistryUserPath(
	root registry.Key,
	keyPath string,
	transform func(userPathSnapshot) (userPathMutation, error),
) (userPathMutation, error) {
	if err := validateUserPathTransactionSupport(); err != nil {
		return userPathMutation{}, err
	}
	key, _, err := registry.CreateKey(root, keyPath, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return userPathMutation{}, err
	}
	if err := key.Close(); err != nil {
		return userPathMutation{}, err
	}

	mutation, err := mutateUserPath(
		func(transform func(userPathSnapshot) (userPathMutation, error)) (userPathMutation, error) {
			return compareAndSwapRegistryUserPath(root, keyPath, transform)
		},
		transform,
	)
	if err != nil {
		return mutation, err
	}
	key, err = registry.OpenKey(root, keyPath, registry.QUERY_VALUE)
	if err != nil {
		return mutation, err
	}
	defer key.Close()
	if err := flushRegistryKey(key); err != nil {
		return mutation, err
	}
	return mutation, nil
}

func validateUserPathTransactionSupport() error {
	for _, required := range []struct {
		name string
		proc *windows.LazyProc
	}{
		{"KtmW32.dll!CreateTransaction", procCreateUserPathTransaction},
		{"KtmW32.dll!CommitTransaction", procCommitUserPathTransaction},
		{"advapi32.dll!RegOpenKeyTransactedW", procOpenUserPathKeyTransactedW},
	} {
		if err := required.proc.Find(); err != nil {
			return fmt.Errorf("resolve required user PATH transaction procedure %s: %w", required.name, err)
		}
	}
	return nil
}

func mutateUserPath(
	compareAndSwap userPathCompareAndSwap,
	transform func(userPathSnapshot) (userPathMutation, error),
) (userPathMutation, error) {
	var conflictErr error
	for attempt := 0; attempt < userPathMutationMaxAttempts; attempt++ {
		mutation, err := compareAndSwap(transform)
		if err == nil {
			return mutation, nil
		}
		if !isUserPathTransactionConflict(err) {
			return mutation, err
		}
		conflictErr = err
	}
	return userPathMutation{}, fmt.Errorf(
		"user PATH changed concurrently during %d mutation attempts: %w",
		userPathMutationMaxAttempts,
		conflictErr,
	)
}

func compareAndSwapRegistryUserPath(
	root registry.Key,
	keyPath string,
	transform func(userPathSnapshot) (userPathMutation, error),
) (userPathMutation, error) {
	transaction, err := createUserPathTransaction()
	if err != nil {
		return userPathMutation{}, err
	}
	defer windows.CloseHandle(transaction)

	keyPathPtr, err := windows.UTF16PtrFromString(keyPath)
	if err != nil {
		return userPathMutation{}, err
	}
	var key registry.Key
	result, _, _ := procOpenUserPathKeyTransactedW.Call(
		uintptr(root),
		uintptr(unsafe.Pointer(keyPathPtr)),
		0,
		registry.QUERY_VALUE|registry.SET_VALUE,
		uintptr(unsafe.Pointer(&key)),
		uintptr(transaction),
		0,
	)
	if result != 0 {
		return userPathMutation{}, syscall.Errno(result)
	}
	defer key.Close()

	current, err := readUserPathSnapshot(key)
	if err != nil {
		return userPathMutation{}, err
	}
	mutation, err := transform(current)
	if err != nil {
		return userPathMutation{}, err
	}
	if mutation.Changed {
		if mutation.Next.Existed {
			err = setRegistryPath(key, mutation.Next.Value, mutation.Next.ValueType)
		} else {
			err = key.DeleteValue("Path")
		}
		if err != nil {
			return userPathMutation{}, err
		}
		// TxR detects a normal write after this transaction has staged its own
		// write. Validate the original snapshot after staging as well, covering
		// the complementary race where another process wrote between our read
		// and staged write. A later external write conflicts with the staged
		// transaction, so the validation and commit form a compare-and-swap.
		observed, err := readRegistryUserPathSnapshot(root, keyPath)
		if err != nil {
			return userPathMutation{}, err
		}
		if observed != current {
			return userPathMutation{}, windows.ERROR_TRANSACTIONAL_CONFLICT
		}
	}
	if err := commitUserPathTransaction(transaction); err != nil {
		return userPathMutation{}, err
	}
	return mutation, nil
}

func createUserPathTransaction() (windows.Handle, error) {
	result, _, callErr := procCreateUserPathTransaction.Call(
		0,
		0,
		0,
		0,
		0,
		userPathTransactionTimeoutMillis,
		0,
	)
	transaction := windows.Handle(result)
	if transaction != windows.InvalidHandle {
		return transaction, nil
	}
	if callErr != nil && callErr != windows.ERROR_SUCCESS {
		return 0, callErr
	}
	return 0, errors.New("create user PATH registry transaction failed")
}

func commitUserPathTransaction(transaction windows.Handle) error {
	result, _, callErr := procCommitUserPathTransaction.Call(uintptr(transaction))
	if result != 0 {
		return nil
	}
	if callErr != nil && callErr != windows.ERROR_SUCCESS {
		return callErr
	}
	return errors.New("commit user PATH registry transaction failed")
}

func isUserPathTransactionConflict(err error) bool {
	return errors.Is(err, windows.ERROR_TRANSACTIONAL_CONFLICT) ||
		errors.Is(err, windows.ERROR_TRANSACTION_NOT_ACTIVE) ||
		errors.Is(err, windows.ERROR_TRANSACTION_ALREADY_ABORTED) ||
		errors.Is(err, windows.ERROR_OPERATION_ABORTED)
}

func readUserPathSnapshot(key registry.Key) (userPathSnapshot, error) {
	value, valueType, err := key.GetStringValue("Path")
	if err == registry.ErrNotExist {
		return userPathSnapshot{}, nil
	}
	if err != nil {
		return userPathSnapshot{}, err
	}
	if valueType != registry.SZ && valueType != registry.EXPAND_SZ {
		return userPathSnapshot{}, fmt.Errorf("unsupported user PATH registry type %d", valueType)
	}
	return userPathSnapshot{Existed: true, Value: value, ValueType: valueType}, nil
}

func readRegistryUserPathSnapshot(root registry.Key, keyPath string) (userPathSnapshot, error) {
	key, err := registry.OpenKey(root, keyPath, registry.QUERY_VALUE)
	if err != nil {
		return userPathSnapshot{}, err
	}
	defer key.Close()
	return readUserPathSnapshot(key)
}

func planOwnedUserPathRemoval(current, commandDir string, reusedSeparator, valueCreated bool) (string, bool, error) {
	next, err := removeOwnedUserPathEntry(current, commandDir, reusedSeparator)
	if err != nil {
		return current, false, err
	}
	// A Setup-created value starts as the exact managed entry. Any syntactic
	// change is user/concurrent state, so retain an empty value instead of
	// claiming enough ownership to delete it.
	return next, valueCreated && next == "" && current == commandDir, nil
}

func removeUserPathEntry(current, commandDir string, reusedSeparator bool) string {
	next, err := removeOwnedUserPathEntry(current, commandDir, reusedSeparator)
	if err != nil {
		return current
	}
	return next
}

func removeOwnedUserPathEntry(current, commandDir string, reusedSeparator bool) (string, error) {
	entries := strings.Split(current, ";")
	// Seeing the managed path at both ownership endpoints is ambiguous: one may
	// be the installer entry and the other may be an operator-added duplicate.
	// Refuse instead of guessing which occurrence is safe to remove.
	if len(entries) > 1 && samePathEntry(entries[0], commandDir) && samePathEntry(entries[len(entries)-1], commandDir) {
		return current, errors.New("managed PATH entry was reordered or is no longer uniquely owned; refusing removal")
	}
	if len(entries) > 0 && samePathEntry(entries[0], commandDir) {
		next := append([]string(nil), entries[1:]...)
		if reusedSeparator {
			next = append([]string{""}, next...)
		}
		return strings.Join(next, ";"), nil
	}
	// Backwards compatibility for the old append strategy: a reused trailing
	// separator proves the owned occurrence was the final entry. Preserve all
	// other equal entries that the user may have added.
	if reusedSeparator && len(entries) > 0 && samePathEntry(entries[len(entries)-1], commandDir) {
		next := append([]string(nil), entries[:len(entries)-1]...)
		next = append(next, "")
		return strings.Join(next, ";"), nil
	}
	// A committed uninstall can be retried after the registry mutation was
	// flushed but a later environment broadcast or Apps & Features operation
	// failed. Absence is therefore an idempotent success. An occurrence that is
	// still present away from its proven ownership endpoint remains a user or
	// concurrent reorder and must continue to fail closed.
	for _, entry := range entries {
		if samePathEntry(entry, commandDir) {
			return current, errors.New("managed PATH entry was reordered or is no longer uniquely owned; refusing removal")
		}
	}
	return current, nil
}

func setRegistryPath(key registry.Key, value string, valueType uint32) error {
	if valueType == registry.EXPAND_SZ {
		return key.SetExpandStringValue("Path", value)
	}
	return key.SetStringValue("Path", value)
}

func updateCurrentProcessPath(commandDir string, add bool) {
	entries := splitPathList(os.Getenv("PATH"))
	next := make([]string, 0, len(entries)+1)
	if add {
		next = append(next, commandDir)
	}
	for _, entry := range entries {
		if !samePathEntry(entry, commandDir) {
			next = append(next, entry)
		}
	}
	_ = os.Setenv("PATH", strings.Join(next, ";"))
}

func broadcastEnvironmentChange() error {
	user32 := windows.NewLazySystemDLL("user32.dll")
	proc := user32.NewProc("SendMessageTimeoutW")
	name, err := windows.UTF16PtrFromString("Environment")
	if err != nil {
		return err
	}
	const (
		hwndBroadcast   = 0xffff
		wmSettingChange = 0x001a
		smtoAbortIfHung = 0x0002
	)
	var result uintptr
	ok, _, callErr := proc.Call(hwndBroadcast, wmSettingChange, 0, uintptr(unsafe.Pointer(name)), smtoAbortIfHung, 5000, uintptr(unsafe.Pointer(&result)))
	if ok == 0 {
		if callErr != nil && callErr != windows.ERROR_SUCCESS {
			return fmt.Errorf("broadcast user environment change: %w", callErr)
		}
		return errors.New("broadcast user environment change timed out")
	}
	return nil
}

func splitPathList(value string) []string {
	raw := strings.Split(value, ";")
	entries := make([]string, 0, len(raw))
	for _, entry := range raw {
		entry = strings.TrimSpace(entry)
		if entry != "" {
			entries = append(entries, entry)
		}
	}
	return entries
}

func pathContains(entries []string, needle string) bool {
	for _, entry := range entries {
		if samePathEntry(entry, needle) {
			return true
		}
	}
	return false
}

func samePathEntry(a, b string) bool {
	prepare := func(value string) string {
		expanded := strings.Trim(value, ` "`)
		if value, err := registry.ExpandString(expanded); err == nil {
			expanded = value
		}
		return expanded
	}
	return pathidentity.Same(prepare(a), prepare(b))
}

const (
	uninstallRegistryPath   = `Software\Microsoft\Windows\CurrentVersion\Uninstall`
	installedAppRegistryKey = "DefenseClaw"
	installedAppOwnerValue  = "DefenseClawTransactionID"
)

var ntDeleteRegistryKey = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtDeleteKey")

func registerInstalledAppAt(
	registryPath, registryKey, maintenancePath, installRoot, version, transactionID string,
	unsigned bool,
	previousState *installState,
) error {
	return registerInstalledAppAtWithHooks(
		registryPath,
		registryKey,
		maintenancePath,
		installRoot,
		version,
		transactionID,
		unsigned,
		previousState,
		nil,
		nil,
		nil,
	)
}

func registerInstalledAppAtWithHook(
	registryPath, registryKey, maintenancePath, installRoot, version, transactionID string,
	unsigned bool,
	previousState *installState,
	beforeMutation func(),
) error {
	return registerInstalledAppAtWithHooks(
		registryPath,
		registryKey,
		maintenancePath,
		installRoot,
		version,
		transactionID,
		unsigned,
		previousState,
		beforeMutation,
		nil,
		nil,
	)
}

func registerInstalledAppAtWithHooks(
	registryPath, registryKey, maintenancePath, installRoot, version, transactionID string,
	unsigned bool,
	previousState *installState,
	beforeExistingMutation func(),
	afterExistingMutation func(),
	beforeFreshPublication func(),
) error {
	if !validSetupTransactionID(transactionID) {
		return errors.New("refusing Apps & Features registration without a valid transaction identity")
	}
	values := newInstalledAppValues(
		maintenancePath,
		installRoot,
		version,
		transactionID,
		unsigned,
		estimateInstallKB(installRoot),
	)
	key, err := registry.OpenKey(
		registry.CURRENT_USER,
		registryPath+`\`+registryKey,
		registry.QUERY_VALUE|registry.SET_VALUE,
	)
	if err == nil {
		owned, ownershipErr := installedAppMutationOwnershipFromKey(
			key,
			installRoot,
			previousState,
			transactionID,
		)
		if ownershipErr != nil {
			return errors.Join(ownershipErr, key.Close())
		}
		if !owned {
			return errors.Join(
				errors.New("refusing to replace an unrelated Apps & Features registration named DefenseClaw"),
				key.Close(),
			)
		}
		if beforeExistingMutation != nil {
			beforeExistingMutation()
		}
		writeErr := writeInstalledAppValuesSnapshot(key, values)
		closeErr := key.Close()
		if writeErr != nil || closeErr != nil {
			return errors.Join(writeErr, closeErr)
		}
		if afterExistingMutation != nil {
			afterExistingMutation()
		}
		matches, verifyErr := installedAppValuesMatchAtSnapshot(
			registryPath,
			registryKey,
			values,
		)
		if verifyErr != nil {
			return verifyErr
		}
		if !matches {
			return errors.New("Apps & Features registration changed during handle-bound update")
		}
		return nil
	}
	if err != registry.ErrNotExist {
		return err
	}

	stagingName := registryKey + ".pending." + transactionID
	stagingPath := registryPath + `\` + stagingName
	// A retry owns this exact random staging name through the durable setup
	// journal, including the create-before-first-value crash boundary.
	if err := registry.DeleteKey(registry.CURRENT_USER, stagingPath); err != nil && err != registry.ErrNotExist {
		return err
	}
	key, _, err = registry.CreateKey(registry.CURRENT_USER, stagingPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	writeErr := writeInstalledAppValuesSnapshot(key, values)
	closeErr := key.Close()
	if writeErr != nil || closeErr != nil {
		_ = registry.DeleteKey(registry.CURRENT_USER, stagingPath)
		return errors.Join(writeErr, closeErr)
	}

	parent, err := registry.OpenKey(registry.CURRENT_USER, registryPath, registry.ALL_ACCESS)
	if err != nil {
		_ = registry.DeleteKey(registry.CURRENT_USER, stagingPath)
		return err
	}
	defer parent.Close()
	if exists, _, _, checkErr := installedAppRegistrationAt(registryPath, registryKey, installRoot); checkErr != nil {
		_ = registry.DeleteKey(registry.CURRENT_USER, stagingPath)
		return checkErr
	} else if exists {
		_ = registry.DeleteKey(registry.CURRENT_USER, stagingPath)
		return errors.New("Apps & Features registration appeared concurrently")
	}
	if beforeFreshPublication != nil {
		beforeFreshPublication()
	}
	if err := renameRegistrySubkey(parent, stagingName, registryKey); err != nil {
		// RegRenameKey may become visible before a later registry I/O error.
		// A complete transaction-owned destination can be re-flushed safely;
		// anything else remains pending without touching the concurrent key.
		matches, inspectErr := installedAppValuesMatchAtSnapshot(
			registryPath,
			registryKey,
			values,
		)
		if inspectErr != nil || !matches {
			// Retain the transaction-owned pending key as evidence. The next
			// recovery retry can validate/delete that exact journal-derived name;
			// a partial same-ID destination is never accepted as success.
			return errors.Join(err, inspectErr)
		}
	}
	if err := flushRegistryKey(parent); err != nil {
		return err
	}
	matches, err := installedAppValuesMatchAtSnapshot(
		registryPath,
		registryKey,
		values,
	)
	if err != nil {
		return err
	}
	if !matches {
		return errors.New("Apps & Features registration changed after publication")
	}
	return nil
}

type installedAppValues struct {
	strings  map[string]string
	integers map[string]uint64
}

func newInstalledAppValues(
	maintenancePath, installRoot, version, transactionID string,
	unsigned bool,
	estimatedSize uint32,
) installedAppValues {
	displayName := productName
	if unsigned {
		displayName += " (Unsigned Local Test Build)"
	}
	return installedAppValues{
		strings: map[string]string{
			installedAppOwnerValue: transactionID,
			"InstallLocation":      installRoot,
			"DisplayName":          displayName,
			"DisplayVersion":       version,
			"Publisher":            defaultPublisher,
			"DisplayIcon":          filepath.Join(installRoot, "bin", "defenseclaw.exe"),
			"UninstallString":      quote(maintenancePath) + " /uninstall",
			"QuietUninstallString": quote(maintenancePath) + " /uninstall /quiet",
			"ModifyPath":           quote(maintenancePath) + " /repair",
			"URLInfoAbout":         "https://github.com/cisco-ai-defense/defenseclaw",
		},
		integers: map[string]uint64{
			"NoModify":      0,
			"EstimatedSize": uint64(estimatedSize),
		},
	}
}

func writeInstalledAppValues(
	key registry.Key,
	maintenancePath, installRoot, version, transactionID string,
	unsigned bool,
) error {
	return writeInstalledAppValuesSnapshot(key, newInstalledAppValues(
		maintenancePath,
		installRoot,
		version,
		transactionID,
		unsigned,
		estimateInstallKB(installRoot),
	))
}

func writeInstalledAppValuesSnapshot(key registry.Key, values installedAppValues) error {
	// Publish the ownership pair first and flush it before decorative values.
	// Existing owned keys remain repairable after every subsequent boundary;
	// fresh keys are not made visible until the entire staged key is complete.
	for _, name := range []string{
		installedAppOwnerValue,
		"InstallLocation",
	} {
		if err := key.SetStringValue(name, values.strings[name]); err != nil {
			return err
		}
	}
	if err := flushRegistryKey(key); err != nil {
		return err
	}
	for _, name := range []string{
		"DisplayName",
		"DisplayVersion",
		"Publisher",
		"DisplayIcon",
		"UninstallString",
		"QuietUninstallString",
		"ModifyPath",
		"URLInfoAbout",
	} {
		if err := key.SetStringValue(name, values.strings[name]); err != nil {
			return err
		}
	}
	if err := key.SetDWordValue("NoModify", uint32(values.integers["NoModify"])); err != nil {
		return err
	}
	if err := key.SetDWordValue("EstimatedSize", uint32(values.integers["EstimatedSize"])); err != nil {
		return err
	}
	return flushRegistryKey(key)
}

func installedAppValuesMatchKey(
	key registry.Key,
	maintenancePath, installRoot, version, transactionID string,
	unsigned bool,
) (bool, error) {
	return installedAppValuesMatchKeySnapshot(key, newInstalledAppValues(
		maintenancePath,
		installRoot,
		version,
		transactionID,
		unsigned,
		estimateInstallKB(installRoot),
	))
}

func installedAppValuesMatchKeySnapshot(key registry.Key, values installedAppValues) (bool, error) {
	for name, want := range values.strings {
		got, valueType, err := key.GetStringValue(name)
		if err != nil {
			if err == registry.ErrNotExist {
				return false, nil
			}
			return false, err
		}
		if valueType != registry.SZ || got != want {
			return false, nil
		}
	}
	for name, want := range values.integers {
		got, valueType, err := key.GetIntegerValue(name)
		if err != nil {
			if err == registry.ErrNotExist {
				return false, nil
			}
			return false, err
		}
		if valueType != registry.DWORD || got != want {
			return false, nil
		}
	}
	return true, nil
}

func installedAppValuesMatchAt(
	registryPath, registryKey, maintenancePath, installRoot, version, transactionID string,
	unsigned bool,
) (bool, error) {
	return installedAppValuesMatchAtSnapshot(
		registryPath,
		registryKey,
		newInstalledAppValues(
			maintenancePath,
			installRoot,
			version,
			transactionID,
			unsigned,
			estimateInstallKB(installRoot),
		),
	)
}

func installedAppValuesMatchAtSnapshot(
	registryPath, registryKey string,
	values installedAppValues,
) (bool, error) {
	key, err := registry.OpenKey(
		registry.CURRENT_USER,
		registryPath+`\`+registryKey,
		registry.QUERY_VALUE,
	)
	if err == registry.ErrNotExist {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	matches, matchErr := installedAppValuesMatchKeySnapshot(key, values)
	return matches, errors.Join(matchErr, key.Close())
}

func installedAppRegistrationAt(
	registryPath, registryKey, installRoot string,
) (bool, bool, string, error) {
	key, err := registry.OpenKey(
		registry.CURRENT_USER,
		registryPath+`\`+registryKey,
		registry.QUERY_VALUE,
	)
	if err == registry.ErrNotExist {
		return false, false, "", nil
	}
	if err != nil {
		return false, false, "", err
	}
	defer key.Close()
	marked, ownerTransaction, err := installedAppRegistrationFromKey(key, installRoot)
	return true, marked, ownerTransaction, err
}

func installedAppRegistrationFromKey(
	key registry.Key,
	installRoot string,
) (bool, string, error) {
	ownerTransaction, _, ownerErr := key.GetStringValue(installedAppOwnerValue)
	if ownerErr != nil && ownerErr != registry.ErrNotExist {
		return false, "", ownerErr
	}
	location, _, err := key.GetStringValue("InstallLocation")
	if err == registry.ErrNotExist {
		return false, ownerTransaction, nil
	}
	if err != nil {
		return false, ownerTransaction, err
	}
	marked := validSetupTransactionID(ownerTransaction) && samePath(location, installRoot)
	return marked, ownerTransaction, nil
}

// legacyInstalledAppRegistrationMatchesKey permits one narrowly proven
// migration from the original native Setup, which predated the durable owner
// marker. A same-location key alone is never ownership: the validated legacy
// install state must have no transaction identity, and every identifying
// string written by that Setup must still match exactly.
func legacyInstalledAppRegistrationMatchesKey(
	key registry.Key,
	installRoot string,
	previousState *installState,
) (bool, error) {
	if previousState == nil || previousState.TransactionID != "" ||
		!samePath(previousState.InstallRoot, installRoot) {
		return false, nil
	}
	if _, _, ownerErr := key.GetStringValue(installedAppOwnerValue); ownerErr == nil {
		// Any marker, including an invalid one, takes this out of the legacy
		// migration path. Only installedAppRegistrationAt may recognize it.
		return false, nil
	} else if ownerErr != registry.ErrNotExist {
		return false, ownerErr
	}

	displayName := productName
	if previousState.UnsignedLocalArtifact {
		displayName += " (Unsigned Local Test Build)"
	}
	expected := map[string]string{
		"DisplayName":          displayName,
		"DisplayVersion":       previousState.Version,
		"Publisher":            defaultPublisher,
		"UninstallString":      quote(previousState.MaintenancePath) + " /uninstall",
		"QuietUninstallString": quote(previousState.MaintenancePath) + " /uninstall /quiet",
		"ModifyPath":           quote(previousState.MaintenancePath) + " /repair",
		"URLInfoAbout":         "https://github.com/cisco-ai-defense/defenseclaw",
	}
	for name, want := range expected {
		got, _, valueErr := key.GetStringValue(name)
		if valueErr != nil {
			if valueErr == registry.ErrNotExist {
				return false, nil
			}
			return false, valueErr
		}
		if got != want {
			return false, nil
		}
	}
	for name, want := range map[string]string{
		"InstallLocation": previousState.InstallRoot,
		"DisplayIcon":     filepath.Join(previousState.InstallRoot, "bin", "defenseclaw.exe"),
	} {
		got, _, valueErr := key.GetStringValue(name)
		if valueErr != nil {
			if valueErr == registry.ErrNotExist {
				return false, nil
			}
			return false, valueErr
		}
		if !samePath(got, want) {
			return false, nil
		}
	}
	return true, nil
}

func installedAppMutationOwnershipAt(
	registryPath, registryKey, installRoot string,
	previousState *installState,
	currentTransactionID string,
) (bool, bool, error) {
	key, err := registry.OpenKey(
		registry.CURRENT_USER,
		registryPath+`\`+registryKey,
		registry.QUERY_VALUE,
	)
	if err == registry.ErrNotExist {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	defer key.Close()
	owned, err := installedAppMutationOwnershipFromKey(
		key,
		installRoot,
		previousState,
		currentTransactionID,
	)
	return true, owned, err
}

func installedAppMutationOwnershipFromKey(
	key registry.Key,
	installRoot string,
	previousState *installState,
	currentTransactionID string,
) (bool, error) {
	marked, ownerTransaction, err := installedAppRegistrationFromKey(key, installRoot)
	if err != nil {
		return false, err
	}
	// A syntactically valid marker is not ownership by itself. Bind it to an
	// identity already protected by durable installer state: the previous
	// install state during upgrade/uninstall, or the current transaction during
	// an idempotent registration retry.
	previousOwned := marked && previousState != nil &&
		validSetupTransactionID(previousState.TransactionID) &&
		ownerTransaction == previousState.TransactionID
	currentOwned := marked && validSetupTransactionID(currentTransactionID) &&
		ownerTransaction == currentTransactionID
	if previousOwned || currentOwned {
		return true, nil
	}
	return legacyInstalledAppRegistrationMatchesKey(
		key,
		installRoot,
		previousState,
	)
}

func validateInstalledAppMutationAt(
	registryPath, registryKey, installRoot string,
	previousState *installState,
) error {
	exists, owned, err := installedAppMutationOwnershipAt(
		registryPath,
		registryKey,
		installRoot,
		previousState,
		"",
	)
	if err != nil {
		return err
	}
	if exists && !owned {
		return errors.New("refusing to replace an unrelated Apps & Features registration named DefenseClaw")
	}
	return nil
}

func validateInstalledAppMutation(installRoot string, previousState *installState) error {
	return validateInstalledAppMutationAt(
		uninstallRegistryPath,
		installedAppRegistryKey,
		installRoot,
		previousState,
	)
}

func registerInstalledAppOwned(
	maintenancePath, installRoot, version, transactionID string,
	unsigned bool,
	previousState *installState,
) error {
	return registerInstalledAppAt(
		uninstallRegistryPath,
		installedAppRegistryKey,
		maintenancePath,
		installRoot,
		version,
		transactionID,
		unsigned,
		previousState,
	)
}

func flushInstalledAppParent(registryPath string) error {
	parent, parentErr := registry.OpenKey(
		registry.CURRENT_USER,
		registryPath,
		registry.QUERY_VALUE,
	)
	if parentErr != nil && parentErr != registry.ErrNotExist {
		return parentErr
	}
	if parentErr == nil {
		defer parent.Close()
	}
	if parentErr == nil {
		return flushRegistryKey(parent)
	}
	return nil
}

func retireInstalledAppPendingOwned(installRoot, transactionID string) error {
	return retireInstalledAppPendingOwnedAt(
		uninstallRegistryPath,
		installedAppRegistryKey,
		installRoot,
		transactionID,
	)
}

func retireInstalledAppPendingOwnedAt(
	registryPath, registryKey, installRoot, transactionID string,
) error {
	return retireInstalledAppPendingOwnedAtWithHook(
		registryPath,
		registryKey,
		installRoot,
		transactionID,
		nil,
	)
}

func retireInstalledAppPendingOwnedAtWithHook(
	registryPath, registryKey, installRoot, transactionID string,
	beforeDelete func(),
) error {
	if !validSetupTransactionID(transactionID) {
		return errors.New("refusing to retire Apps & Features staging without a valid transaction identity")
	}
	stagingName := registryKey + ".pending." + transactionID
	stagingPath := registryPath + `\` + stagingName
	child, err := registry.OpenKey(
		registry.CURRENT_USER,
		stagingPath,
		registry.QUERY_VALUE|windows.DELETE,
	)
	if err == registry.ErrNotExist {
		// Absence may mean a prior retirement reached NtDeleteKey before a crash.
		// Flush the parent before the install journal loses the only durable proof
		// that authorizes deletion of this random staging name.
		flushErr := flushInstalledAppParent(registryPath)
		return errors.Join(flushErr, verifyInstalledAppPendingAbsent(stagingPath))
	}
	if err != nil {
		return err
	}

	owner, ownerType, ownerErr := child.GetStringValue(installedAppOwnerValue)
	if ownerErr != nil && ownerErr != registry.ErrNotExist {
		return errors.Join(ownerErr, child.Close())
	}
	if ownerErr == nil && (ownerType != registry.SZ || owner != transactionID) {
		return errors.Join(
			errors.New("refusing to retire Apps & Features staging owned by another transaction"),
			child.Close(),
		)
	}
	location, locationType, locationErr := child.GetStringValue("InstallLocation")
	if locationErr != nil && locationErr != registry.ErrNotExist {
		return errors.Join(locationErr, child.Close())
	}
	if locationErr == nil && (locationType != registry.SZ || !samePath(location, installRoot)) {
		return errors.Join(
			errors.New("refusing to retire Apps & Features staging for another install location"),
			child.Close(),
		)
	}

	parent, parentErr := registry.OpenKey(
		registry.CURRENT_USER,
		registryPath,
		registry.QUERY_VALUE,
	)
	if parentErr != nil {
		return errors.Join(parentErr, child.Close())
	}
	if beforeDelete != nil {
		beforeDelete()
	}
	deleteErr := deleteInstalledAppRegistryKeyHandle(child)
	childCloseErr := child.Close()
	flushErr := flushRegistryKey(parent)
	parentCloseErr := parent.Close()
	verifyErr := verifyInstalledAppPendingAbsent(stagingPath)
	return errors.Join(deleteErr, childCloseErr, flushErr, parentCloseErr, verifyErr)
}

func verifyInstalledAppPendingAbsent(stagingPath string) error {
	key, err := registry.OpenKey(registry.CURRENT_USER, stagingPath, registry.QUERY_VALUE)
	if err == registry.ErrNotExist {
		return nil
	}
	if err != nil {
		return err
	}
	return errors.Join(
		errors.New("Apps & Features staging changed during exact-handle retirement"),
		key.Close(),
	)
}

func unregisterInstalledAppOwnedAt(
	registryPath, registryKey, installRoot string,
	previousState *installState,
) error {
	return unregisterInstalledAppOwnedAtWithHook(
		registryPath,
		registryKey,
		installRoot,
		previousState,
		nil,
	)
}

func unregisterInstalledAppOwnedAtWithHook(
	registryPath, registryKey, installRoot string,
	previousState *installState,
	beforeDelete func(),
) error {
	child, err := registry.OpenKey(
		registry.CURRENT_USER,
		registryPath+`\`+registryKey,
		registry.QUERY_VALUE|windows.DELETE,
	)
	if err == registry.ErrNotExist {
		// Complete an interrupted delete by flushing the parent key even when
		// the child is already absent on this retry.
		return flushInstalledAppParent(registryPath)
	}
	if err != nil {
		return err
	}
	owned, ownershipErr := installedAppMutationOwnershipFromKey(
		child,
		installRoot,
		previousState,
		"",
	)
	if ownershipErr != nil {
		return errors.Join(ownershipErr, child.Close())
	}
	if !owned {
		return child.Close()
	}
	parent, parentErr := registry.OpenKey(
		registry.CURRENT_USER,
		registryPath,
		registry.QUERY_VALUE,
	)
	if parentErr != nil {
		return errors.Join(parentErr, child.Close())
	}
	if beforeDelete != nil {
		beforeDelete()
	}
	deleteErr := deleteInstalledAppRegistryKeyHandle(child)
	// NtDeleteKey deletes the exact validated key object even when a concurrent
	// process renames it and recreates the public DefenseClaw name. Close the
	// delete-pending handle before flushing the parent so that exact deletion is
	// durable; no path-based delete is permitted after validation.
	childCloseErr := child.Close()
	flushErr := flushRegistryKey(parent)
	parentCloseErr := parent.Close()
	return errors.Join(deleteErr, childCloseErr, flushErr, parentCloseErr)
}

func deleteInstalledAppRegistryKeyHandle(key registry.Key) error {
	statusValue, _, _ := ntDeleteRegistryKey.Call(uintptr(key))
	status := windows.NTStatus(uint32(statusValue))
	if status != 0 {
		return fmt.Errorf("delete exact Apps & Features registry key handle: %w", status)
	}
	return nil
}

func unregisterInstalledAppOwned(installRoot string, previousState *installState) error {
	return unregisterInstalledAppOwnedAt(
		uninstallRegistryPath,
		installedAppRegistryKey,
		installRoot,
		previousState,
	)
}

const gatewayAutoStartValueName = "DefenseClawGateway"

func gatewayAutoStartRegistryCommand(gatewayPath string) (string, error) {
	localAppData, err := winpath.CurrentUserKnownFolderPath(windows.FOLDERID_LocalAppData)
	if err != nil {
		return "", fmt.Errorf("resolve LocalAppData for gateway auto-start: %w", err)
	}
	profile, err := winpath.CurrentUserKnownFolderPath(windows.FOLDERID_Profile)
	if err != nil {
		return "", fmt.Errorf("resolve user profile for gateway auto-start: %w", err)
	}
	return gatewayAutoStartRegistryCommandForRoots(gatewayPath, localAppData, profile)
}

func gatewayAutoStartRegistryCommandForRoots(gatewayPath, localAppData, profile string) (string, error) {
	startupPath := filepath.Join(filepath.Dir(gatewayPath), "defenseclaw-startup.exe")
	command := quote(startupPath)
	for _, root := range []struct {
		path     string
		variable string
	}{
		{path: localAppData, variable: `%LOCALAPPDATA%`},
		{path: profile, variable: `%USERPROFILE%`},
	} {
		compact, ok := compactRunPath(startupPath, root.path, root.variable)
		if !ok {
			continue
		}
		candidate := quote(compact)
		if runCommandUTF16Units(candidate) < runCommandUTF16Units(command) {
			command = candidate
		}
	}
	if err := validateRunCommand(command); err != nil {
		return "", fmt.Errorf("configure %s startup registration: %w", gatewayAutoStartValueName, err)
	}
	return command, nil
}

func compactRunPath(target, root, variable string) (string, bool) {
	if strings.TrimSpace(root) == "" {
		return "", false
	}
	relative, err := filepath.Rel(filepath.Clean(root), filepath.Clean(target))
	if err != nil || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, `..\`) {
		return "", false
	}
	if relative == "." {
		return variable, true
	}
	return filepath.Join(variable, relative), true
}

func gatewayAutoStartValueOwned(gatewayPath, value string) (bool, error) {
	if value == gatewayAutoStartCommand(gatewayPath) || value == legacyGatewayAutoStartCommand(gatewayPath) {
		return true, nil
	}
	want, err := gatewayAutoStartRegistryCommand(gatewayPath)
	if err != nil {
		return false, err
	}
	return value == want, nil
}

func setGatewayAutoStartValue(key registry.Key, command string) error {
	if err := validateRunCommand(command); err != nil {
		return err
	}
	return key.SetExpandStringValue(gatewayAutoStartValueName, command)
}

func captureGatewayAutoStart() (gatewayAutoStartSnapshot, error) {
	key, err := registry.OpenKey(
		registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`,
		registry.QUERY_VALUE,
	)
	if err == registry.ErrNotExist {
		return gatewayAutoStartSnapshot{}, nil
	}
	if err != nil {
		return gatewayAutoStartSnapshot{}, err
	}
	defer key.Close()
	value, _, err := key.GetStringValue(gatewayAutoStartValueName)
	if err == registry.ErrNotExist {
		return gatewayAutoStartSnapshot{}, nil
	}
	if err != nil {
		return gatewayAutoStartSnapshot{}, err
	}
	return gatewayAutoStartSnapshot{Existed: true, Value: value}, nil
}

func gatewayAutoStartConfigured(gatewayPath string) (bool, error) {
	key, err := registry.OpenKey(
		registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`,
		registry.QUERY_VALUE,
	)
	if err == registry.ErrNotExist {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer key.Close()
	value, valueType, err := key.GetStringValue(gatewayAutoStartValueName)
	if err == registry.ErrNotExist {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if value == gatewayAutoStartCommand(gatewayPath) || value == legacyGatewayAutoStartCommand(gatewayPath) {
		return true, nil
	}
	want, err := gatewayAutoStartRegistryCommand(gatewayPath)
	if err != nil {
		return false, err
	}
	return value == want && valueType == registry.EXPAND_SZ, nil
}

func configureGatewayAutoStart(gatewayPath string, enabled bool) (gatewayAutoStartSnapshot, bool, error) {
	key, _, err := registry.CreateKey(
		registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`,
		registry.QUERY_VALUE|registry.SET_VALUE,
	)
	if err != nil {
		return gatewayAutoStartSnapshot{}, false, err
	}
	defer key.Close()

	previous, previousType, readErr := key.GetStringValue(gatewayAutoStartValueName)
	snapshot := gatewayAutoStartSnapshot{Existed: readErr == nil, Value: previous}
	if readErr != nil && readErr != registry.ErrNotExist {
		return gatewayAutoStartSnapshot{}, false, readErr
	}
	want := ""
	if enabled {
		want, err = gatewayAutoStartRegistryCommand(gatewayPath)
		if err != nil {
			return snapshot, false, err
		}
	}
	owned := false
	if snapshot.Existed {
		var ownedErr error
		owned, ownedErr = gatewayAutoStartValueOwned(gatewayPath, previous)
		if ownedErr != nil {
			return snapshot, false, ownedErr
		}
	}
	if snapshot.Existed && !owned {
		if enabled {
			return snapshot, false, fmt.Errorf("refusing to replace unrelated %s startup registration", gatewayAutoStartValueName)
		}
		// Uninstall only removes the exact value this installation owns.
		return snapshot, false, nil
	}
	if snapshot.Existed && previous == want && previousType == registry.EXPAND_SZ {
		if err := flushRegistryKey(key); err != nil {
			return snapshot, false, err
		}
		return snapshot, false, nil
	}
	if want == "" {
		if !snapshot.Existed {
			if err := flushRegistryKey(key); err != nil {
				return snapshot, false, err
			}
			return snapshot, false, nil
		}
		if err := key.DeleteValue(gatewayAutoStartValueName); err != nil && err != registry.ErrNotExist {
			return snapshot, false, err
		}
		if err := flushRegistryKey(key); err != nil {
			return snapshot, false, err
		}
		return snapshot, true, nil
	}
	if err := setGatewayAutoStartValue(key, want); err != nil {
		return snapshot, false, err
	}
	if err := flushRegistryKey(key); err != nil {
		return snapshot, false, err
	}
	return snapshot, true, nil
}

func estimateInstallKB(root string) uint32 {
	var total uint64
	_ = filepath.WalkDir(root, func(_ string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil
		}
		if info, statErr := entry.Info(); statErr == nil {
			total += uint64(info.Size())
		}
		return nil
	})
	return uint32((total + 1023) / 1024)
}

func quote(value string) string {
	return `"` + value + `"`
}

func flushRegistryKey(key registry.Key) error {
	proc := windows.NewLazySystemDLL("advapi32.dll").NewProc("RegFlushKey")
	result, _, callErr := proc.Call(uintptr(key))
	if result == 0 {
		return nil
	}
	if callErr != nil && callErr != windows.ERROR_SUCCESS {
		return callErr
	}
	return syscall.Errno(result)
}

func renameRegistrySubkey(parent registry.Key, oldName, newName string) error {
	oldPtr, err := windows.UTF16PtrFromString(oldName)
	if err != nil {
		return err
	}
	newPtr, err := windows.UTF16PtrFromString(newName)
	if err != nil {
		return err
	}
	proc := windows.NewLazySystemDLL("advapi32.dll").NewProc("RegRenameKey")
	result, _, _ := proc.Call(uintptr(parent), uintptr(unsafe.Pointer(oldPtr)), uintptr(unsafe.Pointer(newPtr)))
	if result != 0 {
		return syscall.Errno(result)
	}
	return nil
}
