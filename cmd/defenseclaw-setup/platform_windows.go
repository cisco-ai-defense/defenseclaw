// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
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
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func publishStableHookRuntime(source, dataRoot, transactionID string) error {
	return hookruntime.Publish(source, dataRoot, transactionID)
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
	pidPath := filepath.Join(dataRoot, pidFile)
	info, err := os.Lstat(pidPath)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("managed gateway PID path is not a regular file: %s", pidPath)
	}
	if reparse, err := isReparsePoint(pidPath); err != nil {
		return false, err
	} else if reparse {
		return false, fmt.Errorf("managed gateway PID path is a reparse point: %s", pidPath)
	}
	data, err := os.ReadFile(pidPath)
	if err != nil {
		return false, err
	}
	var state pidState
	if err := json.Unmarshal(data, &state); err != nil {
		return false, fmt.Errorf("invalid managed gateway PID file %s: %w", pidPath, err)
	}
	if state.PID <= 0 || strings.TrimSpace(state.Executable) == "" {
		return false, fmt.Errorf("managed gateway PID file lacks a complete process identity: %s", pidPath)
	}
	expected, err := filepath.Abs(gatewayPath)
	if err != nil {
		return false, err
	}
	recorded, err := filepath.Abs(state.Executable)
	if err != nil {
		return false, err
	}
	if !strings.EqualFold(recorded, expected) {
		return false, nil
	}
	livePath, identity, err := processIdentity(uint32(state.PID))
	if errors.Is(err, os.ErrProcessDone) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	live, err := filepath.Abs(livePath)
	if err != nil {
		return false, err
	}
	if !strings.EqualFold(live, expected) {
		return false, nil
	}
	if state.StartIdentity != "" && state.StartIdentity != identity {
		return false, nil
	}
	return true, nil
}

func defaultInstallRoot() (string, error) {
	local, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return "", err
	}
	return filepath.Join(local, "Programs", "DefenseClaw"), nil
}

func defaultDataRoot() (string, error) {
	profile, err := defaultProfileRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(profile, ".defenseclaw"), nil
}

func defaultProfileRoot() (string, error) {
	return windows.KnownFolderPath(windows.FOLDERID_Profile, windows.KF_FLAG_DEFAULT)
}

func defaultOpenClawRoot() (string, error) {
	profile, err := defaultProfileRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(profile, ".openclaw"), nil
}

func defaultMaintenancePath() (string, error) {
	local, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return "", err
	}
	return filepath.Join(local, "DefenseClaw", "InstallerCache", setupArtifactName), nil
}

func defaultTransactionRoot() (string, error) {
	local, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return "", err
	}
	return filepath.Join(local, "DefenseClaw", "InstallerState"), nil
}

func defaultPayloadTempRoot() (string, error) {
	local, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, windows.KF_FLAG_DEFAULT)
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
	from, err := winpath.UTF16Ptr(source)
	if err != nil {
		return err
	}
	to, err := winpath.UTF16Ptr(destination)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
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

func removeDirectoryAfterExit(path string, parentPID int) error {
	powerShell, err := systemPowerShellPath()
	if err != nil {
		return err
	}
	cmd := directoryCleanupCommand(powerShell, path, parentPID)
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

func directoryCleanupCommand(powerShell, path string, parentPID int) *exec.Cmd {
	const script = "$target=$env:DEFENSECLAW_CLEANUP_TARGET; $parent=[int]$env:DEFENSECLAW_CLEANUP_PARENT_PID; " +
		"try { Wait-Process -Id $parent -Timeout 120 -ErrorAction SilentlyContinue } catch {}; " +
		"if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Recurse -Force -ErrorAction SilentlyContinue }"
	cmd := newCapturedSetupCommand(context.Background(), powerShell, "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", script)
	// PowerShell treats tokens following -Command as more command text rather
	// than reliably exposing them through $args. Environment variables keep the
	// cleanup path byte-for-byte intact without shell interpolation.
	cmd.Env = append(os.Environ(),
		"DEFENSECLAW_CLEANUP_TARGET="+path,
		"DEFENSECLAW_CLEANUP_PARENT_PID="+strconv.Itoa(parentPID),
	)
	return cmd
}

func processIdentity(pid uint32) (string, string, error) {
	handle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_LIMITED_INFORMATION,
		false,
		pid,
	)
	if err != nil {
		return "", "", err
	}
	defer windows.CloseHandle(handle)

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

func addUserPath(commandDir string) (bool, bool, bool, error) {
	key, _, err := registry.CreateKey(registry.CURRENT_USER, `Environment`, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return false, false, false, err
	}
	defer key.Close()
	current, valueType, err := key.GetStringValue("Path")
	if err != nil && err != registry.ErrNotExist {
		return false, false, false, err
	}
	valueCreated := err == registry.ErrNotExist
	entries := strings.Split(current, ";")
	if pathContains(entries, commandDir) {
		// A previous attempt may have observed its SetValue before RegFlushKey
		// completed. Flush even on the idempotent retry path before convergence
		// is allowed to advance.
		if err := flushRegistryKey(key); err != nil {
			return false, false, false, err
		}
		updateCurrentProcessPath(commandDir, true)
		if err := broadcastEnvironmentChange(); err != nil {
			return false, false, false, err
		}
		return false, false, false, nil
	}
	next, reusedSeparator := prependUserPathEntry(current, commandDir)
	if err := setRegistryPath(key, next, valueType); err != nil {
		return false, false, false, err
	}
	if err := flushRegistryKey(key); err != nil {
		return false, false, false, err
	}
	updateCurrentProcessPath(commandDir, true)
	if err := broadcastEnvironmentChange(); err != nil {
		// The registry mutation is already flushed and therefore owned even if
		// another desktop process did not acknowledge the change broadcast.
		return true, reusedSeparator, valueCreated, err
	}
	return true, reusedSeparator, valueCreated, nil
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
	value, valueType, err := key.GetStringValue("Path")
	if err == registry.ErrNotExist {
		return snapshot, nil
	}
	if err != nil {
		return userPathSnapshot{}, err
	}
	if valueType != registry.SZ && valueType != registry.EXPAND_SZ {
		return userPathSnapshot{}, fmt.Errorf("unsupported user PATH registry type %d", valueType)
	}
	snapshot.Existed = true
	snapshot.Value = value
	snapshot.ValueType = valueType
	return snapshot, nil
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
	key, _, err := registry.CreateKey(registry.CURRENT_USER, `Environment`, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	if err := removeOwnedUserPathValue(key, commandDir, reusedSeparator, valueCreated); err != nil {
		return err
	}
	if err := flushRegistryKey(key); err != nil {
		return err
	}
	updateCurrentProcessPath(commandDir, false)
	return broadcastEnvironmentChange()
}

func removeOwnedUserPathValue(key registry.Key, commandDir string, reusedSeparator, valueCreated bool) error {
	current, valueType, err := key.GetStringValue("Path")
	if err == registry.ErrNotExist {
		return nil
	}
	if err != nil {
		return err
	}
	next, deleteValue, err := planOwnedUserPathRemoval(current, commandDir, reusedSeparator, valueCreated)
	if err != nil {
		return err
	}
	// Missing values are created as REG_SZ. A different current type is a user
	// mutation; preserve that value (empty) even when its content is otherwise
	// identical to the original managed entry.
	if deleteValue && valueType == registry.SZ {
		if err := key.DeleteValue("Path"); err != nil && err != registry.ErrNotExist {
			return err
		}
		return nil
	}
	return setRegistryPath(key, next, valueType)
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
	return current, errors.New("managed PATH entry was reordered or is no longer uniquely owned; refusing removal")
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
	clean := func(value string) string {
		expanded := strings.Trim(value, ` "`)
		if value, err := registry.ExpandString(expanded); err == nil {
			expanded = value
		}
		full, err := filepath.Abs(expanded)
		if err == nil {
			expanded = full
		}
		return strings.TrimRight(strings.ToLower(expanded), `\/`)
	}
	return clean(a) == clean(b)
}

const (
	uninstallRegistryPath   = `Software\Microsoft\Windows\CurrentVersion\Uninstall`
	installedAppRegistryKey = "DefenseClaw"
	installedAppOwnerValue  = "DefenseClawTransactionID"
)

func registerInstalledApp(maintenancePath, installRoot, version, transactionID string, unsigned bool) error {
	if !validSetupTransactionID(transactionID) {
		return errors.New("refusing Apps & Features registration without a valid transaction identity")
	}
	exists, owned, ownerTransaction, err := installedAppRegistration(installRoot)
	if err != nil {
		return err
	}
	if exists {
		if !owned && ownerTransaction != transactionID {
			return errors.New("refusing to replace an unrelated Apps & Features registration named DefenseClaw")
		}
		key, err := registry.OpenKey(
			registry.CURRENT_USER,
			uninstallRegistryPath+`\`+installedAppRegistryKey,
			registry.SET_VALUE,
		)
		if err != nil {
			return err
		}
		defer key.Close()
		return writeInstalledAppValues(key, maintenancePath, installRoot, version, transactionID, unsigned)
	}

	stagingName := installedAppRegistryKey + ".pending." + transactionID
	stagingPath := uninstallRegistryPath + `\` + stagingName
	// A retry owns this exact random staging name through the durable setup
	// journal, including the create-before-first-value crash boundary.
	if err := registry.DeleteKey(registry.CURRENT_USER, stagingPath); err != nil && err != registry.ErrNotExist {
		return err
	}
	key, _, err := registry.CreateKey(registry.CURRENT_USER, stagingPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	writeErr := writeInstalledAppValues(key, maintenancePath, installRoot, version, transactionID, unsigned)
	closeErr := key.Close()
	if writeErr != nil || closeErr != nil {
		_ = registry.DeleteKey(registry.CURRENT_USER, stagingPath)
		return errors.Join(writeErr, closeErr)
	}

	parent, err := registry.OpenKey(registry.CURRENT_USER, uninstallRegistryPath, registry.ALL_ACCESS)
	if err != nil {
		_ = registry.DeleteKey(registry.CURRENT_USER, stagingPath)
		return err
	}
	defer parent.Close()
	if exists, _, _, checkErr := installedAppRegistration(installRoot); checkErr != nil {
		_ = registry.DeleteKey(registry.CURRENT_USER, stagingPath)
		return checkErr
	} else if exists {
		_ = registry.DeleteKey(registry.CURRENT_USER, stagingPath)
		return errors.New("Apps & Features registration appeared concurrently")
	}
	if err := renameRegistrySubkey(parent, stagingName, installedAppRegistryKey); err != nil {
		// RegRenameKey may become visible before a later registry I/O error.
		// A complete transaction-owned destination can be re-flushed safely;
		// anything else remains pending without touching the concurrent key.
		_, finalOwned, finalTransaction, inspectErr := installedAppRegistration(installRoot)
		if inspectErr != nil || !finalOwned || finalTransaction != transactionID {
			_ = registry.DeleteKey(registry.CURRENT_USER, stagingPath)
			return errors.Join(err, inspectErr)
		}
	}
	return flushRegistryKey(parent)
}

func writeInstalledAppValues(
	key registry.Key,
	maintenancePath, installRoot, version, transactionID string,
	unsigned bool,
) error {
	displayName := productName
	if unsigned {
		displayName += " (Unsigned Local Test Build)"
	}
	// Publish the ownership pair first and flush it before decorative values.
	// Existing owned keys remain repairable after every subsequent boundary;
	// fresh keys are not made visible until the entire staged key is complete.
	for _, pair := range [][2]string{
		{installedAppOwnerValue, transactionID},
		{"InstallLocation", installRoot},
	} {
		if err := key.SetStringValue(pair[0], pair[1]); err != nil {
			return err
		}
	}
	if err := flushRegistryKey(key); err != nil {
		return err
	}
	for _, pair := range [][2]string{
		{"DisplayName", displayName},
		{"DisplayVersion", version},
		{"Publisher", defaultPublisher},
		{"DisplayIcon", filepath.Join(installRoot, "bin", "defenseclaw.exe")},
		{"UninstallString", quote(maintenancePath) + " /uninstall"},
		{"QuietUninstallString", quote(maintenancePath) + " /uninstall /quiet"},
		{"ModifyPath", quote(maintenancePath) + " /repair"},
		{"URLInfoAbout", "https://github.com/cisco-ai-defense/defenseclaw"},
	} {
		if err := key.SetStringValue(pair[0], pair[1]); err != nil {
			return err
		}
	}
	if err := key.SetDWordValue("NoModify", 0); err != nil {
		return err
	}
	if err := key.SetDWordValue("EstimatedSize", estimateInstallKB(installRoot)); err != nil {
		return err
	}
	return flushRegistryKey(key)
}

func installedAppRegistration(installRoot string) (bool, bool, string, error) {
	key, err := registry.OpenKey(
		registry.CURRENT_USER,
		uninstallRegistryPath+`\`+installedAppRegistryKey,
		registry.QUERY_VALUE,
	)
	if err == registry.ErrNotExist {
		return false, false, "", nil
	}
	if err != nil {
		return false, false, "", err
	}
	defer key.Close()
	ownerTransaction, _, ownerErr := key.GetStringValue(installedAppOwnerValue)
	if ownerErr != nil && ownerErr != registry.ErrNotExist {
		return true, false, "", ownerErr
	}
	location, _, err := key.GetStringValue("InstallLocation")
	if err == registry.ErrNotExist {
		return true, false, ownerTransaction, nil
	}
	if err != nil {
		return true, false, ownerTransaction, err
	}
	return true, samePath(location, installRoot), ownerTransaction, nil
}

func installedAppOwnership(installRoot string) (bool, bool, error) {
	exists, owned, _, err := installedAppRegistration(installRoot)
	return exists, owned, err
}

func validateInstalledAppMutation(installRoot string) error {
	exists, owned, err := installedAppOwnership(installRoot)
	if err != nil {
		return err
	}
	if exists && !owned {
		return errors.New("refusing to replace an unrelated Apps & Features registration named DefenseClaw")
	}
	return nil
}

func registerInstalledAppOwned(maintenancePath, installRoot, version, transactionID string, unsigned bool) error {
	return registerInstalledApp(maintenancePath, installRoot, version, transactionID, unsigned)
}

func unregisterInstalledApp() error {
	parent, parentErr := registry.OpenKey(
		registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Uninstall`,
		registry.QUERY_VALUE,
	)
	if parentErr != nil && parentErr != registry.ErrNotExist {
		return parentErr
	}
	if parentErr == nil {
		defer parent.Close()
	}
	err := registry.DeleteKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Uninstall\DefenseClaw`)
	if err == registry.ErrNotExist {
		if parentErr == nil {
			return flushRegistryKey(parent)
		}
		return nil
	}
	if err != nil {
		return err
	}
	if parentErr == nil {
		return flushRegistryKey(parent)
	}
	return nil
}

func unregisterInstalledAppOwned(installRoot string) error {
	exists, owned, err := installedAppOwnership(installRoot)
	if err != nil {
		return err
	}
	if !exists {
		// Complete an interrupted delete by flushing the parent key even when
		// the child is already absent on this retry.
		return unregisterInstalledApp()
	}
	if !owned {
		return nil
	}
	return unregisterInstalledApp()
}

const gatewayAutoStartValueName = "DefenseClawGateway"

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
	value, _, err := key.GetStringValue(gatewayAutoStartValueName)
	if err == registry.ErrNotExist {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return value == gatewayAutoStartCommand(gatewayPath) || value == legacyGatewayAutoStartCommand(gatewayPath), nil
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

	previous, _, readErr := key.GetStringValue(gatewayAutoStartValueName)
	snapshot := gatewayAutoStartSnapshot{Existed: readErr == nil, Value: previous}
	if readErr != nil && readErr != registry.ErrNotExist {
		return gatewayAutoStartSnapshot{}, false, readErr
	}
	want := ""
	if enabled {
		want = gatewayAutoStartCommand(gatewayPath)
	}
	owned := previous == gatewayAutoStartCommand(gatewayPath) || previous == legacyGatewayAutoStartCommand(gatewayPath)
	if snapshot.Existed && !owned {
		if enabled {
			return snapshot, false, fmt.Errorf("refusing to replace unrelated %s startup registration", gatewayAutoStartValueName)
		}
		// Uninstall only removes the exact value this installation owns.
		return snapshot, false, nil
	}
	if snapshot.Existed && previous == want {
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
	if err := key.SetStringValue(gatewayAutoStartValueName, want); err != nil {
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
