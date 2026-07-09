// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

type pidState struct {
	PID           int    `json:"pid"`
	Executable    string `json:"executable"`
	StartIdentity string `json:"start_identity"`
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
	profile, err := windows.KnownFolderPath(windows.FOLDERID_Profile, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return "", err
	}
	return filepath.Join(profile, ".defenseclaw"), nil
}

func defaultOpenClawRoot() (string, error) {
	profile, err := windows.KnownFolderPath(windows.FOLDERID_Profile, windows.KF_FLAG_DEFAULT)
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
	script := "$target=$args[0]; $parent=[int]$args[1]; " +
		"try { Wait-Process -Id $parent -Timeout 120 -ErrorAction SilentlyContinue } catch {}; " +
		"if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Recurse -Force -ErrorAction SilentlyContinue }"
	cmd := exec.Command(powerShell, "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", script, path, strconv.Itoa(parentPID))
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
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

	buffer := make([]uint16, windows.MAX_PATH)
	size := uint32(len(buffer))
	if err := windows.QueryFullProcessImageName(handle, 0, &buffer[0], &size); err != nil {
		return "", "", err
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
	ptr, err := windows.UTF16PtrFromString(path)
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

func addUserPath(commandDir string) (bool, error) {
	key, _, err := registry.CreateKey(registry.CURRENT_USER, `Environment`, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return false, err
	}
	defer key.Close()
	current, valueType, err := key.GetStringValue("Path")
	if err != nil && err != registry.ErrNotExist {
		return false, err
	}
	entries := strings.Split(current, ";")
	if pathContains(entries, commandDir) {
		updateCurrentProcessPath(commandDir, true)
		return false, nil
	}
	separator := ";"
	if current == "" || strings.HasSuffix(current, ";") {
		separator = ""
	}
	if err := setRegistryPath(key, current+separator+commandDir, valueType); err != nil {
		return false, err
	}
	updateCurrentProcessPath(commandDir, true)
	broadcastEnvironmentChange()
	return true, nil
}

func removeUserPath(commandDir string) error {
	key, _, err := registry.CreateKey(registry.CURRENT_USER, `Environment`, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	current, valueType, err := key.GetStringValue("Path")
	if err != nil {
		if err == registry.ErrNotExist {
			return nil
		}
		return err
	}
	next := make([]string, 0)
	for _, entry := range strings.Split(current, ";") {
		if !samePathEntry(entry, commandDir) {
			next = append(next, entry)
		}
	}
	if err := setRegistryPath(key, strings.Join(next, ";"), valueType); err != nil {
		return err
	}
	updateCurrentProcessPath(commandDir, false)
	broadcastEnvironmentChange()
	return nil
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

func broadcastEnvironmentChange() {
	user32 := windows.NewLazySystemDLL("user32.dll")
	proc := user32.NewProc("SendMessageTimeoutW")
	name, err := windows.UTF16PtrFromString("Environment")
	if err != nil {
		return
	}
	const (
		hwndBroadcast   = 0xffff
		wmSettingChange = 0x001a
		smtoAbortIfHung = 0x0002
	)
	var result uintptr
	_, _, _ = proc.Call(hwndBroadcast, wmSettingChange, 0, uintptr(unsafe.Pointer(name)), smtoAbortIfHung, 5000, uintptr(unsafe.Pointer(&result)))
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

func registerInstalledApp(maintenancePath, installRoot, version string, unsigned bool) error {
	key, _, err := registry.CreateKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Uninstall\DefenseClaw`, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	displayName := productName
	if unsigned {
		displayName += " (Unsigned Local Test Build)"
	}
	values := map[string]string{
		"DisplayName":          displayName,
		"DisplayVersion":       version,
		"Publisher":            defaultPublisher,
		"InstallLocation":      installRoot,
		"DisplayIcon":          filepath.Join(installRoot, "bin", "defenseclaw.exe"),
		"UninstallString":      quote(maintenancePath) + " /uninstall",
		"QuietUninstallString": quote(maintenancePath) + " /uninstall /quiet",
		"ModifyPath":           quote(maintenancePath) + " /repair",
		"URLInfoAbout":         "https://github.com/cisco-ai-defense/defenseclaw",
	}
	for name, value := range values {
		if err := key.SetStringValue(name, value); err != nil {
			return err
		}
	}
	if err := key.SetDWordValue("NoModify", 0); err != nil {
		return err
	}
	return key.SetDWordValue("EstimatedSize", estimateInstallKB(installRoot))
}

func unregisterInstalledApp() error {
	err := registry.DeleteKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Uninstall\DefenseClaw`)
	if err == registry.ErrNotExist {
		return nil
	}
	return err
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
