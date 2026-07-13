// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

const (
	nativeHookLauncherName  = "defenseclaw-hook.exe"
	nativeHookGatewayName   = "defenseclaw-gateway.exe"
	powerShellHookStateName = "defenseclaw-hook-state.json"
	nativeHookStateMaxBytes = 64 << 10
)

// hookExecutableOverride is a test seam for an immutable packaged layout.
var hookExecutableOverride string

type nativeHookInstallState struct {
	SchemaVersion int    `json:"schema_version"`
	InstallKind   string `json:"install_kind"`
	InstallScope  string `json:"install_scope"`
	InstallRoot   string `json:"install_root"`
	CommandDir    string `json:"command_dir"`
	DataRoot      string `json:"data_root"`
}

// trustedNativeHookHome resolves the installer-owned data root without using
// process environment inherited from an agent or project. It returns false for
// source builds and legacy layouts so their existing developer behavior is
// preserved.
func trustedNativeHookHome() (string, bool) {
	executable := hookExecutableOverride
	if executable == "" {
		var err error
		executable, err = os.Executable()
		if err != nil {
			return "", false
		}
	}
	base := filepath.Base(executable)
	if !strings.EqualFold(base, nativeHookLauncherName) && !strings.EqualFold(base, nativeHookGatewayName) {
		return "", false
	}
	// Once the canonical native launcher is identified, never fall back to
	// DEFENSECLAW_HOME. If its installer state is unavailable, the Windows
	// profile known-folder remains independent of project-supplied environment.
	fallbackHome := ""
	if profile, knownFolderErr := windows.KnownFolderPath(windows.FOLDERID_Profile, windows.KF_FLAG_DEFAULT); knownFolderErr == nil {
		fallbackHome = filepath.Join(profile, config.DefaultDataDirName)
	}

	executable, err := filepath.Abs(executable)
	if err != nil || !windowsHookPathHasNoReparsePoints(executable) {
		return fallbackHome, true
	}
	commandDir := filepath.Dir(executable)
	installRoot := filepath.Dir(commandDir)
	statePath := filepath.Join(installRoot, "installer", "install-state.json")
	state, ok := readNativeHookInstallState(statePath)
	if !ok {
		// The standalone PowerShell installer predates the native setup EXE and
		// publishes binaries directly under ~/.local/bin. Its adjacent protected
		// state binds a custom DEFENSECLAW_HOME without trusting project env.
		statePath = filepath.Join(commandDir, powerShellHookStateName)
		state, ok = readNativeHookInstallState(statePath)
	}
	if !ok {
		return fallbackHome, true
	}
	validNative := state.InstallKind == "native-windows-exe" && state.InstallScope == "user" &&
		sameWindowsHookPath(state.InstallRoot, installRoot)
	validPowerShell := state.InstallKind == "powershell-windows" && state.InstallScope == "user" &&
		sameWindowsHookPath(state.InstallRoot, commandDir)
	if (!validNative && !validPowerShell) || !sameWindowsHookPath(state.CommandDir, commandDir) ||
		!filepath.IsAbs(state.DataRoot) || !windowsHookPathHasNoReparsePoints(state.DataRoot) {
		return fallbackHome, true
	}
	return filepath.Clean(state.DataRoot), true
}

func readNativeHookInstallState(statePath string) (nativeHookInstallState, bool) {
	if !windowsHookPathHasNoReparsePoints(statePath) {
		return nativeHookInstallState{}, false
	}
	info, err := os.Lstat(statePath)
	if err != nil || !info.Mode().IsRegular() || info.Size() > nativeHookStateMaxBytes {
		return nativeHookInstallState{}, false
	}
	data, err := os.ReadFile(statePath)
	if err != nil {
		return nativeHookInstallState{}, false
	}
	var state nativeHookInstallState
	if json.Unmarshal(data, &state) != nil || state.SchemaVersion != 1 {
		return nativeHookInstallState{}, false
	}
	return state, true
}

func sameWindowsHookPath(left, right string) bool {
	leftAbs, leftErr := filepath.Abs(left)
	rightAbs, rightErr := filepath.Abs(right)
	return leftErr == nil && rightErr == nil && strings.EqualFold(filepath.Clean(leftAbs), filepath.Clean(rightAbs))
}

func windowsHookPathHasNoReparsePoints(path string) bool {
	cursor, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	for {
		ptr, err := winpath.UTF16Ptr(cursor)
		if err != nil {
			return false
		}
		attributes, err := windows.GetFileAttributes(ptr)
		if err != nil {
			if err != windows.ERROR_FILE_NOT_FOUND && err != windows.ERROR_PATH_NOT_FOUND {
				return false
			}
		} else if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return false
		}
		parent := filepath.Dir(cursor)
		if parent == cursor {
			return true
		}
		cursor = parent
	}
}
