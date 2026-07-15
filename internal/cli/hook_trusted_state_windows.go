// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/hookruntime"
	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

const (
	nativeHookLauncherName  = "defenseclaw-hook.exe"
	nativeHookGatewayName   = "defenseclaw-gateway.exe"
	powerShellHookStateName = "defenseclaw-hook-state.json"
	nativeHookStateMaxBytes = 64 << 10
)

// hookExecutableOverride is a test seam for an immutable packaged layout.
var (
	hookExecutableOverride           string
	nativeHookRuntimeReader          = hookruntime.ReadTrustedForExecutable
	enterpriseManagedRuntimeResolver = enterprisehooks.ResolveWindowsClaudeManagedHookRuntime
)

var nativeHookRuntimeSnapshot struct {
	sync.Mutex
	prepared   bool
	executable string
	state      hookruntime.State
	recognized bool
	err        error
}

var nativeEnterpriseHookRuntimeSnapshot struct {
	sync.Mutex
	prepared   bool
	executable string
	home       string
	registered bool
	err        error
}

func nativeHookExecutable() string {
	if hookExecutableOverride != "" {
		return hookExecutableOverride
	}
	executable, _ := os.Executable()
	return executable
}

// NativeHookRuntimeNoop reports whether this process is the canonical stable
// Windows launcher while its installer-owned state is disabled or unsafe. The
// launcher must exit before Cobra or hook fail-mode environment is evaluated,
// so a long-running agent can never turn an uninstalled cached command into a
// strict-availability block.
func NativeHookRuntimeNoop() bool {
	enterpriseManaged := hookArgsContainEnterpriseManaged(os.Args[1:])
	if enterpriseManaged {
		// The machine-managed policy is authoritative for this invocation. It
		// must be resolved before stale, inactive, or corrupt per-user launcher
		// state can turn an administrator-managed hook into a permissive no-op.
		return enterpriseManagedHookRuntimeNoop()
	}
	executable := nativeHookExecutable()
	state, recognized, err := nativeHookRuntimeReader(executable)
	nativeHookRuntimeSnapshot.Lock()
	nativeHookRuntimeSnapshot.prepared = true
	nativeHookRuntimeSnapshot.executable = executable
	nativeHookRuntimeSnapshot.state = state
	nativeHookRuntimeSnapshot.recognized = recognized
	nativeHookRuntimeSnapshot.err = err
	nativeHookRuntimeSnapshot.Unlock()
	if !recognized {
		return false
	}
	if err != nil {
		return true
	}
	if !state.Active() || !filepath.IsAbs(state.DataRoot) || !windowsHookPathHasNoReparsePoints(state.DataRoot) {
		return true
	}
	return false
}

func hookArgsContainEnterpriseManaged(args []string) bool {
	for _, arg := range args {
		if arg == "--enterprise-managed" || arg == "--enterprise-managed=true" {
			return true
		}
	}
	return false
}

func enterpriseManagedHookRuntimeNoop() bool {
	executable := nativeHookExecutable()
	nativeEnterpriseHookRuntimeSnapshot.Lock()
	if nativeEnterpriseHookRuntimeSnapshot.prepared && sameWindowsHookPath(nativeEnterpriseHookRuntimeSnapshot.executable, executable) {
		registered := nativeEnterpriseHookRuntimeSnapshot.registered
		err := nativeEnterpriseHookRuntimeSnapshot.err
		nativeEnterpriseHookRuntimeSnapshot.Unlock()
		return err == nil && !registered
	}
	nativeEnterpriseHookRuntimeSnapshot.Unlock()

	home, registered, err := enterpriseManagedRuntimeResolver(executable)
	if err == nil && registered && !filepath.IsAbs(strings.TrimSpace(home)) {
		err = errors.New("enterprise managed hook runtime home is not absolute")
	}
	nativeEnterpriseHookRuntimeSnapshot.Lock()
	nativeEnterpriseHookRuntimeSnapshot.prepared = true
	nativeEnterpriseHookRuntimeSnapshot.executable = executable
	nativeEnterpriseHookRuntimeSnapshot.home = home
	nativeEnterpriseHookRuntimeSnapshot.registered = registered
	nativeEnterpriseHookRuntimeSnapshot.err = err
	nativeEnterpriseHookRuntimeSnapshot.Unlock()
	return err == nil && !registered
}

func enterpriseManagedHookRuntimeForceClosed() bool {
	nativeEnterpriseHookRuntimeSnapshot.Lock()
	prepared := nativeEnterpriseHookRuntimeSnapshot.prepared
	err := nativeEnterpriseHookRuntimeSnapshot.err
	nativeEnterpriseHookRuntimeSnapshot.Unlock()
	return prepared && err != nil
}

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
	executable := nativeHookExecutable()
	if strings.TrimSpace(executable) == "" {
		return "", false
	}
	nativeEnterpriseHookRuntimeSnapshot.Lock()
	enterprisePrepared := nativeEnterpriseHookRuntimeSnapshot.prepared && sameWindowsHookPath(nativeEnterpriseHookRuntimeSnapshot.executable, executable)
	enterpriseHome := nativeEnterpriseHookRuntimeSnapshot.home
	nativeEnterpriseHookRuntimeSnapshot.Unlock()
	if enterprisePrepared {
		if !filepath.IsAbs(strings.TrimSpace(enterpriseHome)) {
			// filepath.Clean("") is ".". Preserve an empty/invalid managed home
			// as unavailable so the fail-closed path never reads project-relative
			// hook state.
			return "", true
		}
		return filepath.Clean(enterpriseHome), true
	}
	nativeHookRuntimeSnapshot.Lock()
	prepared := nativeHookRuntimeSnapshot.prepared && sameWindowsHookPath(nativeHookRuntimeSnapshot.executable, executable)
	preparedState := nativeHookRuntimeSnapshot.state
	preparedRecognized := nativeHookRuntimeSnapshot.recognized
	preparedErr := nativeHookRuntimeSnapshot.err
	nativeHookRuntimeSnapshot.Unlock()
	if prepared && preparedRecognized {
		if preparedErr == nil && preparedState.Active() && filepath.IsAbs(preparedState.DataRoot) &&
			windowsHookPathHasNoReparsePoints(preparedState.DataRoot) {
			return filepath.Clean(preparedState.DataRoot), true
		}
		// main exits before Cobra for every recognized non-active/unsafe state.
		// Returning a trusted empty value here keeps direct callers fail-closed
		// without performing a second state read across the uninstall boundary.
		return "", true
	}
	if state, recognized, stateErr := nativeHookRuntimeReader(executable); recognized {
		if stateErr == nil && state.Active() && filepath.IsAbs(state.DataRoot) &&
			windowsHookPathHasNoReparsePoints(state.DataRoot) {
			return filepath.Clean(state.DataRoot), true
		}
		// The canonical stable launcher never falls back to project environment,
		// even while publishing or after uninstall. main exits it as a no-op; the
		// fallback only keeps direct unit callers deterministic.
		if profile, err := winpath.CurrentUserKnownFolderPath(windows.FOLDERID_Profile); err == nil {
			return filepath.Join(profile, config.DefaultDataDirName), true
		}
		return "", true
	}
	base := filepath.Base(executable)
	if !strings.EqualFold(base, nativeHookLauncherName) && !strings.EqualFold(base, nativeHookGatewayName) {
		return "", false
	}
	// Once the canonical native launcher is identified, never fall back to
	// DEFENSECLAW_HOME. If its installer state is unavailable, the Windows
	// profile known-folder remains independent of project-supplied environment.
	fallbackHome := ""
	if profile, knownFolderErr := winpath.CurrentUserKnownFolderPath(windows.FOLDERID_Profile); knownFolderErr == nil {
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
	return pathidentity.Same(left, right)
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
