// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf16"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	terminalLauncherEnvironment = "DC_SETUP_TERMINAL_LAUNCHER"

	// The executable path is transported as an environment value, never
	// interpolated into PowerShell source. The private value is removed before
	// the installed launcher starts. On the final legacy fallback TERM=dumb stays
	// scoped to this new shell so subsequent non-TUI commands remain ASCII-safe.
	terminalPowerShellCommand = `$launcher=$env:DC_SETUP_TERMINAL_LAUNCHER;Remove-Item Env:DC_SETUP_TERMINAL_LAUNCHER -ErrorAction SilentlyContinue;& $launcher`
)

type terminalExecutables struct {
	windowsTerminal  string
	powerShell7      string
	systemPowerShell string
}

type terminalLaunchPlan struct {
	name          string
	executable    string
	args          []string
	directory     string
	environment   []string
	creationFlags uint32
	legacy        bool
}

type terminalExecutableResolver struct {
	programFiles      func() (string, error)
	machineAppPath    func(string) (string, error)
	systemPowerShell  func() (string, error)
	validateProtected func(string, string, string) error
	validateSystem    func(string, string) error
}

var defaultTerminalExecutableResolver = terminalExecutableResolver{
	programFiles:      terminalProgramFilesPath,
	machineAppPath:    terminalMachineAppPath,
	systemPowerShell:  systemPowerShellPath,
	validateProtected: validateProtectedTerminalExecutable,
	validateSystem:    validateTerminalExecutable,
}

var startWizardTerminalProcess = createTerminalProcess

func terminalProgramFilesPath() (string, error) {
	path, err := winpath.CurrentUserKnownFolderPathWithFlags(
		windows.FOLDERID_ProgramFiles,
		windows.KF_FLAG_DONT_VERIFY,
	)
	if err != nil {
		return "", fmt.Errorf("resolve Program Files Known Folder: %w", err)
	}
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "." || !filepath.IsAbs(path) {
		return "", errors.New("Program Files Known Folder is empty or not absolute")
	}
	return path, nil
}

func terminalMachineAppPath(name string) (string, error) {
	if filepath.Base(name) != name || !strings.EqualFold(filepath.Ext(name), ".exe") {
		return "", errors.New("invalid App Paths executable name")
	}
	key, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\`+name,
		registry.QUERY_VALUE|registry.WOW64_64KEY,
	)
	if err != nil {
		return "", err
	}
	defer key.Close()
	value, valueType, err := key.GetStringValue("")
	if err != nil {
		return "", err
	}
	// Expanding registry text would reintroduce ambient-variable path lookup.
	// Machine App Paths installed by MSI/MSIX use an absolute REG_SZ value.
	if valueType != registry.SZ {
		return "", fmt.Errorf("machine App Paths value for %s is not REG_SZ", name)
	}
	return strings.TrimSpace(value), nil
}

func (resolver terminalExecutableResolver) resolve() (terminalExecutables, error) {
	programFiles, err := resolver.programFiles()
	hasProgramFiles := err == nil

	resolveProtected := func(name string, fixedRelative ...string) string {
		if !hasProgramFiles {
			return ""
		}
		candidates := make([]string, 0, 1+len(fixedRelative))
		if candidate, appPathErr := resolver.machineAppPath(name); appPathErr == nil {
			candidates = append(candidates, candidate)
		}
		for _, relative := range fixedRelative {
			candidates = append(candidates, filepath.Join(programFiles, relative))
		}
		for _, candidate := range candidates {
			if resolver.validateProtected(programFiles, candidate, name) == nil {
				return filepath.Clean(candidate)
			}
		}
		return ""
	}

	executables := terminalExecutables{
		windowsTerminal: resolveProtected("wt.exe"),
		powerShell7:     resolveProtected("pwsh.exe", filepath.Join("PowerShell", "7", "pwsh.exe")),
	}
	systemPowerShell, systemErr := resolver.systemPowerShell()
	if systemErr == nil && resolver.validateSystem(systemPowerShell, "powershell.exe") == nil {
		executables.systemPowerShell = filepath.Clean(systemPowerShell)
	}
	return executables, nil
}

func validateProtectedTerminalExecutable(root, path, baseName string) error {
	root = filepath.Clean(strings.TrimSpace(root))
	path = filepath.Clean(strings.TrimSpace(path))
	if root == "." || path == "." || !filepath.IsAbs(root) || !filepath.IsAbs(path) {
		return errors.New("terminal executable trust root and path must be absolute")
	}
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == "." || relative == ".." ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return fmt.Errorf("terminal executable is outside Program Files: %s", path)
	}
	return validateTerminalExecutable(path, baseName)
}

func validateTerminalExecutable(path, baseName string) error {
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "." || !filepath.IsAbs(path) || strings.ContainsAny(path, "\x00\r\n") {
		return errors.New("terminal executable path is not a clean absolute path")
	}
	if !strings.EqualFold(filepath.Base(path), baseName) {
		return fmt.Errorf("terminal executable basename %q does not match %q", filepath.Base(path), baseName)
	}
	if err := rejectReparseAncestors(path); err != nil {
		return fmt.Errorf("terminal executable traverses a reparse point: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		return fmt.Errorf("terminal executable is not a non-empty regular file: %s", path)
	}
	return nil
}

func terminalLaunchPlans(executables terminalExecutables, installRoot string, baseEnvironment []string) ([]terminalLaunchPlan, error) {
	commandDir := filepath.Join(installRoot, "bin")
	launcher := filepath.Join(commandDir, "defenseclaw.exe")
	if !filepath.IsAbs(commandDir) || !filepath.IsAbs(launcher) || strings.ContainsAny(launcher, "\x00\r\n") {
		return nil, errors.New("installed terminal context is not an absolute Windows path")
	}

	powerShellArgs := []string{"-NoLogo", "-NoProfile", "-NoExit", "-Command", terminalPowerShellCommand}
	newPlan := func(name, executable string, args []string, legacy bool, flags uint32) terminalLaunchPlan {
		return terminalLaunchPlan{
			name:          name,
			executable:    executable,
			args:          append([]string(nil), args...),
			directory:     commandDir,
			environment:   terminalLaunchEnvironment(baseEnvironment, launcher, legacy),
			creationFlags: flags,
			legacy:        legacy,
		}
	}
	terminalPlan := func(name, shell string) terminalLaunchPlan {
		args := []string{"-w", "-1", "new-tab", "-d", commandDir, shell}
		args = append(args, powerShellArgs...)
		return newPlan(name, executables.windowsTerminal, args, false, 0)
	}
	directPlan := func(name, shell string, legacy bool) terminalLaunchPlan {
		return newPlan(
			name,
			shell,
			powerShellArgs,
			legacy,
			windows.CREATE_NEW_CONSOLE|windows.CREATE_NEW_PROCESS_GROUP,
		)
	}

	plans := make([]terminalLaunchPlan, 0, 4)
	if executables.windowsTerminal != "" {
		if executables.powerShell7 != "" {
			plans = append(plans, terminalPlan("windows-terminal-powershell-7", executables.powerShell7))
		}
		if executables.systemPowerShell != "" {
			plans = append(plans, terminalPlan("windows-terminal-system-powershell", executables.systemPowerShell))
		}
	}
	if executables.powerShell7 != "" {
		plans = append(plans, directPlan("powershell-7", executables.powerShell7, false))
	}
	if executables.systemPowerShell != "" {
		plans = append(plans, directPlan("system-powershell-legacy", executables.systemPowerShell, true))
	}
	if len(plans) == 0 {
		return nil, errors.New("no trusted Windows terminal or PowerShell executable is available")
	}
	return plans, nil
}

func terminalLaunchEnvironment(base []string, launcher string, legacy bool) []string {
	environment := append([]string(nil), base...)
	environment = terminalReplaceEnvironment(environment, terminalLauncherEnvironment, launcher)
	if legacy {
		environment = terminalReplaceEnvironment(environment, "TERM", "dumb")
	} else {
		environment = terminalRemoveEnvironmentValue(environment, "TERM", "dumb")
	}
	return environment
}

func terminalRemoveEnvironmentValue(environment []string, name, value string) []string {
	filtered := make([]string, 0, len(environment))
	for _, entry := range environment {
		equals := strings.IndexByte(entry, '=')
		if equals > 0 && strings.EqualFold(entry[:equals], name) &&
			strings.EqualFold(strings.TrimSpace(entry[equals+1:]), value) {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}

func terminalReplaceEnvironment(environment []string, name, value string) []string {
	filtered := make([]string, 0, len(environment)+1)
	for _, entry := range environment {
		equals := strings.IndexByte(entry, '=')
		if equals > 0 && strings.EqualFold(entry[:equals], name) {
			continue
		}
		filtered = append(filtered, entry)
	}
	return append(filtered, name+"="+value)
}

func terminalEnvironmentBlock(environment []string) ([]uint16, error) {
	environment = append([]string(nil), environment...)
	for _, entry := range environment {
		if strings.ContainsRune(entry, '\x00') || strings.IndexByte(entry, '=') < 0 {
			return nil, errors.New("invalid terminal process environment entry")
		}
	}
	sort.SliceStable(environment, func(left, right int) bool {
		return strings.ToUpper(environment[left]) < strings.ToUpper(environment[right])
	})
	block := make([]uint16, 0)
	if len(environment) == 0 {
		return []uint16{0, 0}, nil
	}
	for _, entry := range environment {
		for _, value := range entry {
			block = utf16.AppendRune(block, value)
		}
		block = append(block, 0)
	}
	return append(block, 0), nil
}

func launchInstalledTerminal(installRoot string) error {
	return launchInstalledTerminalWith(
		installRoot,
		defaultTerminalExecutableResolver,
		os.Environ(),
		startWizardTerminalProcess,
	)
}

func launchInstalledTerminalWith(
	installRoot string,
	resolver terminalExecutableResolver,
	baseEnvironment []string,
	start func(terminalLaunchPlan) error,
) error {
	executables, err := resolver.resolve()
	if err != nil {
		return err
	}
	plans, err := terminalLaunchPlans(executables, installRoot, baseEnvironment)
	if err != nil {
		return err
	}
	var startErrors []error
	for _, plan := range plans {
		if err := start(plan); err != nil {
			startErrors = append(startErrors, fmt.Errorf("%s: %w", plan.name, err))
			continue
		}
		return nil
	}
	return fmt.Errorf("all trusted terminal launch attempts failed: %w", errors.Join(startErrors...))
}

func createTerminalProcess(plan terminalLaunchPlan) error {
	if !filepath.IsAbs(plan.executable) || filepath.Clean(plan.executable) != plan.executable {
		return errors.New("terminal process executable is not a clean absolute path")
	}
	applicationName, err := winpath.UTF16Ptr(plan.executable)
	if err != nil {
		return fmt.Errorf("encode terminal executable path: %w", err)
	}
	commandLine, err := windows.UTF16FromString(
		windows.ComposeCommandLine(append([]string{plan.executable}, plan.args...)),
	)
	if err != nil {
		return fmt.Errorf("encode terminal command line: %w", err)
	}
	directory, err := winpath.UTF16Ptr(plan.directory)
	if err != nil {
		return fmt.Errorf("encode terminal working directory: %w", err)
	}
	environment, err := terminalEnvironmentBlock(plan.environment)
	if err != nil {
		return err
	}
	startup := windows.StartupInfo{
		Cb:         uint32(unsafe.Sizeof(windows.StartupInfo{})),
		Flags:      windows.STARTF_USESHOWWINDOW,
		ShowWindow: windows.SW_SHOWNORMAL,
	}
	var process windows.ProcessInformation
	err = windows.CreateProcess(
		applicationName,
		&commandLine[0],
		nil,
		nil,
		false,
		plan.creationFlags|windows.CREATE_UNICODE_ENVIRONMENT,
		&environment[0],
		directory,
		&startup,
		&process,
	)
	if err != nil {
		return err
	}
	// CreateProcess succeeded, so the terminal is already visible. Handle-close
	// failures must not be reported as start failures because the caller would
	// then open a duplicate terminal through the next fallback candidate.
	_ = windows.CloseHandle(process.Thread)
	_ = windows.CloseHandle(process.Process)
	return nil
}
