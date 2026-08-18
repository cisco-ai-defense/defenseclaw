// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestTerminalLaunchPlansAvailabilityMatrixAndExactArguments(t *testing.T) {
	installRoot := `C:\Users\Kévin O'Brien\Defense Claw`
	commandDir := filepath.Join(installRoot, "bin")
	launcher := filepath.Join(commandDir, "defenseclaw.exe")
	wt := `C:\Program Files\WindowsApps\Terminal Ω\wt.exe`
	pwsh := `C:\Program Files\PowerShell\7\pwsh.exe`
	systemPowerShell := `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
	powerShellArgs := []string{"-NoLogo", "-NoProfile", "-NoExit", "-Command", terminalPowerShellCommand}
	directFlags := uint32(windows.CREATE_NEW_CONSOLE | windows.CREATE_NEW_PROCESS_GROUP)

	type expectedPlan struct {
		name       string
		executable string
		args       []string
		flags      uint32
		legacy     bool
	}
	wtPlan := func(name, shell string) expectedPlan {
		args := []string{"-w", "-1", "new-tab", "-d", commandDir, shell}
		return expectedPlan{name: name, executable: wt, args: append(args, powerShellArgs...)}
	}
	directPlan := func(name, shell string, legacy bool) expectedPlan {
		return expectedPlan{name: name, executable: shell, args: powerShellArgs, flags: directFlags, legacy: legacy}
	}

	tests := []struct {
		name        string
		executables terminalExecutables
		want        []expectedPlan
	}{
		{
			name:        "terminal and both shells",
			executables: terminalExecutables{windowsTerminal: wt, powerShell7: pwsh, systemPowerShell: systemPowerShell},
			want: []expectedPlan{
				wtPlan("windows-terminal-powershell-7", pwsh),
				wtPlan("windows-terminal-system-powershell", systemPowerShell),
				directPlan("powershell-7", pwsh, false),
				directPlan("system-powershell-legacy", systemPowerShell, true),
			},
		},
		{
			name:        "terminal and system shell",
			executables: terminalExecutables{windowsTerminal: wt, systemPowerShell: systemPowerShell},
			want: []expectedPlan{
				wtPlan("windows-terminal-system-powershell", systemPowerShell),
				directPlan("system-powershell-legacy", systemPowerShell, true),
			},
		},
		{
			name:        "both shells without terminal",
			executables: terminalExecutables{powerShell7: pwsh, systemPowerShell: systemPowerShell},
			want: []expectedPlan{
				directPlan("powershell-7", pwsh, false),
				directPlan("system-powershell-legacy", systemPowerShell, true),
			},
		},
		{
			name:        "terminal and powershell 7",
			executables: terminalExecutables{windowsTerminal: wt, powerShell7: pwsh},
			want: []expectedPlan{
				wtPlan("windows-terminal-powershell-7", pwsh),
				directPlan("powershell-7", pwsh, false),
			},
		},
		{
			name:        "legacy system shell only",
			executables: terminalExecutables{systemPowerShell: systemPowerShell},
			want: []expectedPlan{
				directPlan("system-powershell-legacy", systemPowerShell, true),
			},
		},
		{
			name:        "powershell 7 only",
			executables: terminalExecutables{powerShell7: pwsh},
			want: []expectedPlan{
				directPlan("powershell-7", pwsh, false),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			plans, err := terminalLaunchPlans(tc.executables, installRoot, []string{"Path=C:\\Windows", "TERM=xterm-256color"})
			if err != nil {
				t.Fatal(err)
			}
			if len(plans) != len(tc.want) {
				t.Fatalf("plan count = %d, want %d: %#v", len(plans), len(tc.want), plans)
			}
			for index, want := range tc.want {
				got := plans[index]
				if got.name != want.name || got.executable != want.executable || got.directory != commandDir ||
					got.creationFlags != want.flags || got.legacy != want.legacy || !reflect.DeepEqual(got.args, want.args) {
					t.Fatalf("plan[%d] = %#v, want %#v with directory %q", index, got, want, commandDir)
				}
				if value, ok := testEnvironmentValue(got.environment, terminalLauncherEnvironment); !ok || value != launcher {
					t.Fatalf("plan[%d] launcher environment = %q, %v; want %q", index, value, ok, launcher)
				}
				term, _ := testEnvironmentValue(got.environment, "TERM")
				wantTerm := "xterm-256color"
				if want.legacy {
					wantTerm = "dumb"
				}
				if term != wantTerm {
					t.Fatalf("plan[%d] TERM = %q, want %q", index, term, wantTerm)
				}

				argv := append([]string{got.executable}, got.args...)
				roundTrip, err := windows.DecomposeCommandLine(windows.ComposeCommandLine(argv))
				if err != nil {
					t.Fatalf("decompose exact command line: %v", err)
				}
				if !reflect.DeepEqual(roundTrip, argv) {
					t.Fatalf("command-line round trip = %#v, want %#v", roundTrip, argv)
				}
			}
		})
	}
}

func TestTerminalLaunchPlansRequireTrustedShellAndAbsoluteContext(t *testing.T) {
	wt := `C:\Program Files\WindowsApps\Terminal\wt.exe`
	if _, err := terminalLaunchPlans(terminalExecutables{}, `C:\DefenseClaw`, nil); err == nil {
		t.Fatal("an empty executable matrix produced a plan")
	}
	if _, err := terminalLaunchPlans(terminalExecutables{windowsTerminal: wt}, `C:\DefenseClaw`, nil); err == nil {
		t.Fatal("Windows Terminal without an explicit trusted shell produced a plan")
	}
	if _, err := terminalLaunchPlans(terminalExecutables{systemPowerShell: `C:\Windows\powershell.exe`}, `relative\root`, nil); err == nil {
		t.Fatal("relative install root produced a terminal plan")
	}
}

func TestTerminalPowerShellCommandTransportsLauncherOnlyThroughEnvironment(t *testing.T) {
	installRoot := `C:\Users\O'Brien\应用 DefenseClaw`
	plans, err := terminalLaunchPlans(
		terminalExecutables{systemPowerShell: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`},
		installRoot,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	launcher := filepath.Join(installRoot, "bin", "defenseclaw.exe")
	if strings.Contains(terminalPowerShellCommand, launcher) || strings.Contains(terminalPowerShellCommand, "defenseclaw init") {
		t.Fatalf("static PowerShell source contains dynamic or initialization text: %q", terminalPowerShellCommand)
	}
	if value, ok := testEnvironmentValue(plans[0].environment, terminalLauncherEnvironment); !ok || value != launcher {
		t.Fatalf("launcher transport = %q, %v; want %q", value, ok, launcher)
	}
	if term, ok := testEnvironmentValue(plans[0].environment, "TERM"); !ok || term != "dumb" {
		t.Fatalf("legacy shell TERM = %q, %v; want dumb for the whole child shell", term, ok)
	}
}

func TestTerminalLaunchPlansClearInheritedLegacyTermFromModernCandidates(t *testing.T) {
	plans, err := terminalLaunchPlans(
		terminalExecutables{
			windowsTerminal:  `C:\Program Files\WindowsApps\Terminal\wt.exe`,
			powerShell7:      `C:\Program Files\PowerShell\7\pwsh.exe`,
			systemPowerShell: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		},
		`C:\DefenseClaw`,
		[]string{"Path=C:\\Windows", "TERM= dumb "},
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, plan := range plans {
		term, ok := testEnvironmentValue(plan.environment, "TERM")
		if plan.legacy {
			if !ok || term != "dumb" {
				t.Fatalf("legacy plan TERM = %q, %v; want dumb", term, ok)
			}
			continue
		}
		if ok {
			t.Fatalf("modern plan %q inherited legacy TERM=%q", plan.name, term)
		}
	}
}

func TestTerminalResolverPrefersProtectedMachineAppPaths(t *testing.T) {
	programFiles := t.TempDir()
	wt := writeTerminalTestExecutable(t, filepath.Join(programFiles, "WindowsApps", "Terminal", "wt.exe"))
	appPwsh := writeTerminalTestExecutable(t, filepath.Join(programFiles, "WindowsApps", "PowerShell", "pwsh.exe"))
	_ = writeTerminalTestExecutable(t, filepath.Join(programFiles, "PowerShell", "7", "pwsh.exe"))
	systemPowerShell := writeTerminalTestExecutable(t, filepath.Join(t.TempDir(), "powershell.exe"))
	resolver := terminalExecutableResolver{
		programFiles: func() (string, error) { return programFiles, nil },
		machineAppPath: func(name string) (string, error) {
			switch name {
			case "wt.exe":
				return wt, nil
			case "pwsh.exe":
				return appPwsh, nil
			default:
				return "", errors.New("not found")
			}
		},
		systemPowerShell:  func() (string, error) { return systemPowerShell, nil },
		validateProtected: validateProtectedTerminalExecutable,
		validateSystem:    validateTerminalExecutable,
	}
	got, err := resolver.resolve()
	if err != nil {
		t.Fatal(err)
	}
	want := terminalExecutables{windowsTerminal: wt, powerShell7: appPwsh, systemPowerShell: systemPowerShell}
	if got != want {
		t.Fatalf("resolved executables = %#v, want %#v", got, want)
	}
}

func TestTerminalResolverKeepsSystemFallbackWhenProgramFilesResolutionFails(t *testing.T) {
	systemPowerShell := `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
	resolver := terminalExecutableResolver{
		programFiles: func() (string, error) { return "", errors.New("known folder unavailable") },
		machineAppPath: func(string) (string, error) {
			t.Fatal("App Paths must not be consulted without a trusted Program Files root")
			return "", nil
		},
		systemPowerShell:  func() (string, error) { return systemPowerShell, nil },
		validateProtected: func(string, string, string) error { return nil },
		validateSystem:    func(string, string) error { return nil },
	}
	got, err := resolver.resolve()
	if err != nil {
		t.Fatal(err)
	}
	if got != (terminalExecutables{systemPowerShell: systemPowerShell}) {
		t.Fatalf("resolved executables = %#v, want only system fallback", got)
	}
}

func TestTerminalResolverIgnoresCurrentDirectoryAndPathExecutables(t *testing.T) {
	workspace := t.TempDir()
	for _, name := range []string{"wt.exe", "pwsh.exe", "powershell.exe"} {
		writeTerminalTestExecutable(t, filepath.Join(workspace, name))
	}
	t.Chdir(workspace)
	t.Setenv("PATH", workspace)
	programFiles := t.TempDir()
	systemPowerShell := writeTerminalTestExecutable(t, filepath.Join(t.TempDir(), "powershell.exe"))
	resolver := terminalExecutableResolver{
		programFiles: func() (string, error) { return programFiles, nil },
		machineAppPath: func(string) (string, error) {
			return "", errors.New("not registered")
		},
		systemPowerShell:  func() (string, error) { return systemPowerShell, nil },
		validateProtected: validateProtectedTerminalExecutable,
		validateSystem:    validateTerminalExecutable,
	}
	got, err := resolver.resolve()
	if err != nil {
		t.Fatal(err)
	}
	if got.windowsTerminal != "" || got.powerShell7 != "" || got.systemPowerShell != systemPowerShell {
		t.Fatalf("workspace/PATH executable influenced resolution: %#v", got)
	}
}

func TestProtectedTerminalValidationRejectsOutsideEmptyAndReparsePaths(t *testing.T) {
	programFiles := t.TempDir()
	outside := writeTerminalTestExecutable(t, filepath.Join(t.TempDir(), "wt.exe"))
	if err := validateProtectedTerminalExecutable(programFiles, outside, "wt.exe"); err == nil {
		t.Fatal("executable outside Program Files was trusted")
	}
	empty := filepath.Join(programFiles, "empty", "wt.exe")
	if err := os.MkdirAll(filepath.Dir(empty), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateProtectedTerminalExecutable(programFiles, empty, "wt.exe"); err == nil {
		t.Fatal("empty executable was trusted")
	}

	realDir := filepath.Join(programFiles, "real")
	writeTerminalTestExecutable(t, filepath.Join(realDir, "wt.exe"))
	linkedDir := filepath.Join(programFiles, "linked")
	if err := os.Symlink(realDir, linkedDir); err != nil {
		t.Skipf("creating a directory symlink requires Windows Developer Mode or elevation: %v", err)
	}
	if err := validateProtectedTerminalExecutable(programFiles, filepath.Join(linkedDir, "wt.exe"), "wt.exe"); err == nil {
		t.Fatal("executable beneath a reparse-point ancestor was trusted")
	}
}

func TestLaunchInstalledTerminalFallsThroughFailedStarts(t *testing.T) {
	executables := terminalExecutables{
		windowsTerminal:  `C:\Program Files\WindowsApps\Terminal\wt.exe`,
		powerShell7:      `C:\Program Files\PowerShell\7\pwsh.exe`,
		systemPowerShell: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
	}
	resolver := terminalResolverForTest(executables)
	var attempts []string
	err := launchInstalledTerminalWith(`C:\Users\Test User\DefenseClaw`, resolver, nil, func(plan terminalLaunchPlan) error {
		attempts = append(attempts, plan.name)
		if plan.name == "system-powershell-legacy" {
			return nil
		}
		return errors.New("start failed")
	})
	if err != nil {
		t.Fatalf("safe final fallback was reported as installer failure: %v", err)
	}
	want := []string{
		"windows-terminal-powershell-7",
		"windows-terminal-system-powershell",
		"powershell-7",
		"system-powershell-legacy",
	}
	if !reflect.DeepEqual(attempts, want) {
		t.Fatalf("launch attempts = %#v, want %#v", attempts, want)
	}
}

func TestLaunchInstalledTerminalReportsEveryFailedCandidate(t *testing.T) {
	executables := terminalExecutables{
		windowsTerminal:  `C:\Program Files\WindowsApps\Terminal\wt.exe`,
		powerShell7:      `C:\Program Files\PowerShell\7\pwsh.exe`,
		systemPowerShell: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
	}
	err := launchInstalledTerminalWith(`C:\DefenseClaw`, terminalResolverForTest(executables), nil, func(plan terminalLaunchPlan) error {
		return errors.New("broken " + plan.name)
	})
	if err == nil {
		t.Fatal("all failed candidates returned success")
	}
	for _, name := range []string{"windows-terminal-powershell-7", "windows-terminal-system-powershell", "powershell-7", "system-powershell-legacy"} {
		if !strings.Contains(err.Error(), name) {
			t.Fatalf("aggregate error %q does not identify %q", err, name)
		}
	}
}

func TestWizardOpenTerminalIsAsynchronousAndDeduplicated(t *testing.T) {
	previous := launchWizardTerminal
	started := make(chan string, 2)
	release := make(chan struct{})
	finished := make(chan struct{})
	launchWizardTerminal = func(root string) error {
		started <- root
		<-release
		close(finished)
		return nil
	}
	t.Cleanup(func() {
		select {
		case <-finished:
		default:
			close(release)
			<-finished
		}
		launchWizardTerminal = previous
	})

	installRoot := `C:\Users\Test User\DefenseClaw`
	wizard := setupWizard{done: true, opts: options{Action: "install"}, installRoot: installRoot}
	begin := time.Now()
	wizard.openTerminal()
	if elapsed := time.Since(begin); elapsed > 250*time.Millisecond {
		t.Fatalf("Open Terminal blocked the UI for %v", elapsed)
	}
	select {
	case got := <-started:
		if got != installRoot {
			t.Fatalf("launch install root = %q, want %q", got, installRoot)
		}
	case <-time.After(time.Second):
		t.Fatal("terminal launch worker did not start")
	}

	wizard.openTerminal()
	select {
	case duplicate := <-started:
		t.Fatalf("second click started duplicate launch for %q", duplicate)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	<-finished
}

func TestWizardOpenTerminalRejectsIncompleteAndUninstallPages(t *testing.T) {
	previous := launchWizardTerminal
	calls := 0
	launchWizardTerminal = func(string) error {
		calls++
		return nil
	}
	t.Cleanup(func() { launchWizardTerminal = previous })

	(&setupWizard{opts: options{Action: "install"}}).openTerminal()
	(&setupWizard{done: true, opts: options{Action: "uninstall"}}).openTerminal()
	if calls != 0 {
		t.Fatalf("terminal launches outside successful install completion = %d, want 0", calls)
	}
}

func TestWizardFinishAndCloseRemainBlockedDuringTerminalLaunch(t *testing.T) {
	wizard := setupWizard{done: true, terminalLaunching: true}
	if !wizard.terminalLaunchBlocksClose() {
		t.Fatal("terminal launch did not block completion-page close paths")
	}

	// The same predicate gates Finish, Escape/IDCANCEL, and WM_CLOSE. Calling
	// these commands with a zero HWND is safe only while the guard prevents the
	// underlying DestroyWindow call.
	wizard.handleCommand(idPrimary, 0)
	wizard.handleCommand(idCancel, 0)
	if !wizard.terminalLaunchBlocksClose() {
		t.Fatal("completion command changed terminal launch state before completion")
	}
}

func TestTerminalEnvironmentBlockSupportsUnicodeAndDoubleNULTermination(t *testing.T) {
	block, err := terminalEnvironmentBlock([]string{"Z=value", "α=应用", "a=first"})
	if err != nil {
		t.Fatal(err)
	}
	if len(block) < 2 || block[len(block)-1] != 0 || block[len(block)-2] != 0 {
		t.Fatalf("environment block is not double-NUL terminated: %#v", block)
	}
	empty, err := terminalEnvironmentBlock(nil)
	if err != nil || !reflect.DeepEqual(empty, []uint16{0, 0}) {
		t.Fatalf("empty environment block = %#v, %v", empty, err)
	}
	if _, err := terminalEnvironmentBlock([]string{"missing-separator"}); err == nil {
		t.Fatal("malformed environment entry was accepted")
	}
}

func terminalResolverForTest(executables terminalExecutables) terminalExecutableResolver {
	return terminalExecutableResolver{
		programFiles: func() (string, error) { return `C:\Program Files`, nil },
		machineAppPath: func(name string) (string, error) {
			switch name {
			case "wt.exe":
				return executables.windowsTerminal, nil
			case "pwsh.exe":
				return executables.powerShell7, nil
			default:
				return "", errors.New("not found")
			}
		},
		systemPowerShell:  func() (string, error) { return executables.systemPowerShell, nil },
		validateProtected: func(string, string, string) error { return nil },
		validateSystem:    func(string, string) error { return nil },
	}
}

func writeTerminalTestExecutable(t *testing.T, path string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("MZ test executable"), 0o600); err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(path)
}

func testEnvironmentValue(environment []string, name string) (string, bool) {
	for index := len(environment) - 1; index >= 0; index-- {
		entry := environment[index]
		equals := strings.IndexByte(entry, '=')
		if equals > 0 && strings.EqualFold(entry[:equals], name) {
			return entry[equals+1:], true
		}
	}
	return "", false
}
