//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"debug/pe"
	"encoding/binary"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

const (
	kiroShellChildEnv = "DEFENSECLAW_TEST_KIRO_SHELL_CHILD"
	kiroShellMarker   = "kiro-shell-boundary-marker"
)

// init makes this test binary stand in for the release hook launcher when
// the Kiro shell test runs it through a rendered command. It exits 2, Kiro's
// block, with a reason on stderr, only when the payload arrived on stdin and
// the arguments are the ones Setup renders; 3 and 4 name what went missing.
func init() {
	surface := os.Getenv(kiroShellChildEnv)
	if surface == "" {
		return
	}
	data, _ := io.ReadAll(os.Stdin)
	want := "hook --connector kiro"
	if surface == KiroHookSurfaceV3 {
		want += " --hook-surface " + KiroHookSurfaceV3
	}
	switch {
	case !strings.Contains(string(data), kiroShellMarker):
		os.Exit(4)
	case strings.Join(os.Args[1:], " ") != want:
		os.Exit(3)
	default:
		os.Stderr.WriteString("blocked: " + kiroShellMarker + "\n")
		os.Exit(2)
	}
}

// guiSubsystemCopyOfTestBinary copies this test binary with its PE subsystem
// set to Windows GUI, like the release launcher (-H=windowsgui).
func guiSubsystemCopyOfTestBinary(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	header := int(binary.LittleEndian.Uint32(data[0x3c:]))
	if string(data[header:header+4]) != "PE\x00\x00" {
		t.Fatalf("%s has no PE header", exe)
	}
	// PE signature, COFF file header, then Subsystem at offset 68 of the
	// optional header (PE32 and PE32+).
	binary.LittleEndian.PutUint16(data[header+4+20+68:], pe.IMAGE_SUBSYSTEM_WINDOWS_GUI)
	dst := filepath.Join(t.TempDir(), windowsHookBinaryName)
	if err := os.WriteFile(dst, data, 0o755); err != nil {
		t.Fatal(err)
	}
	file, err := pe.Open(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	optional, ok := file.OptionalHeader.(*pe.OptionalHeader64)
	if !ok || optional.Subsystem != pe.IMAGE_SUBSYSTEM_WINDOWS_GUI {
		t.Fatalf("copy is not a GUI-subsystem executable: %#v", file.OptionalHeader)
	}
	return dst
}

// Kiro honors only exit 2 as a block and proceeds on any other status. Run
// both rendered Kiro commands, against a GUI-subsystem launcher like the
// release build, every way Kiro can launch them: through `pwsh -Command` and
// `powershell -Command` (Kiro CLI 2.24 runs `"pwsh" -Command "<command>"`),
// through cmd.exe as Node's shell: true does (`cmd.exe /d /s /c
// "<command>"`) and as an argument vector (`cmd /C <command>`), and as a
// directly started command line. A block must come back as 2, with the
// payload delivered on stdin. A PowerShell host reports a native status
// other than 0 as 1 unless the command exits with it, and the earlier
// `& '<launcher>' ...` command exits 1 in cmd.exe ("& was unexpected at this
// time").
func TestKiroWindowsHookCommandsBlockThroughTheShell(t *testing.T) {
	gui := guiSubsystemCopyOfTestBinary(t)
	t.Cleanup(PinNativeHookExecutableForTest(gui))
	conn := NewKiroConnector()
	opts := SetupOpts{DataDir: t.TempDir()}
	cmdExe := filepath.Join(trustedWindowsSystemDirectory(), "cmd.exe")
	pwsh, pwshErr := exec.LookPath("pwsh")
	payload := `{"hook_event_name":"PreToolUse","tool_name":"shell","tool_input":{"command":"` + kiroShellMarker + `"}}`

	run := func(t *testing.T, surface string, command *exec.Cmd) int {
		t.Helper()
		command.Stdin = strings.NewReader(payload)
		command.Env = append(os.Environ(), kiroShellChildEnv+"="+surface)
		out, err := command.CombinedOutput()
		if command.ProcessState == nil {
			t.Fatalf("run %v: %v", command.Args, err)
		}
		if text := strings.TrimSpace(string(out)); text != "" {
			t.Logf("output: %s", text)
		}
		return command.ProcessState.ExitCode()
	}
	type launch struct {
		name    string
		command *exec.Cmd
	}
	for surface, rendered := range map[string]string{
		KiroHookSurfaceV3: conn.hookCommandForV3Surface(opts),
		"v2":              conn.hookCommand(opts),
	} {
		t.Run(surface, func(t *testing.T) {
			node := exec.Command(cmdExe)
			node.SysProcAttr = &syscall.SysProcAttr{CmdLine: `cmd.exe /d /s /c "` + rendered + `"`}
			direct := exec.Command(windowsSystemCmdExe())
			direct.SysProcAttr = &syscall.SysProcAttr{CmdLine: rendered}
			launches := []launch{
				{"cmd.exe /d /s /c", node},
				{"cmd /C", exec.Command(cmdExe, "/C", rendered)},
				{"direct start", direct},
				{"powershell -Command", exec.Command(windowsSystemPowerShellExe(), "-NoProfile", "-Command", rendered)},
			}
			if pwshErr == nil {
				launches = append(launches, launch{"pwsh -Command", exec.Command(pwsh, "-NoProfile", "-Command", rendered)})
			} else {
				t.Logf("pwsh not found, so pwsh -Command is not run: %v", pwshErr)
			}
			for _, l := range launches {
				if code := run(t, surface, l.command); code != 2 {
					t.Fatalf("%s: exit %d, want 2 (Kiro's block)", l.name, code)
				}
			}
		})
	}

	// The launcher above exits as soon as it has read its input. Start-Process
	// -Wait opened its handle to the launcher only after starting it, so a
	// launcher that had already exited came back as 1 ("the process has
	// exited") and Kiro went ahead. Run it many times, several at once, so a
	// busy host gives the fast exit its chance to win; every run must return
	// the block and its reason on stderr.
	t.Run("fast exit", func(t *testing.T) {
		rendered := conn.hookCommandForV3Surface(opts)
		const runs, parallel = 48, 8
		results := make(chan string, runs)
		slots := make(chan struct{}, parallel)
		for i := 0; i < runs; i++ {
			slots <- struct{}{}
			go func() {
				defer func() { <-slots }()
				command := exec.Command(cmdExe, "/C", rendered)
				command.Stdin = strings.NewReader(payload)
				command.Env = append(os.Environ(), kiroShellChildEnv+"="+KiroHookSurfaceV3)
				var stderr strings.Builder
				command.Stderr = &stderr
				_ = command.Run()
				switch {
				case command.ProcessState == nil:
					results <- "not started"
				case command.ProcessState.ExitCode() != 2:
					results <- "exit " + strconv.Itoa(command.ProcessState.ExitCode()) + ": " + strings.TrimSpace(stderr.String())
				case !strings.Contains(stderr.String(), kiroShellMarker):
					results <- "exit 2 without the reason on stderr: " + strings.TrimSpace(stderr.String())
				default:
					results <- ""
				}
			}()
		}
		var lost []string
		for i := 0; i < runs; i++ {
			if result := <-results; result != "" {
				lost = append(lost, result)
			}
		}
		if len(lost) > 0 {
			t.Fatalf("%d of %d runs did not return Kiro's block; first: %s", len(lost), runs, lost[0])
		}
	})

	// WDAC or AppLocker script enforcement runs the command in Constrained
	// Language mode, which refuses the .NET calls. Setting that mode before
	// Invoke-Expression evaluates the script the same way; the block must
	// still come back as 2.
	t.Run("constrained language", func(t *testing.T) {
		script := decodeKiroWindowsBridge(t, conn.hookCommandForV3Surface(opts))
		wrapper := "$ExecutionContext.SessionState.LanguageMode='ConstrainedLanguage'; Invoke-Expression " + powershellQuoteLiteral(script)
		command := exec.Command(windowsSystemPowerShellExe(), "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", powershellEncodedCommand(wrapper))
		if code := run(t, KiroHookSurfaceV3, command); code != 2 {
			t.Fatalf("Constrained Language mode: exit %d, want 2 (Kiro's block)", code)
		}
	})
}
