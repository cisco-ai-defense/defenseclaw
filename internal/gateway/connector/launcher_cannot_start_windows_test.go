//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"crypto/rand"
	"debug/pe"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/hookguard"
)

const (
	// launcherStartChildEnv makes this test binary the launcher
	// (defenseclaw-hook.exe) and the Codex and Devin guard (defenseclaw-hook-guard.exe)
	// of TestWindowsHookCommandsAnswerALauncherThatCannotStart.
	launcherStartChildEnv = "DEFENSECLAW_TEST_LAUNCHER_START_CHILD"
	// launcherStartExitEnv is the exit status the stand-in launcher returns.
	launcherStartExitEnv = "DEFENSECLAW_TEST_LAUNCHER_START_EXIT"
	// launcherStartBaseEnv also runs the forms releases before 1.0.9 wrote
	// and logs their rows (the native evidence cell); they are not asserted.
	launcherStartBaseEnv = "DEFENSECLAW_TEST_LAUNCHER_START_BASE"
	launcherStartRan     = `"launcher":"ran"`
)

func init() {
	if os.Getenv(launcherStartChildEnv) != "1" {
		return
	}
	self, err := os.Executable()
	if err != nil {
		os.Exit(96)
	}
	switch strings.ToLower(filepath.Base(self)) {
	case windowsHookGuardBinaryName:
		if hookArgs, event, contract, ok := hookguard.SiblingArgv(os.Args[1:]); ok {
			os.Exit(hookguard.RunCodex(hookguard.SiblingLauncher(self), hookArgs, event, contract, os.Stdin, os.Stdout, os.Stderr))
		}
		if hookArgs, event, ok := hookguard.DevinArgv(os.Args[1:]); ok {
			os.Exit(hookguard.RunDevin(hookguard.SiblingLauncher(self), hookArgs, event, os.Stdin, os.Stdout, os.Stderr))
		}
		os.Exit(97)
	case windowsHookBinaryName:
		_, _ = io.ReadAll(os.Stdin)
		fmt.Fprintf(os.Stdout, "{%s,\"args\":%q}\n", launcherStartRan, strings.Join(os.Args[1:], " "))
		code, _ := strconv.Atoi(os.Getenv(launcherStartExitEnv))
		os.Exit(code)
	}
}

// launcherShapes are the launcher damage shapes: nothing there, a folder, an
// empty file, the first 64 KiB of the image, random bytes, an image whose
// entry point is ud2 (it loads, then dies with STATUS_ILLEGAL_INSTRUCTION),
// and an image the account may not run.
var launcherShapes = []string{"working", "missing", "folder", "empty", "truncated", "random", "corrupt-code", "no-execute"}

// makeLauncherShape writes shape at dir\defenseclaw-hook.exe, with a working
// guard program beside it, from image (a GUI-subsystem copy of this binary).
func makeLauncherShape(t *testing.T, dir, shape string, image []byte) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, windowsHookGuardBinaryName), image, 0o700); err != nil {
		t.Fatal(err)
	}
	launcher := filepath.Join(dir, windowsHookBinaryName)
	write := func(data []byte) {
		if err := os.WriteFile(launcher, data, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	switch shape {
	case "working":
		write(image)
	case "missing":
	case "folder":
		if err := os.MkdirAll(launcher, 0o700); err != nil {
			t.Fatal(err)
		}
	case "empty":
		write(nil)
	case "truncated":
		write(image[:64*1024])
	case "random":
		data := make([]byte, 4096)
		if _, err := rand.Read(data); err != nil {
			t.Fatal(err)
		}
		write(data)
	case "corrupt-code":
		write(entryPointUD2(t, image))
	case "no-execute":
		write(image)
		sid := currentUserSIDForTest(t)
		if out, err := exec.Command("icacls", launcher, "/deny", "*"+sid+":(X)").CombinedOutput(); err != nil {
			t.Fatalf("icacls /deny: %v: %s", err, out)
		}
		t.Cleanup(func() { _ = exec.Command("icacls", launcher, "/remove:d", "*"+sid).Run() })
	default:
		t.Fatalf("unknown shape %q", shape)
	}
	return launcher
}

// entryPointUD2 returns image with ud2 instructions at its entry point.
func entryPointUD2(t *testing.T, image []byte) []byte {
	t.Helper()
	file, err := pe.NewFile(bytes.NewReader(image))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	optional, ok := file.OptionalHeader.(*pe.OptionalHeader64)
	if !ok {
		t.Fatal("not a PE32+ image")
	}
	data := append([]byte(nil), image...)
	for _, section := range file.Sections {
		entry := optional.AddressOfEntryPoint
		if entry >= section.VirtualAddress && entry < section.VirtualAddress+section.VirtualSize {
			offset := int(entry - section.VirtualAddress + section.Offset)
			for i := 0; i < 64; i += 2 {
				data[offset+i], data[offset+i+1] = 0x0f, 0x0b
			}
			return data
		}
	}
	t.Fatal("entry point is in no section")
	return nil
}

func currentUserSIDForTest(t *testing.T) string {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return user.User.Sid.String()
}

type launcherStartRun struct {
	exit           int
	stdout, stderr string
	hung           bool
	elapsed        time.Duration
}

func runLauncherStartCommand(t *testing.T, start func(context.Context) *exec.Cmd, payload string, timeout time.Duration) launcherStartRun {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := start(ctx)
	cmd.WaitDelay = 3 * time.Second
	cmd.Stdin = strings.NewReader(payload)
	cmd.Env = append(os.Environ(), launcherStartChildEnv+"=1")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	began := time.Now()
	err := cmd.Run()
	result := launcherStartRun{stdout: stdout.String(), stderr: stderr.String(), elapsed: time.Since(began)}
	var exitErr *exec.ExitError
	switch {
	case ctx.Err() != nil:
		result.hung = true
	case err == nil:
	case errors.As(err, &exitErr):
		result.exit = exitErr.ExitCode()
	default:
		t.Fatalf("start %v: %v", cmd.Args, err)
	}
	return result
}

func (r launcherStartRun) row(form, shape, invocation string) string {
	clean := func(s string) string {
		s = strings.Join(strings.Fields(strings.ReplaceAll(s, "|", "/")), " ")
		if len(s) > 150 {
			s = s[:150] + "..."
		}
		return s
	}
	exit := strconv.Itoa(r.exit)
	if r.hung {
		exit = "HUNG"
	}
	return fmt.Sprintf("ROW| %s | %s | %s | %s | %s | %s | %d |", form, shape, invocation, exit, clean(r.stdout), clean(r.stderr), r.elapsed.Milliseconds())
}

// warmLauncherStartRunner pays, before the timed rows, the one-time costs of
// a fresh hosted runner that the first row would pay otherwise: the first
// start of the new GUI-subsystem image (the antivirus' first sight of an
// executable it has not seen) and the first starts of each shell. On the
// Windows runner the first row (Codex guarded, PowerShell -Command, working
// launcher) hung past its 30 s bound with no output, the same command
// through cmd /C answered in 66 ms right after it, the second PowerShell row
// took 10 s and every later PowerShell row about 250 ms (run 43229002732,
// shard gw4). Nothing here is asserted; the rows keep their bounds and every
// row still runs. Each shell is started until one start takes under 5 s
// (at most three times).
func warmLauncherStartRunner(t *testing.T, dir string, image []byte, shells ...string) {
	t.Helper()
	launcher := makeLauncherShape(t, dir, "working", image)
	guard := filepath.Join(dir, windowsHookGuardBinaryName)
	type warm struct {
		name  string
		start func(context.Context) *exec.Cmd
	}
	warms := []warm{
		{"launcher image", func(ctx context.Context) *exec.Cmd { return exec.CommandContext(ctx, launcher) }},
		{"guard image", func(ctx context.Context) *exec.Cmd { return exec.CommandContext(ctx, guard) }},
	}
	for _, shell := range shells {
		if strings.EqualFold(filepath.Base(shell), "cmd.exe") {
			warms = append(warms, warm{shell, func(ctx context.Context) *exec.Cmd { return exec.CommandContext(ctx, shell, "/d", "/c", "exit 0") }})
			continue
		}
		warms = append(warms, warm{shell, func(ctx context.Context) *exec.Cmd {
			return exec.CommandContext(ctx, shell, "-NoProfile", "-Command", "exit 0")
		}})
	}
	for _, w := range warms {
		for attempt := 1; attempt <= 3; attempt++ {
			result := runLauncherStartCommand(t, w.start, "", 2*time.Minute)
			t.Logf("WARM| %s | start %d | exit %d | hung %v | %d ms |", w.name, attempt, result.exit, result.hung, result.elapsed.Milliseconds())
			if !result.hung && result.elapsed < 5*time.Second {
				break
			}
		}
	}
}

// The per-user Windows hook commands answer a launcher that cannot start
// with the agent's block of the event (rel-1-0-6 GAP-0676), every way the
// agent starts them: Codex's guarded start and its bridge (PowerShell
// -Command and cmd /C, Codex's shells), Kiro's command (pwsh and powershell
// -Command, Node's cmd.exe /d /s /c, cmd /C and a direct start) and
// Antigravity's PreToolUse bridge (started directly). A launcher that starts
// keeps its own answer, and a stop gets no blocking answer.
func TestWindowsHookCommandsAnswerALauncherThatCannotStart(t *testing.T) {
	old := windows.SetErrorMode(windows.SEM_FAILCRITICALERRORS | windows.SEM_NOGPFAULTERRORBOX)
	t.Cleanup(func() { windows.SetErrorMode(old) })
	image, err := os.ReadFile(guiSubsystemCopyOfTestBinary(t))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	cmdExe := filepath.Join(trustedWindowsSystemDirectory(), "cmd.exe")
	powershell := windowsSystemPowerShellExe()
	pwsh, pwshErr := exec.LookPath("pwsh.exe")
	warmShells := []string{powershell, cmdExe}
	if pwshErr == nil {
		warmShells = append(warmShells, pwsh)
	}
	warmLauncherStartRunner(t, filepath.Join(root, "warm"), image, warmShells...)
	psCommand := func(shell, command string) func(context.Context) *exec.Cmd {
		return func(ctx context.Context) *exec.Cmd {
			return exec.CommandContext(ctx, shell, "-NoProfile", "-Command", command)
		}
	}
	cmdLine := func(prefix, command string) func(context.Context) *exec.Cmd {
		return func(ctx context.Context) *exec.Cmd {
			cmd := exec.CommandContext(ctx, cmdExe)
			cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: prefix + `"` + command + `"`}
			return cmd
		}
	}
	asIs := func(command string) func(context.Context) *exec.Cmd {
		return func(ctx context.Context) *exec.Cmd {
			cmd := exec.CommandContext(ctx, cmdExe)
			cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: command}
			return cmd
		}
	}
	fields := func(command string) func(context.Context) *exec.Cmd {
		return func(ctx context.Context) *exec.Cmd {
			argv := strings.Fields(command)
			return exec.CommandContext(ctx, argv[0], argv[1:]...)
		}
	}
	type invocation struct {
		name  string
		start func(context.Context) *exec.Cmd
	}
	codexShells := func(command string) []invocation {
		return []invocation{
			{"powershell -Command", psCommand(powershell, command)},
			{"cmd /C", cmdLine("cmd.exe /C ", command)},
		}
	}
	kiroShells := func(command string) []invocation {
		shells := []invocation{
			{"powershell -Command", psCommand(powershell, command)},
			{"cmd /d /s /c", cmdLine("cmd.exe /d /s /c ", command)},
			{"direct", asIs(command)},
		}
		if pwshErr == nil {
			shells = append(shells, invocation{"pwsh -Command", psCommand(pwsh, command)})
		}
		return shells
	}
	type form struct {
		name     string
		event    string
		render   func(launcher string) string
		shells   func(string) []invocation
		blocked  func(t *testing.T, r launcherStartRun) bool // the agent's block of a launcher that cannot start
		base     bool                                        // a pre-1.0.9 form: logged, not asserted
		bridgeOK func(launcher string) bool
	}
	const contract = "codex-hooks-v4"
	codexBlocked := func(want string) func(*testing.T, launcherStartRun) bool {
		return func(_ *testing.T, r launcherStartRun) bool {
			return !r.hung && r.exit == 0 && strings.Contains(r.stdout, want) &&
				strings.Contains(r.stdout, hookguard.LauncherMessage("Codex", false)[:40])
		}
	}
	kiroBlocked := func(_ *testing.T, r launcherStartRun) bool {
		return !r.hung && r.exit == 2 && strings.Contains(r.stderr, "its Kiro hook launcher cannot start")
	}
	antigravityBlocked := func(_ *testing.T, r launcherStartRun) bool {
		return !r.hung && r.exit == 0 && strings.Contains(r.stdout, `"decision":"deny"`) &&
			strings.Contains(r.stdout, "its Antigravity hook launcher cannot start")
	}
	forms := []form{
		{name: "codex guarded", event: "PreToolUse", shells: codexShells, blocked: codexBlocked(`"permissionDecision":"deny"`),
			render: func(l string) string { return windowsCodexHookCommandForBinaryEvent("PreToolUse", contract, l) }},
		{name: "codex guarded", event: "UserPromptSubmit", shells: codexShells, blocked: codexBlocked(`"decision":"block"`),
			render: func(l string) string { return windowsCodexHookCommandForBinaryEvent("UserPromptSubmit", contract, l) }},
		{name: "codex guarded", event: "PermissionRequest", shells: codexShells, blocked: codexBlocked(`"behavior":"deny"`),
			render: func(l string) string { return windowsCodexHookCommandForBinaryEvent("PermissionRequest", contract, l) }},
		{name: "kiro v3", event: "PreToolUse", shells: kiroShells, blocked: kiroBlocked,
			render: func(l string) string { return windowsKiroHookCommandForBinary(l, KiroHookSurfaceV3, false) }},
		{name: "kiro v2", event: "PreToolUse", shells: kiroShells, blocked: kiroBlocked,
			render: func(l string) string { return windowsKiroHookCommandForBinary(l, "", false) }},
		{name: "antigravity", event: "PreToolUse", blocked: antigravityBlocked,
			shells: func(c string) []invocation { return []invocation{{"direct", fields(c)}} },
			render: func(l string) string {
				return windowsAnsweringPowerShellHookCommand("antigravity", "PreToolUse", "", l, antigravityLauncherStartAnswer("PreToolUse"))
			}},
		{name: "codex bridge (path the direct form cannot carry)", event: "UserPromptSubmit", shells: codexShells,
			blocked:  codexBlocked(`"decision":"block"`),
			bridgeOK: func(l string) bool { return strings.Contains(l, "(") },
			render:   func(l string) string { return windowsCodexHookCommandForBinaryEvent("UserPromptSubmit", contract, l) }},
	}
	if os.Getenv(launcherStartBaseEnv) == "1" {
		forms = append(forms,
			form{name: "base codex direct", event: "PreToolUse", shells: codexShells, base: true,
				render: func(l string) string {
					c, _ := windowsCmdDirectHookCommand(l, nativeHookBridgeArguments("codex", "PreToolUse", contract, nil))
					return c
				}},
			form{name: "base kiro v3", event: "PreToolUse", shells: kiroShells, base: true,
				render: func(l string) string { return preStartAnswerWindowsKiroHookCommand(l, KiroHookSurfaceV3) }},
			form{name: "base antigravity", event: "PreToolUse", base: true,
				shells: func(c string) []invocation { return []invocation{{"direct", fields(c)}} },
				render: func(l string) string {
					return windowsNativePowerShellHookCommandForEvent("antigravity", "PreToolUse", l)
				}},
		)
	}
	payloads := map[string]string{
		"PreToolUse":        `{"session_id":"g676","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo ok"}}`,
		"UserPromptSubmit":  `{"session_id":"g676","hook_event_name":"UserPromptSubmit","prompt":"hello"}`,
		"PermissionRequest": `{"session_id":"g676","hook_event_name":"PermissionRequest","tool_name":"Bash","tool_input":{"command":"echo ok"}}`,
	}
	t.Log("ROW| form | launcher | invocation | exit | stdout | stderr | ms |")
	for formIndex, f := range forms {
		for _, shape := range launcherShapes {
			dir := filepath.Join(root, fmt.Sprintf("f%d", formIndex), shape)
			if f.bridgeOK != nil {
				dir = filepath.Join(root, fmt.Sprintf("f%d", formIndex), "a(1)", shape)
			}
			launcher := makeLauncherShape(t, dir, shape, image)
			command := f.render(launcher)
			if f.bridgeOK != nil && (!f.bridgeOK(launcher) || !strings.Contains(command, "-EncodedCommand")) {
				t.Fatalf("%s: %q is not the bridge", f.name, command)
			}
			if strings.HasPrefix(f.name, "codex guarded") && !strings.Contains(command, hookguard.SiblingSubcommand) {
				t.Fatalf("%s: %q does not start the guard", f.name, command)
			}
			for _, shell := range f.shells(command) {
				timeout := 30 * time.Second
				if f.base {
					timeout = 15 * time.Second
				}
				result := runLauncherStartCommand(t, shell.start, payloads[f.event], timeout)
				t.Log(result.row(f.name+" "+f.event, shape, shell.name))
				if f.base {
					continue
				}
				switch {
				case shape == "working":
					if result.hung || !strings.Contains(result.stdout, launcherStartRan) || result.exit != 0 {
						t.Errorf("%s %s, working launcher, %s: %+v; want the launcher's own answer", f.name, f.event, shell.name, result)
					}
				case !f.blocked(t, result):
					t.Errorf("%s %s, %s launcher, %s: %+v; want the agent's block", f.name, f.event, shape, shell.name, result)
				}
			}
		}
	}
	// A stop, and an event Codex gives no control, keep the direct start of
	// the launcher: never a blocking answer.
	launcher := makeLauncherShape(t, filepath.Join(root, "stop"), "working", image)
	for _, event := range []string{"Stop", "SubagentStop", "SessionEnd"} {
		direct, _ := windowsCmdDirectHookCommand(launcher, nativeHookBridgeArguments("codex", event, contract, nil))
		if got := windowsCodexHookCommandForBinaryEvent(event, contract, launcher); got != direct {
			t.Errorf("Codex %s command = %q, want the direct start %q", event, got, direct)
		}
	}
	if got := antigravityLauncherStartAnswer("Stop"); got != nil {
		t.Errorf("Antigravity Stop answer = %+v, want none", got)
	}
}

// Constrained Language mode (WDAC or AppLocker script enforcement) refuses
// the .NET calls, so the bridge starts the launcher with the call operator;
// a launcher that cannot start leaves no exit status there and gets the same
// answer (rel-1-0-6 GAP-0676).
func TestWindowsBridgeAnswersALauncherThatCannotStartInConstrainedLanguage(t *testing.T) {
	image, err := os.ReadFile(guiSubsystemCopyOfTestBinary(t))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	warmLauncherStartRunner(t, filepath.Join(root, "warm"), image, windowsSystemPowerShellExe())
	for _, tc := range []struct {
		name, payload string
		render        func(string) string
		want          func(launcherStartRun) bool
	}{
		{"kiro", `{"hook_event_name":"PreToolUse"}`,
			func(l string) string {
				return windowsKiroPowerShellBridgeForBinary(l, KiroHookSurfaceV3, false)
			},
			func(r launcherStartRun) bool {
				return r.exit == 2 && strings.Contains(r.stderr+r.stdout, "Kiro hook launcher cannot start")
			}},
		{"codex", `{"hook_event_name":"PreToolUse"}`,
			func(l string) string {
				return windowsCodexAnsweringBridgeHookCommand("PreToolUse", "codex-hooks-v4", l)
			},
			func(r launcherStartRun) bool {
				return r.exit == 0 && strings.Contains(r.stdout, `"permissionDecision":"deny"`)
			}},
	} {
		for _, shape := range []string{"missing", "folder", "empty"} {
			t.Run(tc.name+"/"+shape, func(t *testing.T) {
				launcher := makeLauncherShape(t, filepath.Join(root, tc.name, shape), shape, image)
				script := decodePowerShellEncodedCommandForTest(t, tc.render(launcher))
				clm := "$ExecutionContext.SessionState.LanguageMode='ConstrainedLanguage'; Invoke-Expression " + powershellQuoteLiteral(script)
				result := runLauncherStartCommand(t, func(ctx context.Context) *exec.Cmd {
					return exec.CommandContext(ctx, windowsSystemPowerShellExe(), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", clm)
				}, tc.payload, 30*time.Second)
				t.Log(result.row(tc.name+" constrained language", shape, "powershell -Command"))
				if result.hung || !tc.want(result) {
					t.Fatalf("%+v; want the agent's block", result)
				}
			})
		}
	}
}
