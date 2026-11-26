// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// The Windows twins of the Unix per-user registration tests. A per-user
// Windows install registers the native launcher (defenseclaw-hook.exe) behind
// the system cmd.exe launcher guard, never a hook script and never the Unix
// guard pair, and the registration does not depend on the gateway address, the
// data root or Secure Client delivery. Rollback converts the guard back to the
// exec form that 1.0.0 and 0.8.x teardown recognize.

var claudeCodeWindowsHookArgs = []string{"hook", "--connector", "claudecode"}

func claudeCodeWindowsLauncherFixture(t *testing.T) (dataDir, launcher string) {
	t.Helper()
	t.Setenv("SystemRoot", `C:\Windows`)
	root := t.TempDir()
	dataDir = filepath.Join(root, "profile", ".defenseclaw")
	launcher = filepath.Join(root, "profile", ".local", "bin", "defenseclaw-hook.exe")
	if !claudeCodeLauncherGuardable(launcher) {
		t.Fatalf("fixture launcher %q is not one per-user Setup guards", launcher)
	}
	return dataDir, launcher
}

func claudeCodeWindowsHandler(command string, args []string) map[string]interface{} {
	return map[string]interface{}{"type": "command", "command": command, "args": stringsToInterfaces(args)}
}

func claudeCodeWindowsScript(dataDir string) string {
	return filepath.Join(dataDir, "hooks", "claude-code-hook.sh")
}

// claudeCodeWindowsSelectsLauncher is the Windows form of "per-user selects
// the native hook".
func claudeCodeWindowsSelectsLauncher(t *testing.T) {
	t.Helper()
	dataDir, launcher := claudeCodeWindowsLauncherFixture(t)
	script := claudeCodeWindowsScript(dataDir)
	opts := SetupOpts{DataDir: dataDir, HookExecutable: launcher}
	wantCommand := claudeCodeWindowsCommandProcessor()
	wantArgs := claudeCodeLauncherGuardArgs(launcher, claudeCodeWindowsHookArgs)
	command, args := claudeCodeHookInvocation(opts, script)
	if command != wantCommand || !codexValueMatches(args, wantArgs) {
		t.Fatalf("native command = %q, %q; want %q, %q", command, args, wantCommand, wantArgs)
	}
	if strings.Contains(strings.Join(args, " "), "claude-code-hook.sh") || strings.Contains(strings.Join(args, " "), "guard-user-hook") {
		t.Fatalf("Windows registration names the script or the Unix guard pair: %q", args)
	}
	handler := claudeCodeWindowsHandler(command, args)
	view, ok := claudeCodeExecView(handler).(map[string]interface{})
	if !ok || view["command"] != launcher || !codexValueMatches(view["args"], claudeCodeWindowsHookArgs) {
		t.Fatalf("the guard does not read as the exec form of the launcher: %v", view)
	}
	if !claudeCodeHandlerTargetsCurrentRuntime(handler, opts) {
		t.Fatal("native registration is not recognized")
	}
	// The configured gateway address is not part of the Windows registration.
	opts.APIAddr = "127.0.0.1:18971"
	command, args = claudeCodeHookInvocation(opts, script)
	if command != wantCommand || !codexValueMatches(args, wantArgs) ||
		!claudeCodeHandlerTargetsCurrentRuntime(claudeCodeWindowsHandler(command, args), opts) {
		t.Fatalf("configured address changed the registration: %q, %q", command, args)
	}
	// A launcher at another path is not this install's registration.
	other := filepath.Join(filepath.Dir(filepath.Dir(launcher)), "elsewhere", "defenseclaw-hook.exe")
	foreignArgs := claudeCodeLauncherGuardArgs(other, claudeCodeWindowsHookArgs)
	if claudeCodeHandlerTargetsCurrentRuntime(claudeCodeWindowsHandler(wantCommand, foreignArgs), opts) {
		t.Fatal("a guard around another launcher was recognized")
	}
}

// claudeCodeWindowsHasNoScriptTwin is the Windows form of "the script twin":
// no input selects a script, and only the managed form drops the cmd.exe guard.
func claudeCodeWindowsHasNoScriptTwin(t *testing.T) {
	t.Helper()
	dataDir, launcher := claudeCodeWindowsLauncherFixture(t)
	base := SetupOpts{DataDir: dataDir, HookExecutable: launcher}
	wantCommand, wantArgs := claudeCodeHookInvocation(base, claudeCodeWindowsScript(dataDir))
	if wantCommand != claudeCodeWindowsCommandProcessor() ||
		!codexValueMatches(wantArgs, claudeCodeLauncherGuardArgs(launcher, claudeCodeWindowsHookArgs)) {
		t.Fatalf("base registration = %q, %q", wantCommand, wantArgs)
	}
	customRoot := filepath.Join(filepath.Dir(dataDir), "custom-data")
	for name, opts := range map[string]SetupOpts{
		"nonlocal address":      {DataDir: dataDir, HookExecutable: launcher, APIAddr: "example.test:18970"},
		"loopback address":      {DataDir: dataDir, HookExecutable: launcher, APIAddr: "127.0.0.1:18970"},
		"secure client":         {DataDir: dataDir, HookExecutable: launcher, SecureClientHookDelivery: true},
		"custom data directory": {DataDir: customRoot, HookExecutable: launcher},
	} {
		command, args := claudeCodeHookInvocation(opts, claudeCodeWindowsScript(opts.DataDir))
		if command != wantCommand || !codexValueMatches(args, wantArgs) {
			t.Fatalf("%s changed the registration: %q, %q", name, command, args)
		}
	}
	managed := base
	managed.ManagedEnterprise = true
	command, args := claudeCodeHookInvocation(managed, claudeCodeWindowsScript(dataDir))
	if command != launcher || !codexValueMatches(args, claudeCodeWindowsHookArgs) {
		t.Fatalf("managed delivery = %q, %q; want the exec form of the launcher", command, args)
	}
}

// claudeCodeWindowsRollbackKeepsEarlierHookShape is the Windows form of the
// native rollback test: the guard converts to the exec form earlier releases
// own; anything else stays byte for byte.
func claudeCodeWindowsRollbackKeepsEarlierHookShape(t *testing.T) {
	t.Helper()
	dataDir, launcher := claudeCodeWindowsLauncherFixture(t)
	script := claudeCodeWindowsScript(dataDir)
	owned := func(path string) bool { return path == launcher }
	cmd := claudeCodeWindowsCommandProcessor()
	guarded := claudeCodeWindowsHandler(cmd, claudeCodeLauncherGuardArgs(launcher, claudeCodeWindowsHookArgs))
	if !claudeCodeHandlerInEarlierReleaseForm(guarded, "windows", script, owned) ||
		guarded["command"] != launcher || !codexValueMatches(guarded["args"], claudeCodeWindowsHookArgs) {
		t.Fatalf("rollback form = %#v", guarded)
	}
	// The exec form is already what earlier releases own.
	exec := claudeCodeWindowsHandler(launcher, claudeCodeWindowsHookArgs)
	before := map[string]interface{}{"type": "command", "command": launcher, "args": stringsToInterfaces(claudeCodeWindowsHookArgs)}
	if claudeCodeHandlerInEarlierReleaseForm(exec, "windows", script, owned) || !reflect.DeepEqual(exec, before) {
		t.Fatalf("exec form changed: %#v", exec)
	}
	foreignLauncher := filepath.Join(filepath.Dir(filepath.Dir(launcher)), "elsewhere", "defenseclaw-hook.exe")
	foreign := claudeCodeWindowsHandler(cmd, claudeCodeLauncherGuardArgs(foreignLauncher, claudeCodeWindowsHookArgs))
	foreignBefore := claudeCodeWindowsHandler(cmd, claudeCodeLauncherGuardArgs(foreignLauncher, claudeCodeWindowsHookArgs))
	if claudeCodeHandlerInEarlierReleaseForm(foreign, "windows", script, owned) || !reflect.DeepEqual(foreign, foreignBefore) {
		t.Fatalf("foreign launcher guard changed: %#v", foreign)
	}
	extraArgs := append(append([]string(nil), claudeCodeWindowsHookArgs...), "--other")
	extra := claudeCodeWindowsHandler(cmd, claudeCodeLauncherGuardArgs(launcher, extraArgs))
	extraBefore := claudeCodeWindowsHandler(cmd, claudeCodeLauncherGuardArgs(launcher, extraArgs))
	if claudeCodeHandlerInEarlierReleaseForm(extra, "windows", script, owned) || !reflect.DeepEqual(extra, extraBefore) {
		t.Fatalf("guard with an extra hook argument changed: %#v", extra)
	}
	// Through a whole settings document only the guard is converted; the
	// foreign handler beside it is kept.
	settings := map[string]interface{}{"hooks": map[string]interface{}{"PreToolUse": []interface{}{
		map[string]interface{}{"hooks": []interface{}{
			claudeCodeWindowsHandler(cmd, claudeCodeLauncherGuardArgs(launcher, claudeCodeWindowsHookArgs)),
			map[string]interface{}{"type": "command", "command": "foreign-handler.exe"},
		}},
	}}}
	if changed := claudeCodeHooksInEarlierReleaseForm(settings, "windows", script, owned); changed != 1 {
		t.Fatalf("rollback changed %d handlers, want 1", changed)
	}
	handlers := settings["hooks"].(map[string]interface{})["PreToolUse"].([]interface{})[0].(map[string]interface{})["hooks"].([]interface{})
	if len(handlers) != 2 || handlers[0].(map[string]interface{})["command"] != launcher ||
		handlers[1].(map[string]interface{})["command"] != "foreign-handler.exe" {
		t.Fatalf("rollback handlers = %#v", handlers)
	}
}

// claudeCodeWindowsRehomedOwnership is the Windows form of the rehomed-account
// ownership test: the Unix per-user pair (guard and fallback) names an owner
// home only on Linux and macOS, so Windows never claims one.
func claudeCodeWindowsRehomedOwnership(t *testing.T) {
	t.Helper()
	oldHome := filepath.Join(t.TempDir(), "previous")
	bin := filepath.Join(oldHome, ".local", "bin")
	guard := filepath.Join(bin, "defenseclaw-hook-post")
	native := filepath.Join(bin, "defenseclaw-hook-user")
	home := filepath.Join(oldHome, ".defenseclaw")
	guardArgs := []string{"guard-user-hook", native, "hook", "--connector", "claudecode", "--hook-home", home}
	fallbackArgs := []string{"fallback-guard-user-hook", guard, "hook", "--connector", "claudecode", "--hook-home", home}
	for name, handler := range map[string]map[string]interface{}{
		"guard":    {"type": "command", "command": guard, "args": guardArgs},
		"fallback": {"type": "command", "command": native, "args": fallbackArgs},
	} {
		for _, fallback := range []bool{false, true} {
			if got, ok := claudeCodePerUserNativeOwnerHome(handler, fallback); ok || got != "" {
				t.Fatalf("%s (fallback=%v) named owner home %q on Windows", name, fallback, got)
			}
		}
	}
}

// claudeCodeWindowsRehomedShellOwnership is the shell-form half of the rehomed
// ownership twin: the guarded shell command is not claimed on Windows either.
func claudeCodeWindowsRehomedShellOwnership(t *testing.T) {
	t.Helper()
	oldHome := filepath.Join(t.TempDir(), "previous account")
	native := filepath.Join(oldHome, ".local", "bin", "defenseclaw-hook-user")
	home := filepath.Join(oldHome, ".defenseclaw")
	command := posixHookCommandWord(native) + " hook --connector claudecode --hook-home " + posixHookCommandWord(home)
	for name, shell := range map[string]string{
		"native shell":      claudeCodeMissingHookGuard(command),
		"loopback endpoint": claudeCodeMissingHookGuard(command + " --api-addr 127.0.0.1:18970"),
		"unguarded shell":   command,
	} {
		if got, ok := claudeCodePerUserNativeShellOwnerHome(shell); ok || got != "" {
			t.Fatalf("%s named owner home %q on Windows", name, got)
		}
	}
}

// claudeCodeWindowsPerUserHandlersGolden is the Windows form of the Linux
// per-user golden: the Linux handlers are not a Windows registration, and the
// Windows registration is the launcher guard of the Windows golden
// (TestClaudeCodeWindowsHandlersMatchTheSharedGolden).
func claudeCodeWindowsPerUserHandlersGolden(t *testing.T) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "claudecode_linux_peruser_handlers.json"))
	if err != nil {
		t.Fatal(err)
	}
	var golden struct {
		Account string                 `json:"account"`
		APIAddr string                 `json:"api_addr"`
		Hooks   map[string]interface{} `json:"hooks"`
	}
	if err := json.Unmarshal(data, &golden); err != nil {
		t.Fatal(err)
	}
	if len(golden.Hooks) < 2 {
		t.Fatalf("golden holds %d events, want a synchronous and an asynchronous one", len(golden.Hooks))
	}
	handlers := 0
	for event := range golden.Hooks {
		for _, handler := range claudeHandlersOf(t, golden.Hooks, event) {
			handlers++
			if got, ok := claudeCodePerUserNativeOwnerHome(handler, false); ok {
				t.Fatalf("%s: Windows named owner home %q for a Linux guard handler", event, got)
			}
			if got, ok := claudeCodePerUserNativeOwnerHome(handler, true); ok {
				t.Fatalf("%s: Windows named owner home %q for a Linux fallback handler", event, got)
			}
		}
	}
	if handlers == 0 {
		t.Fatal("golden holds no handlers")
	}
	dataDir, launcher := claudeCodeWindowsLauncherFixture(t)
	command, args := claudeCodeHookInvocation(SetupOpts{DataDir: dataDir, HookExecutable: launcher, APIAddr: golden.APIAddr},
		claudeCodeWindowsScript(dataDir))
	if command != claudeCodeWindowsCommandProcessor() ||
		!codexValueMatches(args, claudeCodeLauncherGuardArgs(launcher, claudeCodeWindowsHookArgs)) {
		t.Fatalf("per-user Windows invocation = %q %q", command, args)
	}
	if strings.Contains(command, "claude-code-hook.sh") || strings.Contains(strings.Join(args, " "), "guard-user-hook") {
		t.Fatalf("Windows invocation names the shell hook or the Unix guard: %q %q", command, args)
	}
}

// symlinkOrSkipWithoutPrivilegeForTest links link to target. A standard
// Windows account holds no symlink privilege (ERROR_PRIVILEGE_NOT_HELD,
// 1314): the Limited native leg skips there and the elevated native leg runs
// the test. Any other failure, and every failure off Windows, fails the test.
func symlinkOrSkipWithoutPrivilegeForTest(t *testing.T, target, link string) {
	t.Helper()
	err := os.Symlink(target, link)
	if err == nil {
		return
	}
	if runtime.GOOS == "windows" && errors.Is(err, syscall.Errno(1314)) {
		t.Skipf("this account holds no Windows symlink privilege; the elevated native leg runs this test: %v", err)
	}
	t.Fatal(err)
}

// claudeCodeWindowsRefusesLinkedSettings is the Windows form of "settings
// linked into the home are inspected". The Windows writer replaces only a
// regular file, so a settings file that is a link is refused wherever it
// points (windowsSettingsFileLinkRefusal): an agent-settings refusal before
// Setup writes anything, so a gateway start keeps the other connectors, and
// the link and its target are left as they were.
func claudeCodeWindowsRefusesLinkedSettings(t *testing.T, conn *ClaudeCodeConnector, opts SetupOpts, settingsPath, target string) {
	t.Helper()
	const refusal = "is a symbolic link or junction"
	before, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := claudeCodeUserSettingsReadPath(settingsPath); err == nil || !strings.Contains(err.Error(), refusal) {
		t.Fatalf("claudeCodeUserSettingsReadPath(linked settings) err = %v; want the Windows link refusal", err)
	}
	if err := CheckAgentSettings(conn, opts); !errors.Is(err, ErrAgentConfigRefusal) || !strings.Contains(err.Error(), refusal) {
		t.Fatalf("CheckAgentSettings(linked settings) = %v; want an agent-settings refusal naming the link", err)
	}
	if err := conn.Setup(context.Background(), opts); !errors.Is(err, ErrAgentConfigRefusal) {
		t.Fatalf("Setup(linked settings) = %v; want an agent-settings refusal", err)
	}
	if present, err := OwnedHooksPresent(conn, opts); present {
		t.Fatalf("OwnedHooksPresent(linked settings) = %v, %v; want absent", present, err)
	}
	if info, err := os.Lstat(settingsPath); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("refused setup replaced the settings link: %v", err)
	}
	if after, err := os.ReadFile(target); err != nil || !bytes.Equal(after, before) {
		t.Fatalf("refused setup changed the link target (err %v): %q", err, after)
	}
}

// claudeCodeWindowsEnterpriseContractIgnoresUserSettings is the Windows form
// of "the enterprise script contract uses user settings". Windows enterprise
// policy pins the absolute native launcher in the managed tier
// (claudeCodeEffectiveHookContract managedPolicy): the hooks per-user Setup
// wrote in the user settings satisfy the per-user contract but not the
// enterprise one, which with no managed tier is repairable absence (no
// error), so the guardian re-runs Setup.
func claudeCodeWindowsEnterpriseContractIgnoresUserSettings(t *testing.T, conn *ClaudeCodeConnector, opts SetupOpts) {
	t.Helper()
	if present, err := OwnedHooksPresent(conn, opts); err != nil || !present {
		t.Fatalf("per-user contract = (present=%v, err=%v), want the user-settings hooks", present, err)
	}
	opts.ManagedEnterprise = true
	opts.HookExecutable = filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
	if present, err := OwnedHooksPresent(conn, opts); err != nil || present {
		t.Fatalf("Windows enterprise contract = (present=%v, err=%v), want repairable absence: user settings do not satisfy it", present, err)
	}
}

// claudeCodeWindowsRegisteredCommandBlocksWhenLauncherMissing runs the command
// per-user Setup registers for launcher, which does not exist, as Claude Code
// starts a hook: it blocks (exit 2) and says why.
func claudeCodeWindowsRegisteredCommandBlocksWhenLauncherMissing(t *testing.T, opts SetupOpts, launcher string) {
	t.Helper()
	opts.HookExecutable = launcher
	command, args := claudeCodeHookInvocation(opts, claudeCodeWindowsScript(opts.DataDir))
	code, output := gap0322RunRegistered(t, command, args, "{}")
	if code != 2 || !strings.Contains(output, ClaudeCodeLauncherMissingMessage) {
		t.Fatalf("registered command with no launcher: exit %d, output %q, want a block (2) that says the launcher is missing", code, output)
	}
}

// claudeCodeWindowsPerUserCommandFailsClosedWhenLauncherMissing is the Windows
// form of "the per-user command fails closed when its script is missing"
// (GAP-0542): after an account rename or a home move the registered launcher
// path is gone, and the registered cmd.exe guard blocks (exit 2) with one
// sentence instead of failing to start, which Claude Code treats as
// non-blocking. When the launcher runs, its exit code passes through.
func claudeCodeWindowsPerUserCommandFailsClosedWhenLauncherMissing(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	home := filepath.Join(dir, "Alice Smith")
	launcherDir := filepath.Join(home, ".local", "bin")
	opts := SetupOpts{DataDir: filepath.Join(home, ".defenseclaw"), HookExecutable: filepath.Join(launcherDir, windowsHookBinaryName)}
	command, args := claudeCodeHookInvocation(opts, claudeCodeWindowsScript(opts.DataDir))
	if command != claudeCodeWindowsCommandProcessor() {
		t.Fatalf("command %q is not the guard's command processor", command)
	}
	code, output := gap0322RunRegistered(t, command, args, "{}")
	if code != 2 || !strings.Contains(output, "Run the DefenseClaw installer again to repair it") {
		t.Fatalf("missing launcher: exit %d output %q, want a block (2) that names the repair", code, output)
	}
	copyTestBinaryAsLauncher(t, launcherDir)
	for _, want := range []int{0, 2, 3} {
		t.Setenv(guardLauncherModeEnv, "")
		t.Setenv(guardLauncherExitEnv, strconv.Itoa(want))
		code, output := gap0322RunRegistered(t, command, args, "{}")
		if code != want || strings.Contains(output, ClaudeCodeLauncherMissingMessage) {
			t.Fatalf("launcher exit %d: command exit %d output %q", want, code, output)
		}
	}
	// An entry that names a launcher of another account's home is not this
	// install's registration (a guard around another launcher is not claimed).
	otherCommand, otherArgs := claudeCodeHookInvocation(SetupOpts{
		DataDir: filepath.Join(dir, "old", ".defenseclaw"), HookExecutable: filepath.Join(dir, "old", ".local", "bin", windowsHookBinaryName),
	}, claudeCodeWindowsScript(filepath.Join(dir, "old", ".defenseclaw")))
	if claudeCodeHandlerTargetsCurrentRuntime(claudeCodeWindowsHandler(otherCommand, otherArgs), opts) {
		t.Fatal("an old-home guard was recognized as this install's registration")
	}
}

// claudeCodeWindowsRehomedHandlersReplaced is the Windows form of the rehomed
// account test: the settings carry an old account's launcher guard next to an
// operator hook; Setup's reconcile writes the current launcher's complete
// registration and keeps the operator's hook.
func claudeCodeWindowsRehomedHandlersReplaced(t *testing.T) {
	t.Helper()
	root := t.TempDir()
	oldHome := filepath.Join(root, "previous")
	currentHome := filepath.Join(root, "current")
	t.Setenv("HOME", currentHome)
	t.Setenv("USERPROFILE", currentHome)
	dataDir := filepath.Join(currentHome, ".defenseclaw")
	hooksDir := filepath.Join(dataDir, "hooks")
	if err := os.MkdirAll(hooksDir, 0o700); err != nil {
		t.Fatal(err)
	}
	settingsPath := filepath.Join(root, "settings.json")
	ClaudeCodeSettingsPathOverride = settingsPath
	t.Cleanup(func() { ClaudeCodeSettingsPathOverride = "" })

	oldOpts := SetupOpts{DataDir: filepath.Join(oldHome, ".defenseclaw"),
		HookExecutable: filepath.Join(oldHome, ".local", "bin", windowsHookBinaryName)}
	oldCommand, oldArgs := claudeCodeHookInvocation(oldOpts, claudeCodeWindowsScript(oldOpts.DataDir))
	hooks := map[string]interface{}{}
	appendClaudeCodeHookMatrix(hooks, oldCommand, oldArgs)
	foreign := map[string]interface{}{"type": "command", "command": `C:\operator\ordinary-hook.exe`, "timeout": 30}
	hooks["Stop"] = append(hooks["Stop"].([]interface{}), map[string]interface{}{"hooks": []interface{}{foreign}})
	data, err := json.Marshal(map[string]interface{}{"hooks": hooks})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settingsPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	opts := SetupOpts{DataDir: dataDir, HookExecutable: filepath.Join(currentHome, ".local", "bin", windowsHookBinaryName)}
	if err := NewClaudeCodeConnector().patchClaudeCodeHooks(opts, claudeCodeWindowsScript(dataDir)); err != nil {
		t.Fatalf("reconcile Claude Code hooks: %v", err)
	}
	after, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]interface{}
	if err := json.Unmarshal(after, &settings); err != nil {
		t.Fatal(err)
	}
	// JSON writes a backslash as two characters: look for the paths decoded.
	decoded := string(mustMarshalNoEscape(t, settings))
	if !strings.Contains(decoded, filepath.Join(currentHome, ".local", "bin")) || !strings.Contains(decoded, `C:\operator\ordinary-hook.exe`) {
		t.Fatalf("current registration or the operator's hook missing: %s", after)
	}
	currentCommand, currentArgs := claudeCodeHookInvocation(opts, claudeCodeWindowsScript(dataDir))
	if err := verifyClaudeCodeHookMatrixForSetup(settings["hooks"].(map[string]interface{}), currentCommand, currentArgs, hooksDir, opts); err != nil {
		t.Fatalf("current hook matrix: %v", err)
	}
	t.Logf("old-home launcher still named after reconcile: %v", strings.Contains(decoded, oldHome))
}

func mustMarshalNoEscape(t *testing.T, value interface{}) []byte {
	t.Helper()
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		t.Fatal(err)
	}
	// Decode the escaped backslashes the encoder writes.
	return []byte(strings.ReplaceAll(out.String(), `\\`, `\`))
}

// gap0322WindowsRegistrationMatrixRefusesTampering is the Windows form of the
// missing-guard fallback registration test: the per-user matrix verifies, and
// a PreToolUse handler that is missing, conditional or run through a shell is
// refused.
func gap0322WindowsRegistrationMatrixRefusesTampering(t *testing.T, command string, args []string) {
	t.Helper()
	launcher := args[4]
	dataDir := filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(launcher))), ".defenseclaw")
	opts := SetupOpts{DataDir: dataDir, HookExecutable: launcher}
	hooksDir := filepath.Join(dataDir, "hooks")
	hooks := map[string]interface{}{}
	if err := appendClaudeCodeHookMatrixForSetup(hooks, command, args, opts); err != nil {
		t.Fatal(err)
	}
	if err := verifyClaudeCodeHookMatrixForSetup(hooks, command, args, hooksDir, opts); err != nil {
		t.Fatalf("registered matrix: %v", err)
	}
	groups := hooks["PreToolUse"].([]interface{})
	handlers := groups[0].(map[string]interface{})["hooks"].([]interface{})
	if len(handlers) == 0 {
		t.Fatal("PreToolUse has no handler")
	}
	guard := handlers[0].(map[string]interface{})
	groups[0].(map[string]interface{})["hooks"] = handlers[:0]
	if err := verifyClaudeCodeHookMatrixForSetup(hooks, command, args, hooksDir, opts); err == nil {
		t.Fatal("a missing PreToolUse handler was accepted")
	}
	groups[0].(map[string]interface{})["hooks"] = handlers
	guard["if"] = "Bash(ls)"
	if err := verifyClaudeCodeHookMatrixForSetup(hooks, command, args, hooksDir, opts); err == nil {
		t.Fatal("a conditional PreToolUse handler was accepted")
	}
	delete(guard, "if")
	guard["shell"] = "bash"
	if err := verifyClaudeCodeHookMatrixForSetup(hooks, command, args, hooksDir, opts); err == nil {
		t.Fatal("a PreToolUse handler run through a shell was accepted")
	}
	delete(guard, "shell")
	if err := verifyClaudeCodeHookMatrixForSetup(hooks, command, args, hooksDir, opts); err != nil {
		t.Fatalf("restored matrix: %v", err)
	}
}
