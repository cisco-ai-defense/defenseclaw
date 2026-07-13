// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

func setHookBinaryOverride(t *testing.T, path string) {
	t.Helper()
	prev := defenseclawHookBinaryOverride
	defenseclawHookBinaryOverride = path
	t.Cleanup(func() { defenseclawHookBinaryOverride = prev })
}

func decodePowerShellEncodedCommandForTest(t *testing.T, command string) string {
	t.Helper()
	parts := strings.Fields(command)
	for i, part := range parts {
		if strings.EqualFold(part, "-EncodedCommand") && i+1 < len(parts) {
			data, err := base64.StdEncoding.DecodeString(parts[i+1])
			if err != nil {
				t.Fatalf("decode PowerShell encoded command: %v", err)
			}
			if len(data)%2 != 0 {
				t.Fatalf("encoded PowerShell command has odd byte length: %d", len(data))
			}
			wide := make([]uint16, len(data)/2)
			for j := range wide {
				wide[j] = binary.LittleEndian.Uint16(data[j*2:])
			}
			return string(utf16.Decode(wide))
		}
	}
	t.Fatalf("command has no -EncodedCommand token: %q", command)
	return ""
}

func TestWindowsHookConfigSidecarPreservesMixedConnectorModes(t *testing.T) {
	dir := t.TempDir()
	if err := writeHookConfigSidecar(dir, "127.0.0.1:18970", "claudecode", "closed", false); err != nil {
		t.Fatal(err)
	}
	if err := writeHookConfigSidecar(dir, "127.0.0.1:18970", "codex", "open", false); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, hookConfigSidecarName))
	if err != nil {
		t.Fatal(err)
	}
	var state hookConfigSidecar
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	if state.FailModes["claudecode"] != "closed" || state.FailModes["codex"] != "open" {
		t.Fatalf("mixed fail modes not preserved: %#v", state.FailModes)
	}
}

func TestWindowsHookConfigSidecarMigratesLegacyScalar(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, hookConfigSidecarName)
	legacy := []byte("DEFENSECLAW_GATEWAY_ADDR=127.0.0.1:18970\nDEFENSECLAW_FAIL_MODE=open\n")
	if err := os.WriteFile(path, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeHookConfigSidecar(dir, "127.0.0.1:18970", "claudecode", "closed", false); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var state hookConfigSidecar
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("legacy sidecar was not migrated to v2: %v", err)
	}
	if state.Version != 2 || state.FailModes["claudecode"] != "closed" {
		t.Fatalf("migrated state = %#v", state)
	}
	if state.LegacyMode != "open" {
		t.Fatalf("legacy fallback was not retained for unmigrated connector peers: %#v", state)
	}
}

func TestHookConfigSidecarClearRemovesOnlySelectedConnector(t *testing.T) {
	dir := t.TempDir()
	if err := writeHookConfigSidecar(dir, "127.0.0.1:18970", "claudecode", "closed", false); err != nil {
		t.Fatal(err)
	}
	if err := writeHookConfigSidecar(dir, "127.0.0.1:18970", "codex", "open", false); err != nil {
		t.Fatal(err)
	}
	if err := clearHookConfigSidecarEntry(dir, "claudecode"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, hookConfigSidecarName))
	if err != nil {
		t.Fatal(err)
	}
	var state hookConfigSidecar
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	if _, ok := state.FailModes["claudecode"]; ok {
		t.Fatalf("selected connector survived clear: %#v", state.FailModes)
	}
	if state.FailModes["codex"] != "open" {
		t.Fatalf("peer connector changed during clear: %#v", state.FailModes)
	}
	if _, err := os.Stat(filepath.Join(dir, hookConfigSidecarName+".claudecode")); !os.IsNotExist(err) {
		t.Fatalf("selected flat runtime record survived clear: %v", err)
	}
	peer, err := os.ReadFile(filepath.Join(dir, hookConfigSidecarName+".codex"))
	if err != nil || !strings.Contains(string(peer), "DEFENSECLAW_FAIL_MODE=open") {
		t.Fatalf("peer flat runtime record changed: err=%v body=%q", err, peer)
	}
}

func TestHookConfigSidecarWriteRejectsMalformedPeerState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, hookConfigSidecarName)
	before := []byte(`{"version":2,"fail_modes":`)
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeHookConfigSidecar(dir, "127.0.0.1:18970", "claudecode", "closed", false); err == nil {
		t.Fatal("malformed peer runtime state was overwritten")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("failed sidecar write changed malformed peer state")
	}
}

func TestHookConfigSidecarSecondWriteFailureRollsBackBothFiles(t *testing.T) {
	dir := t.TempDir()
	if err := writeHookConfigSidecar(dir, "127.0.0.1:18970", "claudecode", "open", false); err != nil {
		t.Fatal(err)
	}
	jsonPath := filepath.Join(dir, hookConfigSidecarName)
	flatPath := filepath.Join(dir, hookConfigSidecarName+".claudecode")
	jsonBefore, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	flatBefore, err := os.ReadFile(flatPath)
	if err != nil {
		t.Fatal(err)
	}
	writes := 0
	failSecond := func(path string, data []byte, mode os.FileMode) error {
		writes++
		if writes == 2 {
			return errors.New("injected flat sidecar failure")
		}
		return atomicWriteFile(path, data, mode)
	}
	if err := writeHookConfigSidecarUsing(
		dir,
		"127.0.0.1:18970",
		"claudecode",
		"closed",
		false,
		failSecond,
	); err == nil {
		t.Fatal("injected second-file failure was ignored")
	}
	jsonAfter, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	flatAfter, err := os.ReadFile(flatPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(jsonAfter, jsonBefore) || !bytes.Equal(flatAfter, flatBefore) {
		t.Fatal("second-file failure left JSON and flat runtime state changed")
	}
}

func TestWindowsHookBinaryUsesStableInstalledLocation(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows installed launcher path")
	}
	previous := defenseclawHookBinaryOverride
	defenseclawHookBinaryOverride = ""
	t.Cleanup(func() { defenseclawHookBinaryOverride = previous })

	want := filepath.Join(userHomeDir(), ".local", "bin", windowsHookBinaryName)
	if got := defenseclawHookBinary(); !strings.EqualFold(filepath.Clean(got), filepath.Clean(want)) {
		t.Fatalf("defenseclawHookBinary() = %q, want installed path %q", got, want)
	}
	notify := codexNativeNotifyCommand()
	if len(notify) != 2 || !strings.EqualFold(filepath.Clean(notify[0]), filepath.Clean(want)) || notify[1] != "notify" {
		t.Fatalf("codexNativeNotifyCommand() = %#v, want installed launcher + notify", notify)
	}
}

func TestPackagedWindowsHookBinaryUsesVerifiedNativeInstallState(t *testing.T) {
	root := t.TempDir()
	commandDir := filepath.Join(root, "bin")
	runtimeDir := filepath.Join(root, "runtime", "python")
	installerDir := filepath.Join(root, "installer")
	for _, directory := range []string{commandDir, runtimeDir, installerDir} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	gateway := filepath.Join(commandDir, windowsGatewayBinaryName)
	hook := filepath.Join(commandDir, windowsHookBinaryName)
	for _, path := range []string{gateway, hook} {
		if err := os.WriteFile(path, []byte("MZnative-fixture"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	state := map[string]interface{}{
		"schema_version": 1,
		"install_kind":   "native-windows-exe",
		"install_scope":  "user",
		"install_root":   root,
		"command_dir":    commandDir,
		"runtime":        runtimeDir,
	}
	statePath := filepath.Join(installerDir, "install-state.json")
	writeState := func() {
		t.Helper()
		body, err := json.Marshal(state)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(statePath, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeState()
	if got := packagedWindowsHookBinaryAtRoot(gateway, root); !sameWindowsInstallPath(got, hook) {
		t.Fatalf("packagedWindowsHookBinaryAtRoot() = %q, want %q", got, hook)
	}
	if got := packagedWindowsHookBinary(gateway); got != "" {
		t.Fatalf("arbitrary self-consistent install root selected production hook binary %q", got)
	}
	if got := packagedWindowsHookBinaryAtRoot(gateway, filepath.Join(root, "other-install")); got != "" {
		t.Fatalf("gateway outside expected install root selected hook binary %q", got)
	}

	state["command_dir"] = filepath.Join(root, "spoofed-bin")
	writeState()
	if got := packagedWindowsHookBinaryAtRoot(gateway, root); got != "" {
		t.Fatalf("mismatched installer state selected hook binary %q", got)
	}
	state["command_dir"] = commandDir
	writeState()
	if err := os.WriteFile(hook, []byte("not-a-windows-executable"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := packagedWindowsHookBinaryAtRoot(gateway, root); got != "" {
		t.Fatalf("non-PE hook selected as packaged launcher %q", got)
	}
}

func TestPackagedWindowsHookBinaryRejectsReparseInstallRoot(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows reparse-point trust boundary")
	}
	realRoot := t.TempDir()
	commandDir := filepath.Join(realRoot, "bin")
	installerDir := filepath.Join(realRoot, "installer")
	if err := os.MkdirAll(commandDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(installerDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		filepath.Join(commandDir, windowsGatewayBinaryName),
		filepath.Join(commandDir, windowsHookBinaryName),
	} {
		if err := os.WriteFile(path, []byte("MZnative-fixture"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	linkRoot := filepath.Join(filepath.Dir(realRoot), "linked-install")
	if err := os.Symlink(realRoot, linkRoot); err != nil {
		// Standard Windows users may lack symbolic-link privilege, but creating
		// a directory junction is permitted and exercises the same reparse-point
		// rejection without weakening this security regression into a skip.
		if output, junctionErr := exec.Command(
			"cmd.exe", "/D", "/C", "mklink", "/J", linkRoot, realRoot,
		).CombinedOutput(); junctionErr != nil {
			t.Fatalf("create reparse-point fixture after symlink error %v: %v\n%s", err, junctionErr, output)
		}
	}
	t.Cleanup(func() { _ = os.Remove(linkRoot) })
	state := nativeWindowsInstallState{
		SchemaVersion: 1,
		InstallKind:   "native-windows-exe",
		InstallScope:  "user",
		InstallRoot:   linkRoot,
		CommandDir:    filepath.Join(linkRoot, "bin"),
		Runtime:       filepath.Join(linkRoot, "runtime", "python"),
	}
	body, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(installerDir, "install-state.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := packagedWindowsHookBinaryAtRoot(
		filepath.Join(linkRoot, "bin", windowsGatewayBinaryName),
		linkRoot,
	); got != "" {
		t.Fatalf("reparse-point install root selected hook binary %q", got)
	}
}

func TestNativeHookOwnershipRetainsLegacyUserInstall(t *testing.T) {
	legacy := filepath.Join(userHomeDir(), ".local", "bin", windowsHookBinaryName)
	command := windowsQuoteExe(legacy) + " " + nativeHookFlag + "claudecode"
	if !isNativeHookCommand(command) {
		t.Fatalf("legacy managed hook command was not recognized: %q", command)
	}
}

func TestWindowsHookContractLockIncludesNativeLauncherDigest(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows native launcher contract")
	}
	root := t.TempDir()
	launcher := filepath.Join(root, windowsHookBinaryName)
	if err := os.WriteFile(launcher, []byte("MZfixture-launcher"), 0o700); err != nil {
		t.Fatal(err)
	}
	setHookBinaryOverride(t, launcher)
	opts := SetupOpts{DataDir: filepath.Join(root, "data"), HookFailMode: "closed"}
	entry := NewHookContractLockEntry(opts, NewClaudeCodeConnector(), "test")
	if entry.HookScriptDigests[windowsHookBinaryName] == "" {
		t.Fatalf("native launcher digest missing: %v", entry.HookScriptDigests)
	}
	if !stringInSlice(entry.Locations.HookScriptPaths, launcher) {
		t.Fatalf("native launcher path missing: %v", entry.Locations.HookScriptPaths)
	}
}

// TestHookInvocationCommand pins the platform split: Unix runs the bundled .sh
// path; Windows Cursor uses the PowerShell object-pipeline adapter while other
// connectors invoke the native Go `hook` subcommand directly. PowerShell
// shell-string connectors include its call operator.
func TestHookInvocationCommand(t *testing.T) {
	const unix = "/home/u/.defenseclaw/hooks/codex-hook.sh"
	const cursorUnix = "/home/u/.defenseclaw/hooks/cursor-hook.sh"
	const windowsExe = `C:\Program Files\DefenseClaw\defenseclaw-hook.exe`
	setHookBinaryOverride(t, windowsExe)

	for _, goos := range []string{"linux", "darwin"} {
		if got := hookInvocationCommandFor(goos, "codex", unix); got != unix {
			t.Errorf("%s command = %q, want passthrough %q", goos, got, unix)
		}
	}

	win := hookInvocationCommandFor("windows", "cursor", cursorUnix)
	wantWin := `& '/home/u/.defenseclaw/hooks/cursor-hook.ps1'`
	if win != wantWin {
		t.Errorf("windows command = %q, want %q", win, wantWin)
	}
	if !strings.Contains(win, "cursor-hook.ps1") {
		t.Errorf("windows command = %q, missing Cursor adapter", win)
	}
	if strings.Contains(win, ".sh") || strings.Contains(win, ".cmd") || strings.Contains(win, "bash") {
		t.Errorf("windows command = %q should reference only the PowerShell adapter", win)
	}
	if got := shellWord(win); got != win {
		t.Errorf("shellWord(Cursor adapter) = %q, want complete PowerShell command %q", got, win)
	}
	if isNativeHookCommand(win) {
		t.Errorf("isNativeHookCommand(%q) = true for adapter command", win)
	}
	if isNativeHookCommand(unix) {
		t.Errorf("isNativeHookCommand(%q) = true, want false for a .sh path", unix)
	}

	// Codex passes this string to cmd.exe /C as one argument. Do not use the
	// quoted absolute-path form that Windows re-escapes into a literal argv[0].
	codex := hookInvocationCommandFor("windows", "codex", unix)
	wantCodex := windowsSafePATHCommandPrefix + windowsHookBinaryName + " " + nativeHookFlag + "codex"
	if codex != wantCodex {
		t.Errorf("codex command = %q, want %q", codex, wantCodex)
	}
	if strings.ContainsAny(codex, `"'`) {
		t.Errorf("codex cmd.exe command contains quote characters: %q", codex)
	}
	if !isNativeHookCommand(codex) {
		t.Errorf("isNativeHookCommand(%q) = false, want true", codex)
	}

	// Claude Code accepts an exact command string and therefore uses the
	// absolute, quoted, installer-managed launcher. It must never regress to a
	// bare or PATH-resolved form that an untrusted current directory can shadow.
	claude := hookInvocationCommandFor("windows", "claudecode", unix)
	wantClaude := "& " + powershellQuoteLiteral(windowsExe) + " " + nativeHookFlag + "claudecode"
	if claude != wantClaude {
		t.Errorf("claudecode command = %q, want %q", claude, wantClaude)
	}
	if strings.HasPrefix(claude, windowsSafePATHCommandPrefix) ||
		strings.HasPrefix(claude, windowsHookBinaryName+" ") {
		t.Errorf("claudecode command is PATH/bare resolved: %q", claude)
	}
	if !isNativeHookCommand(claude) {
		t.Errorf("isNativeHookCommand(%q) = false, want true", claude)
	}

	// Antigravity's direct-exec parser does not dequote command paths. Keep the
	// visible command tokenizer-safe and put the absolute managed hook path in a
	// PowerShell encoded command so install roots containing spaces still work.
	agy := hookInvocationCommandFor("windows", "antigravity", unix)
	if !strings.HasPrefix(agy, windowsSystemPowerShellExe()+" -NoLogo -NoProfile -NonInteractive -EncodedCommand ") {
		t.Errorf("antigravity command = %q", agy)
	}
	if strings.ContainsAny(agy, `"'`) {
		t.Errorf("antigravity direct-exec command contains literal quotes: %q", agy)
	}
	if strings.Contains(agy, legacyAntigravityWindowsHookCommand()) {
		t.Errorf("antigravity command still contains vulnerable bare launcher: %q", agy)
	}
	decoded := decodePowerShellEncodedCommandForTest(t, agy)
	if !strings.Contains(decoded, powershellQuoteLiteral(windowsExe)) ||
		!strings.Contains(decoded, nativeHookFlag+"antigravity") ||
		!strings.Contains(decoded, "NoDefaultCurrentDirectoryInExePath") {
		t.Errorf("antigravity encoded command lost managed launcher or hardening:\n%s", decoded)
	}
}

// TestClaudeCodeWindowsHookCommandRunsInPowerShell reproduces the Windows
// shell boundary that treats a quoted path as a string unless it is preceded
// by PowerShell's call operator.
func TestClaudeCodeWindowsHookCommandRunsInPowerShell(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("PowerShell launch semantics are Windows-specific")
	}

	root := filepath.Join(t.TempDir(), "Install Root With Spaces")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(root, windowsHookBinaryName)
	source := filepath.Join(root, "hook-probe.go")
	probeOutput := filepath.Join(root, "hook-args.txt")
	body := `package main
import (
	"os"
	"strings"
)
func main() {
	if len(os.Args) != 4 || os.Args[1] != "hook" || os.Args[2] != "--connector" || os.Args[3] != "claudecode" {
		os.Exit(9)
	}
	if err := os.WriteFile(os.Getenv("DEFENSECLAW_HOOK_PROBE"), []byte(strings.Join(os.Args[1:], "|")), 0600); err != nil {
		os.Exit(10)
	}
}
`
	if err := os.WriteFile(source, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("go", "build", "-o", helper, source).CombinedOutput(); err != nil {
		t.Fatalf("build hook probe: %v\n%s", err, out)
	}
	setHookBinaryOverride(t, helper)
	command := hookInvocationCommandFor("windows", "claudecode", "")

	ps := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command)
	ps.Env = append(os.Environ(), "DEFENSECLAW_HOOK_PROBE="+probeOutput)
	if out, err := ps.CombinedOutput(); err != nil {
		t.Fatalf("Claude Code-style PowerShell launch failed: %v\ncommand: %s\noutput: %s", err, command, out)
	}
	got, err := os.ReadFile(probeOutput)
	if err != nil {
		t.Fatalf("read hook probe output: %v", err)
	}
	if string(got) != "hook|--connector|claudecode" {
		t.Fatalf("hook args = %q", got)
	}
}

// TestCursorWindowsAdapterPreservesObjectPipelineJSON reproduces Cursor 3.9's
// actual Windows launch boundary: Get-Content reads a vendor temp file and
// passes the payload through PowerShell's object pipeline into the configured
// hook command. A native executable receives only encoding preambles on this
// boundary; the generated adapter must recover the JSON exactly, invoke the
// launcher through --input-file, forward stdout, and remove its payload file.
func TestCursorWindowsAdapterPreservesObjectPipelineJSON(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Cursor PowerShell transport is Windows-specific")
	}

	root := t.TempDir()
	hookDir := filepath.Join(root, "hooks")
	helper := filepath.Join(root, "fake-defenseclaw-hook.exe")
	helperSource := filepath.Join(root, "fake-defenseclaw-hook.go")
	helperBody := `package main

import (
	"fmt"
	"os"
)

func main() {
	for i, arg := range os.Args {
		if arg != "--input-file" || i+1 >= len(os.Args) {
			continue
		}
		payload, err := os.ReadFile(os.Args[i+1])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(8)
		}
		_, _ = os.Stdout.Write(payload)
		return
	}
	fmt.Fprintln(os.Stderr, "missing input file argument")
	os.Exit(9)
}
`
	if err := os.WriteFile(helperSource, []byte(helperBody), 0o600); err != nil {
		t.Fatalf("write launcher probe source: %v", err)
	}
	build := exec.Command("go", "build", "-o", helper, helperSource)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build launcher probe: %v\n%s", err, output)
	}
	setHookBinaryOverride(t, helper)

	if err := WriteHookScriptsForConnectorObject(
		hookDir,
		"127.0.0.1:18970",
		"tok-test",
		NewCursorConnector(),
	); err != nil {
		t.Fatalf("render Cursor adapter: %v", err)
	}

	payload := `{"hook_event_name":"beforeSubmitPrompt","prompt":"DefenseClaw Cursor adapter test"}`
	vendorInput := filepath.Join(root, "cursor-vendor-input.json")
	if err := os.WriteFile(vendorInput, []byte(payload), 0o600); err != nil {
		t.Fatalf("write Cursor vendor input: %v", err)
	}
	configuredCommand := hookInvocationCommand(
		"cursor",
		filepath.Join(hookDir, "cursor-hook.sh"),
	)
	command := "$OutputEncoding = [System.Text.Encoding]::UTF8; " +
		"Get-Content -LiteralPath " + powershellQuoteLiteral(vendorInput) +
		" -Raw | & { $input | " + configuredCommand + " }"

	out, err := exec.Command(
		"powershell.exe",
		"-NoProfile",
		"-NonInteractive",
		"-Command",
		command,
	).CombinedOutput()
	if err != nil {
		t.Fatalf("Cursor-style PowerShell launch failed: %v\ncommand: %s\noutput: %s", err, command, out)
	}
	if !strings.Contains(strings.TrimSpace(string(out)), payload) {
		t.Fatalf("adapter output did not preserve JSON\nwant: %s\ngot: %q", payload, out)
	}
	leftovers, err := filepath.Glob(filepath.Join(hookDir, ".cursor-input-*.json"))
	if err != nil {
		t.Fatalf("find adapter payload leftovers: %v", err)
	}
	if len(leftovers) != 0 {
		t.Fatalf("adapter left temporary payload files behind: %v", leftovers)
	}
}

// TestCodexWindowsHookCommandRunsAsSingleCmdArgument reproduces Codex's native
// Windows launch shape. The probe substitutes a system executable for the
// gateway while preserving the generated command prefix and single-argument
// cmd.exe /C boundary; a leading quoted executable would fail before where.exe
// starts, which is the production regression this test guards against.
func TestCodexWindowsHookCommandRunsAsSingleCmdArgument(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("cmd.exe launch semantics are Windows-specific")
	}

	command := hookInvocationCommandFor("windows", "codex", "")
	wantTail := windowsHookBinaryName + " " + nativeHookFlag + "codex"
	probe := strings.Replace(command, wantTail, "where.exe cmd.exe", 1)
	if probe == command {
		t.Fatalf("generated Codex command %q did not contain %q", command, wantTail)
	}
	comspec := os.Getenv("COMSPEC")
	if comspec == "" {
		comspec = "cmd.exe"
	}
	out, err := exec.Command(comspec, "/C", probe).CombinedOutput()
	if err != nil {
		t.Fatalf("Codex-style cmd.exe launch failed: %v\ncommand: %s\noutput: %s", err, probe, out)
	}
	if !strings.Contains(strings.ToLower(string(out)), "cmd.exe") {
		t.Fatalf("Codex-style cmd.exe probe did not execute where.exe; output: %s", out)
	}
}

func TestAntigravityWindowsHookCommandBypassesUntrustedCurrentDirectory(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Antigravity direct-exec exploit regression is Windows-specific")
	}

	root := t.TempDir()
	managedDir := filepath.Join(root, "Managed Install With Spaces")
	untrustedDir := filepath.Join(root, "Untrusted Workspace")
	if err := os.MkdirAll(managedDir, 0o700); err != nil {
		t.Fatalf("create managed dir: %v", err)
	}
	if err := os.MkdirAll(untrustedDir, 0o700); err != nil {
		t.Fatalf("create untrusted dir: %v", err)
	}
	managedMarker := filepath.Join(root, "managed.txt")
	fakeMarker := filepath.Join(root, "fake.txt")
	managedHook := buildAntigravityProbeLauncher(t, managedDir, "managed", managedMarker, 0, true)
	_ = buildAntigravityProbeLauncher(t, untrustedDir, "fake", fakeMarker, 42, false)
	setHookBinaryOverride(t, managedHook)

	command := hookInvocationCommandFor("windows", "antigravity", "")
	argv := strings.Fields(command)
	if len(argv) == 0 {
		t.Fatalf("empty Antigravity command")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir = untrustedDir
	cmd.Env = append(os.Environ(), "PATH="+untrustedDir+";"+managedDir+";"+os.Getenv("PATH"))
	cmd.Stdin = strings.NewReader(`{"hookEventName":"PreToolUse"}`)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Antigravity direct-exec probe failed: %v\ncommand: %s\noutput: %s", err, command, out)
	}
	if _, err := os.Stat(fakeMarker); !os.IsNotExist(err) {
		t.Fatalf("untrusted current-directory launcher was executed; marker err=%v", err)
	}
	data, err := os.ReadFile(managedMarker)
	if err != nil {
		t.Fatalf("managed launcher marker missing: %v\ncommand: %s\noutput: %s", err, command, out)
	}
	text := string(data)
	if !strings.Contains(text, "managed") ||
		!strings.Contains(text, "hook") ||
		!strings.Contains(text, "--connector") ||
		!strings.Contains(text, "antigravity") ||
		!strings.Contains(text, `"hookEventName":"PreToolUse"`) {
		t.Fatalf("managed launcher received wrong invocation: %q", text)
	}
}

func buildAntigravityProbeLauncher(t *testing.T, dir, label, marker string, exitCode int, validate bool) string {
	t.Helper()
	source := filepath.Join(dir, label+"-hook-probe.go")
	body := fmt.Sprintf(`package main

import (
	"io"
	"os"
	"strings"
)

func main() {
	stdin, _ := io.ReadAll(os.Stdin)
	_ = os.WriteFile(%q, []byte(%q+"\n"+strings.Join(os.Args, "\n")+"\n"+string(stdin)), 0o600)
	if %t && (len(os.Args) != 4 || os.Args[1] != "hook" || os.Args[2] != "--connector" || os.Args[3] != "antigravity") {
		os.Exit(7)
	}
	os.Exit(%d)
}
`, marker, label, validate, exitCode)
	if err := os.WriteFile(source, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s probe source: %v", label, err)
	}
	exe := filepath.Join(dir, windowsHookBinaryName)
	build := exec.Command("go", "build", "-o", exe, source)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build %s probe launcher: %v\n%s", label, err, output)
	}
	return exe
}

// TestShellWordPassesNativeCommandThrough ensures the bash-style quoter does not
// corrupt the native Windows command (which is already a complete command line)
// while still quoting Unix script paths for the agent's shell.
func TestShellWordPassesNativeCommandThrough(t *testing.T) {
	setHookBinaryOverride(t, `C:\Program Files\DefenseClaw\defenseclaw-hook.exe`)
	native := `"C:\Program Files\DefenseClaw\defenseclaw-hook.exe" hook --connector cursor`
	if got := shellWord(native); got != native {
		t.Errorf("shellWord(native) = %q, want unchanged", got)
	}
	if got := shellWord("/home/u/hooks/cursor-hook.sh"); got != "'/home/u/hooks/cursor-hook.sh'" {
		t.Errorf("shellWord(path) = %q, want single-quoted", got)
	}
}

// TestBuildCodexHooksTableHashesTheCommand verifies the Codex hooks table writes
// the trust hash over the exact command it executes (so Codex recognizes it),
// and that teardown reproduces the same fingerprint to remove the state.
func TestBuildCodexHooksTableHashesTheCommand(t *testing.T) {
	const cmd = windowsSafePATHCommandPrefix + windowsHookBinaryName + " " + nativeHookFlag + "codex"
	const configPath = "/home/u/.codex/config.toml"

	table := buildCodexHooksTable(configPath, cmd)

	for _, group := range codexHookGroups {
		raw, ok := table[group.eventType].([]interface{})
		if !ok || len(raw) == 0 {
			t.Fatalf("missing event %s", group.eventType)
		}
		mg := raw[0].(map[string]interface{})
		hooks := mg["hooks"].([]interface{})
		h0 := hooks[0].(map[string]interface{})
		if got := h0["command"].(string); got != cmd {
			t.Errorf("event %s command = %q, want %q", group.eventType, got, cmd)
		}
	}

	state, ok := table["state"].(map[string]interface{})
	if !ok || len(state) == 0 {
		t.Fatal("expected non-empty state table")
	}

	// Teardown with the same command recognizes and removes every entry.
	hooks := map[string]interface{}{"state": state}
	if !removeOwnedCodexHookState(hooks, configPath, cmd) {
		t.Fatal("removeOwnedCodexHookState did not recognize its own hash")
	}
	if _, present := hooks["state"]; present {
		t.Error("state should be deleted once every owned entry is removed")
	}

	// A different command must NOT match (ownership specificity).
	fresh := buildCodexHooksTable(configPath, cmd)
	freshHooks := map[string]interface{}{"state": fresh["state"]}
	if removeOwnedCodexHookState(freshHooks, configPath, `"other.exe" hook --connector codex`) {
		t.Error("teardown removed state for a command it never wrote")
	}
}

// TestIsOwnedHookRecognizesNativeCommand covers the Claude Code / hook teardown
// recognizer for the native Windows command, which is not a file path under the
// hooks dir and carries no on-disk marker.
func TestIsOwnedHookRecognizesNativeCommand(t *testing.T) {
	const hooksDir = "/home/u/.defenseclaw/hooks"
	setHookBinaryOverride(t, `C:\Program Files\DefenseClaw\defenseclaw-hook.exe`)

	owned := map[string]interface{}{
		"hooks": []interface{}{
			map[string]interface{}{
				"type":    "command",
				"command": `& 'C:\Program Files\DefenseClaw\defenseclaw-hook.exe' hook --connector claudecode`,
			},
		},
	}
	if !isOwnedHook(owned, hooksDir) {
		t.Error("native hook command not recognized as DefenseClaw-owned")
	}

	foreign := map[string]interface{}{
		"hooks": []interface{}{
			map[string]interface{}{"type": "command", "command": "/usr/bin/some-other-tool --flag"},
		},
	}
	if isOwnedHook(foreign, hooksDir) {
		t.Error("foreign command wrongly recognized as DefenseClaw-owned")
	}

	spoofed := map[string]interface{}{
		"hooks": []interface{}{
			map[string]interface{}{
				"type":    "command",
				"command": `"C:\Tools\other.exe" hook --connector claudecode`,
			},
		},
	}
	if isOwnedHook(spoofed, hooksDir) {
		t.Error("foreign executable with native-hook arguments wrongly recognized as owned")
	}

	foreignSameBasename := map[string]interface{}{
		"hooks": []interface{}{
			map[string]interface{}{
				"type":    "command",
				"command": `"C:\Tools\defenseclaw-hook.exe" hook --connector claudecode`,
			},
		},
	}
	if isOwnedHook(foreignSameBasename, hooksDir) {
		t.Error("different absolute gateway path was incorrectly recognized as owned")
	}
}

func TestCodexNativeNotifyOwnership(t *testing.T) {
	setHookBinaryOverride(t, `C:\Program Files\DefenseClaw\defenseclaw-hook.exe`)
	opts := SetupOpts{DataDir: `C:\Users\me\.defenseclaw`}
	owned := []interface{}{`C:\Program Files\DefenseClaw\defenseclaw-hook.exe`, "notify"}
	if !codexNotifyLooksManaged(owned, opts) {
		t.Fatal("native Codex notifier was not recognized as managed")
	}
	legacy := []interface{}{filepath.Join(userHomeDir(), ".local", "bin", windowsGatewayBinaryName), "notify"}
	if !codexNotifyLooksManaged(legacy, opts) {
		t.Fatal("legacy installed gateway notifier was not recognized for migration")
	}
	foreign := []interface{}{`C:\Tools\desktop-notifier.exe`, "notify"}
	if codexNotifyLooksManaged(foreign, opts) {
		t.Fatal("foreign notifier was incorrectly recognized as managed")
	}
	foreignSameBasename := []interface{}{`C:\Tools\defenseclaw-hook.exe`, "notify"}
	if codexNotifyLooksManaged(foreignSameBasename, opts) {
		t.Fatal("different absolute hook notifier was incorrectly recognized as managed")
	}
}

// TestWindowsNativeConfigMatrix exercises the generated on-disk configs for
// every WIN-016 native target plus the Hermes preview. OpenCode is intentionally
// absent: its bridge remains a JavaScript plugin and has separate tests.
func TestWindowsNativeConfigMatrix(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-native config matrix")
	}
	setHookBinaryOverride(t, `C:\Program Files\DefenseClaw\defenseclaw-hook.exe`)

	tests := []struct {
		name     string
		conn     Connector
		override *string
		ext      string
	}{
		{"codex", NewCodexConnector(), &CodexConfigPathOverride, ".toml"},
		{"claudecode", NewClaudeCodeConnector(), &ClaudeCodeSettingsPathOverride, ".json"},
		{"cursor", NewCursorConnector(), &CursorHooksPathOverride, ".json"},
		{"windsurf", NewWindsurfConnector(), &WindsurfHooksPathOverride, ".json"},
		{"geminicli", NewGeminiCLIConnector(), &GeminiSettingsPathOverride, ".json"},
		{"copilot", NewCopilotConnector(), &CopilotHooksPathOverride, ".json"},
		{"antigravity", NewAntigravityConnector(), &AntigravityHooksPathOverride, ".json"},
		{"hermes-preview", NewHermesConnector(), &HermesConfigPathOverride, ".yaml"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "Defense Claw Matrix")
			configPath := filepath.Join(root, tt.name+tt.ext)
			previous := *tt.override
			*tt.override = configPath
			t.Cleanup(func() { *tt.override = previous })

			dataDir := filepath.Join(root, "Data Dir")
			opts := SetupOpts{
				DataDir:      dataDir,
				APIAddr:      "127.0.0.1:18970",
				APIToken:     "matrix-token",
				HookFailMode: "closed",
				WorkspaceDir: filepath.Join(root, "Workspace"),
			}
			if err := tt.conn.Setup(context.Background(), opts); err != nil {
				t.Fatalf("Setup: %v", err)
			}
			data, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatalf("read generated config: %v", err)
			}
			text := string(data)
			connectorName := tt.conn.Name()
			if connectorName == "cursor" {
				wantCommand := hookInvocationCommand(
					"cursor",
					filepath.Join(dataDir, "hooks", "cursor-hook.sh"),
				)
				encodedCommand, err := json.Marshal(wantCommand)
				if err != nil {
					t.Fatalf("encode Cursor Windows adapter command: %v", err)
				}
				if !strings.Contains(text, string(encodedCommand)) {
					t.Errorf("config missing Cursor Windows adapter command %q:\n%s", wantCommand, text)
				}
				adapter, err := os.ReadFile(filepath.Join(dataDir, "hooks", "cursor-hook.ps1"))
				if err != nil {
					t.Fatalf("read Cursor Windows adapter: %v", err)
				}
				adapterText := string(adapter)
				if !strings.Contains(adapterText, windowsHookBinaryName) ||
					!strings.Contains(adapterText, "--input-file") {
					t.Errorf("Cursor adapter does not invoke the native launcher through --input-file:\n%s", adapter)
				}
				for _, marker := range []string{
					"$timeoutMs = 10000",
					"WaitForExit($timeoutMs)",
					"$process.Kill()",
					`{"continue":true}`,
					"could not remove temporary Cursor payload",
				} {
					if !strings.Contains(adapterText, marker) {
						t.Errorf("Cursor adapter missing hardening marker %q:\n%s", marker, adapter)
					}
				}
			} else if connectorName == "antigravity" {
				wantCommand := hookInvocationCommand(
					"antigravity",
					filepath.Join(dataDir, "hooks", "antigravity-hook.sh"),
				)
				encodedCommand, err := json.Marshal(wantCommand)
				if err != nil {
					t.Fatalf("encode Antigravity Windows command: %v", err)
				}
				if !strings.Contains(text, string(encodedCommand)) {
					t.Errorf("config missing safe Antigravity command %q:\n%s", wantCommand, text)
				}
				if strings.Contains(text, legacyAntigravityWindowsHookCommand()) {
					t.Errorf("config still contains legacy bare Antigravity launcher:\n%s", text)
				}
				decoded := decodePowerShellEncodedCommandForTest(t, wantCommand)
				if !strings.Contains(decoded, powershellQuoteLiteral(defenseclawHookBinary())) {
					t.Errorf("Antigravity encoded command missing managed launcher path:\n%s", decoded)
				}
			} else {
				if !strings.Contains(text, windowsHookBinaryName) {
					t.Errorf("config does not invoke %s:\n%s", windowsHookBinaryName, text)
				}
				if !strings.Contains(text, nativeHookFlag+connectorName) {
					t.Errorf("config missing native connector command for %s:\n%s", connectorName, text)
				}
			}
			lower := strings.ToLower(text)
			for _, forbidden := range []string{".sh", `"bash"`, "curl", "jq"} {
				if strings.Contains(lower, forbidden) {
					t.Errorf("config contains forbidden Windows hook dependency %q:\n%s", forbidden, text)
				}
			}
			if connectorName == "copilot" {
				cfg, err := readJSONObject(configPath)
				if err != nil {
					t.Fatalf("parse Copilot config: %v", err)
				}
				hooks, _ := cfg["hooks"].(map[string]interface{})
				want := "& " + hookInvocationCommand("copilot", "")
				for event, raw := range hooks {
					entries, _ := raw.([]interface{})
					if len(entries) == 0 {
						t.Fatalf("Copilot %s hook has no entries", event)
					}
					entry, _ := entries[0].(map[string]interface{})
					if got, _ := entry["powershell"].(string); got != want {
						t.Errorf("Copilot %s powershell command = %q, want %q", event, got, want)
					}
					if _, present := entry["bash"]; present {
						t.Errorf("Copilot %s retained a bash command on Windows", event)
					}
				}
			}

			hookDir := filepath.Join(dataDir, "hooks")
			tokenPath := filepath.Join(hookDir, ".token")
			scopedToken := !IsProxyConnector(connectorName)
			if scopedToken {
				tokenPath, err = HookTokenFilePath(hookDir, connectorName)
				if err != nil {
					t.Fatalf("resolve connector-scoped hook token sidecar: %v", err)
				}
				if _, err := os.Lstat(filepath.Join(hookDir, ".token")); !os.IsNotExist(err) {
					t.Fatalf("legacy shared hook token sidecar still exists: %v", err)
				}
			}
			token, err := os.ReadFile(tokenPath)
			if err != nil {
				t.Fatalf("read hook token sidecar: %v", err)
			}
			if !strings.Contains(string(token), "matrix-token") {
				t.Error("hook token sidecar does not contain the configured token")
			}
			hookCfg, err := os.ReadFile(filepath.Join(dataDir, "hooks", hookConfigSidecarName))
			if err != nil {
				t.Fatalf("read native hook config sidecar: %v", err)
			}
			var hookState hookConfigSidecar
			if err := json.Unmarshal(hookCfg, &hookState); err != nil {
				t.Fatalf("parse native hook config sidecar: %v", err)
			}
			if hookState.GatewayAddr != "127.0.0.1:18970" {
				t.Errorf("hook config sidecar API address = %q", hookState.GatewayAddr)
			}
			wantFailMode := resolveHookFailMode(opts, tt.conn)
			if hp, ok := tt.conn.(HookCapabilityProvider); ok &&
				wantFailMode == "closed" && !hp.HookCapabilities(opts).SupportsFailClosed {
				wantFailMode = "open"
			}
			if got := hookState.FailModes[connectorName]; got != wantFailMode {
				t.Errorf("hook config sidecar fail mode = %q, want %q", got, wantFailMode)
			}

			if err := tt.conn.Teardown(context.Background(), opts); err != nil {
				t.Fatalf("Teardown: %v", err)
			}
			if err := tt.conn.VerifyClean(opts); err != nil {
				t.Fatalf("VerifyClean after teardown: %v", err)
			}
			if _, err := os.Stat(configPath); !os.IsNotExist(err) {
				t.Errorf("generated config survived teardown: %v", err)
			}
			// Runtime sidecars can still be referenced by another managed config
			// for the same connector, so one config teardown must preserve them.
			if _, err := os.Stat(filepath.Join(hookDir, hookConfigSidecarName)); err != nil {
				t.Errorf("shared sidecar %s removed by connector teardown: %v", hookConfigSidecarName, err)
			}
			if _, err := os.Stat(tokenPath); err != nil {
				t.Errorf("hook token sidecar removed by connector teardown: %v", err)
			}
		})
	}
}
