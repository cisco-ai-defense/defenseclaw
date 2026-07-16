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

//go:build windows

package connector

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
	"github.com/pelletier/go-toml/v2"
)

const windowsHookTransportProbeStderr = "hook-probe stderr Ω\n"

type windowsHookTransport struct {
	name    string
	command string
	args    []string
	viaCmd  bool
}

type windowsHookTransportResult struct {
	exitCode int
	stdout   []byte
	stderr   []byte
	elapsed  time.Duration
}

// TestWindowsNativeHookTransportsWaitPropagateExitAndPreserveStreams exercises
// the commands actually persisted for both affected Windows connectors. Codex
// crosses cmd.exe and the encoded system Windows PowerShell boundary. Claude
// Code uses its current structured command-plus-args native exec transport.
func TestWindowsNativeHookTransportsWaitPropagateExitAndPreserveStreams(t *testing.T) {
	root := filepath.Join(t.TempDir(), "WIN-AUD-069 hook Ω O'Brien")
	managedDir := filepath.Join(root, "Managed Install")
	untrustedDir := filepath.Join(root, "Workspace")
	managedHook := buildWindowsGUIHookTransportProbe(t, managedDir)
	_ = buildWindowsGUIHookTransportProbe(t, untrustedDir)
	setHookBinaryOverride(t, managedHook)

	claudeCommand, claudeArgs := claudeCodeHookInvocation(
		SetupOpts{HookExecutable: managedHook},
		"",
	)
	if !sameWindowsInstallPath(claudeCommand, managedHook) {
		t.Fatalf("Claude Code command = %q, want managed hook %q", claudeCommand, managedHook)
	}
	transports := []windowsHookTransport{
		{
			name:    "codex encoded PowerShell",
			command: generatedCodexWindowsHookCommand(t),
			viaCmd:  true,
		},
		{
			name:    "claudecode structured exec",
			command: claudeCommand,
			args:    claudeArgs,
		},
	}

	payload := []byte("{\"hook_event_name\":\"PreToolUse\",\"text\":\"Ω O'Brien\"}\n")
	for _, transport := range transports {
		transport := transport
		t.Run(transport.name, func(t *testing.T) {
			for _, wantExit := range []int{0, 1, 2} {
				t.Run(fmt.Sprintf("exit_%d", wantExit), func(t *testing.T) {
					marker := filepath.Join(root, transport.name+"-"+strconv.Itoa(wantExit)+".marker")
					result := runWindowsHookTransport(
						t,
						transport,
						untrustedDir,
						marker,
						wantExit,
						payload,
					)
					if result.exitCode != wantExit {
						t.Fatalf(
							"wrapper exit = %d, want child exit %d; stdout=%q stderr=%q",
							result.exitCode,
							wantExit,
							result.stdout,
							result.stderr,
						)
					}
					if result.elapsed < 300*time.Millisecond {
						t.Fatalf("transport returned before delayed GUI child: %s", result.elapsed)
					}
					if !bytes.Equal(result.stdout, payload) {
						t.Fatalf("stdout bytes changed:\n got %x\nwant %x", result.stdout, payload)
					}
					if !bytes.Equal(result.stderr, []byte(windowsHookTransportProbeStderr)) {
						t.Fatalf(
							"stderr bytes changed:\n got %x\nwant %x",
							result.stderr,
							[]byte(windowsHookTransportProbeStderr),
						)
					}
					executed, err := os.ReadFile(marker)
					if err != nil {
						t.Fatalf("read hook probe marker: %v", err)
					}
					if !sameWindowsInstallPath(string(executed), managedHook) {
						t.Fatalf(
							"workspace/PATH launcher won: executed %q, want %q",
							string(executed),
							managedHook,
						)
					}
				})
			}
		})
	}
}

func TestWindowsCodexHookWrapperIgnoresStaleLastExitCode(t *testing.T) {
	root := filepath.Join(t.TempDir(), "WIN-AUD-069 stale exit")
	managedHook := buildWindowsGUIHookTransportProbe(t, filepath.Join(root, "Managed"))
	untrustedDir := filepath.Join(root, "Workspace")
	if err := os.MkdirAll(untrustedDir, 0o700); err != nil {
		t.Fatal(err)
	}

	script := "$global:LASTEXITCODE=73; " + windowsNativePowerShellHookScriptForBinary("codex", managedHook)
	command := windowsSystemPowerShellExe() + " -NoLogo -NoProfile -NonInteractive -EncodedCommand " +
		powershellEncodedCommand(script)
	payload := []byte("{\"hook_event_name\":\"PreToolUse\"}\n")
	result := runWindowsHookTransport(
		t,
		windowsHookTransport{name: "codex stale LASTEXITCODE", command: command, viaCmd: true},
		untrustedDir,
		filepath.Join(root, "stale.marker"),
		2,
		payload,
	)
	if result.exitCode != 2 {
		t.Fatalf("wrapper exit = %d, want child exit 2; stderr=%q", result.exitCode, result.stderr)
	}
}

func TestWindowsCodexSetupRepairsLegacyEncodedHookAndTrustState(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	configPath := filepath.Join(root, "codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	previousConfigPath := CodexConfigPathOverride
	CodexConfigPathOverride = configPath
	t.Cleanup(func() { CodexConfigPathOverride = previousConfigPath })

	managedHook := buildWindowsGUIHookTransportProbe(t, filepath.Join(root, "Managed Hook"))
	setHookBinaryOverride(t, managedHook)
	connector := NewCodexConnector()
	opts := SetupOpts{DataDir: filepath.Join(root, "data"), APIAddr: "127.0.0.1:18970"}
	if err := connector.Setup(context.Background(), opts); err != nil {
		t.Fatalf("initial Setup: %v", err)
	}

	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	configured := map[string]interface{}{}
	if err := toml.Unmarshal(raw, &configured); err != nil {
		t.Fatal(err)
	}
	hooks := configured["hooks"].(map[string]interface{})
	legacyCommand := legacyWindowsNativePowerShellHookCommandForBinary("codex", managedHook)
	legacyState := map[string]interface{}{}
	keySource := codexHookStateKeySource(configPath)
	for _, expected := range codexHookGroups {
		groups := hooks[expected.eventType].([]interface{})
		group := groups[0].(map[string]interface{})
		handler := group["hooks"].([]interface{})[0].(map[string]interface{})
		handler["command"] = legacyCommand
		handler["command_windows"] = legacyCommand
		eventKey := codexHookEventKeyLabel(expected.eventType)
		hash, err := codexCommandHookHashForPlatform("windows", eventKey, group["matcher"], handler)
		if err != nil {
			t.Fatalf("hash legacy %s handler: %v", expected.eventType, err)
		}
		key := codexHookStateKey(keySource, eventKey, 0, 0)
		legacyState[key] = map[string]interface{}{"trusted_hash": hash}
	}
	hooks["state"] = legacyState
	legacyRaw, err := toml.Marshal(configured)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, legacyRaw, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := connector.Setup(context.Background(), opts); err != nil {
		t.Fatalf("repair Setup: %v", err)
	}
	repairedRaw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(repairedRaw, []byte(legacyCommand)) {
		t.Fatal("repair left the legacy asynchronous encoded command registered")
	}
	repaired := map[string]interface{}{}
	if err := toml.Unmarshal(repairedRaw, &repaired); err != nil {
		t.Fatal(err)
	}
	repairedHooks := repaired["hooks"].(map[string]interface{})
	if err := verifyTrustedCodexHookMatrix(
		repairedHooks,
		configPath,
		filepath.Join(opts.DataDir, "hooks"),
	); err != nil {
		t.Fatalf("repaired hook matrix or trust hashes are invalid: %v", err)
	}
	if err := connector.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown after repair: %v", err)
	}
	if err := connector.VerifyClean(opts); err != nil {
		t.Fatalf("VerifyClean after repaired teardown: %v", err)
	}
}

func generatedCodexWindowsHookCommand(t *testing.T) string {
	t.Helper()
	table := buildCodexHooksTable("", "")
	groups, ok := table["PreToolUse"].([]interface{})
	if !ok || len(groups) == 0 {
		t.Fatalf("generated Codex hooks omit PreToolUse: %#v", table)
	}
	group, ok := groups[0].(map[string]interface{})
	if !ok {
		t.Fatalf("generated Codex matcher has type %T", groups[0])
	}
	hooks, ok := group["hooks"].([]interface{})
	if !ok || len(hooks) == 0 {
		t.Fatalf("generated Codex matcher omits hooks: %#v", group)
	}
	handler, ok := hooks[0].(map[string]interface{})
	if !ok {
		t.Fatalf("generated Codex handler has type %T", hooks[0])
	}
	command, _ := handler["command_windows"].(string)
	if command == "" {
		t.Fatalf("generated Codex handler omits command_windows: %#v", handler)
	}
	return command
}

func runWindowsHookTransport(
	t *testing.T,
	transport windowsHookTransport,
	workingDir string,
	marker string,
	exitCode int,
	stdin []byte,
) windowsHookTransportResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	var command *exec.Cmd
	if transport.viaCmd {
		comspec := os.Getenv("COMSPEC")
		if comspec == "" {
			comspec = "cmd.exe"
		}
		command = exec.CommandContext(ctx, comspec, "/D", "/S", "/C", transport.command)
	} else {
		command = exec.CommandContext(ctx, transport.command, transport.args...)
	}
	command.Dir = workingDir
	command.Env = append(
		os.Environ(),
		"PATH="+workingDir+";"+os.Getenv("PATH"),
		"WIN_AUD_069_EXIT="+strconv.Itoa(exitCode),
		"WIN_AUD_069_MARKER="+marker,
	)
	command.Stdin = bytes.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr

	started := time.Now()
	err := command.Run()
	elapsed := time.Since(started)
	actualExit := 0
	if err != nil {
		var exitError *exec.ExitError
		if !errors.As(err, &exitError) {
			t.Fatalf("run %s transport: %v", transport.name, err)
		}
		actualExit = exitError.ExitCode()
	}
	return windowsHookTransportResult{
		exitCode: actualExit,
		stdout:   stdout.Bytes(),
		stderr:   stderr.Bytes(),
		elapsed:  elapsed,
	}
}

func buildWindowsGUIHookTransportProbe(t *testing.T, dir string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(dir, "hook-probe.go")
	body := `package main

import (
	"io"
	"os"
	"strconv"
	"time"
)

func main() {
	time.Sleep(400 * time.Millisecond)
	if len(os.Args) != 4 || os.Args[1] != "hook" || os.Args[2] != "--connector" ||
		(os.Args[3] != "codex" && os.Args[3] != "claudecode") {
		os.Exit(91)
	}
	payload, err := io.ReadAll(os.Stdin)
	if err != nil {
		os.Exit(92)
	}
	executable, err := os.Executable()
	if err != nil {
		os.Exit(93)
	}
	if err := os.WriteFile(os.Getenv("WIN_AUD_069_MARKER"), []byte(executable), 0600); err != nil {
		os.Exit(94)
	}
	if _, err := os.Stdout.Write(payload); err != nil {
		os.Exit(95)
	}
	if _, err := os.Stderr.Write([]byte("hook-probe stderr Ω\n")); err != nil {
		os.Exit(96)
	}
	exitCode, err := strconv.Atoi(os.Getenv("WIN_AUD_069_EXIT"))
	if err != nil {
		os.Exit(97)
	}
	os.Exit(exitCode)
}
`
	if err := os.WriteFile(source, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(dir, windowsHookBinaryName)
	build := exec.Command("go", "build", "-trimpath", "-ldflags=-H=windowsgui", "-o", executable, source)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build Windows GUI hook transport probe: %v\n%s", err, output)
	}
	return executable
}
