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
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func setHookBinaryOverride(t *testing.T, path string) {
	t.Helper()
	prev := defenseclawHookBinaryOverride
	defenseclawHookBinaryOverride = path
	t.Cleanup(func() { defenseclawHookBinaryOverride = prev })
}

// TestHookInvocationCommand pins the platform split: Unix runs the bundled .sh
// path; Windows invokes the native Go `hook` subcommand instead of any Bash/.cmd
// wrapper.
func TestHookInvocationCommand(t *testing.T) {
	const unix = "/home/u/.defenseclaw/hooks/codex-hook.sh"
	const windowsExe = `C:\Program Files\DefenseClaw\defenseclaw-gateway.exe`
	setHookBinaryOverride(t, windowsExe)

	for _, goos := range []string{"linux", "darwin"} {
		if got := hookInvocationCommandFor(goos, "codex", unix); got != unix {
			t.Errorf("%s command = %q, want passthrough %q", goos, got, unix)
		}
	}

	win := hookInvocationCommandFor("windows", "cursor", unix)
	wantWin := `"C:\Program Files\DefenseClaw\defenseclaw-gateway.exe" hook --connector cursor`
	if win != wantWin {
		t.Errorf("windows command = %q, want %q", win, wantWin)
	}
	if !strings.Contains(win, nativeHookFlag+"cursor") {
		t.Errorf("windows command = %q, missing %q", win, nativeHookFlag+"cursor")
	}
	if strings.Contains(win, ".sh") || strings.Contains(win, ".cmd") || strings.Contains(win, "bash") {
		t.Errorf("windows command = %q should not reference a shell/script wrapper", win)
	}
	if !isNativeHookCommand(win) {
		t.Errorf("isNativeHookCommand(%q) = false, want true", win)
	}
	if isNativeHookCommand(unix) {
		t.Errorf("isNativeHookCommand(%q) = true, want false for a .sh path", unix)
	}

	// Codex passes this string to cmd.exe /C as one argument. Do not use the
	// quoted absolute-path form that Windows re-escapes into a literal argv[0].
	codex := hookInvocationCommandFor("windows", "codex", unix)
	wantCodex := windowsSafePATHCommandPrefix + windowsGatewayBinaryName + " " + nativeHookFlag + "codex"
	if codex != wantCodex {
		t.Errorf("codex command = %q, want %q", codex, wantCodex)
	}
	if strings.ContainsAny(codex, `"'`) {
		t.Errorf("codex cmd.exe command contains quote characters: %q", codex)
	}
	if !isNativeHookCommand(codex) {
		t.Errorf("isNativeHookCommand(%q) = false, want true", codex)
	}

	// Antigravity's direct-exec parser does not dequote command paths. Use the
	// installer-provided PATH entry so an install root containing spaces still
	// works without quote characters becoming part of argv[0].
	agy := hookInvocationCommandFor("windows", "antigravity", unix)
	if agy != `defenseclaw-gateway.exe hook --connector antigravity` {
		t.Errorf("antigravity command = %q", agy)
	}
	if strings.ContainsAny(agy, `"'`) {
		t.Errorf("antigravity direct-exec command contains literal quotes: %q", agy)
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
	wantTail := windowsGatewayBinaryName + " " + nativeHookFlag + "codex"
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

// TestShellWordPassesNativeCommandThrough ensures the bash-style quoter does not
// corrupt the native Windows command (which is already a complete command line)
// while still quoting Unix script paths for the agent's shell.
func TestShellWordPassesNativeCommandThrough(t *testing.T) {
	setHookBinaryOverride(t, `C:\Program Files\DefenseClaw\defenseclaw-gateway.exe`)
	native := `"C:\Program Files\DefenseClaw\defenseclaw-gateway.exe" hook --connector cursor`
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
	const cmd = windowsSafePATHCommandPrefix + windowsGatewayBinaryName + " " + nativeHookFlag + "codex"
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
	setHookBinaryOverride(t, `C:\Program Files\DefenseClaw\defenseclaw-gateway.exe`)

	owned := map[string]interface{}{
		"hooks": []interface{}{
			map[string]interface{}{
				"type":    "command",
				"command": `"C:\Program Files\DefenseClaw\defenseclaw-gateway.exe" hook --connector claudecode`,
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
				"command": `"C:\Tools\defenseclaw-gateway.exe" hook --connector claudecode`,
			},
		},
	}
	if isOwnedHook(foreignSameBasename, hooksDir) {
		t.Error("different absolute gateway path was incorrectly recognized as owned")
	}
}

func TestCodexNativeNotifyOwnership(t *testing.T) {
	setHookBinaryOverride(t, `C:\Program Files\DefenseClaw\defenseclaw-gateway.exe`)
	opts := SetupOpts{DataDir: `C:\Users\me\.defenseclaw`}
	owned := []interface{}{`C:\Program Files\DefenseClaw\defenseclaw-gateway.exe`, "notify"}
	if !codexNotifyLooksManaged(owned, opts) {
		t.Fatal("native Codex notifier was not recognized as managed")
	}
	foreign := []interface{}{`C:\Tools\desktop-notifier.exe`, "notify"}
	if codexNotifyLooksManaged(foreign, opts) {
		t.Fatal("foreign notifier was incorrectly recognized as managed")
	}
	foreignSameBasename := []interface{}{`C:\Tools\defenseclaw-gateway.exe`, "notify"}
	if codexNotifyLooksManaged(foreignSameBasename, opts) {
		t.Fatal("different absolute gateway notifier was incorrectly recognized as managed")
	}
}

// TestWindowsNativeConfigMatrix exercises the generated on-disk configs for
// every WIN-016 native target plus the Hermes preview. OpenCode is intentionally
// absent: its bridge remains a JavaScript plugin and has separate tests.
func TestWindowsNativeConfigMatrix(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-native config matrix")
	}
	setHookBinaryOverride(t, `C:\Program Files\DefenseClaw\defenseclaw-gateway.exe`)

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
			if !strings.Contains(text, windowsGatewayBinaryName) {
				t.Errorf("config does not invoke %s:\n%s", windowsGatewayBinaryName, text)
			}
			if !strings.Contains(text, nativeHookFlag+connectorName) {
				t.Errorf("config missing native connector command for %s:\n%s", connectorName, text)
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

			token, err := os.ReadFile(filepath.Join(dataDir, "hooks", ".token"))
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
			if !strings.Contains(string(hookCfg), "DEFENSECLAW_GATEWAY_ADDR=127.0.0.1:18970") {
				t.Errorf("hook config sidecar missing API address: %s", hookCfg)
			}
			wantFailMode := resolveHookFailMode(opts, tt.conn)
			if hp, ok := tt.conn.(HookCapabilityProvider); ok &&
				wantFailMode == "closed" && !hp.HookCapabilities(opts).SupportsFailClosed {
				wantFailMode = "open"
			}
			if !strings.Contains(string(hookCfg), "DEFENSECLAW_FAIL_MODE="+wantFailMode) {
				t.Errorf("hook config sidecar fail mode = %q, want %q", hookCfg, wantFailMode)
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
			// These sidecars are shared by all active native connectors. A
			// single connector teardown must not remove them and break peers.
			for _, name := range []string{".token", hookConfigSidecarName} {
				if _, err := os.Stat(filepath.Join(dataDir, "hooks", name)); err != nil {
					t.Errorf("shared sidecar %s removed by connector teardown: %v", name, err)
				}
			}
		})
	}
}
