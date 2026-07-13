// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// cursorTestSetup wires the cursor connector to a temp config path and returns
// a connector + opts ready for Setup. The path override is reset on cleanup so
// it never leaks across tests in this package.
func cursorTestSetup(t *testing.T) (Connector, SetupOpts, string) {
	t.Helper()
	cfgPath := filepath.Join(t.TempDir(), "hooks.json")
	prev := CursorHooksPathOverride
	CursorHooksPathOverride = cfgPath
	t.Cleanup(func() { CursorHooksPathOverride = prev })
	opts := SetupOpts{
		DataDir:      t.TempDir(),
		APIAddr:      "127.0.0.1:18970",
		APIToken:     "tok-test",
		WorkspaceDir: t.TempDir(),
	}
	return NewCursorConnector(), opts, cfgPath
}

func TestHookConfigPathsForConnector_ResolvesOverride(t *testing.T) {
	conn, opts, cfgPath := cursorTestSetup(t)

	paths := HookConfigPathsForConnector(conn, opts)
	if len(paths) != 1 {
		t.Fatalf("HookConfigPathsForConnector = %v, want exactly the cursor hooks path", paths)
	}
	if paths[0] != cfgPath {
		t.Fatalf("HookConfigPathsForConnector[0] = %q, want %q", paths[0], cfgPath)
	}
}

func TestHookConfigPathsForConnector_ProxyConnectorsAreInert(t *testing.T) {
	opts := SetupOpts{DataDir: t.TempDir(), ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970"}
	for _, conn := range []Connector{NewOpenClawConnector(), NewZeptoClawConnector()} {
		if paths := HookConfigPathsForConnector(conn, opts); paths != nil {
			t.Errorf("%s: HookConfigPathsForConnector = %v, want nil (proxy/plugin connector must be inert)", conn.Name(), paths)
		}
	}
}

func TestHookConfigPathsForConnector_NilConnector(t *testing.T) {
	if paths := HookConfigPathsForConnector(nil, SetupOpts{}); paths != nil {
		t.Fatalf("HookConfigPathsForConnector(nil) = %v, want nil", paths)
	}
}

func TestOwnedHooksPresent_TrueAfterSetup_FalseAfterRemoval(t *testing.T) {
	conn, opts, cfgPath := cursorTestSetup(t)

	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	present, err := OwnedHooksPresent(conn, opts)
	if err != nil {
		t.Fatalf("OwnedHooksPresent after Setup: %v", err)
	}
	if !present {
		data, _ := os.ReadFile(cfgPath)
		t.Fatalf("OwnedHooksPresent=false after Setup; config:\n%s", data)
	}

	// Strip the hook block: an empty JSON object no longer references our
	// hook command.
	if err := os.WriteFile(cfgPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("strip config: %v", err)
	}
	present, err = OwnedHooksPresent(conn, opts)
	if err != nil {
		t.Fatalf("OwnedHooksPresent after strip: %v", err)
	}
	if present {
		t.Fatal("OwnedHooksPresent=true after stripping the hook block; want false")
	}
}

func TestOwnedHooksPresent_FalseWhenFileMissing(t *testing.T) {
	conn, opts, cfgPath := cursorTestSetup(t)

	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if err := os.Remove(cfgPath); err != nil {
		t.Fatalf("remove config: %v", err)
	}

	present, err := OwnedHooksPresent(conn, opts)
	if err != nil {
		t.Fatalf("OwnedHooksPresent with missing file returned error: %v", err)
	}
	if present {
		t.Fatal("OwnedHooksPresent=true for a deleted config file; want false")
	}
}

func TestOwnedHooksPresent_ProxyConnectorReportsPresent(t *testing.T) {
	// Proxy/plugin connectors have no guarded hook config paths, so they
	// are reported present (never heal-eligible).
	opts := SetupOpts{DataDir: t.TempDir(), ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970"}
	present, err := OwnedHooksPresent(NewOpenClawConnector(), opts)
	if err != nil {
		t.Fatalf("OwnedHooksPresent: %v", err)
	}
	if !present {
		t.Fatal("OwnedHooksPresent=false for proxy connector; want true (inert)")
	}
}

func installedClaudeCodeConnectorForPresence(t *testing.T) (Connector, SetupOpts, string) {
	t.Helper()
	settingsPath := filepath.Join(t.TempDir(), "settings.json")
	previous := ClaudeCodeSettingsPathOverride
	ClaudeCodeSettingsPathOverride = settingsPath
	t.Cleanup(func() { ClaudeCodeSettingsPathOverride = previous })

	opts := SetupOpts{
		DataDir:  t.TempDir(),
		APIAddr:  "127.0.0.1:18970",
		APIToken: "tok-test",
	}
	conn := NewClaudeCodeConnector()
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Claude Code Setup: %v", err)
	}
	return conn, opts, settingsPath
}

func mutateClaudeSettings(t *testing.T, path string, mutate func(map[string]interface{})) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]interface{}
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatal(err)
	}
	mutate(settings)
	out, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestOwnedHooksPresent_ClaudeRequiresEffectiveContract(t *testing.T) {
	conn, opts, settingsPath := installedClaudeCodeConnectorForPresence(t)
	baseline, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]func(map[string]interface{}){
		"irrelevant-event-only": func(settings map[string]interface{}) {
			hooks := settings["hooks"].(map[string]interface{})
			settings["hooks"] = map[string]interface{}{"Notification": hooks["Notification"]}
		},
		"missing-block-event": func(settings map[string]interface{}) {
			delete(settings["hooks"].(map[string]interface{}), "PreToolUse")
		},
		"narrow-block-matcher": func(settings map[string]interface{}) {
			entries := settings["hooks"].(map[string]interface{})["PreToolUse"].([]interface{})
			entries[0].(map[string]interface{})["matcher"] = "Bash"
		},
		"whitespace-padded-wildcard": func(settings map[string]interface{}) {
			entries := settings["hooks"].(map[string]interface{})["PreToolUse"].([]interface{})
			entries[0].(map[string]interface{})["matcher"] = " * "
		},
		"asynchronous-block-handler": func(settings map[string]interface{}) {
			entries := settings["hooks"].(map[string]interface{})["PreToolUse"].([]interface{})
			handler := entries[0].(map[string]interface{})["hooks"].([]interface{})[0].(map[string]interface{})
			handler["async"] = true
		},
		"async-rewake-block-handler": func(settings map[string]interface{}) {
			entries := settings["hooks"].(map[string]interface{})["PreToolUse"].([]interface{})
			handler := entries[0].(map[string]interface{})["hooks"].([]interface{})[0].(map[string]interface{})
			handler["asyncRewake"] = true
		},
		"non-command-block-handler": func(settings map[string]interface{}) {
			entries := settings["hooks"].(map[string]interface{})["PreToolUse"].([]interface{})
			handler := entries[0].(map[string]interface{})["hooks"].([]interface{})[0].(map[string]interface{})
			handler["type"] = "http"
		},
		"conditional-block-handler": func(settings map[string]interface{}) {
			entries := settings["hooks"].(map[string]interface{})["PreToolUse"].([]interface{})
			handler := entries[0].(map[string]interface{})["hooks"].([]interface{})[0].(map[string]interface{})
			handler["if"] = "Bash(git *)"
		},
		"hooks-disabled": func(settings map[string]interface{}) {
			settings["disableAllHooks"] = true
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(settingsPath, baseline, 0o600); err != nil {
				t.Fatal(err)
			}
			mutateClaudeSettings(t, settingsPath, mutate)
			present, err := OwnedHooksPresent(conn, opts)
			if err != nil {
				t.Fatalf("OwnedHooksPresent: %v", err)
			}
			if present {
				t.Fatal("OwnedHooksPresent=true for a non-enforcing Claude Code hook contract")
			}
		})
	}
}

// TestOwnedHookNeedles_WindowsSurvivesConfigEscaping guards the Windows
// presence-detection path. On Windows the agent config stores the native
// invocation (`"C:\...\defenseclaw-gateway.exe" hook --connector <name>`),
// whose backslashes and quotes are escaped when serialized into JSON/TOML.
// The needle must therefore key on an escaping-invariant marker, not the full
// command, or OwnedHooksPresent would false-negative on every check and the
// guard would spuriously re-install hooks. This test runs on any host because
// the OS is parameterized.
func TestOwnedHookNeedles_WindowsSurvivesConfigEscaping(t *testing.T) {
	opts := SetupOpts{DataDir: `C:\Users\me\AppData\Local\defenseclaw`}
	conn := NewCursorConnector()

	needles := ownedHookCommandNeedlesFor("windows", opts, conn)
	wantCommand := hookInvocationCommandFor(
		"windows",
		conn.Name(),
		filepath.Join(opts.DataDir, "hooks", "cursor-hook.sh"),
	)
	if len(needles) != 1 || needles[0] != wantCommand {
		t.Fatalf("windows needles = %v, want [%q]", needles, wantCommand)
	}

	// What Setup actually writes on Windows: the native command embedded in a
	// JSON config, where the exe path's backslashes/quotes get escaped.
	winCmd := wantCommand
	encoded, err := json.Marshal(map[string]string{"command": winCmd})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	path := filepath.Join(t.TempDir(), "hooks.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	present, err := configFileReferencesHook(path, needles)
	if err != nil {
		t.Fatalf("configFileReferencesHook: %v", err)
	}
	if !present {
		t.Fatalf("decoded matcher did not recognize Cursor adapter command %q", winCmd)
	}
}

func TestConfigFileReferencesHookIgnoresDecoyPathOutsideCommandField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	needle := "/home/alice/.defenseclaw/hooks/cursor-hook.sh"
	data := []byte(`{"hooks":{"beforeSubmitPrompt":[{"note":"` + needle + `"}]}}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write hook config: %v", err)
	}
	present, err := configFileReferencesHook(path, []string{needle})
	if err != nil {
		t.Fatalf("configFileReferencesHook: %v", err)
	}
	if present {
		t.Fatal("decoy path outside command field was treated as a managed hook")
	}
}

func TestConfigFileReferencesHookRejectsWrapperCommand(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	needle := "/home/alice/.defenseclaw/hooks/cursor-hook.sh"
	data := []byte(`{"hooks":{"beforeSubmitPrompt":[{"command":"echo ` + needle + `"}]}}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write hook config: %v", err)
	}
	present, err := configFileReferencesHook(path, []string{needle})
	if err != nil {
		t.Fatalf("configFileReferencesHook: %v", err)
	}
	if present {
		t.Fatal("wrapper command was treated as an enforcing managed hook")
	}
}

func TestConfigFileReferencesHookAcceptsManagedCommandField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	needle := "/home/alice/.defenseclaw/hooks/cursor-hook.sh"
	data := []byte(`{"hooks":{"beforeSubmitPrompt":[{"command":"'` + needle + `'"}]}}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write hook config: %v", err)
	}
	present, err := configFileReferencesHook(path, []string{needle})
	if err != nil {
		t.Fatalf("configFileReferencesHook: %v", err)
	}
	if !present {
		t.Fatal("managed command field was not detected")
	}
}

func TestConfigFileReferencesHookAcceptsNestedTOMLCommand(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.toml")
	needle := "/home/alice/.defenseclaw/hooks/codex-hook.sh"
	data := []byte("[[hooks.beforeSubmitPrompt]]\ncommand = \"'" + needle + "'\"\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write hook config: %v", err)
	}
	present, err := configFileReferencesHook(path, []string{needle})
	if err != nil {
		t.Fatalf("configFileReferencesHook: %v", err)
	}
	if !present {
		t.Fatal("nested TOML command field was not detected")
	}
}
