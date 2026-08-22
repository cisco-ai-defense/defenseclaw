// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/pelletier/go-toml/v2"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

const (
	codexManagedSubprocessMarker = "DEFENSECLAW_TEST_CODEX_MANAGED_SUBPROCESS"
	codexManagedSubprocessData   = "DEFENSECLAW_TEST_CODEX_MANAGED_DATA"
	codexManagedSubprocessHome   = "DEFENSECLAW_TEST_CODEX_MANAGED_HOME"
)

func TestConnectorReconcilePublishesManagedCodexRegistrationInSubprocess(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	dataDir := filepath.Join(root, "data")
	userHome := filepath.Join(root, "user")
	codexHome := filepath.Join(userHome, ".codex")
	for _, path := range []string{dataDir, codexHome, filepath.Join(userHome, ".local", "bin")} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatalf("create subprocess fixture %s: %v", path, err)
		}
	}
	expectedHook := filepath.Join(userHome, ".local", "bin", "defenseclaw-hook.exe")
	if err := os.WriteFile(expectedHook, []byte("MZ-native-hook-fixture"), 0o700); err != nil {
		t.Fatalf("write native hook fixture: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(
		ctx,
		os.Args[0],
		"-test.run=^TestConnectorReconcileManagedCodexRegistrationSubprocessHelper$",
	)
	cmd.Env = append(subprocessWindowsEnvironment(),
		codexManagedSubprocessMarker+"=1",
		codexManagedSubprocessData+"="+dataDir,
		codexManagedSubprocessHome+"="+userHome,
		"CODEX_HOME="+codexHome,
	)
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("Codex reconcile subprocess timed out: %v", ctx.Err())
	}
	if err != nil {
		t.Fatalf("Codex reconcile subprocess: %v\n%s", err, output)
	}

	managedPath := filepath.Join(codexHome, "managed_config.toml")
	managed := readCodexSubprocessTOML(t, managedPath)
	hooks, ok := managed["hooks"].(map[string]interface{})
	if !ok {
		t.Fatalf("managed_config.toml has no hooks table: %#v", managed)
	}
	if _, exists := hooks["state"]; exists {
		t.Fatalf("managed hook source unexpectedly contains private trust state: %#v", hooks["state"])
	}

	expectedEvents := []string{
		"PreToolUse", "PermissionRequest", "PostToolUse", "SubagentStart", "SubagentStop",
		"PreCompact", "PostCompact", "SessionStart", "UserPromptSubmit", "Stop",
	}
	for _, event := range expectedEvents {
		groups, ok := hooks[event].([]interface{})
		if !ok || len(groups) != 1 {
			t.Fatalf("managed hooks.%s groups = %#v, want exactly one", event, hooks[event])
		}
		group, ok := groups[0].(map[string]interface{})
		if !ok {
			t.Fatalf("managed hooks.%s group is malformed: %#v", event, groups[0])
		}
		handlers, ok := group["hooks"].([]interface{})
		if !ok || len(handlers) != 1 {
			t.Fatalf("managed hooks.%s handlers = %#v, want exactly one", event, group["hooks"])
		}
		handler, ok := handlers[0].(map[string]interface{})
		if !ok || handler["type"] != "command" {
			t.Fatalf("managed hooks.%s handler is malformed: %#v", event, handlers[0])
		}
		command, ok := handler["command_windows"].(string)
		if !ok || command == "" {
			t.Fatalf("managed hooks.%s has no command_windows: %#v", event, handler)
		}
		decoded := decodeCodexManagedPowerShellCommand(t, command)
		if !strings.Contains(strings.ToLower(decoded), strings.ToLower(expectedHook)) ||
			!strings.Contains(strings.ToLower(decoded), "'hook','--connector','codex'") {
			t.Fatalf("managed hooks.%s does not name the exact hook contract: %q", event, decoded)
		}
	}

	user := readCodexSubprocessTOML(t, filepath.Join(codexHome, "config.toml"))
	if _, exists := user["hooks"]; exists {
		t.Fatalf("user config.toml contains the Windows managed hook matrix: %#v", user["hooks"])
	}
}

func TestConnectorReconcileManagedCodexRegistrationSubprocessHelper(t *testing.T) {
	if os.Getenv(codexManagedSubprocessMarker) != "1" {
		return
	}
	dataDir := os.Getenv(codexManagedSubprocessData)
	userHome := os.Getenv(codexManagedSubprocessHome)
	if dataDir == "" || userHome == "" || os.Getenv("CODEX_HOME") == "" {
		t.Fatal("managed Codex subprocess fixture environment is incomplete")
	}
	testenv.SetHome(t, userHome)
	seedCodexSelectionForTest(t, dataDir)
	defer withConnectorState(t, dataDir, "codex")()
	cfg.Guardrail.Enabled = true
	cfg.Guardrail.HookFailMode = "open"
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"codex": {HookFailMode: "open"},
	}

	stdout, stderr, exitCode := runConnectorCmd(
		t,
		"reconcile",
		"--connector", "codex",
		"--data-dir", dataDir,
		"--json",
	)
	if exitCode != 0 || stderr != "" || !strings.Contains(stdout, `"ok":true`) {
		t.Fatalf("reconcile: exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	opts := resolveConnectorOpts(dataDir)
	opts.AgentVersion = connector.LoadCachedAgentVersion(dataDir, "codex")
	opts.AgentExecutable = connector.LoadCachedAgentExecutable(dataDir, "codex")
	present, err := connector.OwnedHooksPresent(connector.NewCodexConnector(), opts)
	if err != nil {
		t.Fatalf("read back managed Codex registration: %v", err)
	}
	if !present {
		t.Fatal("reconcile returned success before the managed Codex registration was effective")
	}
}

func subprocessWindowsEnvironment() []string {
	keep := map[string]struct{}{
		"PATH": {}, "PATHEXT": {}, "SYSTEMROOT": {}, "TEMP": {}, "TMP": {}, "WINDIR": {},
	}
	env := make([]string, 0, len(keep))
	for _, item := range os.Environ() {
		name, _, found := strings.Cut(item, "=")
		if !found {
			continue
		}
		for allowed := range keep {
			if strings.EqualFold(name, allowed) {
				env = append(env, item)
				break
			}
		}
	}
	return env
}

func readCodexSubprocessTOML(t *testing.T, path string) map[string]interface{} {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	document := map[string]interface{}{}
	if err := toml.Unmarshal(body, &document); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return document
}

func decodeCodexManagedPowerShellCommand(t *testing.T, command string) string {
	t.Helper()
	parts := strings.Fields(command)
	for i, part := range parts {
		if !strings.EqualFold(part, "-EncodedCommand") || i+1 >= len(parts) {
			continue
		}
		data, err := base64.StdEncoding.DecodeString(parts[i+1])
		if err != nil || len(data)%2 != 0 {
			t.Fatalf("decode managed PowerShell command %q: bytes=%d err=%v", command, len(data), err)
		}
		wide := make([]uint16, len(data)/2)
		for j := range wide {
			wide[j] = binary.LittleEndian.Uint16(data[j*2:])
		}
		return string(utf16.Decode(wide))
	}
	t.Fatalf("managed Windows hook command has no EncodedCommand: %q", command)
	return ""
}
