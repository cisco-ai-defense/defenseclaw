//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pelletier/go-toml/v2"
)

func decodeJSONInto(data []byte, out *map[string]interface{}) error {
	decoded, err := decodeJSONObject("settings", data)
	if err != nil {
		return err
	}
	*out = decoded
	return nil
}

func countPrefix(lines []string, prefix string) int {
	n := 0
	for _, line := range lines {
		if strings.HasPrefix(line, prefix) {
			n++
		}
	}
	return n
}

func TestClaudeUserDisabledHooksAreTurnedBackOnIdempotently(t *testing.T) {
	f := newManagedPreferencesFixture(t, "")
	conn, opts, settingsPath, _ := isolatedClaudePolicyFixture(t)
	opts.ManagedEnterprise = true

	settings := map[string]interface{}{}
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := decodeJSONInto(data, &settings); err != nil {
		t.Fatal(err)
	}
	settings["disableAllHooks"] = true
	settings["model"] = "user-choice"
	writeClaudePolicyJSON(t, settingsPath, settings)
	if _, err := claudeCodeEffectiveHookContract(opts); err == nil {
		t.Fatal("user disableAllHooks was not detected")
	}

	for round := 0; round < 2; round++ {
		if err := conn.Setup(context.Background(), opts); err != nil {
			t.Fatalf("round %d Setup: %v", round, err)
		}
		after := map[string]interface{}{}
		data, err := os.ReadFile(settingsPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := decodeJSONInto(data, &after); err != nil {
			t.Fatal(err)
		}
		if _, present := after["disableAllHooks"]; present {
			t.Fatalf("round %d: disableAllHooks was not removed", round)
		}
		if after["model"] != "user-choice" {
			t.Fatalf("round %d: another user setting changed: %#v", round, after["model"])
		}
		if present, err := claudeCodeEffectiveHookContract(opts); err != nil || !present {
			t.Fatalf("round %d: hooks not effective: present=%v err=%v", round, present, err)
		}
		// The user turns them off again.
		after["disableAllHooks"] = true
		writeClaudePolicyJSON(t, settingsPath, after)
	}
	lines := f.lines()
	if countPrefix(lines, "defenseclaw_repair ") != 1 ||
		!strings.Contains(lines[0], `reason="user_disabled_hooks"`) ||
		!strings.Contains(lines[0], `connector="claudecode"`) ||
		!strings.Contains(lines[0], `path="`+settingsPath+`"`) {
		t.Fatalf("want one user_disabled_hooks repair per streak, got %v", lines)
	}
}

func TestClaudeUserDisabledHooksKeptOutsideManagedMode(t *testing.T) {
	newManagedPreferencesFixture(t, "")
	conn, opts, settingsPath, _ := isolatedClaudePolicyFixture(t)
	writeClaudePolicyJSON(t, settingsPath, map[string]interface{}{"disableAllHooks": true})
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"disableAllHooks": true`) {
		t.Fatal("an unmanaged Setup removed the user's disableAllHooks")
	}
}

func codexDisabledFixture(t *testing.T, body string) (*CodexConnector, SetupOpts, string) {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	previousConfig := CodexConfigPathOverride
	CodexConfigPathOverride = configPath
	previousInspector := codexPolicyInspector
	codexPolicyInspector = func(context.Context, SetupOpts) (codexEffectivePolicy, error) {
		return codexEffectivePolicy{}, nil
	}
	t.Cleanup(func() {
		CodexConfigPathOverride = previousConfig
		codexPolicyInspector = previousInspector
	})
	opts := SetupOpts{
		DataDir:           filepath.Join(dir, "dc"),
		APIAddr:           "127.0.0.1:18970",
		APIToken:          "tok",
		ManagedEnterprise: true,
		AgentVersion:      "0.163.0",
	}
	return NewCodexConnector(), opts, configPath
}

func TestCodexUserDisabledHooksAreTurnedBackOnIdempotently(t *testing.T) {
	for name, body := range map[string]string{
		"hooks":       "model = \"o3\"\n[features]\nhooks = false\nweb_search = true\n",
		"codex_hooks": "model = \"o3\"\n[features]\ncodex_hooks = false\nweb_search = true\n",
	} {
		t.Run(name, func(t *testing.T) {
			f := newManagedPreferencesFixture(t, "")
			conn, opts, configPath := codexDisabledFixture(t, body)
			for round := 0; round < 2; round++ {
				if err := conn.Setup(context.Background(), opts); err != nil {
					t.Fatalf("round %d Setup: %v", round, err)
				}
				raw, err := os.ReadFile(configPath)
				if err != nil {
					t.Fatal(err)
				}
				cfg := map[string]interface{}{}
				if err := toml.Unmarshal(raw, &cfg); err != nil {
					t.Fatal(err)
				}
				if reason := codexHooksFeatureDisabled(cfg, configPath); reason != "" {
					t.Fatalf("round %d: hooks still disabled: %s", round, reason)
				}
				features, _ := cfg["features"].(map[string]interface{})
				if features["web_search"] != true || cfg["model"] != "o3" {
					t.Fatalf("round %d: another setting changed: %#v", round, cfg)
				}
				// The user turns hooks off again.
				features[name] = false
				out, err := toml.Marshal(cfg)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(configPath, out, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			lines := f.lines()
			if countPrefix(lines, "defenseclaw_repair ") != 1 || !strings.Contains(lines[0], `reason="user_disabled_hooks"`) {
				t.Fatalf("want one user_disabled_hooks repair per streak, got %v", lines)
			}
		})
	}
}

func TestCodexUserDisabledHooksStillRefusedOutsideManagedMode(t *testing.T) {
	newManagedPreferencesFixture(t, "")
	conn, opts, _ := codexDisabledFixture(t, "[features]\nhooks = false\n")
	opts.ManagedEnterprise = false
	if err := conn.Setup(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "hooks are disabled") {
		t.Fatalf("Setup error = %v", err)
	}
}

func TestCodexPolicyReadFailureNeverFailsSetup(t *testing.T) {
	f := newManagedPreferencesFixture(t, "")
	previous := codexPolicyInspector
	codexPolicyInspector = func(context.Context, SetupOpts) (codexEffectivePolicy, error) {
		return codexEffectivePolicy{}, errors.New("app-server timed out")
	}
	t.Cleanup(func() { codexPolicyInspector = previous })
	if err := enforceCodexUserHookPolicy(context.Background(), SetupOpts{ManagedEnterprise: true}); err != nil {
		t.Fatalf("a failed policy read failed the reconcile: %v", err)
	}
	if lines := f.lines(); len(lines) != 1 || !strings.Contains(lines[0], "policy_read_failed") {
		t.Fatalf("lines = %v", lines)
	}
}

func TestCodexManagedPreferencesRequirementsAreReported(t *testing.T) {
	f := newManagedPreferencesFixture(t, "alice")
	requirements := base64.StdEncoding.EncodeToString([]byte("allow_managed_hooks_only = true\n"))
	path := f.write(t, "alice/com.openai.codex.plist", `{"requirements_toml_base64":"`+requirements+`"}`)
	previous := codexSystemRequirementsPathForInspection
	codexSystemRequirementsPathForInspection = func() (string, error) {
		return filepath.Join(t.TempDir(), "absent", "requirements.toml"), nil
	}
	t.Cleanup(func() { codexSystemRequirementsPathForInspection = previous })

	policy, err := inspectCodexEffectivePolicy(context.Background(), SetupOpts{ManagedEnterprise: true})
	if err != nil {
		t.Fatal(err)
	}
	if policy.AllowManagedHooksOnly == nil || !*policy.AllowManagedHooksOnly || policy.SourceKind != "mdm-user" || policy.Source != path {
		t.Fatalf("policy = %+v", policy)
	}
	previousInspector := codexPolicyInspector
	codexPolicyInspector = inspectCodexEffectivePolicy
	t.Cleanup(func() { codexPolicyInspector = previousInspector })
	if err := enforceCodexUserHookPolicy(context.Background(), SetupOpts{ManagedEnterprise: true}); err == nil {
		t.Fatal("MDM allow_managed_hooks_only did not refuse user hooks")
	}
	got := strings.Join(f.lines(), "\n")
	for _, want := range []string{`check="agent_policy_blocks_user_hooks"`, `connector="codex"`, `key="allow_managed_hooks_only"`, `source="mdm-user"`} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %s in %s", want, got)
		}
	}
}

func TestCodexPreinspectedPolicyIsUsedAndNoChildStartsInsideTheDrop(t *testing.T) {
	newManagedPreferencesFixture(t, "")
	home := t.TempDir()
	executable := filepath.Join(t.TempDir(), "codex")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CODEX_HOME", filepath.Join(home, ".codex"))
	blocked := true
	codexPreinspections.Lock()
	codexPreinspections.entries = map[string]codexPreinspection{
		codexPreinspectionKey(executable, filepath.Join(home, ".codex")): {
			policy: codexEffectivePolicy{AllowManagedHooksOnly: &blocked, Source: "app-server"},
			at:     time.Now(),
		},
	}
	codexPreinspections.Unlock()
	previous := codexAppServerCommand
	codexAppServerCommand = func(context.Context, string) *exec.Cmd {
		t.Fatal("a Codex child was started although a preinspected answer existed")
		return nil
	}
	t.Cleanup(func() { codexAppServerCommand = previous })

	policy, err := inspectCodexEffectivePolicy(context.Background(), SetupOpts{AgentExecutable: executable, ManagedEnterprise: true})
	if err != nil || policy.AllowManagedHooksOnly == nil || !*policy.AllowManagedHooksOnly {
		t.Fatalf("policy = %+v err = %v", policy, err)
	}
	if policy.SourceKind != "server" {
		t.Fatalf("an app-server answer without a file or MDM source should be attributed to server: %+v", policy)
	}
}

func TestPreinspectCodexPolicyIsRootOnly(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("runs as root")
	}
	called := false
	previous := codexPolicyInspectionAsUser
	codexPolicyInspectionAsUser = func(context.Context, string, string, func(*exec.Cmd)) (codexEffectivePolicy, error) {
		called = true
		return codexEffectivePolicy{}, nil
	}
	t.Cleanup(func() { codexPolicyInspectionAsUser = previous })
	if err := PreinspectCodexPolicy(context.Background(), "/usr/bin/true", t.TempDir(), 501, 20); err != nil || called {
		t.Fatalf("unprivileged preinspection ran: err=%v called=%v", err, called)
	}
}

func TestCursorMachineHooksConflictIsReported(t *testing.T) {
	f := newManagedPreferencesFixture(t, "")
	path := filepath.Join(t.TempDir(), "hooks.json")
	previous := cursorMachineHooksPath
	cursorMachineHooksPath = path
	t.Cleanup(func() { cursorMachineHooksPath = previous })

	ReportCursorMachineHooksPolicy()
	if len(f.lines()) != 0 {
		t.Fatalf("absent machine hooks.json reported: %v", f.lines())
	}
	if err := os.WriteFile(path, []byte(`{"version":1,"hooks":{"preToolUse":[{"command":"/opt/corp/hook"}],"unrelated":[{"command":"x"}]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	ReportCursorMachineHooksPolicy()
	ReportCursorMachineHooksPolicy()
	lines := f.lines()
	if len(lines) != 1 || !strings.Contains(lines[0], `connector="cursor"`) ||
		!strings.Contains(lines[0], `key="hooks.preToolUse"`) || !strings.Contains(lines[0], `source="file"`) {
		t.Fatalf("lines = %v", lines)
	}
	if err := os.WriteFile(path, []byte(`not json`), 0o644); err != nil {
		t.Fatal(err)
	}
	ReportCursorMachineHooksPolicy()
	if got := f.lines(); len(got) != 2 || !strings.Contains(got[1], "policy_read_failed") {
		t.Fatalf("unreadable machine hooks.json: %v", got)
	}
}

func TestCursorManagedWriterUsesLockAndCompareAndSwap(t *testing.T) {
	newManagedPreferencesFixture(t, "")
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "hooks.json")
	if err := os.WriteFile(cfgPath, []byte(`{"version":1,"hooks":{"stop":[{"command":"/usr/local/bin/user-hook"}]},"userKey":"keep"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	prev := CursorHooksPathOverride
	CursorHooksPathOverride = cfgPath
	t.Cleanup(func() { CursorHooksPathOverride = prev })

	conn := NewCursorConnector()
	opts := SetupOpts{DataDir: filepath.Join(dir, "dc"), APIAddr: "127.0.0.1:18970", APIToken: "tok", ManagedEnterprise: true}
	release := holdFlock(t, cfgPath+".lock")
	previousWait := userLockWait
	userLockWait = 100 * time.Millisecond
	t.Cleanup(func() { userLockWait = previousWait })
	if err := conn.Setup(context.Background(), opts); !errors.Is(err, ErrLockBusy) {
		t.Fatalf("Setup with the config lock held: %v, want lock_busy", err)
	}
	release()
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	cfg, err := readJSONObject(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg["userKey"] != "keep" {
		t.Fatalf("user key lost: %#v", cfg)
	}
	hooks, _ := cfg["hooks"].(map[string]interface{})
	if stop, _ := hooks["stop"].([]interface{}); len(stop) < 1 {
		t.Fatalf("user stop hook lost: %#v", hooks["stop"])
	}
}
