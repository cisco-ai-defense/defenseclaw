// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func forceManagedHookRenderChecks(t *testing.T) *[]string {
	t.Helper()
	forceManagedShellGuard(t)
	previousRender, previousCursor := managedHookRenderGOOS, cursorUserHooksMatrixGOOS
	managedHookRenderGOOS, cursorUserHooksMatrixGOOS = "darwin", "darwin"
	var events []string
	previousSink := managed.ReportResilienceEvent
	managed.ReportResilienceEvent = func(marker string, fields map[string]string) {
		events = append(events, managed.FormatResilienceEvent(marker, fields))
	}
	t.Cleanup(func() {
		managedHookRenderGOOS, cursorUserHooksMatrixGOOS = previousRender, previousCursor
		managed.ReportResilienceEvent = previousSink
	})
	return &events
}

func TestVerifyManagedHookRenderDetectsTamperAndHealsOnRerender(t *testing.T) {
	tampers := map[string]func(t *testing.T, hookDir string){
		"script replaced": func(t *testing.T, hookDir string) {
			if err := os.WriteFile(filepath.Join(hookDir, "claude-code-hook.sh"), []byte("#!/bin/bash\nexit 0\n"), 0o700); err != nil {
				t.Fatal(err)
			}
		},
		"script not executable": func(t *testing.T, hookDir string) {
			if err := os.Chmod(filepath.Join(hookDir, "claude-code-hook.sh"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"helper edited": func(t *testing.T, hookDir string) {
			path := filepath.Join(hookDir, "_hardening.sh")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, append(data, []byte("\nexit 0\n")...), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"token deleted": func(t *testing.T, hookDir string) {
			if err := os.Remove(filepath.Join(hookDir, ".hook-claudecode.token")); err != nil {
				t.Fatal(err)
			}
		},
		"token replaced": func(t *testing.T, hookDir string) {
			if err := os.WriteFile(filepath.Join(hookDir, ".hook-claudecode.token"), []byte("other\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"fail mode flipped in the runtime sidecar": func(t *testing.T, hookDir string) {
			if err := os.WriteFile(filepath.Join(hookDir, ".hookcfg.claudecode"), []byte("DEFENSECLAW_CONNECTOR=claudecode\nDEFENSECLAW_FAIL_MODE=open\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, tamper := range tampers {
		t.Run(name, func(t *testing.T) {
			events := forceManagedHookRenderChecks(t)
			dataDir := t.TempDir()
			hookDir := filepath.Join(dataDir, "hooks")
			conn := NewClaudeCodeConnector()
			opts := SetupOpts{
				DataDir:           dataDir,
				APIAddr:           "127.0.0.1:18970",
				APIToken:          managedHookTestToken,
				ManagedEnterprise: true,
				HookFailMode:      "closed",
			}
			if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, conn); err != nil {
				t.Fatal(err)
			}
			if err := VerifyManagedHookRender(opts, conn); err != nil {
				t.Fatalf("fresh render does not verify: %v", err)
			}
			tamper(t, hookDir)
			err := VerifyManagedHookRender(opts, conn)
			if !errors.Is(err, ErrManagedHookRenderDrift) {
				t.Fatalf("tamper not detected: %v", err)
			}
			boundary := false
			for _, event := range *events {
				if strings.HasPrefix(event, managed.MarkerBoundary) && strings.Contains(event, "hook_runtime_tampered") {
					boundary = true
				}
			}
			if !boundary {
				t.Fatalf("no boundary line for the tamper: %v", *events)
			}
			if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, conn); err != nil {
				t.Fatal(err)
			}
			if err := VerifyManagedHookRender(opts, conn); err != nil {
				t.Fatalf("re-render did not heal the tamper: %v", err)
			}
		})
	}
}

func TestVerifyManagedHookRenderIsOffForUnmanagedAndOtherHosts(t *testing.T) {
	forceManagedHookRenderChecks(t)
	dataDir := t.TempDir()
	conn := NewClaudeCodeConnector()
	unmanaged := SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970", APIToken: managedHookTestToken}
	if err := VerifyManagedHookRender(unmanaged, conn); err != nil {
		t.Fatalf("unmanaged target verified: %v", err)
	}
	managedHookRenderGOOS = "linux"
	managedOpts := unmanaged
	managedOpts.ManagedEnterprise = true
	if err := VerifyManagedHookRender(managedOpts, conn); err != nil {
		t.Fatalf("non-macOS host verified script bytes: %v", err)
	}
}

func cursorHooksForTest(t *testing.T, hookScript string, failClosed bool) map[string]interface{} {
	t.Helper()
	path := filepath.Join(t.TempDir(), "hooks.json")
	user := `{"version":1,"hooks":{"stop":[{"type":"command","command":"/usr/local/bin/my-hook"}]}}`
	if err := os.WriteFile(path, []byte(user), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := patchCursorHooks(path, hookScript, "", failClosed); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestVerifyCursorUserHooksMatrixDetectsPartialRemoval(t *testing.T) {
	hookScript := "/Users/u/.defenseclaw/hooks/cursor-hook.sh"
	encode := func(cfg map[string]interface{}) []byte {
		data, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	cfg := cursorHooksForTest(t, hookScript, true)
	if err := verifyCursorUserHooksMatrix(encode(cfg), hookScript, true); err != nil {
		t.Fatalf("writer output does not verify: %v", err)
	}
	if err := verifyCursorUserHooksMatrix(encode(cfg), hookScript, false); err == nil {
		t.Fatal("a fail-closed matrix verified as fail-open")
	}

	removed := cursorHooksForTest(t, hookScript, true)
	delete(removed["hooks"].(map[string]interface{}), "beforeShellExecution")
	if err := verifyCursorUserHooksMatrix(encode(removed), hookScript, true); err == nil {
		t.Fatal("a removed event verified")
	}

	flipped := cursorHooksForTest(t, hookScript, true)
	entries := flipped["hooks"].(map[string]interface{})["preToolUse"].([]interface{})
	entries[len(entries)-1].(map[string]interface{})["failClosed"] = false
	if err := verifyCursorUserHooksMatrix(encode(flipped), hookScript, true); err == nil {
		t.Fatal("a flipped failClosed entry verified")
	}
}

func TestCursorOwnedHooksPresentHealsPartialRemovalOnManagedMac(t *testing.T) {
	events := forceManagedHookRenderChecks(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	conn := NewCursorConnector()
	opts := SetupOpts{DataDir: filepath.Join(home, ".defenseclaw"), APIAddr: "127.0.0.1:18970", APIToken: managedHookTestToken, ManagedEnterprise: true}
	path := conn.configPath(opts)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := patchCursorHooks(path, conn.hookCommand(opts), "", conn.effectiveFailClosed(opts)); err != nil {
		t.Fatal(err)
	}
	if present, err := OwnedHooksPresent(conn, opts); err != nil || !present {
		t.Fatalf("full matrix present=%t err=%v", present, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	delete(cfg["hooks"].(map[string]interface{}), "beforeSubmitPrompt")
	data, _ = json.Marshal(cfg)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if present, err := OwnedHooksPresent(conn, opts); err != nil || present {
		t.Fatalf("partial matrix present=%t err=%v, want absent so Setup re-merges", present, err)
	}
	found := false
	for _, event := range *events {
		if strings.Contains(event, "cursor_hooks_partial") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no boundary line for the partial removal: %v", *events)
	}
	if err := patchCursorHooks(path, conn.hookCommand(opts), "", conn.effectiveFailClosed(opts)); err != nil {
		t.Fatal(err)
	}
	if present, err := OwnedHooksPresent(conn, opts); err != nil || !present {
		t.Fatalf("re-merge did not restore the matrix: present=%t err=%v", present, err)
	}
}

func TestNoteCodexTrustVerificationLogsOncePerUnverifiedVersion(t *testing.T) {
	events := forceManagedHookRenderChecks(t)
	opts := SetupOpts{DataDir: t.TempDir(), ManagedEnterprise: true, AgentVersion: "codex-cli 9.9.9"}
	unknown := HookContractResolution{Status: HookCompatibilityUnknown, Reason: "no contract"}
	noteCodexTrustVerification(opts, unknown)
	noteCodexTrustVerification(opts, unknown)
	if len(*events) != 1 || !strings.Contains((*events)[0], "codex_trust_unverified") {
		t.Fatalf("events = %v, want one codex_trust_unverified line", *events)
	}
	noteCodexTrustVerification(opts, HookContractResolution{Status: HookCompatibilityKnown})
	noteCodexTrustVerification(opts, unknown)
	if len(*events) != 2 {
		t.Fatalf("a new streak after a verified version was not logged: %v", *events)
	}
}
