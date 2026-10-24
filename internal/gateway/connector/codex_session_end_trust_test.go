// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// codexReferenceTrustHash restates, independently of
// codexCommandHookHashForPlatform, how Codex records trust for a command hook
// (codex-rs/hooks/src/engine/discovery.rs): SessionEnd and Interrupt default
// to one second and are capped at three, every other event defaults to 600
// and is at least one, and the hash covers the normalized handler.
func codexReferenceTrustHash(t *testing.T, eventKey string, matcher interface{}, command string, timeout *int) string {
	t.Helper()
	normalized := 600
	if eventKey == "session_end" || eventKey == "interrupt" {
		normalized = 1
	}
	if timeout != nil {
		normalized = *timeout
	}
	if normalized < 1 {
		normalized = 1
	}
	if (eventKey == "session_end" || eventKey == "interrupt") && normalized > 3 {
		normalized = 3
	}
	if eventKey == "user_prompt_submit" || eventKey == "stop" {
		matcher = nil
	}
	identity := map[string]interface{}{
		"event_name": eventKey,
		"hooks": []interface{}{map[string]interface{}{
			"type": "command", "command": command, "timeout": normalized, "async": false,
		}},
	}
	if matcher != nil {
		identity["matcher"] = matcher
	}
	encoded, err := json.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("sha256:%x", sha256.Sum256(encoded))
}

// Codex caps the SessionEnd timeout at three seconds before it hashes the
// handler, so a SessionEnd registration hashes the same whatever timeout above
// three it names. Hashing the raw value left every DefenseClaw-registered
// SessionEnd untrusted to the guardian once Codex recorded its own trust.
func TestCodexSessionEndTrustHashUsesCodexCappedTimeout(t *testing.T) {
	const command = "/home/user/.defenseclaw/hooks/codex-hook.sh"
	three, sixty, one := 3, 60, 1
	for _, test := range []struct {
		name    string
		event   string
		timeout *int
	}{
		{"session_end above the cap", "session_end", &sixty},
		{"session_end at the cap", "session_end", &three},
		{"session_end without a timeout", "session_end", nil},
		{"session_end at one", "session_end", &one},
		{"pre_tool_use is not capped", "pre_tool_use", &sixty},
	} {
		handler := map[string]interface{}{"type": "command", "command": command}
		if test.timeout != nil {
			handler["timeout"] = *test.timeout
		}
		got, err := codexCommandHookHashForPlatform("linux", test.event, nil, handler)
		if err != nil {
			t.Fatalf("%s: %v", test.name, err)
		}
		if want := codexReferenceTrustHash(t, test.event, nil, command, test.timeout); got != want {
			t.Errorf("%s: hash=%s want Codex's %s", test.name, got, want)
		}
	}
	capped, _ := codexCommandHookHashForPlatform("linux", "session_end", nil,
		map[string]interface{}{"type": "command", "command": command, "timeout": 60})
	atCap, _ := codexCommandHookHashForPlatform("linux", "session_end", nil,
		map[string]interface{}{"type": "command", "command": command, "timeout": 3})
	if capped != atCap {
		t.Errorf("SessionEnd timeout 60 hashes %s, timeout 3 hashes %s; Codex records both as 3", capped, atCap)
	}
	if codexSessionEndHookGroup.timeout > codexSessionEndMaxTimeoutSeconds {
		t.Errorf("SessionEnd registered with timeout %d, above Codex's %d-second cap",
			codexSessionEndHookGroup.timeout, codexSessionEndMaxTimeoutSeconds)
	}
}

// The matrix DefenseClaw writes for codex-hooks-v4, with the trust state Codex
// records for it, passes the guardian's verification. On Codex 0.163 the
// SessionEnd entry failed here and the guardian looped on an unrepairable
// "owned hook command not present".
func TestCodexTrustedMatrixAcceptsCodexRecordedTrust(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("user-scoped Codex trust state is not installed on Windows")
	}
	root := t.TempDir()
	configPath := filepath.Join(root, "codex", "config.toml")
	hooksDir := filepath.Join(root, "dc", "hooks")
	command := filepath.ToSlash(filepath.Join(hooksDir, "codex-hook.sh"))
	groups, err := codexHookGroupsForOptions(SetupOpts{HookContractID: "codex-hooks-v4"})
	if err != nil {
		t.Fatalf("resolve codex-hooks-v4 groups: %v", err)
	}

	hooks := buildCodexHooksTableForGroups(configPath, command, groups)
	state := map[string]interface{}{}
	keySource := codexHookStateKeySource(configPath)
	for _, group := range groups {
		eventKey := codexHookEventKeyLabel(group.eventType)
		var matcher interface{}
		if group.matcher != "" {
			matcher = group.matcher
		}
		timeout := group.timeout
		state[codexHookStateKey(keySource, eventKey, 0, 0)] = map[string]interface{}{
			"trusted_hash": codexReferenceTrustHash(t, eventKey, matcher, command, &timeout),
		}
	}
	hooks["state"] = state

	if err := verifyTrustedCodexHookMatrixForGroups(hooks, configPath, hooksDir, groups); err != nil {
		t.Fatalf("matrix with Codex-recorded trust rejected: %v", err)
	}
}

// OwnedHooksPresent stays (false, nil) for a rejected Codex matrix, which hook
// guards read as "absent, heal by Setup"; OwnedHooksAbsentReason says why, for
// the guardian's messages.
func TestCodexOwnedHooksAbsentReasonExplainsRejection(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("user-scoped Codex trust state is not installed on Windows")
	}
	root := t.TempDir()
	configPath := filepath.Join(root, "codex", "config.toml")
	previous := CodexConfigPathOverride
	CodexConfigPathOverride = configPath
	t.Cleanup(func() { CodexConfigPathOverride = previous })
	conn := NewCodexConnector()
	opts := SetupOpts{DataDir: filepath.Join(root, "dc"), AgentVersion: "0.163.0"}

	present, err := OwnedHooksPresent(conn, opts)
	if err != nil || present {
		t.Fatalf("missing config: present=%v err=%v, want false/nil", present, err)
	}
	if reason := OwnedHooksAbsentReason(conn, opts); !strings.Contains(reason, "does not exist") {
		t.Fatalf("missing config reason = %q", reason)
	}

	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("[features]\nhooks = false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A user who turned hooks off outside managed mode gets an error at once
	// (GAP-1094); a managed install reports it as absent, with the reason.
	if present, err := OwnedHooksPresent(conn, opts); err == nil || present {
		t.Fatalf("hooks disabled, unmanaged: present=%v err=%v, want the turned-off error", present, err)
	}
	managed := opts
	managed.ManagedEnterprise = true
	if present, err := OwnedHooksPresent(conn, managed); err != nil || present {
		t.Fatalf("hooks disabled, managed: present=%v err=%v, want false/nil", present, err)
	}
	if reason := OwnedHooksAbsentReason(conn, managed); !strings.Contains(reason, "[features].hooks") {
		t.Fatalf("hooks disabled reason = %q", reason)
	}
}
