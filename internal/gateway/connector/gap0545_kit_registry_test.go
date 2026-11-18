// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package connector_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// gap0545Home is a home with the actor's synthetic key, its authorized keys,
// DefenseClaw state and a project app with a link to the key (the J19
// layout of the kit's tests).
func gap0545Home(t *testing.T) (home, app string) {
	t.Helper()
	home = filepath.Join(t.TempDir(), "home", "alice")
	app = filepath.Join(home, "app")
	for _, dir := range []string{".ssh", "app"} {
		if err := os.MkdirAll(filepath.Join(home, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "id_ed25519"),
		[]byte("-----BEGIN OPENSSH PRIVATE KEY-----\ngap0545\n-----END OPENSSH PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, ".ssh", "id_ed25519"), filepath.Join(app, "key-link")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	return home, app
}

// gap0545ShellPayload is a hook call of connectorName's shell tool tool
// running command in cwd, in the payload shape the connector's hook sends:
// tool_name and tool_input with the tool's own command key, Copilot's
// toolName and toolArgs (a JSON string), and Cursor's beforeShellExecution,
// which names no tool.
func gap0545ShellPayload(t *testing.T, connectorName, event, tool, key, command, cwd string) []byte {
	t.Helper()
	body := map[string]any{"hook_event_name": event, "session_id": "gap0545", "cwd": cwd}
	switch {
	case connectorName == "cursor" && event == "beforeShellExecution":
		body["command"] = command
	case connectorName == "copilot":
		args, _ := json.Marshal(map[string]any{key: command})
		body["toolName"], body["toolArgs"] = tool, string(args)
		delete(body, "hook_event_name")
	default:
		body["tool_name"], body["tool_input"] = tool, map[string]any{key: command}
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestGAP0545EveryRegisteredShellToolGetsTheKitsProofs: for every connector
// the kit runs, on every event its hook contracts route to structured action
// evaluation, every shell tool the connector registry lists, with the tool's
// own command key, gets the kit's private-key read proof and link facts in the
// actor's file system. Codex exec_command and Amp Bash (cmd), OpenCode bash
// and Cursor beforeShellExecution got none (substrate-1 GAP-0545). A tool or
// connector the registry adds is covered, or this test fails. It reads the
// registry's test-only views (export_kit_test.go, substrate-1 GAP-0626).
func TestGAP0545EveryRegisteredShellToolGetsTheKitsProofs(t *testing.T) {
	home, app := gap0545Home(t)
	key := filepath.Join(home, ".ssh", "id_ed25519")
	hasWord := func(f *kit.Facts) bool {
		return f != nil && slices.ContainsFunc(f.Paths, func(p kit.PathFact) bool {
			return p.Field == kit.CommandWordField && p.Path == "key-link" && p.Resolved == key
		})
	}
	covered := 0
	for _, connectorName := range kit.Connectors() {
		events := connector.StructuredActionEvents(connectorName)
		tools := connector.ShellTools(connectorName)
		if len(events) == 0 || len(tools) == 0 {
			t.Errorf("%s: the registry lists events %v and shell tools %v: a connector the kit runs needs both", connectorName, events, tools)
			continue
		}
		type call struct{ event, tool string }
		calls := []call{}
		for _, event := range events {
			for _, tool := range tools {
				calls = append(calls, call{event, tool})
			}
			if connectorName == "cursor" && event == "beforeShellExecution" {
				calls = append(calls, call{event, ""})
			}
		}
		for _, c := range calls {
			commandKey := connector.ShellCommandKey(connectorName, c.tool)
			if c.tool != "" && commandKey == "" {
				t.Errorf("%s %s: the registry names no command key for its shell tool", connectorName, c.tool)
				continue
			}
			payload := gap0545ShellPayload(t, connectorName, c.event, c.tool, commandKey, "cat key-link", app)
			command, _, ok := kit.ShellCommandOf(connectorName, c.event, payload)
			if !ok || command != "cat key-link" {
				t.Errorf("%s %s %s: ShellCommandOf = %q %v, want the call's command", connectorName, c.event, c.tool, command, ok)
				continue
			}
			f := kit.CollectFacts(connectorName, c.event, payload, 1<<20)
			if f == nil || !slices.Contains(f.Proofs, kit.ProofPrivateKeyRead) || !hasWord(f) {
				t.Errorf("%s %s %s: facts %+v, want the private-key read proof and key-link -> %s", connectorName, c.event, c.tool, f, key)
				continue
			}
			covered++
		}
	}
	if covered == 0 {
		t.Fatal("no shell tool covered")
	}
	// After the call ran, and for a tool that runs no shell, no proof.
	payload := gap0545ShellPayload(t, "claudecode", "PostToolUse", "Bash", "command", "cat key-link", app)
	if f := kit.CollectFacts("claudecode", "PostToolUse", payload, 1<<20); f != nil && len(f.Proofs) != 0 {
		t.Errorf("PostToolUse: proofs %v, want none", f.Proofs)
	}
	payload = gap0545ShellPayload(t, "claudecode", "PreToolUse", "Grep", "command", "cat key-link", app)
	if f := kit.CollectFacts("claudecode", "PreToolUse", payload, 1<<20); f != nil && len(f.Proofs) != 0 {
		t.Errorf("Grep: proofs %v, want none", f.Proofs)
	}
}
