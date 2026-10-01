// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
package connector

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func deepseekTestOpts(t *testing.T) SetupOpts {
	t.Helper()
	root := t.TempDir()
	opts := SetupOpts{DataDir: filepath.Join(root, "defenseclaw"), ConfigHome: filepath.Join(root, "dsh home"), APIAddr: "127.0.0.1:18970", AgentVersion: "0.2.0-rc.2"}
	for _, path := range []string{opts.DataDir, opts.ConfigHome} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	return opts
}
func TestDeepSeekSetupRoundTripPreservesDocuments(t *testing.T) {
	opts := deepseekTestOpts(t)
	c := NewDeepSeekConnector()
	patch := []byte("# operator comment\n- insert:\n    - id: existing\n      name: example-plugin\n")
	hooks := []byte(`{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"foreign-check"}]}]},"theme":"dark"}`)
	for path, body := range map[string][]byte{deepseekPatchPath(opts): patch, deepseekHooksPath(opts): hooks} {
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 2; i++ {
		if err := c.Setup(context.Background(), opts); err != nil {
			t.Fatal(err)
		}
	}
	if ok, err := c.ownedHookContractPresent(opts); err != nil || !ok {
		t.Fatalf("registration=%v error=%v", ok, err)
	}
	body, _ := os.ReadFile(deepseekPatchPath(opts))
	if bytes.Count(body, []byte(deepseekPatchID)) != 1 {
		t.Fatalf("duplicate bridge: %s", body)
	}
	if err := c.Teardown(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string][]byte{deepseekPatchPath(opts): patch, deepseekHooksPath(opts): hooks} {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("did not restore %s: %v", path, err)
		}
	}
	if err := c.VerifyClean(opts); err != nil {
		t.Fatal(err)
	}
}
func TestDeepSeekRefusesInvalidPatchBeforeWriting(t *testing.T) {
	for _, body := range []string{"bad: mapping", "- insert: wrong", "- insert:\n  - id: defenseclaw-deepseek\n    name: another-plugin\n"} {
		t.Run(body, func(t *testing.T) {
			opts := deepseekTestOpts(t)
			os.WriteFile(deepseekPatchPath(opts), []byte(body), 0600)
			if err := NewDeepSeekConnector().Setup(context.Background(), opts); err == nil {
				t.Fatal("accepted invalid/foreign patch")
			}
			if _, err := os.Stat(deepseekHooksPath(opts)); !os.IsNotExist(err) {
				t.Fatal("wrote hooks before validation")
			}
			got, _ := os.ReadFile(deepseekPatchPath(opts))
			if string(got) != body {
				t.Fatal("changed foreign document")
			}
		})
	}
}
func TestDeepSeekTeardownPreservesLaterEdits(t *testing.T) {
	opts := deepseekTestOpts(t)
	c := NewDeepSeekConnector()
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(deepseekPatchPath(opts), os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("\n- insert:\n    - id: later-plugin\n      name: operator-plugin\n")
	f.Close()
	if err := c.Teardown(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(deepseekPatchPath(opts))
	if !bytes.Contains(got, []byte("later-plugin")) || bytes.Contains(got, []byte(deepseekPatchID)) {
		t.Fatalf("incorrect cleanup: %s", got)
	}
	if err := c.VerifyClean(opts); err != nil {
		t.Fatal(err)
	}
}
func TestDeepSeekContractAndVendorResponses(t *testing.T) {
	c := NewDeepSeekConnector()
	profile := c.HookProfile(SetupOpts{AgentVersion: "0.2.0-rc.2"})
	if !profile.Capabilities.CanBlock || profile.Capabilities.SupportsFailClosed {
		t.Fatal("incorrect enforcement claim")
	}
	for _, event := range []string{"Stop", "PostToolUse", "SubagentStop"} {
		if out := DeepSeekHookOutput(event, "block", "reason"); out != nil {
			t.Fatalf("unsupported veto %s: %v", event, out)
		}
	}
	for action, want := range map[string]string{"block": "deny", "confirm": "ask"} {
		out := DeepSeekHookOutput("PreToolUse", action, "reason")
		if out["hookSpecificOutput"].(map[string]interface{})["permissionDecision"] != want {
			t.Fatal(out)
		}
	}
	req := deepseekProfileDecode(map[string]interface{}{"hook_event_name": "PreToolUse", "tool_name": "bash", "tool_input": map[string]interface{}{"command": "echo safe", "description": "fixture"}, "session_id": "session-fixture", "tool_use_id": "call-fixture"})
	var args map[string]interface{}
	if err := json.Unmarshal(req.ToolArgs, &args); err != nil {
		t.Fatal(err)
	}
	if req.ConnectorName != "deepseek" || req.ToolName != "bash" || args["command"] != "echo safe" || !req.ToolArgsAuthoritative {
		t.Fatalf("bad projection: %+v", req)
	}
	opts := deepseekTestOpts(t)
	opts.ManagedEnterprise = true
	if err := c.Setup(context.Background(), opts); err == nil {
		t.Fatal("accepted managed enrollment")
	}
}
func TestDeepSeekFreshTeardownDoesNotCreateConfig(t *testing.T) {
	opts := deepseekTestOpts(t)
	c := NewDeepSeekConnector()
	if err := c.Teardown(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{deepseekHooksPath(opts), deepseekPatchPath(opts)} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("created %s", p)
		}
	}
}

// This opt-in test runs the actual vendor npm bridge, not a reimplementation.
// Install pinned dependencies outside the repository and supply its module path.
func TestDeepSeekPublishedBridge(t *testing.T) {
	module := os.Getenv("DEEPSEEK_BRIDGE_MODULE")
	if module == "" {
		t.Skip("set DEEPSEEK_BRIDGE_MODULE to pinned @deepseek-ai/dsh-hooks-claude-code@0.2.0-rc.2 lib/index.js")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "invalid JSON", 400)
			return
		}
		if r.URL.Path != "/api/v1/deepseek/hook" || r.Header.Get("Authorization") == "" {
			http.Error(w, "invalid request", 403)
			return
		}
		action := "allow"
		if input, ok := payload["tool_input"].(map[string]interface{}); ok {
			if input["command"] == "blocked" {
				action = "block"
			}
			if input["command"] == "confirm" {
				action = "confirm"
			}
		}
		if payload["prompt"] == "blocked prompt" {
			action = "block"
		}
		event, _ := payload["hook_event_name"].(string)
		json.NewEncoder(w).Encode(map[string]interface{}{"action": action, "hook_output": DeepSeekHookOutput(event, action, "fixture policy")})
	}))
	defer server.Close()
	opts := deepseekTestOpts(t)
	opts.APIAddr = strings.TrimPrefix(server.URL, "http://")
	// Test-only scoped material is local and never printed or used as argv.
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		t.Fatal(err)
	}
	opts.HookAPIToken = hex.EncodeToString(tokenBytes)
	opts.HookAPITokenScoped = true
	c := NewDeepSeekConnector()
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join("..", "..", "..", "scripts", "test-deepseek-vendor-bridge.mjs")
	cmd := exec.Command("node", script, module, deepseekHooksPath(opts), filepath.Join(opts.DataDir, "hooks", "deepseek-hook.sh"), opts.DataDir)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("published vendor bridge: %v\n%s", err, output)
	} else {
		t.Log(string(output))
	}
}

func TestDeepSeekSetupAndTeardownPreserveMixedForeignHandlers(t *testing.T) {
	opts := deepseekTestOpts(t)
	c := NewDeepSeekConnector()
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	cfg, err := readJSONObject(deepseekHooksPath(opts))
	if err != nil {
		t.Fatal(err)
	}
	group := cfg["hooks"].(map[string]interface{})["PreToolUse"].([]interface{})[0].(map[string]interface{})
	group["hooks"] = append(group["hooks"].([]interface{}), map[string]interface{}{"type": "command", "command": "operator-check"})
	if err := writeJSONObject(deepseekHooksPath(opts), cfg); err != nil {
		t.Fatal(err)
	}
	patch, _ := os.ReadFile(deepseekPatchPath(opts))
	patch = append(patch, []byte("\n- insert:\n    - id: operator-later\n      name: operator-plugin\n")...)
	if err := os.WriteFile(deepseekPatchPath(opts), patch, 0600); err != nil {
		t.Fatal(err)
	}
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if err := c.Teardown(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	hooks, _ := os.ReadFile(deepseekHooksPath(opts))
	if !bytes.Contains(hooks, []byte("operator-check")) || bytes.Contains(hooks, []byte("deepseek-hook.sh")) {
		t.Fatalf("lost foreign handler: %s", hooks)
	}
	patch, _ = os.ReadFile(deepseekPatchPath(opts))
	if !bytes.Contains(patch, []byte("operator-later")) || bytes.Contains(patch, []byte(deepseekPatchID)) {
		t.Fatalf("lost foreign patch: %s", patch)
	}
}

func TestDeepSeekRejectsAmbiguousAndDisabledRegistration(t *testing.T) {
	opts := deepseekTestOpts(t)
	patch, err := deepseekPatch(nil, opts, false)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"duplicate": append(append([]byte(nil), patch...), patch...),
		"disabled":  bytes.Replace(patch, []byte("id: defenseclaw-deepseek"), []byte("id: defenseclaw-deepseek\n      disabled: true"), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := deepseekPatch(data, opts, false); err == nil {
				t.Fatal("accepted ambiguous or modified bridge")
			}
		})
	}
}

func TestDeepSeekRefusesSymlinkAndChangedConfigHome(t *testing.T) {
	opts := deepseekTestOpts(t)
	c := NewDeepSeekConnector()
	target := filepath.Join(t.TempDir(), "foreign.yml")
	original := []byte("[]\n")
	if err := os.WriteFile(target, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, deepseekPatchPath(opts)); err != nil {
		t.Skip(err)
	}
	if err := c.Setup(context.Background(), opts); err == nil {
		t.Fatal("accepted symlink")
	}
	actual, _ := os.ReadFile(target)
	if !bytes.Equal(actual, original) {
		t.Fatal("changed symlink target")
	}
	if err := os.Remove(deepseekPatchPath(opts)); err != nil {
		t.Fatal(err)
	}
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	other := opts
	other.ConfigHome = t.TempDir()
	if err := c.Teardown(context.Background(), other); err == nil {
		t.Fatal("accepted different backup target")
	}
	if ok, err := c.ownedHookContractPresent(opts); err != nil || !ok {
		t.Fatalf("changed original registration: %v", err)
	}
}
