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

//go:build !windows

package connector

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path"
	"reflect"
	"strings"
	"testing"
)

// TestKiroSandboxContractIsSandboxOnly keeps host Kiro hooks ungated while
// an overlay image resolves (and a sandbox binding pins) the reviewed
// kiro-cli-hooks-v1 contract.
func TestKiroSandboxContractIsSandboxOnly(t *testing.T) {
	if got := ResolveHookContract("kiro", "2.24.1"); got.Status != HookCompatibilityNotGated || got.Contract.ContractID != "" {
		t.Fatalf("host Kiro resolution changed: %+v", got)
	}
	got := ResolveSandboxHookContract("kiro", "2.24.1")
	if got.Status != HookCompatibilityKnown || got.Contract.ContractID != "kiro-cli-hooks-v1" {
		t.Fatalf("sandbox Kiro resolution = %+v", got)
	}
	for _, version := range []string{"2.22.0", "2.24.2", "kiro-cli 2.25.0", "latest"} {
		if got := ResolveSandboxHookContract("kiro", version); got.Status == HookCompatibilityKnown {
			t.Fatalf("Kiro %q resolved to %s", version, got.Contract.ContractID)
		}
	}
	if got := ResolveSandboxHookContract("kiro", ""); got.Status != HookCompatibilityUnversioned {
		t.Fatalf("unversioned Kiro = %+v", got)
	}
	if _, err := NewKiroConnector().SandboxArtifacts(SandboxRenderTarget{IngressPort: 18971}); err == nil {
		t.Fatal("Kiro sandbox artifacts rendered without a pinned version")
	}
	if _, ok := hookContractByIDForOS("kiro", "kiro-cli-hooks-v1", "linux"); !ok {
		t.Fatal("a sandbox binding cannot pin the Kiro contract")
	}
	if _, ok := hookContractByIDForOS("kiro", "kiro-cli-hooks-v1", "darwin"); ok {
		t.Fatal("the sandbox-only Kiro contract leaked to macOS")
	}
	// The gateway builds a sandboxed Kiro profile from the binding's pin.
	profile := NewKiroConnector().HookProfile(SetupOpts{APIAddr: "127.0.0.1:18970", AgentVersion: "2.24.1", HookContractID: "kiro-cli-hooks-v1", GOOS: "linux"})
	if profile.ContractID != "kiro-cli-hooks-v1" || !reflect.DeepEqual(profile.Capabilities.BlockEvents, []string{"PreToolUse"}) {
		t.Fatalf("sandbox Kiro profile = %+v", profile)
	}
	if host := NewKiroConnector().HookProfile(SetupOpts{APIAddr: "127.0.0.1:18970"}); host.ContractID != "" {
		t.Fatalf("host Kiro profile picked up a contract: %s", host.ContractID)
	}
	// Mutating a returned contract never reaches the table.
	contracts := sandboxOnlyHookContracts("kiro")
	contracts[0].Events[0] = "mutated"
	if sandboxOnlyHookContracts("kiro")[0].Events[0] == "mutated" {
		t.Fatal("sandbox-only contracts alias their table")
	}
	if len(sandboxOnlyHookContracts("codex")) != 0 {
		t.Fatal("codex has no sandbox-only contracts")
	}
}

func TestKiroSandboxArtifactsShape(t *testing.T) {
	a := sandboxArtifactsFor(t, NewKiroConnector(), "2.24.1")
	if a.TamperTier != SandboxTamperTierUser || a.HookContract != "kiro-cli-hooks-v1" {
		t.Fatalf("tier %s contract %s", a.TamperTier, a.HookContract)
	}
	// Kiro picks an agent by the name inside any file of its agents
	// directories, so the DefenseClaw agent is alone in a root-owned one and
	// no agent file lives in the workload-writable HOME.
	agent := sandboxFile(t, a, KiroSandboxAgentPath)
	if agent.Owner != SandboxOwnerRoot || agent.Mode != 0o644 || path.Dir(KiroSandboxAgentPath) != KiroSandboxAgentDir {
		t.Fatalf("agent %s %s %v", KiroSandboxAgentPath, agent.Owner, agent.Mode)
	}
	for _, file := range a.Files {
		if file.Path != KiroSandboxAgentPath && (strings.HasPrefix(file.Path, KiroSandboxAgentDir+"/") || strings.Contains(file.Path, "/.kiro/agents")) {
			t.Fatalf("%s is another agent file Kiro could read", file.Path)
		}
	}
	if a.Env[KiroSandboxAgentDirEnv] != KiroSandboxAgentDir || len(a.Env) != 1 {
		t.Fatalf("env = %v, want %s=%s", a.Env, KiroSandboxAgentDirEnv, KiroSandboxAgentDir)
	}
	var doc struct {
		Name  string `json:"name"`
		Tools []string
		Hooks map[string][]map[string]string `json:"hooks"`
	}
	if err := json.Unmarshal(agent.Data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Name != KiroSandboxAgentName || !reflect.DeepEqual(doc.Tools, []string{"*"}) || len(doc.Hooks) != 4 {
		t.Fatalf("agent = %s", agent.Data)
	}
	for _, event := range []string{"userPromptSubmit", "preToolUse", "postToolUse", "stop"} {
		if hooks := doc.Hooks[event]; len(hooks) != 1 || hooks[0]["command"] != SandboxHookDir+"/kiro-hook.sh" || hooks[0]["matcher"] != "*" {
			t.Fatalf("%s hooks = %v", event, doc.Hooks[event])
		}
	}
	var settings map[string]interface{}
	if err := json.Unmarshal(sandboxFile(t, a, KiroSandboxSettingsPath).Data, &settings); err != nil {
		t.Fatal(err)
	}
	if settings["chat.defaultAgent"] != KiroSandboxAgentName || settings["telemetry.enabled"] != false || settings["app.disableAutoupdates"] != true ||
		settings["chat.disableTrustAllConfirmation"] != true || settings["chat.greeting.enabled"] != false {
		t.Fatalf("settings = %v", settings)
	}
}

func TestVerifyKiroSandboxAgentRejectsTampering(t *testing.T) {
	good, err := renderKiroSandboxAgent()
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyKiroSandboxAgent(good); err != nil {
		t.Fatal(err)
	}
	mutate := func(f func(doc map[string]interface{})) []byte {
		var doc map[string]interface{}
		if err := json.Unmarshal(good, &doc); err != nil {
			t.Fatal(err)
		}
		f(doc)
		out, _ := json.Marshal(doc)
		return out
	}
	hook := func(doc map[string]interface{}, event string) map[string]interface{} {
		return doc["hooks"].(map[string]interface{})[event].([]interface{})[0].(map[string]interface{})
	}
	for name, body := range map[string][]byte{
		// The regular expression ".*" matches no tool on Kiro 2.24.1.
		"regex-matcher":   mutate(func(d map[string]interface{}) { hook(d, "preToolUse")["matcher"] = ".*" }),
		"other-command":   mutate(func(d map[string]interface{}) { hook(d, "stop")["command"] = "/bin/true" }),
		"missing-trigger": mutate(func(d map[string]interface{}) { delete(d["hooks"].(map[string]interface{}), "postToolUse") }),
		"extra-trigger":   mutate(func(d map[string]interface{}) { d["hooks"].(map[string]interface{})["agentSpawn"] = []interface{}{} }),
		"pre-approved":    mutate(func(d map[string]interface{}) { d["allowedTools"] = []interface{}{"*"} }),
		"unknown-key":     mutate(func(d map[string]interface{}) { d["mcpServers"] = map[string]interface{}{} }),
		"renamed":         mutate(func(d map[string]interface{}) { d["name"] = "kiro_default" }),
		"not-json":        []byte(`{"name":`),
	} {
		if err := verifyKiroSandboxAgent(body); err == nil {
			t.Errorf("%s: tampered agent accepted", name)
		}
	}
}

func TestCursorSandboxArtifactsShape(t *testing.T) {
	a := sandboxArtifactsFor(t, NewCursorConnector(), "2026.07.23-e383d2b")
	if a.TamperTier != SandboxTamperTierManaged || a.HookContract != "cursor-hooks-v1" {
		t.Fatalf("tier %s contract %s", a.TamperTier, a.HookContract)
	}
	hooksFile := sandboxFile(t, a, CursorSandboxHooksPath)
	if hooksFile.Owner != SandboxOwnerRoot || hooksFile.Mode != 0o644 {
		t.Fatalf("hooks.json %s %v", hooksFile.Owner, hooksFile.Mode)
	}
	var doc struct {
		Version int                                 `json:"version"`
		Hooks   map[string][]map[string]interface{} `json:"hooks"`
	}
	if err := json.Unmarshal(hooksFile.Data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Version != 1 || len(doc.Hooks) != len(cursorHookEvents) {
		t.Fatalf("hooks.json = %s", hooksFile.Data)
	}
	for _, event := range cursorHookEvents {
		entries := doc.Hooks[event]
		if len(entries) != 1 || entries[0]["failClosed"] != true || entries[0]["timeout"] != float64(30) ||
			entries[0]["command"] != "'"+SandboxHookDir+"/cursor-hook.sh'" || entries[0]["type"] != "command" {
			t.Fatalf("%s entries = %v", event, entries)
		}
	}
	for _, versions := range []string{"2026.09.26-dd393fe", "2.3.0", "4.0.0"} {
		if _, err := NewCursorConnector().SandboxArtifacts(SandboxRenderTarget{IngressPort: 18971, AgentVersion: versions}); err == nil {
			t.Errorf("Cursor %s rendered sandbox artifacts", versions)
		}
	}
}

func TestVerifyCursorSandboxHooksRejectsTampering(t *testing.T) {
	rt, err := resolveSandboxTarget("cursor", SandboxRenderTarget{IngressPort: 18971, AgentVersion: "2026.07.23-e383d2b"})
	if err != nil {
		t.Fatal(err)
	}
	good, err := renderCursorSandboxHooks(rt)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyCursorSandboxHooks(good, rt); err != nil {
		t.Fatal(err)
	}
	mutate := func(f func(doc map[string]interface{})) []byte {
		var doc map[string]interface{}
		if err := json.Unmarshal(good, &doc); err != nil {
			t.Fatal(err)
		}
		f(doc)
		out, _ := json.Marshal(doc)
		return out
	}
	entry := func(doc map[string]interface{}, event string) map[string]interface{} {
		return doc["hooks"].(map[string]interface{})[event].([]interface{})[0].(map[string]interface{})
	}
	for name, body := range map[string][]byte{
		"fail-open":     mutate(func(d map[string]interface{}) { entry(d, "preToolUse")["failClosed"] = false }),
		"short-timeout": mutate(func(d map[string]interface{}) { entry(d, "beforeShellExecution")["timeout"] = 5 }),
		"other-command": mutate(func(d map[string]interface{}) { entry(d, "beforeReadFile")["command"] = "/bin/true" }),
		"missing-event": mutate(func(d map[string]interface{}) { delete(d["hooks"].(map[string]interface{}), "beforeMCPExecution") }),
		"extra-event": mutate(func(d map[string]interface{}) {
			d["hooks"].(map[string]interface{})["notAnEvent"] = []interface{}{map[string]interface{}{"command": "/bin/true"}}
		}),
		"extra-key":   mutate(func(d map[string]interface{}) { d["other"] = true }),
		"old-version": mutate(func(d map[string]interface{}) { d["version"] = 2 }),
		"not-json":    []byte(`{"version":`),
	} {
		if err := verifyCursorSandboxHooks(body, rt); err == nil {
			t.Errorf("%s: tampered hooks.json accepted", name)
		}
	}
}

func TestDevinSandboxArtifactsShape(t *testing.T) {
	a := sandboxArtifactsFor(t, NewDevinConnector(), "3000.4.25")
	if a.TamperTier != SandboxTamperTierUser || a.HookContract != "devin-hooks-v1" {
		t.Fatalf("tier %s contract %s", a.TamperTier, a.HookContract)
	}
	template := sandboxFile(t, a, DevinSandboxConfigTemplatePath)
	config := sandboxFile(t, a, DevinSandboxConfigPath)
	if template.Owner != SandboxOwnerRoot || config.Owner != SandboxOwnerUser || config.Mode != 0o600 || !bytes.Equal(template.Data, config.Data) {
		t.Fatalf("template %s, config %s %v", template.Owner, config.Owner, config.Mode)
	}
	var doc struct {
		Hooks map[string][]struct {
			Matcher string `json:"matcher"`
			Hooks   []struct {
				Type    string `json:"type"`
				Command string `json:"command"`
				Timeout int    `json:"timeout"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(config.Data, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Hooks) != len(devinHookEvents) {
		t.Fatalf("config = %s", config.Data)
	}
	for _, event := range devinHookEvents {
		groups := doc.Hooks[event]
		if len(groups) != 1 || len(groups[0].Hooks) != 1 || groups[0].Hooks[0].Command != SandboxHookDir+"/devin-hook.sh" || groups[0].Hooks[0].Timeout != 30 {
			t.Fatalf("%s groups = %+v", event, groups)
		}
	}
	if _, err := NewDevinConnector().SandboxArtifacts(SandboxRenderTarget{IngressPort: 18971, AgentVersion: "3000.11.3"}); err == nil {
		t.Fatal("an unreviewed Devin release rendered sandbox artifacts")
	}
}

func TestVerifyDevinSandboxConfigRejectsTampering(t *testing.T) {
	rt, err := resolveSandboxTarget("devin", SandboxRenderTarget{IngressPort: 18971, AgentVersion: "3000.4.25"})
	if err != nil {
		t.Fatal(err)
	}
	good, err := renderDevinSandboxConfig(rt)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyDevinSandboxConfig(good, rt); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"host-timeout":  strings.Replace(string(good), `"timeout": 30`, `"timeout": 10`, 1),
		"other-command": strings.Replace(string(good), SandboxHookDir+"/devin-hook.sh", "/bin/true", 1),
		"extra-key":     strings.Replace(string(good), `{`, `{"permissions": {},`, 1),
		"matcher":       strings.Replace(string(good), `"matcher": ""`, `"matcher": "exec"`, 1),
		"not-json":      `{"hooks":`,
	} {
		if err := verifyDevinSandboxConfig([]byte(body), rt); err == nil {
			t.Errorf("%s: tampered config accepted", name)
		}
	}
}

// TestSandboxCursorHook pins the Cursor sandbox hook: every verdict and
// failure prints an object Cursor accepts for the event, a block exits 2
// whether or not the gateway rendered the event-native object, and no host
// token or fail-open override is honoured.
func TestSandboxCursorHook(t *testing.T) {
	h := newSandboxHookHarness(t, NewCursorConnector(), "2026.07.23-e383d2b")
	hook := SandboxHookDir + "/cursor-hook.sh"
	if err := os.WriteFile(h.path(SandboxHookDir+"/.hook-cursor.token"), []byte("host\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{SandboxTokenEnv: "tok", "DEFENSECLAW_FAIL_MODE": "open", "DEFENSECLAW_GATEWAY_TOKEN": "host"}
	deny := func(stdout string) bool {
		var out map[string]interface{}
		return json.Unmarshal([]byte(stdout), &out) == nil && out["permission"] == "deny"
	}

	run := h.run(t, hook, nil, cursorPreToolUse, env, []string{"exit:52", allowResponse})
	if run.exitCode != 0 || len(run.calls) != 2 || strings.TrimSpace(run.stdout) != `{"permission":"allow"}` {
		t.Fatalf("allow after a dropped request: exit %d calls %d stdout %q stderr %s", run.exitCode, len(run.calls), run.stdout, run.stderr)
	}
	call := run.calls[1]
	if call.url() != "http://host.openshell.internal:18971/api/v1/cursor/hook" || call.headers["authorization"] != "Bearer tok" ||
		call.body != cursorPreToolUse || !sandboxIdempotencyKeyRE.MatchString(call.headers["x-defenseclaw-hook-idempotency-key"]) ||
		call.headers["x-defenseclaw-hook-idempotency-key"] != run.calls[0].headers["x-defenseclaw-hook-idempotency-key"] {
		t.Fatalf("request %v headers %v", call.argv, call.headers)
	}
	verdict := `{"permission":"deny","user_message":"nope","agent_message":"nope"}`
	run = h.run(t, hook, nil, cursorPreToolUse, env, []string{`200|{"action":"block","reason":"nope","hook_output":` + verdict + `}`})
	if run.exitCode != 2 || strings.TrimSpace(run.stdout) != verdict {
		t.Fatalf("block with verdict: exit %d stdout %q", run.exitCode, run.stdout)
	}
	run = h.run(t, hook, nil, cursorPreToolUse, env, []string{`200|{"action":"block","reason":"nope"}`})
	if run.exitCode != 2 || !deny(run.stdout) {
		t.Fatalf("block without verdict: exit %d stdout %q", run.exitCode, run.stdout)
	}
	for name, responses := range map[string][]string{"down": {"exit:7", "exit:7"}, "unauthorized": {`401|{}`}, "garbage": {`200|<html>`}} {
		run = h.run(t, hook, nil, cursorPreToolUse, env, responses)
		if run.exitCode != 2 || !deny(run.stdout) {
			t.Fatalf("%s: exit %d stdout %q", name, run.exitCode, run.stdout)
		}
	}
	// No binding token: denied without asking the ingress, never with the
	// host token.
	run = h.run(t, hook, nil, cursorPreToolUse, map[string]string{"DEFENSECLAW_GATEWAY_TOKEN": "host"}, []string{allowResponse})
	if run.exitCode != 2 || len(run.calls) != 0 || !deny(run.stdout) {
		t.Fatalf("no token: exit %d calls %d stdout %q", run.exitCode, len(run.calls), run.stdout)
	}
	// Event-native shapes: a prompt gate says continue, an observation event
	// prints {}.
	prompt := `{"hook_event_name":"beforeSubmitPrompt","prompt":"hi"}`
	run = h.run(t, hook, nil, prompt, env, []string{allowResponse})
	if run.exitCode != 0 || strings.TrimSpace(run.stdout) != `{"continue":true}` {
		t.Fatalf("prompt allow: exit %d stdout %q", run.exitCode, run.stdout)
	}
	run = h.run(t, hook, nil, prompt, env, []string{"exit:7", "exit:7"})
	if run.exitCode != 2 || !strings.Contains(run.stdout, `"continue":false`) {
		t.Fatalf("prompt down: exit %d stdout %q", run.exitCode, run.stdout)
	}
	run = h.run(t, hook, nil, `{"hook_event_name":"afterShellExecution","command":"ls"}`, env, []string{allowResponse})
	if run.exitCode != 0 || strings.TrimSpace(run.stdout) != `{}` {
		t.Fatalf("observation: exit %d stdout %q", run.exitCode, run.stdout)
	}
}

// TestSandboxKiroHook pins the Kiro sandbox hook: stdout stays empty (Kiro
// adds it to the agent context), a block exits 2 with the reason on stderr
// with or without hook_output, and every failure exits 2.
func TestSandboxKiroHook(t *testing.T) {
	h := newSandboxHookHarness(t, NewKiroConnector(), "2.24.1")
	hook := SandboxHookDir + "/kiro-hook.sh"
	env := map[string]string{SandboxTokenEnv: "tok", "DEFENSECLAW_FAIL_MODE": "open"}

	run := h.run(t, hook, nil, kiroPreToolUse, env, []string{"exit:56", allowResponse})
	if run.exitCode != 0 || run.stdout != "" || len(run.calls) != 2 {
		t.Fatalf("allow: exit %d calls %d stdout %q stderr %s", run.exitCode, len(run.calls), run.stdout, run.stderr)
	}
	if call := run.calls[1]; call.url() != "http://host.openshell.internal:18971/api/v1/kiro/hook" || call.body != kiroPreToolUse ||
		call.headers["authorization"] != "Bearer tok" || call.headers["x-defenseclaw-kiro-surface"] != "" {
		t.Fatalf("request %v headers %v", call.argv, call.headers)
	}
	for name, response := range map[string]string{
		"block-with-output":    `200|{"action":"block","reason":"nope","hook_output":{"decision":"block","reason":"nope"}}`,
		"block-without-output": `200|{"action":"block","reason":"nope"}`,
		"output-deny":          `200|{"action":"allow","hook_output":{"decision":"deny","reason":"nope"}}`,
	} {
		run = h.run(t, hook, nil, kiroPreToolUse, env, []string{response})
		if run.exitCode != 2 || run.stdout != "" || !strings.Contains(run.stderr, "nope") {
			t.Fatalf("%s: exit %d stdout %q stderr %q", name, run.exitCode, run.stdout, run.stderr)
		}
	}
	for name, responses := range map[string][]string{"down": {"exit:7", "exit:7"}, "unauthorized": {`401|{}`}, "no-action": {`200|{}`}} {
		run = h.run(t, hook, nil, kiroPreToolUse, env, responses)
		if run.exitCode != 2 || run.stdout != "" {
			t.Fatalf("%s: exit %d stdout %q", name, run.exitCode, run.stdout)
		}
	}
	run = h.run(t, hook, nil, kiroPreToolUse, map[string]string{"DEFENSECLAW_GATEWAY_TOKEN": "host"}, []string{allowResponse})
	if run.exitCode != 2 || len(run.calls) != 0 {
		t.Fatalf("no token: exit %d calls %d", run.exitCode, len(run.calls))
	}
}

// TestSandboxDevinHook pins the Devin sandbox hook: a block exits 2 and
// prints Devin's decision object, also when the gateway rendered none, and
// every failure exits 2 with the block object.
func TestSandboxDevinHook(t *testing.T) {
	h := newSandboxHookHarness(t, NewDevinConnector(), "3000.4.25")
	hook := SandboxHookDir + "/devin-hook.sh"
	env := map[string]string{SandboxTokenEnv: "tok", "DEFENSECLAW_FAIL_MODE": "open"}
	block := func(stdout string) bool {
		var out map[string]interface{}
		return json.Unmarshal([]byte(strings.TrimSpace(stdout)), &out) == nil && out["decision"] == "block"
	}

	run := h.run(t, hook, nil, devinPreToolUse, env, []string{"exit:52", allowResponse})
	if run.exitCode != 0 || run.stdout != "" || len(run.calls) != 2 || run.calls[1].url() != "http://host.openshell.internal:18971/api/v1/devin/hook" {
		t.Fatalf("allow: exit %d calls %d stdout %q stderr %s", run.exitCode, len(run.calls), run.stdout, run.stderr)
	}
	run = h.run(t, hook, nil, devinPreToolUse, env, []string{`200|{"action":"block","reason":"nope","hook_output":{"decision":"block","reason":"nope"}}`})
	if run.exitCode != 2 || strings.TrimSpace(run.stdout) != `{"decision":"block","reason":"nope"}` {
		t.Fatalf("block with output: exit %d stdout %q", run.exitCode, run.stdout)
	}
	for name, responses := range map[string][]string{
		"block-without-output": {`200|{"action":"block","reason":"nope"}`},
		"down":                 {"exit:7", "exit:7"},
		"forbidden":            {`403|{}`},
		"unknown-action":       {`200|{"action":"maybe"}`},
	} {
		run = h.run(t, hook, nil, devinPreToolUse, env, responses)
		if run.exitCode != 2 || !block(run.stdout) {
			t.Fatalf("%s: exit %d stdout %q", name, run.exitCode, run.stdout)
		}
	}
	run = h.run(t, hook, nil, devinPreToolUse, env, []string{`200|{"action":"block","reason":"nope"}`})
	if run.exitCode != 2 || !strings.Contains(run.stderr, "nope") {
		t.Fatalf("block without output: exit %d stderr %q", run.exitCode, run.stderr)
	}
	// Context for an observation event is printed without blocking.
	context := `{"hookSpecificOutput":{"hookEventName":"PostToolUse","additionalContext":"note"}}`
	run = h.run(t, hook, nil, `{"hook_event_name":"PostToolUse","tool_name":"exec"}`, env, []string{`200|{"action":"alert","hook_output":` + context + `}`})
	if run.exitCode != 0 || strings.TrimSpace(run.stdout) != context {
		t.Fatalf("context: exit %d stdout %q", run.exitCode, run.stdout)
	}
}

// TestSandboxHookOnlyHookVariantsKeepHostBytes renders each of the three
// hooks for the host and requires the sandbox branches to be gone.
func TestSandboxHookOnlyHookVariantsKeepHostBytes(t *testing.T) {
	for _, script := range []string{"cursor-hook.sh", "kiro-hook.sh", "devin-hook.sh"} {
		host, err := renderHookTemplate(script, templateData{APIAddr: "127.0.0.1:18970", FailMode: "open", TokenFile: ".token"})
		if err != nil {
			t.Fatal(err)
		}
		for _, marker := range []string{"defenseclaw_sandbox_post", "_sandbox.sh", SandboxTokenEnv, "sandbox hooks fail closed"} {
			if bytes.Contains(host, []byte(marker)) {
				t.Errorf("host %s carries sandbox-only %q", script, marker)
			}
		}
		if _, err := os.Stat("/bin/bash"); err == nil {
			cmd := exec.Command("/bin/bash", "-n")
			cmd.Stdin = bytes.NewReader(host)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("host %s does not parse: %v\n%s", script, err, out)
			}
		}
	}
}
