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
	if sandboxOnlyHookContracts("kiro")[0].Events[0] == "mutated" || len(sandboxOnlyHookContracts("codex")) != 0 {
		t.Fatal("sandbox-only contracts alias their table, or codex grew one")
	}
}

// TestKiroSandboxAgentIsAlone: Kiro picks an agent by the name inside any
// file of its agents directories, so the DefenseClaw agent is alone in the
// root-owned directory the launcher points Kiro at, and no agent file lives
// in the workload-writable HOME.
func TestKiroSandboxAgentIsAlone(t *testing.T) {
	a := sandboxArtifactsFor(t, NewKiroConnector(), "2.24.1")
	if agent := sandboxFile(t, a, KiroSandboxAgentPath); agent.Owner != SandboxOwnerRoot || path.Dir(KiroSandboxAgentPath) != KiroSandboxAgentDir ||
		a.Env[KiroSandboxAgentDirEnv] != KiroSandboxAgentDir || len(a.Env) != 1 {
		t.Fatalf("agent %s (%s), env %v", KiroSandboxAgentPath, agent.Owner, a.Env)
	}
	for _, file := range a.Files {
		if file.Path != KiroSandboxAgentPath && (strings.HasPrefix(file.Path, KiroSandboxAgentDir+"/") || strings.Contains(file.Path, "/.kiro/agents")) {
			t.Fatalf("%s is another agent file Kiro could read", file.Path)
		}
	}
}

func TestVerifyKiroSandboxAgentRejectsTampering(t *testing.T) {
	good, err := renderKiroSandboxAgent()
	if err != nil {
		t.Fatal(err)
	}
	mutate := func(fn func(map[string]interface{})) []byte {
		return tampered(t, good, json.Unmarshal, json.Marshal, fn)
	}
	hook := func(doc map[string]interface{}, event string) map[string]interface{} {
		return doc["hooks"].(map[string]interface{})[event].([]interface{})[0].(map[string]interface{})
	}
	assertTamperRejected(t, verifyKiroSandboxAgent, good, map[string][]byte{
		// The regular expression ".*" matches no tool on Kiro 2.24.1.
		"regex-matcher": mutate(func(d map[string]interface{}) { hook(d, "preToolUse")["matcher"] = ".*" }),
		// Without timeout_ms Kiro gives up on the hook after about ten
		// seconds and runs the tool.
		"default-timeout": mutate(func(d map[string]interface{}) { delete(hook(d, "preToolUse"), "timeout_ms") }),
		"short-timeout":   mutate(func(d map[string]interface{}) { hook(d, "preToolUse")["timeout_ms"] = 5000 }),
		"other-command":   mutate(func(d map[string]interface{}) { hook(d, "stop")["command"] = "/bin/true" }),
		"missing-trigger": mutate(func(d map[string]interface{}) { delete(d["hooks"].(map[string]interface{}), "postToolUse") }),
		"extra-trigger":   mutate(func(d map[string]interface{}) { d["hooks"].(map[string]interface{})["agentSpawn"] = []interface{}{} }),
		"pre-approved":    mutate(func(d map[string]interface{}) { d["allowedTools"] = []interface{}{"*"} }),
		"unknown-key":     mutate(func(d map[string]interface{}) { d["mcpServers"] = map[string]interface{}{} }),
		"renamed":         mutate(func(d map[string]interface{}) { d["name"] = "kiro_default" }),
		"not-json":        []byte(`{"name":`),
	})
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
	mutate := func(fn func(map[string]interface{})) []byte {
		return tampered(t, good, json.Unmarshal, json.Marshal, fn)
	}
	entry := func(doc map[string]interface{}, event string) map[string]interface{} {
		return doc["hooks"].(map[string]interface{})[event].([]interface{})[0].(map[string]interface{})
	}
	assertTamperRejected(t, func(b []byte) error { return verifyCursorSandboxHooks(b, rt) }, good, map[string][]byte{
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
	})
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
	assertTamperRejected(t, func(b []byte) error { return verifyDevinSandboxConfig(b, rt) }, good, map[string][]byte{
		"host-timeout":  []byte(strings.Replace(string(good), `"timeout": 30`, `"timeout": 10`, 1)),
		"other-command": []byte(strings.Replace(string(good), SandboxHookDir+"/devin-hook.sh", "/bin/true", 1)),
		"extra-key":     []byte(strings.Replace(string(good), `{`, `{"permissions": {},`, 1)),
		"matcher":       []byte(strings.Replace(string(good), `"matcher": ""`, `"matcher": "exec"`, 1)),
		"not-json":      []byte(`{"hooks":`),
	})
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
