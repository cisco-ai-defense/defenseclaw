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
	"encoding/json"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Sandbox variants of the hook-only connectors that run in OpenShell images
// (Hermes, OpenHands, Antigravity). Each harness honours a different block
// signal, so every failure path is checked against that harness's own
// contract: Hermes enforces only a stdout block directive (its exit status is
// ignored and a timeout is "no opinion"), OpenHands enforces exit status 2,
// and Antigravity enforces only a synchronous PreToolUse {"decision":"deny"}.

const (
	hermesPreToolCall     = `{"hook_event_name":"pre_tool_call","tool_name":"terminal","tool_input":{"command":"ls"},"session_id":"s1","cwd":"/work/p","extra":{}}`
	openHandsPreToolUse   = `{"event_type":"PreToolUse","tool_name":"terminal","tool_input":{"command":"ls"},"session_id":"s1","working_dir":"/work/p","metadata":{}}`
	antigravityPreToolUse = `{"toolName":"run_command","toolInput":{"CommandLine":"ls"}}`
)

type hookOnlySandboxCase struct {
	name      string
	provider  SandboxArtifactProvider
	version   string
	script    string
	args      []string
	stdin     string
	route     string
	eventHdr  string
	eventName string
}

func hookOnlySandboxCases() []hookOnlySandboxCase {
	return []hookOnlySandboxCase{
		{"hermes", NewHermesConnector(), "0.19.0", "hermes-hook.sh", nil, hermesPreToolCall, "/api/v1/hermes/hook", "", ""},
		{"openhands", NewOpenHandsConnector(), "1.16.0", "openhands-hook.sh", nil, openHandsPreToolUse, "/api/v1/openhands/hook", "", ""},
		{"antigravity", NewAntigravityConnector(), "1.2.12", "antigravity-hook.sh", []string{"PreToolUse"}, antigravityPreToolUse,
			"/api/v1/antigravity/hook", "x-defenseclaw-antigravity-event", "PreToolUse"},
	}
}

// blockedFor reports whether run is a block under the harness's contract.
func blockedFor(t *testing.T, connector string, run sandboxHookRun) bool {
	t.Helper()
	out := strings.TrimSpace(run.stdout)
	switch connector {
	case "hermes":
		var directive map[string]interface{}
		if json.Unmarshal([]byte(lastLine(out)), &directive) != nil {
			return false
		}
		return directive["action"] == "block" || directive["decision"] == "block"
	case "openhands":
		return run.exitCode == 2
	case "antigravity":
		var directive map[string]interface{}
		if json.Unmarshal([]byte(lastLine(out)), &directive) != nil {
			return false
		}
		return run.exitCode == 0 && directive["decision"] == "deny"
	}
	t.Fatalf("unknown connector %s", connector)
	return false
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return lines[len(lines)-1]
}

func TestSandboxHookOnlyHooksRetryOnceWithIdempotencyKey(t *testing.T) {
	for _, tc := range hookOnlySandboxCases() {
		t.Run(tc.name, func(t *testing.T) {
			h := newSandboxHookHarness(t, tc.provider, tc.version)
			token := "openshell:resolve:env:v3_DEFENSECLAW_SANDBOX_TOKEN"
			run := h.run(t, SandboxHookDir+"/"+tc.script, tc.args, tc.stdin, map[string]string{SandboxTokenEnv: token}, []string{"exit:52", allowResponse})
			if blockedFor(t, tc.name, run) || len(run.calls) != 2 {
				t.Fatalf("exit %d calls %d stdout %q; stderr=%s", run.exitCode, len(run.calls), run.stdout, run.stderr)
			}
			key := run.calls[0].headers["x-defenseclaw-hook-idempotency-key"]
			if !sandboxIdempotencyKeyRE.MatchString(key) || run.calls[1].headers["x-defenseclaw-hook-idempotency-key"] != key {
				t.Fatalf("idempotency keys %q / %q", key, run.calls[1].headers["x-defenseclaw-hook-idempotency-key"])
			}
			for i, call := range run.calls {
				if call.url() != "http://host.openshell.internal:18971"+tc.route {
					t.Fatalf("call %d url = %q", i, call.url())
				}
				if call.headers["authorization"] != "Bearer "+token || call.body != tc.stdin {
					t.Fatalf("call %d authorization %q body %q", i, call.headers["authorization"], call.body)
				}
				if tc.eventHdr != "" && call.headers[tc.eventHdr] != tc.eventName {
					t.Fatalf("call %d %s = %q", i, tc.eventHdr, call.headers[tc.eventHdr])
				}
				if call.argv[0] != "-q" || call.flagValue("--noproxy") != "*" {
					t.Fatalf("call %d must ignore curlrc and proxies: %v", i, call.argv)
				}
			}
			if run.calls[0].flagValue("--max-time") != strconv.Itoa(sandboxHookMaxTimeSeconds) ||
				run.calls[1].flagValue("--max-time") != strconv.Itoa(sandboxHookRetryMaxTimeSeconds) {
				t.Fatalf("attempt budgets = %s/%s", run.calls[0].flagValue("--max-time"), run.calls[1].flagValue("--max-time"))
			}
		})
	}
}

// TestSandboxHookOnlyHooksFailClosed pins that no reply the workload can
// provoke, no missing token and no host override turns into an allow. The
// templates are rendered with an "open" fail mode forced into the template
// data, so the sandbox branches are proven never to consult it.
func TestSandboxHookOnlyHooksFailClosed(t *testing.T) {
	replies := map[string][]string{
		"ingress-down":   {"exit:7", "exit:7"},
		"unauthorized":   {`401|{"error":"bad token"}`},
		"forbidden":      {`403|{"error":"route not allowed"}`},
		"not-found":      {`404|{"error":"no route"}`},
		"rate-limited":   {`429|{"error":"slow down"}`},
		"relay-500":      {`500|placeholder did not resolve`},
		"relay-502":      {`502|{}`, `502|{}`},
		"no-status":      {`|`},
		"garbled-status": {`2x0|{"action":"allow"}`},
		"not-json":       {`200|<html>proxy</html>`},
		"empty-2xx":      {`204|`},
		"no-action":      {`200|{"ok":true}`},
		"unknown-action": {`200|{"action":"maybe"}`},
	}
	hostOverrides := map[string]string{
		"DEFENSECLAW_FAIL_MODE":           "open",
		"DEFENSECLAW_STRICT_AVAILABILITY": "0",
		"DEFENSECLAW_GATEWAY_TOKEN":       "host-master",
		"DEFENSECLAW_HOME":                "/nonexistent",
	}
	for _, tc := range hookOnlySandboxCases() {
		rt, err := resolveSandboxTarget(tc.name, SandboxRenderTarget{IngressPort: 18971, AgentVersion: tc.version})
		if err != nil {
			t.Fatal(err)
		}
		rt.failMode = "open"
		files, err := renderSandboxHookFiles(tc.name, rt)
		if err != nil {
			t.Fatal(err)
		}
		h := newSandboxHookHarnessFiles(t, files, SandboxHookPATH)
		env := map[string]string{SandboxTokenEnv: "garbage"}
		for key, value := range hostOverrides {
			env[key] = value
		}
		for name, responses := range replies {
			t.Run(tc.name+"/"+name, func(t *testing.T) {
				run := h.run(t, SandboxHookDir+"/"+tc.script, tc.args, tc.stdin, env, responses)
				if !blockedFor(t, tc.name, run) {
					t.Fatalf("not blocked: exit %d stdout=%q stderr=%s", run.exitCode, run.stdout, run.stderr)
				}
				if len(run.calls) == 0 {
					t.Fatal("the hook never asked the ingress")
				}
			})
		}
		t.Run(tc.name+"/missing-token", func(t *testing.T) {
			run := h.run(t, SandboxHookDir+"/"+tc.script, tc.args, tc.stdin, hostOverrides, []string{allowResponse})
			if !blockedFor(t, tc.name, run) || len(run.calls) != 0 {
				t.Fatalf("exit %d calls %d stdout=%q, want a block and no request", run.exitCode, len(run.calls), run.stdout)
			}
		})
		t.Run(tc.name+"/oversized-payload", func(t *testing.T) {
			big := strings.Replace(tc.stdin, `"ls"`, `"`+strings.Repeat("a", 1<<20)+`"`, 1)
			run := h.run(t, SandboxHookDir+"/"+tc.script, tc.args, big, map[string]string{SandboxTokenEnv: "tok", "DEFENSECLAW_HOOK_MAX_BODY": "99999999"}, []string{allowResponse})
			if !blockedFor(t, tc.name, run) || len(run.calls) != 0 {
				t.Fatalf("exit %d calls %d stdout=%q, want a block and no request", run.exitCode, len(run.calls), run.stdout)
			}
		})
		t.Run(tc.name+"/allow", func(t *testing.T) {
			run := h.run(t, SandboxHookDir+"/"+tc.script, tc.args, tc.stdin, map[string]string{SandboxTokenEnv: "tok"}, []string{allowResponse})
			if blockedFor(t, tc.name, run) || run.exitCode != 0 || len(run.calls) != 1 {
				t.Fatalf("allow: exit %d calls %d stdout=%q stderr=%s", run.exitCode, len(run.calls), run.stdout, run.stderr)
			}
		})
	}
}

func TestSandboxHookOnlyHooksRenderBlockVerdicts(t *testing.T) {
	for _, tc := range hookOnlySandboxCases() {
		t.Run(tc.name, func(t *testing.T) {
			h := newSandboxHookHarness(t, tc.provider, tc.version)
			env := map[string]string{SandboxTokenEnv: "tok"}
			var output string
			switch tc.name {
			case "hermes":
				output = `{"decision":"block","reason":"rule X"}`
			default:
				output = `{"decision":"deny","reason":"rule X"}`
			}
			withOutput := h.run(t, SandboxHookDir+"/"+tc.script, tc.args, tc.stdin, env,
				[]string{`200|{"action":"block","reason":"rule X","hook_output":` + output + `}`})
			if !blockedFor(t, tc.name, withOutput) || !strings.Contains(withOutput.stdout, "rule X") {
				t.Fatalf("rendered verdict: exit %d stdout=%q", withOutput.exitCode, withOutput.stdout)
			}
			// A block without hook_output still reaches the harness as its
			// own block signal, with the gateway's reason.
			bare := h.run(t, SandboxHookDir+"/"+tc.script, tc.args, tc.stdin, env, []string{`200|{"action":"block","reason":"rule Y"}`})
			if !blockedFor(t, tc.name, bare) || !strings.Contains(bare.stdout, "rule Y") {
				t.Fatalf("bare block: exit %d stdout=%q", bare.exitCode, bare.stdout)
			}
		})
	}
}

func TestSandboxAntigravityHookBindsEvent(t *testing.T) {
	h := newSandboxHookHarness(t, NewAntigravityConnector(), "1.2.12")
	env := map[string]string{SandboxTokenEnv: "tok", "HOOK_EVENT": "Stop"}
	hook := SandboxHookDir + "/antigravity-hook.sh"
	// An exported HOOK_EVENT is dropped with the rest of the environment;
	// the registered argv wins.
	run := h.run(t, hook, []string{"PostToolUse"}, `{}`, env, []string{allowResponse})
	if run.exitCode != 0 || len(run.calls) != 1 || run.calls[0].headers["x-defenseclaw-antigravity-event"] != "PostToolUse" {
		t.Fatalf("exit %d calls %d headers %v", run.exitCode, len(run.calls), run.calls)
	}
	for name, args := range map[string][]string{"none": nil, "unknown": {"BeforeTool"}, "extra": {"PreToolUse", "x"}} {
		run := h.run(t, hook, args, antigravityPreToolUse, env, []string{allowResponse})
		if len(run.calls) != 0 {
			t.Fatalf("%s: the hook posted an unregistered event", name)
		}
		if len(args) > 0 && args[0] == "PreToolUse" && !blockedFor(t, "antigravity", run) {
			t.Fatalf("%s: PreToolUse with a bad registration was not denied: %q", name, run.stdout)
		}
	}
}

func TestSandboxHookOnlyArtifacts(t *testing.T) {
	for _, tc := range hookOnlySandboxCases() {
		t.Run(tc.name, func(t *testing.T) {
			a, err := tc.provider.SandboxArtifacts(SandboxRenderTarget{IngressPort: 18971, AgentVersion: tc.version})
			if err != nil {
				t.Fatal(err)
			}
			files := map[string]SandboxFile{}
			for _, f := range a.Files {
				files[f.Path] = f
			}
			if f, ok := files[SandboxHookDir+"/"+tc.script]; !ok || f.Owner != SandboxOwnerRoot || f.Mode != 0o755 {
				t.Fatalf("hook script %#v", f)
			}
			switch tc.name {
			case "hermes":
				// The hooks are registered in the root-owned managed layer,
				// but Hermes reads .env files and imports plugins from its
				// workload-writable home, so the tier is user.
				if a.TamperTier != SandboxTamperTierUser {
					t.Fatalf("tier %s", a.TamperTier)
				}
				managed, ok := files[HermesSandboxManagedConfigPath]
				if !ok || managed.Owner != SandboxOwnerRoot {
					t.Fatalf("managed config %#v", managed)
				}
				// The managed .env pins the switches Hermes would otherwise
				// take from ~/.hermes/.env.
				env, ok := files[HermesSandboxManagedEnvPath]
				if !ok || env.Owner != SandboxOwnerRoot || env.Mode != 0o644 {
					t.Fatalf("managed env %#v", env)
				}
				for _, pin := range []string{"\nHERMES_SAFE_MODE=0\n", "\nHERMES_ENABLE_PROJECT_PLUGINS=0\n", "\nHERMES_ACCEPT_HOOKS=1\n", "\nTIRITH_ENABLED=0\n", "\nHERMES_DISABLE_LAZY_INSTALLS=1\n"} {
					if !strings.Contains(string(env.Data), pin) {
						t.Fatalf("managed env lacks %q:\n%s", pin, env.Data)
					}
				}
				if user := files[HermesSandboxUserConfigPath]; user.Owner != SandboxOwnerUser {
					t.Fatalf("user preseed %#v", user)
				}
			case "openhands", "antigravity":
				if a.TamperTier != SandboxTamperTierUser {
					t.Fatalf("tier %s", a.TamperTier)
				}
				canonical, user := OpenHandsSandboxCanonicalHooksPath, OpenHandsSandboxHooksPath
				if tc.name == "antigravity" {
					canonical, user = AntigravitySandboxCanonicalHooksPath, AntigravitySandboxHooksPath
				}
				c, u := files[canonical], files[user]
				if c.Owner != SandboxOwnerRoot || u.Owner != SandboxOwnerUser || string(c.Data) != string(u.Data) || len(c.Data) == 0 {
					t.Fatalf("canonical %#v / user %#v", c, u)
				}
			}
		})
	}
}

func TestVerifyHermesSandboxManagedConfigRejectsTampering(t *testing.T) {
	rt, err := resolveSandboxTarget("hermes", SandboxRenderTarget{IngressPort: 18971, AgentVersion: "0.19.0"})
	if err != nil {
		t.Fatal(err)
	}
	good, err := renderHermesSandboxManagedConfig(rt)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyHermesSandboxManagedConfig(good, rt); err != nil {
		t.Fatalf("rendered managed config rejected: %v", err)
	}
	mutate := func(fn func(map[string]interface{})) []byte {
		var doc map[string]interface{}
		if err := yaml.Unmarshal(good, &doc); err != nil {
			t.Fatal(err)
		}
		fn(doc)
		out, err := yaml.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	hooks := func(d map[string]interface{}) map[string]interface{} { return d["hooks"].(map[string]interface{}) }
	cases := map[string][]byte{
		"missing-pre-tool-call": mutate(func(d map[string]interface{}) { delete(hooks(d), "pre_tool_call") }),
		"foreign-command": mutate(func(d map[string]interface{}) {
			hooks(d)["pre_tool_call"] = []interface{}{map[string]interface{}{"command": "/tmp/x.sh", "matcher": ".*", "timeout": 30}}
		}),
		"second-handler": mutate(func(d map[string]interface{}) {
			hooks(d)["on_session_start"] = append(hooks(d)["on_session_start"].([]interface{}), map[string]interface{}{"command": "/tmp/x.sh"})
		}),
		"auto-accept-off":   mutate(func(d map[string]interface{}) { d["hooks_auto_accept"] = false }),
		"plugins-enabled":   mutate(func(d map[string]interface{}) { d["plugins"] = map[string]interface{}{"enabled": []interface{}{"x"}} }),
		"plugins-unpinned":  mutate(func(d map[string]interface{}) { delete(d, "plugins") }),
		"remote-terminal":   mutate(func(d map[string]interface{}) { d["terminal"] = map[string]interface{}{"backend": "ssh"} }),
		"code-execution-on": mutate(func(d map[string]interface{}) { delete(d, "agent") }),
		"tirith-on": mutate(func(d map[string]interface{}) {
			d["security"] = map[string]interface{}{"tirith_enabled": true, "allow_lazy_installs": false}
		}),
		"lazy-installs-on": mutate(func(d map[string]interface{}) { d["security"] = map[string]interface{}{"tirith_enabled": false} }),
		"provider-pinned-url": mutate(func(d map[string]interface{}) {
			d["providers"].(map[string]interface{})[HermesSandboxProviderName].(map[string]interface{})["base_url"] = "http://example.invalid/v1"
		}),
		"invalid-yaml": []byte("hooks: ["),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if err := verifyHermesSandboxManagedConfig(body, rt); err == nil {
				t.Fatal("tampered managed config accepted")
			}
		})
	}
}

func TestSandboxArtifactsSupported(t *testing.T) {
	for _, conn := range []Connector{NewHermesConnector(), NewOpenHandsConnector(), NewAntigravityConnector(), NewClaudeCodeConnector(), NewCodexConnector()} {
		if !SandboxArtifactsSupported(conn) {
			t.Errorf("%s: sandbox artifacts not reported as supported", conn.Name())
		}
	}
	for _, conn := range []Connector{NewWindsurfConnector(), NewGeminiCLIConnector()} {
		if SandboxArtifactsSupported(conn) {
			t.Errorf("%s: reported as supported without a sandbox variant", conn.Name())
		}
		provider, ok := conn.(SandboxArtifactProvider)
		if !ok {
			continue
		}
		if _, err := provider.SandboxArtifacts(SandboxRenderTarget{IngressPort: 18971, AgentVersion: "1.0.0"}); err == nil ||
			!strings.Contains(err.Error(), "no OpenShell sandbox variant") {
			t.Errorf("%s: SandboxArtifacts error = %v", conn.Name(), err)
		}
	}
}

func TestSandboxHookOnlyScriptsParse(t *testing.T) {
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("/bin/bash is required")
	}
	for _, tc := range hookOnlySandboxCases() {
		a, err := tc.provider.SandboxArtifacts(SandboxRenderTarget{IngressPort: 18971, AgentVersion: tc.version})
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range a.Files {
			if !strings.HasSuffix(f.Path, ".sh") {
				continue
			}
			cmd := exec.Command("/bin/bash", "-n")
			cmd.Stdin = strings.NewReader(string(f.Data))
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("%s %s: %v\n%s", tc.name, f.Path, err, out)
			}
		}
	}
}
