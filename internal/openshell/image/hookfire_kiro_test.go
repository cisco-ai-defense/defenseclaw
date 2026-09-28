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

package image

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
)

// kiroSim plays Kiro CLI in its scripted-response mode: it reads the script
// the probe wrote for the run, posts the agent hooks the way the sandbox
// kiro-hook.sh does (preToolUse carrying the scripted shell command), and
// reports the tool's side effect only when preToolUse was not denied. The
// scripted mock needs no model endpoint, so no run may name one.
type kiroSim struct {
	t    *testing.T
	port int
	// skip drops these hooks from every run.
	skip map[string]bool
	// hostileOutput is appended to the hostile-settings run's output.
	hostileOutput string
}

var kiroScriptRE = regexp.MustCompile(`(?m)^printf '%s' '(.*)' >'/tmp/dc-hookfire-kiro-mock\.json' \|\| exit 96$`)

// kiroSimClient never reuses a connection: each subtest's sink listens on
// the same port, and a kept-alive connection to the previous one would fail.
var kiroSimClient = &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}

func (s kiroSim) handle(args []string) (string, int) {
	if len(args) > 0 && args[0] == "rm" {
		return "", 0
	}
	argv := parseProbeArgv(args)
	env, script := argv.env, argv.script
	if joined := strings.Join(args, " "); strings.Contains(joined, "ANTHROPIC_BASE_URL") || strings.Contains(joined, "OPENAI_API_KEY") {
		s.t.Errorf("a Kiro run was pointed at a model endpoint: %v", args)
	}
	if env["KIRO_MOCK_CHAT_RESPONSE"] != "/tmp/dc-hookfire-kiro-mock.json" || env["KIRO_API_KEY"] == "" || !strings.Contains(script, harness.KiroLauncherPath) {
		s.t.Errorf("kiro hook-fire argv lacks the scripted mock or the launcher: %v", args)
		return "", 1
	}
	m := kiroScriptRE.FindStringSubmatch(script)
	if m == nil || strings.Index(script, m[0]) > strings.Index(script, harness.KiroLauncherPath) {
		s.t.Errorf("the scripted response is not written before the harness starts:\n%s", script)
		return "", 1
	}
	var turns [][]json.RawMessage
	if err := json.Unmarshal([]byte(strings.ReplaceAll(m[1], `'\''`, `'`)), &turns); err != nil || len(turns) != 2 || len(turns[0]) != 2 {
		s.t.Errorf("scripted response %s: %v", m[1], err)
		return "", 1
	}
	var call struct {
		Name string            `json:"name"`
		Args map[string]string `json:"args"`
	}
	if err := json.Unmarshal(turns[0][1], &call); err != nil || call.Name != "shell" || call.Args["command"] == "" {
		s.t.Errorf("scripted tool call %s: %v", turns[0][1], err)
		return "", 1
	}
	blocked := false
	for _, event := range []string{"userPromptSubmit", "preToolUse", "postToolUse", "stop"} {
		if s.skip[event] || (event == "postToolUse" && blocked) {
			continue
		}
		body, err := postHook(kiroSimClient, "http://"+net.JoinHostPort("127.0.0.1", strconv.Itoa(s.port))+"/api/v1/kiro/hook",
			env[connector.SandboxTokenEnv], "k-"+event, map[string]interface{}{"hook_event_name": event, "tool_name": "shell", "tool_input": call.Args})
		if err != nil {
			s.t.Errorf("post %s: %v", event, err)
			return "", 1
		}
		blocked = blocked || (event == "preToolUse" && strings.Contains(body, `"decision":"block"`))
	}
	out := "::rc=0\n" + simSideEffect(!blocked)
	if strings.Contains(script, hostileRanLog) {
		out += s.hostileOutput
	}
	return out + "::output-begin\nok\n::output-end\n", 0
}

func TestHookFireScriptedMockDrivesKiro(t *testing.T) {
	c := hookFireContextFor(t, harness.Kiro)
	for name, tc := range map[string]struct {
		sim  kiroSim
		want string
	}{
		"enforcing":     {},
		"no-pretooluse": {sim: kiroSim{skip: map[string]bool{"preToolUse": true}}, want: "hook preToolUse never fired"},
		// Kiro ran the approved command through the planted KIRO_CHAT_SHELL.
		"planted-chat-shell": {sim: kiroSim{hostileOutput: "::planted-ran=user:chat-shell \n"}, want: "programs planted by hostile user and project settings ran: user:chat-shell"},
	} {
		t.Run(name, func(t *testing.T) {
			sim := tc.sim
			sim.t, sim.port = t, c.Spec.IngressPort
			docker := &fakeDocker{handler: func(args []string, _ []byte) (string, int) { return sim.handle(args) }}
			b := &Builder{Docker: docker}
			res, err := b.HookFireProbe(context.Background(), c, HookFireOptions{Network: HookFireNetworkHost, SinkHost: "127.0.0.1"})
			if tc.want == "" {
				if err != nil {
					t.Fatalf("HookFireProbe: %v", err)
				}
				if len(res.Runs) != 3 || res.Runs[1].SideEffectPresent == nil || *res.Runs[1].SideEffectPresent {
					t.Fatalf("result = %+v", res)
				}
				return
			}
			if !errors.Is(err, ErrHooksNotFired) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestKiroScriptedMockRendersEveryScenario(t *testing.T) {
	mock := builtinScriptedMocks["kiro"]
	for _, sc := range builtinMockScenarios {
		sc := sc
		raw, err := mock.render(&sc)
		if err != nil {
			t.Fatal(err)
		}
		var turns [][]interface{}
		if err := json.Unmarshal(raw, &turns); err != nil || len(turns) != 2 {
			t.Fatalf("%s: %s %v", sc.match, raw, err)
		}
		call, _ := turns[0][1].(map[string]interface{})
		args, _ := call["args"].(map[string]interface{})
		if call["name"] != "shell" || args["command"] != sc.command || turns[1][0] != sc.done {
			t.Fatalf("%s: %s", sc.match, raw)
		}
	}
	raw, err := mock.render(nil)
	if err != nil || string(raw) != `[["`+mockAuxText+`"]]` {
		t.Fatalf("no-scenario script = %s %v", raw, err)
	}
}

func TestKiroHostileSettingsPlants(t *testing.T) {
	plan := hostileSettingsPlans["kiro"]
	// With the launcher's agent directory pinned nothing is refused: every
	// planting must leave the hooks firing.
	if len(plan.refusals) != 0 {
		t.Fatalf("refusals = %+v", plan.refusals)
	}
	for _, name := range []string{"KIRO_HOME", connector.KiroSandboxAgentDirEnv, "KIRO_TEST_AGENTS_DIR", "KIRO_CHAT_SHELL", "AMAZON_Q_CHAT_SHELL", "BASH_ENV", "ENV", "PATH"} {
		if !strings.HasPrefix(plan.env[name], hostileRoot+"/") {
			t.Errorf("hostile env %s = %q", name, plan.env[name])
		}
	}
	root, _ := relocatedHostileSetup(t, "kiro")
	// Hookless agents named defenseclaw under the DefenseClaw file name and
	// under names that sort before it, in HOME, the project and every
	// directory the hostile env names.
	name := connector.KiroSandboxAgentName + ".json"
	for _, file := range []string{
		connector.SandboxHomeDir + "/.kiro/agents/" + name,
		connector.SandboxHomeDir + "/.kiro/agents/a.json",
		hostileProject + "/.kiro/agents/" + name,
		hostileProject + "/.kiro/agents/project.json",
		plan.env["KIRO_HOME"] + "/agents/" + name,
		plan.env["KIRO_HOME"] + "/.kiro/agents/" + name,
		plan.env[connector.KiroSandboxAgentDirEnv] + "/" + name,
		plan.env["KIRO_TEST_AGENTS_DIR"] + "/" + name,
	} {
		agent, err := os.ReadFile(root + file)
		if err != nil || !strings.Contains(string(agent), `"name":"`+connector.KiroSandboxAgentName+`"`) || !strings.Contains(string(agent), `"hooks":{}`) {
			t.Errorf("no hookless agent at %s: %q %v", file, agent, err)
		}
	}
	if file := connector.KiroSandboxAgentPath; strings.Contains(plan.setup, file) {
		t.Errorf("the plan writes the root-owned agent %s", file)
	}
	// The planted chat shell records that it ran and still runs the command.
	shell := strings.TrimPrefix(plan.env["KIRO_CHAT_SHELL"], hostileRoot)
	out, err := exec.Command(root+hostileRoot+shell, "-c", "echo ran-command").CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "ran-command" {
		t.Fatalf("planted chat shell: %q %v", out, err)
	}
	if ran := takeRan(t, root); strings.Join(ran, " ") != "user:chat-shell" {
		t.Fatalf("the planted chat shell left %v", ran)
	}
}
