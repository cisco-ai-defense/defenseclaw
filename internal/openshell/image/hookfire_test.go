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

package image

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
)

// containerSim plays the harness inside the image: it posts hook events to
// the ingress the docker argv points at, the way the rendered hooks do. With
// llm set it first asks the model endpoint the argv configures (the
// built-in mock) for its tool call and reports the tool's side effect only
// when the hook allowed it.
type containerSim struct {
	t *testing.T
	// events per scenario, in order; the tool input of PreToolUse carries
	// the scenario prompt (or, with llm, the mock's tool command) so the
	// block marker can match.
	events        []string
	port          int
	badToken      bool
	noKey         bool
	ignoreVerdict bool
	// llm drives the tool call from the configured model endpoint.
	llm bool
	// toolNeverRuns suppresses the allowed tool's side effect.
	toolNeverRuns bool
	// relay expects the relay-mode argv instead of the host network.
	relay bool
	// hostileEvents replaces events in the hostile-settings run (nil keeps
	// events), and plantedRan is what that run reports as planted programs
	// that ran.
	hostileEvents []string
	plantedRan    string
	// refusals is what the hostile-settings run reports as the launcher's
	// refusals.
	refusals string
}

var (
	simRelayPortRE = regexp.MustCompile(`host\.docker\.internal ([0-9]+) >/tmp/dc-hookfire-relay\.log`)
	simBaseURLRE   = regexp.MustCompile(`model_providers\.dcprobe\.base_url="([^"]+)"`)
)

// probeArgv is what a hook-fire docker run hands the harness: the run-as
// user, the ingress host it maps, its environment and the shell script.
type probeArgv struct {
	user, host, script string
	env                map[string]string
}

func parseProbeArgv(args []string) probeArgv {
	p := probeArgv{env: map[string]string{}, script: args[len(args)-1]}
	for i := 0; i+1 < len(args); i++ {
		switch args[i] {
		case "--user":
			p.user = args[i+1]
		case "--add-host":
			if v, ok := strings.CutPrefix(args[i+1], connector.SandboxIngressHost+":"); ok {
				p.host = v
			}
		case "-e":
			k, v, _ := strings.Cut(args[i+1], "=")
			p.env[k] = v
		}
	}
	return p
}

// postHook posts one hook event with token (and the idempotency key, when
// set) the way the rendered hooks do and returns the verdict.
func postHook(client *http.Client, url, token, key string, payload interface{}) (string, error) {
	raw, _ := json.Marshal(payload)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+token)
	if key != "" {
		req.Header.Set("X-DefenseClaw-Hook-Idempotency-Key", key)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body), nil
}

// simSideEffect is the probe script's report of the tool's side effect.
func simSideEffect(ran bool) string {
	if ran {
		return "::side-effect=present\n"
	}
	return "::side-effect=absent\n"
}

func (s containerSim) handle(args []string) (string, int) {
	argv := parseProbeArgv(args)
	host, token, script, user, env := argv.host, argv.env[connector.SandboxTokenEnv], argv.script, argv.user, argv.env
	if host == "" || token == "" || !(strings.Contains(script, harness.ClaudeCodeLauncherPath) || strings.Contains(script, harness.CodexLauncherPath)) {
		s.t.Errorf("hook-fire argv lacks the sink host, token or launcher: %v", args)
		return "", 1
	}
	if !containsSeq(args, "-e", "HOME="+connector.SandboxHomeDir) {
		s.t.Errorf("hook-fire argv = %v", args)
	}
	target := net.JoinHostPort(host, strconv.Itoa(s.port))
	if s.relay {
		m := simRelayPortRE.FindStringSubmatch(script)
		if containsSeq(args, "--network", "host") || host != "127.0.0.1" || !containsSeq(args, "--add-host", "host.docker.internal:host-gateway") || m == nil ||
			!strings.Contains(script, "until (exec 3<>/dev/tcp/127.0.0.1/"+strconv.Itoa(s.port)+")") {
			s.t.Errorf("relay-mode argv = %v\n%s", args, script)
			return "", 1
		}
		// The in-container relay forwards the baked port to the sink.
		target = "127.0.0.1:" + m[1]
	} else if !containsSeq(args, "--network", "host") || strings.Contains(script, "host.docker.internal") {
		s.t.Errorf("host-mode argv = %v", args)
		return "", 1
	}
	if s.badToken {
		token = "forged"
	}
	hostile := strings.Contains(script, hostileRanLog)
	uid, gid, _ := strings.Cut(user, ":")
	if hostile != containsSeq(args, "--tmpfs", fmt.Sprintf("%s:uid=%s,gid=%s,mode=0755", harness.WorkRoot, uid, gid)) {
		s.t.Errorf("hostile-settings run and workload-owned work-root tmpfs disagree: %v", args)
	}
	if hostile && !strings.Contains(script, "cd '/work/dc-hookfire-project' || exit 97") {
		s.t.Errorf("hostile-settings run does not start in the planted project: %s", script)
	}
	toolInput := map[string]string{"command": script}
	if s.llm {
		command, err := s.askModel(env, script)
		if err != nil {
			s.t.Errorf("mock LLM: %v", err)
			return "", 1
		}
		toolInput = map[string]string{"command": command}
	}
	events := s.events
	if hostile && s.hostileEvents != nil {
		events = s.hostileEvents
	}
	blocked := false
	for _, event := range events {
		key := "k-" + event
		if s.noKey {
			key = ""
		}
		body, err := postHook(http.DefaultClient, "http://"+target+"/api/v1/claude-code/hook", token, key,
			map[string]interface{}{"hook_event_name": event, "tool_input": toolInput})
		if err != nil {
			s.t.Errorf("post %s: %v", event, err)
			return "", 1
		}
		blocked = blocked || (event == "PreToolUse" && strings.Contains(body, `"action":"block"`) && !s.ignoreVerdict)
	}
	out := "::rc=0\n"
	if strings.Contains(script, "::side-effect=") {
		out += simSideEffect(!blocked && !s.toolNeverRuns)
	}
	if hostile && s.plantedRan != "" {
		out += "::planted-ran=" + s.plantedRan + "\n"
	}
	if hostile {
		out += s.refusals
	}
	return out + "::output-begin\nok\n::output-end\n", 0
}

// askModel asks the model endpoint the argv configures for the prompt's
// tool call, as Claude Code (Messages) or Codex (Responses) would.
func (s containerSim) askModel(env map[string]string, script string) (string, error) {
	prompt := builtinAllowPrompt
	if strings.Contains(script, builtinBlockPrompt) {
		prompt = builtinBlockPrompt
	} else if !strings.Contains(script, builtinAllowPrompt) {
		return "", fmt.Errorf("the script runs neither built-in prompt")
	}
	container := func(url string) string { return strings.Replace(url, "host.docker.internal", "127.0.0.1", 1) }
	post := func(url, body string) (map[string]interface{}, error) {
		resp, err := http.Post(url, "application/json", strings.NewReader(body))
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		var out map[string]interface{}
		return out, json.NewDecoder(resp.Body).Decode(&out)
	}
	if base, ok := env["ANTHROPIC_BASE_URL"]; ok {
		msg, _ := json.Marshal(prompt)
		out, err := post(container(base)+"/v1/messages", `{"model":"m","max_tokens":64,"messages":[{"role":"user","content":`+string(msg)+`}],"tools":[{"name":"Bash"}]}`)
		if err != nil {
			return "", err
		}
		block := out["content"].([]interface{})[0].(map[string]interface{})
		if block["type"] != "tool_use" {
			return "", fmt.Errorf("messages answered %v", out)
		}
		return block["input"].(map[string]interface{})["command"].(string), nil
	}
	m := simBaseURLRE.FindStringSubmatch(script)
	if m == nil || env["OPENAI_API_KEY"] == "" {
		return "", fmt.Errorf("argv configures no mock model endpoint")
	}
	msg, _ := json.Marshal(prompt)
	out, err := post(container(m[1])+"/responses", `{"model":"mock-model","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":`+string(msg)+`}]}],"tools":[{"type":"function","name":"shell_command"}]}`)
	if err != nil {
		return "", err
	}
	item := out["output"].([]interface{})[0].(map[string]interface{})
	var call struct {
		Command string `json:"command"`
	}
	if item["type"] != "function_call" || json.Unmarshal([]byte(item["arguments"].(string)), &call) != nil {
		return "", fmt.Errorf("responses answered %v", out)
	}
	return call.Command, nil
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func hookFireContextFor(t *testing.T, h *harness.Spec) *Context {
	t.Helper()
	spec := testSpec(h)
	spec.IngressPort = freePort(t)
	return mustContext(t, spec)
}

func hookFireContext(t *testing.T) *Context {
	t.Helper()
	return hookFireContextFor(t, harness.ClaudeCode)
}

// hostOpts are caller-mock options on the host network with the sink on
// 127.0.0.1 (the test binds the context's free ingress port there).
func hostOpts(block bool) HookFireOptions {
	opts := HookFireOptions{Network: HookFireNetworkHost, SinkHost: "127.0.0.1", Env: map[string]string{"ANTHROPIC_BASE_URL": "http://127.0.0.1:1"}, Prompt: "write the marker"}
	if block {
		opts.Block = &BlockScenario{Prompt: "BLOCKME", Marker: "BLOCKME", SideEffect: "/tmp/blocked.txt"}
	}
	return opts
}

var fullClaudeRun = []string{"SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop", "SessionEnd"}

func TestHookFireProbePassesWhenHooksFire(t *testing.T) {
	c := hookFireContext(t)
	sim := containerSim{t: t, events: fullClaudeRun, port: c.Spec.IngressPort}
	b := &Builder{Docker: &fakeDocker{handler: func(args []string, _ []byte) (string, int) { return sim.handle(args) }}}
	res, err := b.HookFireProbe(context.Background(), c, hostOpts(true))
	if err != nil {
		t.Fatalf("HookFireProbe: %v", err)
	}
	if res.Network != HookFireNetworkHost || len(res.Runs) != 3 || len(res.Runs[0].Events) != len(fullClaudeRun) {
		t.Fatalf("result = %+v", res)
	}
	for i, want := range []string{ScenarioAllow, ScenarioBlock, ScenarioHostileSettings} {
		if res.Runs[i].Scenario != want {
			t.Fatalf("run %d is %q, want %q", i, res.Runs[i].Scenario, want)
		}
	}
	blocked := false
	for _, ev := range res.Runs[1].Events {
		blocked = blocked || (ev.Event == "PreToolUse" && ev.Blocked)
	}
	if !blocked || res.Runs[1].SideEffectPresent == nil || *res.Runs[1].SideEffectPresent {
		t.Fatalf("block run = %+v", res.Runs[1])
	}
	if hostile := res.Runs[2]; len(hostile.Events) != len(fullClaudeRun) || len(hostile.PlantedRan) != 0 {
		t.Fatalf("hostile-settings run = %+v", hostile)
	}
}

// TestHookFireBuiltinMockDrivesEveryHarness runs the zero-value options:
// the probe serves the built-in mock LLM itself, points each harness at it,
// and requires the allowed tool's side effect and the blocked tool's
// absence, on both network modes.
func TestHookFireBuiltinMockDrivesEveryHarness(t *testing.T) {
	for _, h := range []*harness.Spec{harness.ClaudeCode, harness.Codex} {
		for _, mode := range []HookFireNetwork{HookFireNetworkHost, HookFireNetworkRelay} {
			t.Run(h.Name+"/"+string(mode), func(t *testing.T) {
				c := hookFireContextFor(t, h)
				sim := containerSim{t: t, events: fullClaudeRun, port: c.Spec.IngressPort, llm: true, relay: mode == HookFireNetworkRelay}
				b := &Builder{Docker: &fakeDocker{handler: func(args []string, _ []byte) (string, int) { return sim.handle(args) }}}
				opts := HookFireOptions{Network: mode}
				if mode == HookFireNetworkHost {
					// The test cannot rely on 127.0.0.2 existing (macOS).
					opts.SinkHost = "127.0.0.1"
				}
				res, err := b.HookFireProbe(context.Background(), c, opts)
				if err != nil {
					t.Fatalf("HookFireProbe: %v", err)
				}
				// Allow, block and hostile settings.
				if len(res.Runs) != 3 || res.Network != mode {
					t.Fatalf("result = %+v", res)
				}
				for _, run := range res.Runs {
					if run.SideEffectPresent == nil || *run.SideEffectPresent != (run.Scenario != ScenarioBlock) {
						t.Fatalf("%s run side effect = %v", run.Scenario, run.SideEffectPresent)
					}
				}
			})
		}
	}
}

func TestHookFireProbeFailures(t *testing.T) {
	cases := map[string]struct {
		sim   containerSim
		block bool
		want  string
	}{
		"missing-pretooluse": {containerSim{events: []string{"SessionStart", "UserPromptSubmit", "Stop"}}, false, "hook PreToolUse never fired"},
		"forged-token":       {containerSim{events: fullClaudeRun, badToken: true}, false, "without the sandbox token"},
		"no-idempotency-key": {containerSim{events: fullClaudeRun, noKey: true}, false, "no idempotency key"},
		"verdict-ignored":    {containerSim{events: fullClaudeRun, ignoreVerdict: true}, true, "still ran"},
		// Under the built-in mock every hook fires but the allowed tool call
		// never runs (for example a planted shell that swallows it).
		"allowed-tool-never-ran": {containerSim{events: fullClaudeRun, llm: true, toolNeverRuns: true}, false,
			"the allowed tool call never ran (" + builtinAllowSideEffect + " is missing)"},
		// A settings knob that diverts the hooks: the planted wrapper
		// swallows them, so none reaches the sink.
		"hostile-settings-swallow-hooks": {
			containerSim{events: fullClaudeRun, hostileEvents: []string{}, plantedRan: "project:shell-prefix"},
			false, "with hostile user and project settings, hook SessionStart never fired",
		},
		"hostile-settings-host-token": {
			containerSim{events: fullClaudeRun, hostileEvents: []string{"SessionStart", "UserPromptSubmit", "Stop"}},
			false, "with hostile user and project settings, hook PreToolUse never fired",
		},
		// Hooks still fire, but a planted shell ran the approved Bash command.
		"hostile-settings-planted-shell": {
			containerSim{events: fullClaudeRun, plantedRan: "project:shell user:bash-env"},
			false, "planted by hostile user and project settings ran: project:shell, user:bash-env",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := hookFireContext(t)
			sim := tc.sim
			sim.t, sim.port = t, c.Spec.IngressPort
			b := &Builder{Docker: &fakeDocker{handler: func(args []string, _ []byte) (string, int) { return sim.handle(args) }}}
			opts := hostOpts(tc.block)
			if sim.llm {
				opts = HookFireOptions{Network: HookFireNetworkHost, SinkHost: "127.0.0.1"}
			}
			_, err := b.HookFireProbe(context.Background(), c, opts)
			if !errors.Is(err, ErrHooksNotFired) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want ErrHooksNotFired saying %q", err, tc.want)
			}
		})
	}
}

// TestHookFireHostileLaunchEnvAndRefusals runs a hostile plan with a launch
// env and two plantings the launcher must refuse: the env reaches only the
// harness command (never the probe's shell or the container env), each
// planting is tried on its own before the hostile-settings run, and the
// probe fails when the launcher started the harness, refused without naming
// the file, or was never tried.
func TestHookFireHostileLaunchEnvAndRefusals(t *testing.T) {
	saved := hostileSettingsPlans["claudecode"]
	t.Cleanup(func() { hostileSettingsPlans["claudecode"] = saved })
	plan := saved
	plan.env = map[string]string{"BASH_ENV": hostileRoot + "/bash-env", "PATH": hostileRoot + "/bin:/usr/bin:/bin"}
	plan.refusals = []hostileRefusal{
		{label: "project-plugin", file: hostileProject + "/.opencode/plugins/x.js", setup: ": plant-project\n", message: "refusing: project"},
		{label: "user-plugin", file: "/sandbox/.config/opencode/plugins/x.js", setup: ": plant-user\n", message: "refusing: user"},
	}
	hostileSettingsPlans["claudecode"] = plan
	for name, tc := range map[string]struct{ refusals, want string }{
		"refused": {"::refusal=project-plugin 2 1\n::refusal=user-plugin 2 1\n", ""},
		"started": {"::refusal=project-plugin 0 0\n::refusal=user-plugin 2 1\n", "the launcher started the harness with the planted project-plugin (" + hostileProject + "/.opencode/plugins/x.js)"},
		"unnamed": {"::refusal=project-plugin 2 1\n::refusal=user-plugin 2 0\n", "the launcher exited 2 with the planted user-plugin without the refusal naming /sandbox/.config/opencode/plugins/x.js"},
		"untried": {"::refusal=project-plugin 2 1\n", "the launcher was never started with the planted user-plugin"},
	} {
		t.Run(name, func(t *testing.T) {
			c := hookFireContext(t)
			sim := containerSim{t: t, events: fullClaudeRun, port: c.Spec.IngressPort, refusals: tc.refusals}
			var scripts []string
			b := &Builder{Docker: &fakeDocker{handler: func(args []string, _ []byte) (string, int) {
				for i := 0; i+1 < len(args); i++ {
					if args[i] == "-e" && (strings.HasPrefix(args[i+1], "BASH_ENV=") || strings.HasPrefix(args[i+1], "PATH=")) {
						t.Errorf("the hostile launch env reached the container env: %v", args)
					}
				}
				scripts = append(scripts, args[len(args)-1])
				return sim.handle(args)
			}}}
			res, err := b.HookFireProbe(context.Background(), c, hostOpts(true))
			if tc.want != "" {
				if !errors.Is(err, ErrHooksNotFired) || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("error = %v, want %q", err, tc.want)
				}
				return
			}
			if err != nil {
				t.Fatalf("HookFireProbe: %v", err)
			}
			if got := res.Runs[2].Refusals; len(got) != 2 || !got[0].Named || got[1].ExitCode != 2 {
				t.Fatalf("refusals = %+v", got)
			}
			if len(scripts) != 3 {
				t.Fatalf("%d runs", len(scripts))
			}
			launch := "/usr/bin/env 'BASH_ENV=" + hostileRoot + "/bash-env' 'PATH=" + hostileRoot + "/bin:/usr/bin:/bin' '" + harness.ClaudeCodeLauncherPath + "'"
			for _, script := range scripts[:2] {
				if strings.Contains(script, "/usr/bin/env 'BASH_ENV") || strings.Contains(script, "::refusal=") {
					t.Errorf("a clean run got the hostile launch env or refusals:\n%s", script)
				}
			}
			hostile := scripts[2]
			if strings.Count(hostile, launch) != 3 || strings.Contains(hostile, "export BASH_ENV") {
				t.Errorf("the hostile env is not confined to the three harness starts:\n%s", hostile)
			}
			order := []string{
				"cd '/work/dc-hookfire-project' || exit 97",
				": plant-project\n" + launch, "grep -qF -- 'refusing: project' /tmp/dc-hookfire-refusal.out", "::refusal=project-plugin $rc $named",
				"rm -f '" + hostileProject + "/.opencode/plugins/x.js'",
				": plant-user\n" + launch, "::refusal=user-plugin $rc $named", "rm -f '/sandbox/.config/opencode/plugins/x.js'",
				launch, "</dev/null >/tmp/dc-hookfire.out 2>&1",
			}
			at := 0
			for _, want := range order {
				i := strings.Index(hostile[at:], want)
				if i < 0 {
					t.Fatalf("hostile script lacks %q after offset %d:\n%s", want, at, hostile)
				}
				at += i + len(want)
			}
		})
	}
}

func TestHookFireProbeRejectsBadOptions(t *testing.T) {
	c := hookFireContext(t)
	cases := map[string]HookFireOptions{
		"custom-mock-no-prompt": {Network: HookFireNetworkHost, SinkHost: "127.0.0.1", Env: map[string]string{"ANTHROPIC_BASE_URL": "http://127.0.0.1:1"}},
		"public-sink":           {Network: HookFireNetworkHost, SinkHost: "10.0.0.5", Prompt: "p"},
		"hostname-sink":         {Network: HookFireNetworkHost, SinkHost: "localhost", Prompt: "p"},
		"relay-public-sink":     {Network: HookFireNetworkRelay, SinkHost: "8.8.8.8", Prompt: "p"},
		"unknown-network":       {Network: "bridge", Prompt: "p"},
		"bad-side-effect":       {Network: HookFireNetworkHost, SinkHost: "127.0.0.1", Prompt: "p", Block: &BlockScenario{Prompt: "b", Marker: "m", SideEffect: "/tmp/$(x)"}},
		"bad-allow-side-effect": {Network: HookFireNetworkHost, SinkHost: "127.0.0.1", Prompt: "p", AllowSideEffect: "relative/file"},
		"incomplete-block":      {Network: HookFireNetworkHost, SinkHost: "127.0.0.1", Prompt: "p", Block: &BlockScenario{Prompt: "b"}},
	}
	// Run files are bind-mounted read-only: only clean absolute paths
	// without mount-option separators.
	for name, bad := range map[string]RunFile{
		"relative-run-file-host": {HostPath: "run.json", Path: "/etc/x.json"},
		"relative-run-file-path": {HostPath: "/tmp/run.json", Path: "etc/x.json"},
		"run-file-comma":         {HostPath: "/tmp/run.json,x", Path: "/etc/x.json"},
		"unclean-run-file":       {HostPath: "/tmp/run.json", Path: "/etc/../x.json"},
	} {
		opts := hostOpts(true)
		opts.RunFiles = []RunFile{bad}
		cases[name] = opts
	}
	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			sim := containerSim{t: t, events: fullClaudeRun, port: c.Spec.IngressPort}
			b := &Builder{Docker: &fakeDocker{handler: func(args []string, _ []byte) (string, int) {
				// The block scenario's side effect is checked when its run
				// starts, after the allow run; it never reaches a container.
				if name == "bad-side-effect" && !strings.Contains(strings.Join(args, " "), "$(x)") {
					return sim.handle(args)
				}
				t.Errorf("a container ran with bad options: %v", args)
				return "", 1
			}}}
			if _, err := b.HookFireProbe(context.Background(), c, opts); err == nil || errors.Is(err, ErrHooksNotFired) {
				t.Fatalf("bad options: %v, want a refusal before their run", err)
			}
		})
	}
}

func TestDefaultHookFireNetworkMatchesPlatform(t *testing.T) {
	n, err := resolveHookFireNet(HookFireOptions{}, 18971)
	if err != nil {
		t.Fatal(err)
	}
	switch n.mode {
	case HookFireNetworkHost:
		if n.bindHost != DefaultHookFireSinkHost || n.sinkPort != 18971 || n.containerHost != DefaultHookFireSinkHost {
			t.Fatalf("host mode = %+v", n)
		}
	case HookFireNetworkRelay:
		// Docker Desktop forwards host.docker.internal to host loopback;
		// the sink takes a free port, never the ingress port a running
		// DefenseClaw holds.
		if n.bindHost != "127.0.0.1" || n.sinkPort != 0 || n.containerHost != "host.docker.internal" {
			t.Fatalf("relay mode = %+v", n)
		}
	default:
		t.Fatalf("mode = %q", n.mode)
	}
	if n.mode != DefaultHookFireNetwork() {
		t.Fatalf("resolved %q, default %q", n.mode, DefaultHookFireNetwork())
	}
}

// sinkPost sends one hook request carrying token to sink and returns the
// status and body.
func sinkPost(sink *hookSink, path, token, body string, header map[string]string) (int, string) {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	sink.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// TestHookSinkRequiresTheToken: a hook or OTLP request without the sandbox
// token is refused and recorded as unauthorized; an authorized OTLP export
// is only counted, and for Codex (whose launcher hands the harness the OTLP
// header) an export without the token fails the probe.
func TestHookSinkRequiresTheToken(t *testing.T) {
	sink := &hookSink{token: "tok"}
	sink.begin(&BlockScenario{Marker: "BLOCKME"})
	if code, body := sinkPost(sink, "/api/v1/claude-code/hook", "tok", `{"hook_event_name":"PreToolUse","tool_input":{"command":"echo BLOCKME"}}`, nil); code != 200 ||
		!strings.Contains(body, `"permissionDecision":"deny"`) || !strings.Contains(body, `"codex_output"`) {
		t.Fatalf("block verdict = %d %s", code, body)
	}
	for path, token := range map[string]string{"/api/v1/claude-code/hook": "nope", "/v1/metrics": "bad"} {
		if code, _ := sinkPost(sink, path, token, `{"hook_event_name":"Stop"}`, nil); code != http.StatusUnauthorized {
			t.Fatalf("forged token on %s = %d", path, code)
		}
	}
	if code, _ := sinkPost(sink, "/v1/logs", "tok", `{}`, nil); code != 200 {
		t.Fatalf("otlp = %d", code)
	}
	events, otlp := sink.end()
	if len(events) != 2 || otlp != 1 || !events[0].Blocked || events[1].Authorized {
		t.Fatalf("events = %+v otlp=%d", events, otlp)
	}

	codex := &hookSink{token: "tok", adapter: hookSinkAdapters["codex"]}
	codex.begin(nil)
	for _, token := range []string{"tok", ""} {
		sinkPost(codex, "/v1/logs", token, "{}", nil)
	}
	events, otlp = codex.end()
	if otlp != 1 || len(events) != 1 || events[0].Authorized || events[0].Path != "/v1/logs" {
		t.Fatalf("codex events = %+v otlp=%d", events, otlp)
	}
	problems := requiredHookProblems(HookFireRun{Events: events}, nil)
	if len(problems) != 1 || !strings.Contains(problems[0], "/v1/logs OTLP export arrived without the sandbox token") {
		t.Fatalf("problems = %q", problems)
	}
}

// TestHookSinkAdvisoryAlert: for Claude Code and Codex the stand-in answers
// an allowed PreToolUse with the gateway's advisory alert, so the allowed
// runs prove an alert lets the tool run; the marker is still blocked and
// every other hook is still a plain allow.
func TestHookSinkAdvisoryAlert(t *testing.T) {
	for _, tc := range []struct {
		harness, path, header string
	}{
		{"claudecode", "/api/v1/claude-code/hook", ""},
		{"codex", "/api/v1/codex/hook", "X-DefenseClaw-Hook-Event"},
	} {
		t.Run(tc.harness, func(t *testing.T) {
			sink := &hookSink{token: "tok", adapter: hookSinkAdapters[tc.harness]}
			sink.begin(&BlockScenario{Marker: "BLOCKME"})
			post := func(event, command string) map[string]interface{} {
				header := map[string]string{}
				if tc.header != "" {
					header[tc.header] = event
				}
				code, body := sinkPost(sink, tc.path, "tok", `{"hook_event_name":"`+event+`","tool_input":{"command":"`+command+`"}}`, header)
				var out map[string]interface{}
				if err := json.Unmarshal([]byte(body), &out); err != nil || code != http.StatusOK {
					t.Fatalf("answer %d %q: %v", code, body, err)
				}
				return out
			}
			alert := post("PreToolUse", "echo ok")
			if alert["action"] != "alert" || alert["would_block"] != false {
				t.Fatalf("allowed PreToolUse answered %v, want an advisory alert", alert)
			}
			for _, field := range []string{"claude_code_output", "codex_output"} {
				notice, _ := alert[field].(map[string]interface{})
				if msg, _ := notice["systemMessage"].(string); msg == "" || len(notice) != 1 {
					t.Fatalf("%s = %v, want the harness notice only", field, alert[field])
				}
			}
			if blocked := post("PreToolUse", "echo BLOCKME"); blocked["action"] != "block" {
				t.Fatalf("the marker was answered %v", blocked)
			}
			if stop := post("Stop", "echo ok"); stop["action"] != "allow" || len(stop) != 1 {
				t.Fatalf("Stop answered %v, want a plain allow", stop)
			}
			events, _ := sink.end()
			if len(events) != 3 || !events[0].Alerted || events[0].Blocked || !events[1].Blocked || events[1].Alerted || events[2].Alerted {
				t.Fatalf("events = %+v", events)
			}
		})
	}
	// The other harnesses keep the plain allow.
	for name, adapter := range hookSinkAdapters {
		if adapter.advisoryAllow && name != "claudecode" && name != "codex" {
			t.Errorf("%s answers allowed tool calls with an alert its probe was never verified with", name)
		}
	}
}

// TestHookSinkDeniesThePreToolMarker drives the stand-in ingress the way each
// harness's sandbox hook does: the event comes from the body or the
// harness's event header, the marker is found wherever the harness puts the
// tool input, the deny is shaped for the harness's hook, and the marker in
// another event or field is a plain allow.
func TestHookSinkDeniesThePreToolMarker(t *testing.T) {
	cmd := `"tool_input":{"command":"echo BLOCKME"}`
	for _, tc := range []struct {
		harness string
		header  string // the event header the hook sends, if any
		preTool string // the pre-tool payload
		verdict string
		// other are event, payload pairs carrying the marker that must be
		// allowed.
		other []string
	}{
		{"claudecode", "", cmd, `"permissionDecision":"deny"`, []string{"Stop", cmd}},
		{"codex", "X-DefenseClaw-Hook-Event", cmd, `"permissionDecision":"deny"`, []string{"PostToolUse", cmd}},
		{"opencode", "", cmd, `"hook_output":{"decision":"deny"`, []string{"tool.execute.after", cmd}},
		{"copilot", "X-DefenseClaw-Copilot-Event", `"sessionId":"s","toolName":"bash","toolArgs":{"command":"echo BLOCKME"}`,
			`"hook_output":{"permissionDecision":"deny"`, []string{"userPromptSubmitted", `"sessionId":"s","prompt":"BLOCKME"`}},
		{"amp", "", `"tool_input":{"cmd":"echo BLOCKME"}`, `"action":"block"`, []string{"agent.start", `"prompt":"BLOCKME"`}},
		{"cursor", "", cmd, `"permission":"deny"`, nil},
		{"kiro", "", cmd, `"hook_output":{"decision":"block"`, nil},
		{"devin", "", cmd, `"hook_output":{"decision":"block"`, nil},
		{"hermes", "", cmd, `"hook_output":{"decision":"block"`, []string{"PreToolUse", cmd}},
		{"openhands", "", cmd, `"hook_output":{"decision":"deny"`, []string{"PreToolUse", `"message":"BLOCKME"`}},
		{"antigravity", "X-DefenseClaw-Antigravity-Event", `"toolInput":{"CommandLine":"echo BLOCKME"}`, `"hook_output":{"decision":"deny"`,
			[]string{"PostToolUse", `"toolInput":{"CommandLine":"echo BLOCKME"}`}},
		{"omnigent", "", cmd, `"action":"block"`, nil},
	} {
		t.Run(tc.harness, func(t *testing.T) {
			adapter := hookSinkAdapters[tc.harness]
			sink := &hookSink{token: "tok", adapter: adapter}
			sink.begin(&BlockScenario{Marker: "BLOCKME"})
			post := func(event, payload string) string {
				header := map[string]string{"X-DefenseClaw-Hook-Idempotency-Key": "k"}
				if tc.header != "" {
					header[tc.header] = event
				} else {
					payload = `"hook_event_name":"` + event + `",` + payload
				}
				_, body := sinkPost(sink, "/api/v1/"+tc.harness+"/hook", "tok", "{"+payload+"}", header)
				return body
			}
			if body := post(adapter.preToolEvent(), tc.preTool); !strings.Contains(body, tc.verdict) || !strings.Contains(body, `"action":"block"`) {
				t.Fatalf("pre-tool verdict = %s", body)
			}
			for i := 0; i < len(tc.other); i += 2 {
				if body := post(tc.other[i], tc.other[i+1]); body != `{"action":"allow"}` {
					t.Fatalf("%s %s was answered %s", tc.other[i], tc.other[i+1], body)
				}
			}
			events, _ := sink.end()
			if len(events) != 1+len(tc.other)/2 || !events[0].Blocked || events[0].Event != adapter.preToolEvent() {
				t.Fatalf("events = %+v", events)
			}
			for _, ev := range events[1:] {
				if ev.Blocked {
					t.Fatalf("events = %+v", events)
				}
			}
		})
	}
	for _, name := range harness.Names() {
		if len(requiredHookEvents[name]) == 0 {
			t.Errorf("harness %s has no required hook events", name)
		}
		if name != "claudecode" && name != "codex" && hookSinkAdapters[name].preTool == "" && !hookSinkAdapters[name].wholePayload {
			t.Errorf("harness %s has no hook-sink adapter", name)
		}
	}
	// The hook-only harnesses the Chat Completions, Gemini and Responses
	// mocks drive.
	for _, name := range []string{"antigravity", "hermes", "omnigent", "openhands"} {
		if _, ok := builtinMockLaunch[name]; !ok {
			t.Errorf("%s has no built-in mock wiring", name)
		}
	}
}

// TestHookFireBuiltinRefusesUnprobeableHarnesses: the built-in mock cannot
// drive Amp (no model endpoint), Cursor or Devin (a vendor account runs every
// turn), so the zero-value probe refuses before any container runs and names
// what is missing and what it means, not a Go option (`sandbox image build`
// prints it); their images stay unverified.
func TestHookFireBuiltinRefusesUnprobeableHarnesses(t *testing.T) {
	for _, tc := range []struct {
		spec *harness.Spec
		want string
	}{
		{harness.Amp, "AMP_API_KEY"},
		{harness.Cursor, "CURSOR_API_KEY"},
		{harness.Devin, "devin auth login"},
	} {
		c := hookFireContextFor(t, tc.spec)
		b := &Builder{Docker: &fakeDocker{handler: func(args []string, _ []byte) (string, int) {
			t.Errorf("a container ran: %v", args)
			return "", 1
		}}}
		_, err := b.HookFireProbe(context.Background(), c, HookFireOptions{Network: HookFireNetworkHost, SinkHost: "127.0.0.1"})
		if err == nil || errors.Is(err, ErrHooksNotFired) || !strings.Contains(err.Error(), tc.want) ||
			!strings.Contains(err.Error(), "image stays unverified") || strings.Contains(err.Error(), "HookFireOptions") {
			t.Fatalf("%s: error = %v", tc.spec.Name, err)
		}
	}
}

// TestBuiltinMockLaunchReachesTheMock checks the built-in mock wiring of the
// Messages-speaking hook-only harnesses: OpenCode's custom provider config
// and Copilot's offline BYOK environment both point at the mock.
func TestBuiltinMockLaunchReachesTheMock(t *testing.T) {
	env, args := builtinMockLaunch["opencode"]("http://127.0.0.2:4242")
	var cfg struct {
		Provider map[string]struct {
			NPM     string            `json:"npm"`
			Options map[string]string `json:"options"`
		} `json:"provider"`
		Model string `json:"model"`
	}
	if err := json.Unmarshal([]byte(env["OPENCODE_CONFIG_CONTENT"]), &cfg); err != nil || len(args) != 0 {
		t.Fatalf("opencode config %q: %v", env["OPENCODE_CONFIG_CONTENT"], err)
	}
	if p := cfg.Provider["dcprobe"]; p.NPM != "@ai-sdk/anthropic" || p.Options["baseURL"] != "http://127.0.0.2:4242/v1" || cfg.Model != "dcprobe/claude-sonnet-4-5" {
		t.Fatalf("opencode provider = %+v model %s", cfg, cfg.Model)
	}
	env, _ = builtinMockLaunch["copilot"]("http://127.0.0.2:4242")
	if env["COPILOT_PROVIDER_BASE_URL"] != "http://127.0.0.2:4242" || env["COPILOT_PROVIDER_TYPE"] != "anthropic" || env["COPILOT_OFFLINE"] != "true" {
		t.Fatalf("copilot env = %v", env)
	}
	if _, ok := builtinMockLaunch["amp"]; ok {
		t.Fatal("Amp has no model endpoint a mock can serve")
	}
}

// verifyDocker simulates a daemon that builds c, runs its static probe, and
// plays the harness for hook-fire runs through sim. onHookFire, when set,
// sees each hook-fire argv first and may fail the run with a non-zero exit.
func verifyDocker(t *testing.T, c *Context, sim *containerSim, onHookFire func(args []string) int) *fakeDocker {
	t.Helper()
	docker := imageDocker(t, c, goodProbeOutput(c))
	inner := docker.handler
	docker.handler = func(args []string, stdin []byte) (string, int) {
		switch {
		case args[0] == "run" && !containsSeq(args, "--network", "none"):
			if onHookFire != nil {
				if exit := onHookFire(args); exit != 0 {
					return "", exit
				}
			}
			return sim.handle(args)
		case args[0] == "rm" && args[1] == "-f":
			return "", 0
		}
		return inner(args, stdin)
	}
	return docker
}

// hookFireImage is the image reference a hook-fire docker run starts.
func hookFireImage(args []string) string {
	for i := 0; i+2 < len(args); i++ {
		if args[i] == "--entrypoint" {
			return args[i+2]
		}
	}
	return ""
}

func TestVerifyHooksRecordsVerdictAndGatesCurrent(t *testing.T) {
	c := hookFireContext(t)
	sim := &containerSim{t: t, events: fullClaudeRun, port: c.Spec.IngressPort}
	var images []string
	docker := verifyDocker(t, c, sim, func(args []string) int {
		images = append(images, hookFireImage(args))
		return 0
	})
	store := testStore(t)
	clock := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	b := &Builder{Docker: docker, Store: store, Now: func() time.Time { return clock }}
	ctx := context.Background()
	opts := hostOpts(true)
	current := func() (Record, bool) {
		t.Helper()
		rec, ok, err := store.Current(c)
		if err != nil {
			t.Fatal(err)
		}
		return rec, ok
	}

	built, err := b.Build(ctx, c.Spec, BuildOptions{SkipHookFire: true})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if built.HookFireVerified || len(images) != 0 {
		t.Fatal("a build that skipped the hook-fire probe is recorded as hook-verified")
	}
	if _, ok := current(); ok {
		t.Fatal("Current selected an image whose hooks were never proven to fire")
	}

	clock = clock.Add(time.Minute)
	rec, res, err := b.VerifyHooks(ctx, c, opts)
	if err != nil {
		t.Fatalf("VerifyHooks: %v", err)
	}
	if !rec.HookFireVerified || !rec.HookFireVerifiedAt.Equal(clock) || rec.ImageID != built.ImageID || len(res.Runs) != 3 {
		t.Fatalf("verified record = %+v runs=%d", rec, len(res.Runs))
	}
	if len(images) != 3 || images[0] != built.ImageID || images[2] != built.ImageID {
		t.Fatalf("hook-fire ran %v, want the recorded image ID %s", images, built.ImageID)
	}
	if got, ok := current(); !ok || got.Tag != c.Tag || !got.HookFireVerified {
		t.Fatalf("Current = %+v %t after a passing probe", got, ok)
	}
	if cached, err := b.Build(ctx, c.Spec, BuildOptions{HookFire: opts}); err != nil || !cached.HookFireVerified || docker.count("build") != 1 || len(images) != 3 {
		t.Fatalf("cached build = %+v %v (docker builds %d, probes %d)", cached, err, docker.count("build"), len(images))
	}

	// A probe that proves the hooks no longer fire clears the verdict.
	sim.events = []string{"SessionStart", "UserPromptSubmit", "Stop"}
	rec, _, err = b.VerifyHooks(ctx, c, opts)
	if !errors.Is(err, ErrHooksNotFired) || rec.HookFireVerified || !rec.HookFireVerifiedAt.IsZero() {
		t.Fatalf("failed probe: record %+v err %v", rec, err)
	}
	if _, ok := current(); ok {
		t.Fatal("Current still selects an image whose hooks did not fire")
	}

	// A cached but unverified image is probed again by Build.
	sim.events = fullClaudeRun
	if again, err := b.Build(ctx, c.Spec, BuildOptions{HookFire: opts}); err != nil || !again.HookFireVerified || docker.count("build") != 1 {
		t.Fatalf("re-verified cached build = %+v %v (docker builds %d)", again, err, docker.count("build"))
	}

	// A rebuild records a fresh image and verifies it before returning.
	probes := len(images)
	rebuilt, err := b.Build(ctx, c.Spec, BuildOptions{Force: true, HookFire: opts})
	if err != nil || !rebuilt.HookFireVerified || docker.count("build") != 2 || len(images) != probes+3 {
		t.Fatalf("forced rebuild = %+v %v", rebuilt, err)
	}
	// A rebuild whose hooks do not fire stays recorded, unverified.
	sim.events = []string{"SessionStart"}
	failed, err := b.Build(ctx, c.Spec, BuildOptions{Force: true, HookFire: opts})
	if !errors.Is(err, ErrHooksNotFired) || failed.HookFireVerified || failed.Tag != c.Tag {
		t.Fatalf("rebuild with silent hooks = %+v %v", failed, err)
	}
	if _, ok := current(); ok {
		t.Fatal("Current selects a rebuilt image whose hooks did not fire")
	}
	if _, ok, _ := store.Get(c.Tag); !ok {
		t.Fatal("an image whose hooks did not fire was forgotten")
	}
}

func TestBuildVerifiesWithTheBuiltinMock(t *testing.T) {
	c := hookFireContextFor(t, harness.Codex)
	sim := &containerSim{t: t, events: fullClaudeRun, port: c.Spec.IngressPort, llm: true}
	docker := verifyDocker(t, c, sim, nil)
	b := &Builder{Docker: docker, Store: testStore(t)}
	rec, err := b.Build(context.Background(), c.Spec, BuildOptions{HookFire: HookFireOptions{Network: HookFireNetworkHost, SinkHost: "127.0.0.1"}})
	if err != nil || !rec.HookFireVerified {
		t.Fatalf("Build = %+v %v", rec, err)
	}
	if cur, ok, err := b.Current(c.Spec); err != nil || !ok || cur.Tag != c.Tag {
		t.Fatalf("Current = %+v %t %v", cur, ok, err)
	}
}

func TestVerifyHooksRefusesUnrecordedOrReplacedImages(t *testing.T) {
	c := hookFireContext(t)
	sim := &containerSim{t: t, events: fullClaudeRun, port: c.Spec.IngressPort}
	opts := hostOpts(true)
	for name, stored := range map[string]*Record{
		"not-built":        nil,
		"other-content":    {Tag: c.Tag, ContentHash: "sha256:other", ImageID: "sha256:" + strings.Repeat("1", 64)},
		"retagged-image":   {Tag: c.Tag, ContentHash: c.ContentHash, ImageID: "sha256:" + strings.Repeat("2", 64)},
		"image-not-listed": {Tag: c.Tag, ContentHash: c.ContentHash, ImageID: "sha256:" + strings.Repeat("1", 64)},
	} {
		t.Run(name, func(t *testing.T) {
			store := testStore(t)
			if stored != nil {
				if err := store.Put(*stored); err != nil {
					t.Fatal(err)
				}
			}
			docker := &fakeDocker{handler: func(args []string, _ []byte) (string, int) {
				switch {
				case args[0] == "image" && args[1] == "inspect":
					if name == "image-not-listed" {
						return "", 1
					}
					return "sha256:" + strings.Repeat("1", 64) + "\n", 0
				case args[0] == "run":
					return sim.handle(args)
				}
				return "", 1
			}}
			b := &Builder{Docker: docker, Store: store}
			if _, _, err := b.VerifyHooks(context.Background(), c, opts); err == nil {
				t.Fatal("VerifyHooks accepted an image it cannot tie to the build record")
			}
			if docker.count("run") != 0 {
				t.Fatal("the hook-fire probe ran")
			}
			if rec, ok, _ := store.Get(c.Tag); ok && rec.HookFireVerified {
				t.Fatalf("record marked verified: %+v", rec)
			}
		})
	}
}

func TestVerifyHooksKeepsVerdictWhenProbeCannotRun(t *testing.T) {
	c := hookFireContext(t)
	store := testStore(t)
	verifiedAt := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	if err := store.Put(Record{
		Tag: c.Tag, ContentHash: c.ContentHash, ImageID: "sha256:" + strings.Repeat("1", 64),
		Connector: c.Spec.Harness.Name, UID: c.Spec.UID, GID: c.Spec.GID, IngressPort: c.Spec.IngressPort,
		HookFireVerified: true, HookFireVerifiedAt: verifiedAt,
	}); err != nil {
		t.Fatal(err)
	}
	docker := &fakeDocker{handler: func(args []string, _ []byte) (string, int) {
		switch {
		case args[0] == "image" && args[1] == "inspect":
			return "sha256:" + strings.Repeat("1", 64) + "\n", 0
		case args[0] == "run":
			return "", 125 // the daemon could not start the container
		case args[0] == "rm":
			return "", 0
		}
		return "", 1
	}}
	b := &Builder{Docker: docker, Store: store}
	for name, tc := range map[string]struct {
		opts HookFireOptions
		// refusal is what options refused before any container runs say.
		refusal string
	}{
		"docker-failure":         {hostOpts(true), ""},
		"builtin-docker-failure": {HookFireOptions{Network: HookFireNetworkRelay}, ""},
		"bad-options":            {HookFireOptions{Network: HookFireNetworkHost, SinkHost: "10.0.0.5"}, "must be a loopback address"},
		"no-block-scenario":      {hostOpts(false), "block scenario"},
	} {
		runs := docker.count("run")
		_, _, err := b.VerifyHooks(context.Background(), c, tc.opts)
		if err == nil || errors.Is(err, ErrHooksNotFired) || !strings.Contains(err.Error(), tc.refusal) {
			t.Fatalf("%s: error = %v, want a probe error that is not a verdict", name, err)
		}
		if tc.refusal != "" && docker.count("run") != runs {
			t.Fatalf("%s: a container ran", name)
		}
		rec, _, _ := store.Get(c.Tag)
		if !rec.HookFireVerified || !rec.HookFireVerifiedAt.Equal(verifiedAt) {
			t.Fatalf("%s: a probe that could not run changed the verdict: %+v", name, rec)
		}
	}
}

func TestVerifyHooksIgnoresProbeOfReplacedImage(t *testing.T) {
	c := hookFireContext(t)
	sim := &containerSim{t: t, events: fullClaudeRun, port: c.Spec.IngressPort}
	store := testStore(t)
	docker := verifyDocker(t, c, sim, func([]string) int {
		// A concurrent rebuild replaces the record while the probe runs.
		if err := store.Put(Record{Tag: c.Tag, ContentHash: c.ContentHash, ImageID: "sha256:" + strings.Repeat("3", 64)}); err != nil {
			t.Error(err)
		}
		return 0
	})
	b := &Builder{Docker: docker, Store: store}
	if _, err := b.Build(context.Background(), c.Spec, BuildOptions{SkipHookFire: true}); err != nil {
		t.Fatal(err)
	}
	_, _, err := b.VerifyHooks(context.Background(), c, hostOpts(true))
	if err == nil || !strings.Contains(err.Error(), "rebuilt while") {
		t.Fatalf("error = %v", err)
	}
	rec, _, _ := store.Get(c.Tag)
	if rec.ImageID != "sha256:"+strings.Repeat("3", 64) || rec.HookFireVerified {
		t.Fatalf("the rebuilt image inherited its predecessor's verdict: %+v", rec)
	}
}

// TestHookFireProbeMountsRunFiles pins that every probe container sees the
// run files read-only, so VerifyHooks proves an image together with a
// sandbox's per-run managed configuration.
func TestHookFireProbeMountsRunFiles(t *testing.T) {
	c := hookFireContext(t)
	sim := containerSim{t: t, events: fullClaudeRun, port: c.Spec.IngressPort}
	file := filepath.Join(t.TempDir(), "run.json")
	var runs int
	b := &Builder{Docker: &fakeDocker{handler: func(args []string, _ []byte) (string, int) {
		runs++
		if !containsSeq(args, "--mount", "type=bind,source="+file+",target="+connector.ClaudeCodeSandboxRunDropInPath+",readonly") {
			t.Errorf("probe container without the run file: %v", args)
		}
		return sim.handle(args)
	}}}
	opts := hostOpts(true)
	opts.RunFiles = []RunFile{{HostPath: file, Path: connector.ClaudeCodeSandboxRunDropInPath}}
	if _, err := b.HookFireProbe(context.Background(), c, opts); err != nil {
		t.Fatalf("HookFireProbe: %v", err)
	}
	if runs != 3 {
		t.Fatalf("%d probe containers", runs)
	}
}

// TestHookFireScenarioChecks pins the scenario hooks the run-config probe
// uses: a safe launch, raw extra flags, a work-root project, setup and post
// scripts, markers and reports.
func TestHookFireScenarioChecks(t *testing.T) {
	c := hookFireContext(t)
	var script string
	var args []string
	b := &Builder{Docker: &fakeDocker{handler: func(a []string, _ []byte) (string, int) {
		args, script = a, a[len(a)-1]
		return "::rc=0\n::marker=/tmp/m1=present\n::marker=/tmp/m2=absent\n::report=approval: on-request\n::output-begin\nok\n::output-end\n", 0
	}}}
	netw, err := resolveHookFireNet(HookFireOptions{Network: HookFireNetworkHost, SinkHost: "127.0.0.1"}, c.Spec.IngressPort)
	if err != nil {
		t.Fatal(err)
	}
	sc := hookFireScenario{
		name: "custom", prompt: "p", safe: true, extraArgs: []string{"--dangerously-skip-permissions"},
		env: map[string]string{"MCP_TIMEOUT": "5000"}, workdir: "/work/proj", setup: "echo setup-ran\n", post: "echo '::report=x'\n",
		markers: []string{"/tmp/m1", "/tmp/m2"},
	}
	run, err := b.hookFireRun(context.Background(), c, c.Tag, HookFireOptions{}, netw, &hookSink{token: "t"}, sc)
	if err != nil {
		t.Fatal(err)
	}
	if !run.Markers["/tmp/m1"] || run.Markers["/tmp/m2"] || len(run.Markers) != 2 || len(run.Report) != 1 || run.Report[0] != "approval: on-request" {
		t.Fatalf("run = %+v", run)
	}
	launch := harness.ClaudeCodeLauncherPath + "' '-p' 'p'"
	for _, want := range []string{"mkdir -p '/work/proj'", "echo setup-ran", "cd '/work/proj' || exit 97", launch, "'--dangerously-skip-permissions' </dev/null",
		"echo '::report=x'", "if [ -e '/tmp/m1' ]"} {
		if !strings.Contains(script, want) {
			t.Fatalf("script lacks %q:\n%s", want, script)
		}
	}
	if strings.Count(script, "--dangerously-skip-permissions") != 1 {
		t.Fatalf("a safe launch added skip-permissions itself:\n%s", script)
	}
	if !containsSeq(args, "-e", "MCP_TIMEOUT=5000") || !containsSeq(args, "--tmpfs", fmt.Sprintf("%s:uid=%d,gid=%d,mode=0755", harness.WorkRoot, c.Spec.UID, c.Spec.GID)) {
		t.Fatalf("argv = %v", args)
	}
	sc.markers = []string{"/tmp/a b"}
	if _, err := b.hookFireRun(context.Background(), c, c.Tag, HookFireOptions{}, netw, &hookSink{token: "t"}, sc); err == nil {
		t.Fatal("a marker path with a space was accepted")
	}
}
