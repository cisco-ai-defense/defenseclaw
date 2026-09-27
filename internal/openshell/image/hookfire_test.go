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
}

var (
	simRelayPortRE = regexp.MustCompile(`host\.docker\.internal ([0-9]+) >/tmp/dc-hookfire-relay\.log`)
	simBaseURLRE   = regexp.MustCompile(`model_providers\.dcprobe\.base_url="([^"]+)"`)
)

func (s containerSim) handle(args []string) (string, int) {
	host, token, script, user := "", "", "", ""
	env := map[string]string{}
	for i := 0; i+1 < len(args); i++ {
		switch args[i] {
		case "--user":
			user = args[i+1]
		case "--add-host":
			if v, ok := strings.CutPrefix(args[i+1], connector.SandboxIngressHost+":"); ok {
				host = v
			}
		case "-e":
			k, v, _ := strings.Cut(args[i+1], "=")
			env[k] = v
			if k == connector.SandboxTokenEnv {
				token = v
			}
		}
	}
	script = args[len(args)-1]
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
		payload, _ := json.Marshal(map[string]interface{}{"hook_event_name": event, "tool_input": toolInput})
		req, _ := http.NewRequest(http.MethodPost, "http://"+target+"/api/v1/claude-code/hook", bytes.NewReader(payload))
		req.Header.Set("Authorization", "Bearer "+token)
		if !s.noKey {
			req.Header.Set("X-DefenseClaw-Hook-Idempotency-Key", "k-"+event)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			s.t.Errorf("post %s: %v", event, err)
			return "", 1
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if event == "PreToolUse" && strings.Contains(string(body), `"action":"block"`) && !s.ignoreVerdict {
			blocked = true
		}
	}
	out := "::rc=0\n"
	if strings.Contains(script, "::side-effect=") {
		if blocked || s.toolNeverRuns {
			out += "::side-effect=absent\n"
		} else {
			out += "::side-effect=present\n"
		}
	}
	if hostile && s.plantedRan != "" {
		out += "::planted-ran=" + s.plantedRan + "\n"
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
				// p2-render-10: Codex now has hostile-settings too, so both harnesses get 3 runs.
				wantRuns := 3
				if len(res.Runs) != wantRuns || res.Network != mode {
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
			_, err := b.HookFireProbe(context.Background(), c, hostOpts(tc.block))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			if !errors.Is(err, ErrHooksNotFired) {
				t.Fatalf("error = %v, want ErrHooksNotFired", err)
			}
		})
	}
}

// TestHookFireBuiltinRequiresTheAllowedToolToRun fails an image whose hooks
// all fire but whose allowed tool call never runs (for example a planted
// shell that swallows it).
func TestHookFireBuiltinRequiresTheAllowedToolToRun(t *testing.T) {
	c := hookFireContextFor(t, harness.Codex)
	sim := containerSim{t: t, events: fullClaudeRun, port: c.Spec.IngressPort, llm: true, toolNeverRuns: true}
	b := &Builder{Docker: &fakeDocker{handler: func(args []string, _ []byte) (string, int) { return sim.handle(args) }}}
	_, err := b.HookFireProbe(context.Background(), c, HookFireOptions{Network: HookFireNetworkHost, SinkHost: "127.0.0.1"})
	if !errors.Is(err, ErrHooksNotFired) || !strings.Contains(err.Error(), "the allowed tool call never ran ("+builtinAllowSideEffect+" is missing)") {
		t.Fatalf("error = %v", err)
	}
}

func TestHookFireProbeRejectsBadOptions(t *testing.T) {
	c := hookFireContext(t)
	b := &Builder{Docker: &fakeDocker{handler: func([]string, []byte) (string, int) { return "", 0 }}}
	for name, opts := range map[string]HookFireOptions{
		"custom-mock-no-prompt": {Network: HookFireNetworkHost, SinkHost: "127.0.0.1", Env: map[string]string{"ANTHROPIC_BASE_URL": "http://127.0.0.1:1"}},
		"public-sink":           {Network: HookFireNetworkHost, SinkHost: "10.0.0.5", Prompt: "p"},
		"hostname-sink":         {Network: HookFireNetworkHost, SinkHost: "localhost", Prompt: "p"},
		"relay-public-sink":     {Network: HookFireNetworkRelay, SinkHost: "8.8.8.8", Prompt: "p"},
		"unknown-network":       {Network: "bridge", Prompt: "p"},
		"bad-side-effect":       {Network: HookFireNetworkHost, SinkHost: "127.0.0.1", Prompt: "p", Block: &BlockScenario{Prompt: "b", Marker: "m", SideEffect: "/tmp/$(x)"}},
		"bad-allow-side-effect": {Network: HookFireNetworkHost, SinkHost: "127.0.0.1", Prompt: "p", AllowSideEffect: "relative/file"},
		"incomplete-block":      {Network: HookFireNetworkHost, SinkHost: "127.0.0.1", Prompt: "p", Block: &BlockScenario{Prompt: "b"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := b.HookFireProbe(context.Background(), c, opts); err == nil {
				t.Fatal("bad options accepted")
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

func TestHookSinkVerdicts(t *testing.T) {
	sink := &hookSink{token: "tok"}
	sink.begin(&BlockScenario{Marker: "BLOCKME"})
	post := func(path, event, token, body string, headers map[string]string) (int, string) {
		req, _ := http.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		rec := &responseRecorder{header: http.Header{}}
		sink.ServeHTTP(rec, req)
		return rec.status(), rec.body.String()
	}
	if code, body := post("/api/v1/claude-code/hook", "", "tok", `{"hook_event_name":"PreToolUse","tool_input":{"command":"echo BLOCKME"}}`, nil); code != 200 ||
		!strings.Contains(body, `"permissionDecision":"deny"`) || !strings.Contains(body, `"codex_output"`) {
		t.Fatalf("block verdict = %d %s", code, body)
	}
	if code, body := post("/api/v1/codex/hook", "", "tok", `{"hook_event_name":"PreToolUse","tool_input":{"command":"ls"}}`, map[string]string{"X-DefenseClaw-Hook-Event": "PreToolUse"}); code != 200 || body != `{"action":"allow"}` {
		t.Fatalf("allow verdict = %d %s", code, body)
	}
	if code, _ := post("/api/v1/claude-code/hook", "", "nope", `{"hook_event_name":"Stop"}`, nil); code != http.StatusUnauthorized {
		t.Fatalf("forged token = %d", code)
	}
	if code, _ := post("/v1/logs", "", "tok", `{}`, nil); code != 200 {
		t.Fatalf("otlp = %d", code)
	}
	if code, _ := post("/v1/metrics", "", "bad", `{}`, nil); code != http.StatusUnauthorized {
		t.Fatalf("forged otlp = %d", code)
	}
	events, otlp := sink.end()
	if len(events) != 3 || otlp != 1 || !events[0].Blocked || events[1].Event != "PreToolUse" || events[2].Authorized {
		t.Fatalf("events = %+v otlp=%d", events, otlp)
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

func TestVerifyHooksRequiresABlockScenario(t *testing.T) {
	c := hookFireContext(t)
	docker := &fakeDocker{handler: func([]string, []byte) (string, int) { return "", 1 }}
	b := &Builder{Docker: docker, Store: testStore(t)}
	if _, _, err := b.VerifyHooks(context.Background(), c, hostOpts(false)); err == nil || !strings.Contains(err.Error(), "block scenario") {
		t.Fatalf("error = %v", err)
	}
	if len(docker.calls) != 0 {
		t.Fatalf("docker ran: %v", docker.calls)
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
	for name, opts := range map[string]HookFireOptions{
		"docker-failure":         hostOpts(true),
		"builtin-docker-failure": {Network: HookFireNetworkRelay},
		"bad-options":            {Network: HookFireNetworkHost, SinkHost: "10.0.0.5"},
		"no-block-scenario":      hostOpts(false),
	} {
		_, _, err := b.VerifyHooks(context.Background(), c, opts)
		if err == nil || errors.Is(err, ErrHooksNotFired) {
			t.Fatalf("%s: error = %v, want a probe error that is not a verdict", name, err)
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

type responseRecorder struct {
	header http.Header
	code   int
	body   bytes.Buffer
}

func (r *responseRecorder) Header() http.Header         { return r.header }
func (r *responseRecorder) Write(b []byte) (int, error) { return r.body.Write(b) }
func (r *responseRecorder) WriteHeader(code int)        { r.code = code }
func (r *responseRecorder) status() int {
	if r.code == 0 {
		return http.StatusOK
	}
	return r.code
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
	for name, bad := range map[string]RunFile{
		"relative host": {HostPath: "run.json", Path: "/etc/x.json"},
		"relative path": {HostPath: file, Path: "etc/x.json"},
		"comma":         {HostPath: file + ",x", Path: "/etc/x.json"},
		"unclean":       {HostPath: file, Path: "/etc/../x.json"},
	} {
		opts.RunFiles = []RunFile{bad}
		if _, err := b.HookFireProbe(context.Background(), c, opts); err == nil {
			t.Errorf("%s run file accepted", name)
		}
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
