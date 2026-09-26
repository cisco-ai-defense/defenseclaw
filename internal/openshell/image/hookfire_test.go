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
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
)

// containerSim plays the harness inside the image: it posts hook events to
// the ingress the docker argv points at, the way the rendered hooks do.
type containerSim struct {
	t *testing.T
	// events per scenario, in order; the tool input of PreToolUse carries
	// the scenario prompt so the block marker can match.
	events        []string
	port          int
	badToken      bool
	noKey         bool
	ignoreVerdict bool
}

func (s containerSim) handle(args []string) (string, int) {
	host, token, script := "", "", ""
	for i := 0; i+1 < len(args); i++ {
		switch args[i] {
		case "--add-host":
			host = strings.TrimPrefix(args[i+1], connector.SandboxIngressHost+":")
		case "-e":
			if v, ok := strings.CutPrefix(args[i+1], connector.SandboxTokenEnv+"="); ok {
				token = v
			}
		}
	}
	script = args[len(args)-1]
	if host == "" || token == "" || !strings.Contains(script, harness.ClaudeCodeLauncherPath) {
		s.t.Errorf("hook-fire argv lacks the sink host, token or launcher: %v", args)
		return "", 1
	}
	if !containsSeq(args, "--network", "host") || !containsSeq(args, "-e", "HOME="+connector.SandboxHomeDir) {
		s.t.Errorf("hook-fire argv = %v", args)
	}
	if s.badToken {
		token = "forged"
	}
	blocked := false
	for _, event := range s.events {
		payload, _ := json.Marshal(map[string]interface{}{
			"hook_event_name": event,
			"tool_input":      map[string]string{"command": script},
		})
		req, _ := http.NewRequest(http.MethodPost, "http://"+net.JoinHostPort(host, strconv.Itoa(s.port))+"/api/v1/claude-code/hook", bytes.NewReader(payload))
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
		if blocked {
			out += "::side-effect=absent\n"
		} else {
			out += "::side-effect=present\n"
		}
	}
	return out + "::output-begin\nok\n::output-end\n", 0
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

func hookFireContext(t *testing.T) *Context {
	t.Helper()
	spec := testSpec(harness.ClaudeCode)
	spec.IngressPort = freePort(t)
	return mustContext(t, spec)
}

var fullClaudeRun = []string{"SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop", "SessionEnd"}

func TestHookFireProbePassesWhenHooksFire(t *testing.T) {
	c := hookFireContext(t)
	sim := containerSim{t: t, events: fullClaudeRun, port: c.Spec.IngressPort}
	b := &Builder{Docker: &fakeDocker{handler: func(args []string, _ []byte) (string, int) { return sim.handle(args) }}}
	res, err := b.HookFireProbe(context.Background(), c, HookFireOptions{
		SinkHost: "127.0.0.1",
		Env:      map[string]string{"ANTHROPIC_BASE_URL": "http://127.0.0.1:1"},
		Prompt:   "write the marker",
		Block:    &BlockScenario{Prompt: "BLOCKME", Marker: "BLOCKME", SideEffect: "/tmp/blocked.txt"},
	})
	if err != nil {
		t.Fatalf("HookFireProbe: %v", err)
	}
	if len(res.Runs) != 2 || len(res.Runs[0].Events) != len(fullClaudeRun) {
		t.Fatalf("runs = %+v", res.Runs)
	}
	blocked := false
	for _, ev := range res.Runs[1].Events {
		blocked = blocked || (ev.Event == "PreToolUse" && ev.Blocked)
	}
	if !blocked || res.Runs[1].SideEffectPresent == nil || *res.Runs[1].SideEffectPresent {
		t.Fatalf("block run = %+v", res.Runs[1])
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
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := hookFireContext(t)
			sim := tc.sim
			sim.t, sim.port = t, c.Spec.IngressPort
			b := &Builder{Docker: &fakeDocker{handler: func(args []string, _ []byte) (string, int) { return sim.handle(args) }}}
			opts := HookFireOptions{SinkHost: "127.0.0.1", Prompt: "write the marker"}
			if tc.block {
				opts.Block = &BlockScenario{Prompt: "BLOCKME", Marker: "BLOCKME", SideEffect: "/tmp/blocked.txt"}
			}
			_, err := b.HookFireProbe(context.Background(), c, opts)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestHookFireProbeRejectsBadOptions(t *testing.T) {
	c := hookFireContext(t)
	b := &Builder{Docker: &fakeDocker{handler: func([]string, []byte) (string, int) { return "", 0 }}}
	for name, opts := range map[string]HookFireOptions{
		"no-prompt":        {SinkHost: "127.0.0.1"},
		"public-sink":      {SinkHost: "10.0.0.5", Prompt: "p"},
		"hostname-sink":    {SinkHost: "localhost", Prompt: "p"},
		"bad-side-effect":  {SinkHost: "127.0.0.1", Prompt: "p", Block: &BlockScenario{Prompt: "b", Marker: "m", SideEffect: "/tmp/$(x)"}},
		"incomplete-block": {SinkHost: "127.0.0.1", Prompt: "p", Block: &BlockScenario{Prompt: "b"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := b.HookFireProbe(context.Background(), c, opts); err == nil {
				t.Fatal("bad options accepted")
			}
		})
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
