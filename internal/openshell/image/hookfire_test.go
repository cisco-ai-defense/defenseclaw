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
	"strconv"
	"strings"
	"testing"
	"time"

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
	// hostileEvents replaces events in the hostile-settings run (nil keeps
	// events), and plantedRan is what that run reports as planted programs
	// that ran.
	hostileEvents []string
	plantedRan    string
}

func (s containerSim) handle(args []string) (string, int) {
	host, token, script, user := "", "", "", ""
	for i := 0; i+1 < len(args); i++ {
		switch args[i] {
		case "--user":
			user = args[i+1]
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
	hostile := strings.Contains(script, hostileRanLog)
	uid, gid, _ := strings.Cut(user, ":")
	if hostile != containsSeq(args, "--tmpfs", fmt.Sprintf("%s:uid=%s,gid=%s,mode=0755", harness.WorkRoot, uid, gid)) {
		s.t.Errorf("hostile-settings run and workload-owned work-root tmpfs disagree: %v", args)
	}
	if hostile && !strings.Contains(script, "cd '/work/dc-hookfire-project' || exit 97") {
		s.t.Errorf("hostile-settings run does not start in the planted project: %s", script)
	}
	events := s.events
	if hostile && s.hostileEvents != nil {
		events = s.hostileEvents
	}
	blocked := false
	for _, event := range events {
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
	if hostile && s.plantedRan != "" {
		out += "::planted-ran=" + s.plantedRan + "\n"
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
	if len(res.Runs) != 3 || len(res.Runs[0].Events) != len(fullClaudeRun) {
		t.Fatalf("runs = %+v", res.Runs)
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
			opts := HookFireOptions{SinkHost: "127.0.0.1", Prompt: "write the marker"}
			if tc.block {
				opts.Block = &BlockScenario{Prompt: "BLOCKME", Marker: "BLOCKME", SideEffect: "/tmp/blocked.txt"}
			}
			_, err := b.HookFireProbe(context.Background(), c, opts)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			if !errors.Is(err, ErrHooksNotFired) {
				t.Fatalf("error = %v, want ErrHooksNotFired", err)
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

// verifyDocker simulates a daemon that builds c, runs its static probe, and
// plays the harness for hook-fire runs through sim. onHookFire, when set,
// sees each hook-fire argv first and may fail the run with a non-zero exit.
func verifyDocker(t *testing.T, c *Context, sim *containerSim, onHookFire func(args []string) int) *fakeDocker {
	t.Helper()
	docker := imageDocker(t, c, goodProbeOutput(c))
	inner := docker.handler
	docker.handler = func(args []string, stdin []byte) (string, int) {
		switch {
		case args[0] == "run" && containsSeq(args, "--network", "host"):
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
	opts := HookFireOptions{SinkHost: "127.0.0.1", Prompt: "write the marker"}
	current := func() (Record, bool) {
		t.Helper()
		rec, ok, err := store.Current(c)
		if err != nil {
			t.Fatal(err)
		}
		return rec, ok
	}

	built, err := b.Build(ctx, c.Spec, BuildOptions{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if built.HookFireVerified {
		t.Fatal("a fresh build is recorded as hook-verified")
	}
	if _, ok := current(); ok {
		t.Fatal("Current selected an image whose hooks were never proven to fire")
	}

	clock = clock.Add(time.Minute)
	rec, res, err := b.VerifyHooks(ctx, c, opts)
	if err != nil {
		t.Fatalf("VerifyHooks: %v", err)
	}
	if !rec.HookFireVerified || !rec.HookFireVerifiedAt.Equal(clock) || rec.ImageID != built.ImageID || len(res.Runs) != 2 {
		t.Fatalf("verified record = %+v runs=%d", rec, len(res.Runs))
	}
	if len(images) != 2 || images[0] != built.ImageID || images[1] != built.ImageID {
		t.Fatalf("hook-fire ran %v, want the recorded image ID %s", images, built.ImageID)
	}
	if got, ok := current(); !ok || got.Tag != c.Tag || !got.HookFireVerified {
		t.Fatalf("Current = %+v %t after a passing probe", got, ok)
	}
	if cached, err := b.Build(ctx, c.Spec, BuildOptions{}); err != nil || !cached.HookFireVerified || docker.count("build") != 1 {
		t.Fatalf("cached build = %+v %v (docker builds %d)", cached, err, docker.count("build"))
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

	// A rebuild records a fresh, unverified image.
	sim.events = fullClaudeRun
	if _, _, err := b.VerifyHooks(ctx, c, opts); err != nil {
		t.Fatal(err)
	}
	rebuilt, err := b.Build(ctx, c.Spec, BuildOptions{Force: true})
	if err != nil {
		t.Fatal(err)
	}
	if rebuilt.HookFireVerified || docker.count("build") != 2 {
		t.Fatalf("forced rebuild = %+v", rebuilt)
	}
	if _, ok := current(); ok {
		t.Fatal("Current selects a rebuilt image before its hooks were probed")
	}
}

func TestVerifyHooksRefusesUnrecordedOrReplacedImages(t *testing.T) {
	c := hookFireContext(t)
	sim := &containerSim{t: t, events: fullClaudeRun, port: c.Spec.IngressPort}
	opts := HookFireOptions{SinkHost: "127.0.0.1", Prompt: "write the marker"}
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
		"docker-failure": {SinkHost: "127.0.0.1", Prompt: "write the marker"},
		"bad-options":    {SinkHost: "127.0.0.1"},
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
	if _, err := b.Build(context.Background(), c.Spec, BuildOptions{}); err != nil {
		t.Fatal(err)
	}
	_, _, err := b.VerifyHooks(context.Background(), c, HookFireOptions{SinkHost: "127.0.0.1", Prompt: "write the marker"})
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
