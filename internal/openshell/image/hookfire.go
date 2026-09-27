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
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
)

// Claude silently drops a managed-settings drop-in that carries one
// schema-invalid field, and a hook script can be present yet never run, so
// the only proof that an image enforces is a harness run whose hooks reach
// an ingress. The hook-fire probe runs the harness headless in the built
// image against a mock LLM (supplied by the caller) and a stand-in hook
// ingress it serves itself on the image's baked port.

// ErrHooksNotFired marks a hook-fire probe that ran the harness to completion
// and proved the image does not enforce: a required hook never fired,
// arrived unauthenticated or without an idempotency key, or a blocked tool
// call still ran. Other probe errors (docker, sink or option failures) say
// nothing about the image.
var ErrHooksNotFired = errors.New("hooks did not fire as required")

// DefaultHookFireSinkHost keeps 127.0.0.1:<ingress> free for a running
// DefenseClaw: all of 127.0.0.0/8 is loopback on Linux.
const DefaultHookFireSinkHost = "127.0.0.2"

// requiredHookEvents must each arrive, authenticated, from a clean run.
var requiredHookEvents = map[string][]string{
	"claudecode": {"SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop"},
	"codex":      {"SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop"},
}

// HookFireOptions configure a hook-fire probe.
type HookFireOptions struct {
	// SinkHost is the loopback address the stand-in ingress binds and the
	// container resolves host.openshell.internal to.
	SinkHost string
	// Env holds the mock LLM settings (ANTHROPIC_BASE_URL/ANTHROPIC_API_KEY
	// for Claude Code, OPENAI_API_KEY for Codex).
	Env map[string]string
	// Args are extra harness arguments (for example a Codex mock provider).
	Args []string
	// Prompt drives the allow scenario; the mock must answer it with one
	// tool call.
	Prompt string
	// Block, when set, adds a scenario whose tool call the hook must deny.
	Block *BlockScenario
	// Timeout bounds each harness run (default 3 minutes).
	Timeout time.Duration
	// ContainerPrefix names the probe containers (default
	// defenseclaw-hookfire).
	ContainerPrefix string
}

// BlockScenario is a run whose PreToolUse the stand-in ingress blocks.
type BlockScenario struct {
	Prompt string
	// Marker is matched against the PreToolUse tool input.
	Marker string
	// SideEffect is the absolute file the blocked tool would create.
	SideEffect string
}

// HookEvent is one request the stand-in ingress received.
type HookEvent struct {
	Path           string `json:"path"`
	Event          string `json:"event,omitempty"`
	Authorized     bool   `json:"authorized"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
	Blocked        bool   `json:"blocked,omitempty"`
}

// HookFireRun is one harness run.
type HookFireRun struct {
	Scenario          string      `json:"scenario"`
	ExitCode          int         `json:"exit_code"`
	Events            []HookEvent `json:"events"`
	OTLPRequests      int         `json:"otlp_requests"`
	SideEffectPresent *bool       `json:"side_effect_present,omitempty"`
	Output            string      `json:"output"`
}

// HookFireResult is the outcome of HookFireProbe.
type HookFireResult struct {
	Runs []HookFireRun `json:"runs"`
}

// VerifyHooks runs the hook-fire probe against the recorded image of c and
// persists the verdict under the store lock: HookFireVerified is set when
// every required hook fired, and cleared when the probe proves the image
// does not enforce (ErrHooksNotFired). Store.Current selects only verified
// images. The probe runs against the recorded image ID, and the verdict is
// stored only while the record still names that image, so a concurrent
// rebuild is never marked verified by a probe of its predecessor. A probe
// that could not run leaves the record unchanged.
func (b *Builder) VerifyHooks(ctx context.Context, c *Context, opts HookFireOptions) (Record, HookFireResult, error) {
	rec, ok, err := b.Store.Get(c.Tag)
	if err != nil {
		return Record{}, HookFireResult{}, err
	}
	if !ok || rec.ContentHash != c.ContentHash {
		return Record{}, HookFireResult{}, fmt.Errorf("openshell image: %s has no build record for content %s; build it first", c.Tag, c.ContentHash)
	}
	id, err := b.imageID(ctx, c.Tag)
	if err != nil {
		return rec, HookFireResult{}, err
	}
	if id != rec.ImageID {
		return rec, HookFireResult{}, fmt.Errorf("openshell image: %s now names %s, not the recorded %s; rebuild it", c.Tag, id, rec.ImageID)
	}
	res, probeErr := b.hookFireProbe(ctx, c, rec.ImageID, opts)
	if probeErr != nil && !errors.Is(probeErr, ErrHooksNotFired) {
		return rec, res, probeErr
	}
	verified := probeErr == nil
	verifiedAt := b.now().UTC()
	updated, err := b.Store.update(c.Tag, func(r *Record) error {
		if r.ImageID != rec.ImageID || r.ContentHash != rec.ContentHash {
			return fmt.Errorf("openshell image: %s was rebuilt while its hooks were probed; verify the new image", c.Tag)
		}
		r.HookFireVerified = verified
		r.HookFireVerifiedAt = time.Time{}
		if verified {
			r.HookFireVerifiedAt = verifiedAt
		}
		return nil
	})
	if err != nil {
		return rec, res, errors.Join(probeErr, err)
	}
	return updated, res, probeErr
}

// HookFireProbe runs the image's harness against the caller's mock LLM and
// verifies that every required hook fires with the sandbox token and an
// idempotency key, and that a blocked tool call has no side effect. It only
// reports: VerifyHooks is the path that records the verdict.
func (b *Builder) HookFireProbe(ctx context.Context, c *Context, opts HookFireOptions) (HookFireResult, error) {
	return b.hookFireProbe(ctx, c, c.Tag, opts)
}

// hookFireProbe runs the probe against image ref (a tag or image ID).
func (b *Builder) hookFireProbe(ctx context.Context, c *Context, ref string, opts HookFireOptions) (HookFireResult, error) {
	required, ok := requiredHookEvents[c.Spec.Harness.Name]
	if !ok {
		return HookFireResult{}, fmt.Errorf("openshell image: no hook-fire contract for %s", c.Spec.Harness.Name)
	}
	if strings.TrimSpace(opts.Prompt) == "" {
		return HookFireResult{}, errors.New("openshell image: hook-fire probe needs a prompt the mock answers with a tool call")
	}
	if opts.Block != nil && (opts.Block.Marker == "" || opts.Block.SideEffect == "" || opts.Block.Prompt == "") {
		return HookFireResult{}, errors.New("openshell image: block scenario needs a prompt, marker and side effect")
	}
	host := opts.SinkHost
	if host == "" {
		host = DefaultHookFireSinkHost
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return HookFireResult{}, fmt.Errorf("openshell image: hook-fire sink host %q must be a loopback address", host)
	}
	token, err := randomHex(24)
	if err != nil {
		return HookFireResult{}, err
	}
	sink := &hookSink{token: "dcprobe-" + token}
	listener, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(c.Spec.IngressPort)))
	if err != nil {
		return HookFireResult{}, fmt.Errorf("openshell image: hook-fire sink: %w", err)
	}
	server := &http.Server{Handler: sink, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = server.Serve(listener) }()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	var result HookFireResult
	allow, err := b.hookFireRun(ctx, c, ref, opts, host, sink, "allow", opts.Prompt, nil)
	result.Runs = append(result.Runs, allow)
	if err != nil {
		return result, err
	}
	var problems []string
	seen := map[string]bool{}
	for _, ev := range allow.Events {
		if !ev.Authorized {
			problems = append(problems, fmt.Sprintf("%s %s arrived without the sandbox token", ev.Path, ev.Event))
			continue
		}
		if strings.HasSuffix(ev.Path, "/hook") && ev.IdempotencyKey == "" {
			problems = append(problems, fmt.Sprintf("%s %s carried no idempotency key", ev.Path, ev.Event))
		}
		seen[ev.Event] = true
	}
	for _, event := range required {
		if !seen[event] {
			problems = append(problems, "hook "+event+" never fired")
		}
	}
	if opts.Block != nil {
		blocked, err := b.hookFireRun(ctx, c, ref, opts, host, sink, "block", opts.Block.Prompt, opts.Block)
		result.Runs = append(result.Runs, blocked)
		if err != nil {
			return result, err
		}
		denied := false
		for _, ev := range blocked.Events {
			denied = denied || ev.Blocked
		}
		switch {
		case !denied:
			problems = append(problems, "the block scenario never reached a PreToolUse carrying the marker")
		case blocked.SideEffectPresent == nil || *blocked.SideEffectPresent:
			problems = append(problems, "the blocked tool call still ran ("+opts.Block.SideEffect+" exists)")
		}
	}
	if len(problems) > 0 {
		return result, fmt.Errorf("openshell image %s hook-fire probe failed: %w: %s", c.Tag, ErrHooksNotFired, strings.Join(problems, "; "))
	}
	return result, nil
}

func (b *Builder) hookFireRun(
	ctx context.Context, c *Context, ref string, opts HookFireOptions, host string, sink *hookSink,
	scenario, prompt string, block *BlockScenario,
) (HookFireRun, error) {
	run := HookFireRun{Scenario: scenario}
	argv, err := c.Spec.Harness.LaunchArgv(harness.LaunchOptions{Mode: harness.Headless, Yolo: true, Prompt: prompt, Args: opts.Args})
	if err != nil {
		return run, err
	}
	sideEffect := ""
	if block != nil {
		sideEffect = block.SideEffect
		if !safePathRE.MatchString(sideEffect) {
			return run, fmt.Errorf("openshell image: side effect %q must be a plain absolute path", sideEffect)
		}
	}
	quoted := make([]string, len(argv))
	for i, a := range argv {
		quoted[i] = shQuote(a)
	}
	script := "cd " + shQuote(connector.SandboxHomeDir) + " || exit 97\n"
	if sideEffect != "" {
		script += "rm -f " + shQuote(sideEffect) + "\n"
	}
	script += strings.Join(quoted, " ") + " </dev/null >/tmp/dc-hookfire.out 2>&1\n" +
		"echo \"::rc=$?\"\n"
	if sideEffect != "" {
		script += "if [ -e " + shQuote(sideEffect) + " ]; then echo '::side-effect=present'; else echo '::side-effect=absent'; fi\n"
	}
	script += "echo '::output-begin'; tail -c 4000 /tmp/dc-hookfire.out; echo; echo '::output-end'\n"

	suffix, err := randomHex(4)
	if err != nil {
		return run, err
	}
	prefix := opts.ContainerPrefix
	if prefix == "" {
		prefix = "defenseclaw-hookfire"
	}
	name := prefix + "-" + c.Spec.Harness.Name + "-" + scenario + "-" + suffix
	args := []string{"run", "--rm", "--name", name, "--network", "host",
		"--add-host", connector.SandboxIngressHost + ":" + host,
		"--user", strconv.Itoa(c.Spec.UID) + ":" + strconv.Itoa(c.Spec.GID),
		"-e", "HOME=" + connector.SandboxHomeDir,
		"-e", connector.SandboxTokenEnv + "=" + sink.token,
	}
	env := map[string]string{}
	for key, value := range c.Artifacts.Env {
		env[key] = value
	}
	for key, value := range opts.Env {
		env[key] = value
	}
	keys := make([]string, 0, len(env))
	for key := range env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		args = append(args, "-e", key+"="+env[key])
	}
	args = append(args, "--entrypoint", "/bin/bash", ref, "-c", script)

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Minute
	}
	sink.begin(block)
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	out, err := output(runCtx, b.Docker, nil, args...)
	cancel()
	// Hooks such as SessionEnd may still be in flight when the harness
	// exits; give the relay a moment before reading the log.
	time.Sleep(500 * time.Millisecond)
	run.Events, run.OTLPRequests = sink.end()
	run.Output = out
	if err != nil {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		_, _ = output(cleanupCtx, b.Docker, nil, "rm", "-f", name)
		cleanupCancel()
		return run, fmt.Errorf("openshell image: hook-fire %s run: %w", scenario, err)
	}
	for _, line := range strings.Split(out, "\n") {
		switch {
		case strings.HasPrefix(line, "::rc="):
			run.ExitCode, _ = strconv.Atoi(strings.TrimPrefix(line, "::rc="))
		case line == "::side-effect=present":
			present := true
			run.SideEffectPresent = &present
		case line == "::side-effect=absent":
			present := false
			run.SideEffectPresent = &present
		}
	}
	return run, nil
}

// hookSink stands in for the DefenseClaw hook ingress: it authenticates the
// bearer, records every hook, notify and OTLP request, and answers with
// DefenseClaw-shaped verdicts.
type hookSink struct {
	token  string
	mu     sync.Mutex
	events []HookEvent
	otlp   int
	block  *BlockScenario
}

func (s *hookSink) begin(block *BlockScenario) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events, s.otlp, s.block = nil, 0, block
}

func (s *hookSink) end() ([]HookEvent, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]HookEvent(nil), s.events...), s.otlp
}

func (s *hookSink) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	authorized := r.Header.Get("Authorization") == "Bearer "+s.token
	ev := HookEvent{Path: r.URL.Path, Authorized: authorized, IdempotencyKey: r.Header.Get("X-DefenseClaw-Hook-Idempotency-Key")}
	var payload map[string]json.RawMessage
	_ = json.Unmarshal(body, &payload)
	if name := r.Header.Get("X-DefenseClaw-Hook-Event"); name != "" {
		ev.Event = name
	} else if raw, ok := payload["hook_event_name"]; ok {
		_ = json.Unmarshal(raw, &ev.Event)
	}

	s.mu.Lock()
	block := s.block
	if strings.HasPrefix(r.URL.Path, "/v1/") {
		if authorized {
			s.otlp++
		}
		s.mu.Unlock()
		if !authorized {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{}"))
		return
	}
	if authorized && block != nil && ev.Event == "PreToolUse" && bytes.Contains(payload["tool_input"], []byte(block.Marker)) {
		ev.Blocked = true
	}
	s.events = append(s.events, ev)
	s.mu.Unlock()

	if !authorized {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if !ev.Blocked {
		_, _ = w.Write([]byte(`{"action":"allow"}`))
		return
	}
	reason := "Blocked by the DefenseClaw hook-fire probe"
	deny := map[string]interface{}{
		"hookSpecificOutput": map[string]interface{}{
			"hookEventName":            "PreToolUse",
			"permissionDecision":       "deny",
			"permissionDecisionReason": reason,
		},
	}
	resp, _ := json.Marshal(map[string]interface{}{
		"action":             "block",
		"reason":             reason,
		"claude_code_output": deny,
		"codex_output":       deny,
	})
	_, _ = w.Write(resp)
}

func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("openshell image: randomness: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
