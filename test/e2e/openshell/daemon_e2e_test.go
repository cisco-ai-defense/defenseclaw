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

//go:build openshell_integration && (linux || darwin)

// Package openshelle2e is the live end-to-end test of the DefenseClaw
// sandbox daemon. It builds the gateway, starts it with openshell.enabled in
// a private data directory, and drives one Claude Code sandbox through the
// daemon's REST API against the local OpenShell gateway, with the mock
// Anthropic server (mock_anthropic.py) standing in for the model:
//
//   - create (overlay image build and hook-fire verification when missing),
//     then a tool call whose hook reaches the sandbox ingress;
//   - a harmless marker command that a test-only guardrail rule
//     (testdata/guardrail-e2e-marker.yaml) blocks, denied by the hook with a
//     plain reason (rule, title, what to do instead) that reaches the model,
//     last_blocked and the activity feed;
//   - hook tamper: a PostToolUse for a harmless marker call whose PreToolUse
//     never reached DefenseClaw raises a hook_tamper finding; the open pack
//     alerts and keeps the sandbox running;
//   - egress through the DefenseClaw proxy: an allowed host, a blocklisted
//     host, a sandbox-scoped unblock, and a direct connection OpenShell
//     denies until triage approves the proposal;
//   - stop, start (with a rotated ingress binding), review, undo;
//   - hook tamper in a second sandbox whose custom pack sets
//     hooks.on_tamper: stop, which DefenseClaw stops;
//   - delete.
//
// Opt-in, on a host with OpenShell 0.1.x, Docker, git, Python 3 and the
// openshell CLI on PATH:
//
//	DEFENSECLAW_E2E_WORK_DIR=/data/dc-openshell/scratch/e2e \
//	DEFENSECLAW_E2E_PREFIX=f2a-e2e \
//	go test -tags openshell_integration ./test/e2e/openshell/ -run TestSandboxDaemon -v -timeout 60m
//
// Every OpenShell object the test creates is named after
// DEFENSECLAW_E2E_PREFIX (default dc-e2e) and deleted at the end, as are the
// provider profiles the daemon imported for it and, unless
// DEFENSECLAW_E2E_KEEP_IMAGE=1, the overlay image it built. The work
// directory keeps the daemon and mock logs of the last run.
package openshelle2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/manager"
	"github.com/defenseclaw/defenseclaw/internal/openshell/profiles"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

const (
	blockedMarkerFile = "/tmp/dce2e-blocked.txt"
	allowedMarkerFile = "/tmp/dce2e-allowed.txt"
	// allowedHost answers through the egress proxy in the open pack;
	// blockedHost is on the built-in exfiltration blocklist (a webhook
	// catcher); directHost is reached without the proxy, which OpenShell
	// denies until triage approves the proposal.
	allowedHost = "example.org"
	blockedHost = "webhook.site"
	directHost  = "www.example.com"
	// stopSuffix names the second sandbox and its custom pack, a copy of
	// the open pack with hooks.on_tamper: stop.
	stopSuffix = "-stop"
	// blockedReason is the plain reason of the marker rule's denial.
	blockedReason = "Blocked by DefenseClaw rule E2E-SANDBOX-MARKER: E2E sandbox marker command."
	// mockKey is what the sandbox's ANTHROPIC_API_KEY binding carries. The
	// mock never checks it; it only proves the credential path.
	mockKey = "dce2e-mock-key-not-a-secret"
)

type env struct {
	// t is the running step's test; root is TestSandboxDaemon's, which
	// owns every cleanup.
	t       *testing.T
	root    *testing.T
	repo    string
	work    string
	prefix  string
	apiPort int
	mock    int
	token   string
	project string
	readme  string
	// stopProject is the second sandbox's project.
	stopProject string

	gw  openshell.Client
	api *sandboxapi.Client

	daemon *exec.Cmd
	mockPx *exec.Cmd

	profilesBefore map[string]bool
	imagesBefore   map[string]bool
}

func TestSandboxDaemon(t *testing.T) {
	work := os.Getenv("DEFENSECLAW_E2E_WORK_DIR")
	if work == "" {
		t.Skip("set DEFENSECLAW_E2E_WORK_DIR to run the live sandbox daemon test")
	}
	e := &env{
		t: t, root: t, prefix: envOr("DEFENSECLAW_E2E_PREFIX", "dc-e2e"),
		apiPort: envInt(t, "DEFENSECLAW_E2E_API_PORT", 28970),
		mock:    envInt(t, "DEFENSECLAW_E2E_MOCK_PORT", 28921),
	}
	if !openshell.ValidSandboxName(e.prefix) {
		t.Fatalf("DEFENSECLAW_E2E_PREFIX %q is not a valid sandbox name", e.prefix)
	}
	e.repo = repoRoot(t)
	e.work = filepath.Join(work, e.prefix)

	e.step("setup", e.setup)
	e.step("start daemon", e.startDaemon)
	sb := e.stepValue("create", e.create)
	e.step("hook reaches the ingress", func() { e.hookReachesIngress(sb) })
	e.step("DefenseClaw blocks the marker command", func() { e.blockedToolCall(sb) })
	e.step("hook tamper raises an alert", func() { e.tamperAlert(sb) })
	e.step("egress through the proxy", func() { e.egressThroughProxy(sb) })
	e.step("direct connection and triage", func() { e.directConnection(sb) })
	e.step("stop and start", func() { e.stopStart(sb) })
	e.step("review and undo", func() { e.reviewUndo(sb) })
	e.step("hook tamper stops the sandbox", e.tamperStop)
	e.step("delete", func() { e.deleteSandbox(sb) })
}

// step runs one stage as a subtest and stops the test at the first failure
// (later stages depend on earlier ones; cleanups still run).
func (e *env) step(name string, fn func()) {
	e.t.Helper()
	if !e.t.Run(name, func(t *testing.T) {
		prev := e.t
		e.t = t
		defer func() { e.t = prev }()
		fn()
	}) {
		e.t.FailNow()
	}
}

func (e *env) stepValue(name string, fn func() *sandboxapi.Sandbox) *sandboxapi.Sandbox {
	var out *sandboxapi.Sandbox
	e.step(name, func() { out = fn() })
	return out
}

// ---- setup -----------------------------------------------------------------

func (e *env) setup() {
	t := e.t
	for _, port := range []int{e.apiPort, e.apiPort + 1, e.apiPort + 2, e.apiPort + 10, e.mock} {
		l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			t.Fatalf("port %d is in use; pick other ports with DEFENSECLAW_E2E_API_PORT/_MOCK_PORT: %v", port, err)
		}
		_ = l.Close()
	}
	if err := os.RemoveAll(e.work); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"bin", "home", "dc", "logs", "proj"} {
		if err := os.MkdirAll(filepath.Join(e.work, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}

	reg, err := openshell.Discover(openshell.DiscoverOptions{Gateway: os.Getenv("DEFENSECLAW_OPENSHELL_GATEWAY")})
	if err != nil {
		t.Fatalf("discover the OpenShell gateway: %v", err)
	}
	gw, err := openshell.Dial(reg, openshell.ClientOptions{})
	if err != nil {
		t.Fatalf("dial the OpenShell gateway: %v", err)
	}
	e.gw = gw
	e.root.Cleanup(func() { _ = gw.Close() })
	ctx := e.ctx(time.Minute)
	e.sweep(ctx) // leftovers of an aborted run carry our prefix

	e.profilesBefore = map[string]bool{}
	list, err := gw.ListProfiles(ctx)
	if err != nil {
		t.Fatalf("list profiles: %v", err)
	}
	for _, p := range list {
		e.profilesBefore[p.ID] = true
	}
	if e.imagesBefore, err = sandboxImages(); err != nil {
		t.Fatal(err)
	}
	e.root.Cleanup(e.removeImages)
	e.root.Cleanup(e.deleteProfiles)
	e.root.Cleanup(func() { e.sweep(context.Background()) })

	// The gateway binary.
	bin := filepath.Join(e.work, "bin", "defenseclaw-gateway")
	e.run(e.repo, "go", "build", "-o", bin, "./cmd/defenseclaw")

	// Policies: the repository's, plus the test-only marker rule in the
	// default guardrail rule pack.
	dc := filepath.Join(e.work, "dc")
	policies := filepath.Join(dc, "policies")
	if err := os.CopyFS(policies, os.DirFS(filepath.Join(e.repo, "policies"))); err != nil {
		t.Fatalf("copy policies: %v", err)
	}
	// The sandbox packs are built in; a copy would be read as custom packs
	// (openshell.pack_dir defaults to <data_dir>/policies/sandbox).
	if err := os.RemoveAll(filepath.Join(policies, "sandbox")); err != nil {
		t.Fatal(err)
	}
	rule, err := os.ReadFile(filepath.Join(e.repo, "test", "e2e", "openshell", "testdata", "guardrail-e2e-marker.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(policies, "guardrail", "default", "rules", "e2e-marker.yaml"), rule, 0o600)
	// The second sandbox's custom pack: the open pack with hooks.on_tamper:
	// stop.
	open, err := os.ReadFile(filepath.Join(e.repo, "policies", "sandbox", "open", "pack.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	stopPack := strings.Replace(string(open), "\nname: open\n", "\nname: "+e.prefix+stopSuffix+"\n", 1)
	stopPack = strings.Replace(stopPack, "on_tamper: alert", "on_tamper: stop", 1)
	if !strings.Contains(stopPack, "name: "+e.prefix+stopSuffix) || !strings.Contains(stopPack, "on_tamper: stop") {
		t.Fatal("the open pack no longer has the name and hooks.on_tamper lines the stop pack rewrites")
	}
	writeFile(t, filepath.Join(policies, "sandbox", e.prefix+stopSuffix, "pack.yaml"), []byte(stopPack), 0o600)

	// The project: a git repository with a masked secret-looking file.
	e.project = filepath.Join(e.work, "proj", e.prefix+"-proj")
	e.readme = "hello from the dce2e project\n"
	writeFile(t, filepath.Join(e.project, "README.md"), []byte(e.readme), 0o644)
	writeFile(t, filepath.Join(e.project, ".env"), []byte("DCE2E_PLACEHOLDER=not-a-secret\n"), 0o600)
	git := func(args ...string) {
		e.run(e.project, "git", append([]string{"-c", "user.name=dce2e", "-c", "user.email=dce2e@example.invalid"}, args...)...)
	}
	git("init", "-q")
	git("add", "README.md")
	git("commit", "-q", "-m", "initial")
	e.stopProject = filepath.Join(e.work, "proj", e.prefix+stopSuffix+"-proj")
	writeFile(t, filepath.Join(e.stopProject, "README.md"), []byte(e.readme), 0o644)

	// The daemon configuration (schema v8). gateway.port points the
	// OpenClaw client at a port nothing listens on.
	cfg := fmt.Sprintf(`config_version: 8
data_dir: %s
gateway:
  host: 127.0.0.1
  port: %d
  api_bind: 127.0.0.1
  api_port: %d
openshell:
  enabled: true
  harnesses: [claudecode]
  approvals:
    debounce_ms: 500
`, dc, e.apiPort+10, e.apiPort)
	writeFile(t, filepath.Join(dc, "config.yaml"), []byte(cfg), 0o600)

	var raw [24]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	e.token = hex.EncodeToString(raw[:])
	e.api = sandboxapi.NewClient("http://127.0.0.1:"+strconv.Itoa(e.apiPort), e.token)

	// The mock model.
	mockLog := filepath.Join(e.work, "logs", "mock.jsonl")
	e.mockPx = e.spawn("mock", "python3", filepath.Join(e.repo, "test", "e2e", "openshell", "mock_anthropic.py"),
		"--host", "127.0.0.1", "--port", strconv.Itoa(e.mock), "--quiet", "--log", mockLog,
		"--script", filepath.Join(e.repo, "test", "e2e", "openshell", "scenarios", "daemon-claude.json"))
	e.root.Cleanup(func() { stop(e.mockPx) })
	waitFor(t, 20*time.Second, "the mock model", func() error {
		resp, err := http.Get("http://127.0.0.1:" + strconv.Itoa(e.mock) + "/v1/models")
		if err == nil {
			resp.Body.Close()
		}
		return err
	})
}

func (e *env) startDaemon() {
	t := e.t
	home := filepath.Join(e.work, "home")
	real, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	xdg := os.Getenv("XDG_CONFIG_HOME")
	if xdg == "" {
		xdg = filepath.Join(real, ".config") // the OpenShell registration
	}
	var environ []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(k, "DEFENSECLAW_") || strings.HasPrefix(k, "OPENCLAW_") || k == "HOME" || k == "XDG_CONFIG_HOME" {
			continue
		}
		environ = append(environ, kv)
	}
	environ = append(environ, "HOME="+home, "XDG_CONFIG_HOME="+xdg,
		"DEFENSECLAW_HOME="+filepath.Join(e.work, "dc"), "DEFENSECLAW_GATEWAY_TOKEN="+e.token)
	e.daemon = e.spawnEnv("daemon", environ, filepath.Join(e.work, "bin", "defenseclaw-gateway"))
	e.root.Cleanup(func() { stop(e.daemon) })

	waitFor(t, 90*time.Second, "the daemon API", func() error {
		resp, err := http.Get("http://127.0.0.1:" + strconv.Itoa(e.apiPort) + "/health")
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("health %d", resp.StatusCode)
		}
		return nil
	})
	var st *sandboxapi.Status
	waitFor(t, 90*time.Second, "the sandbox subsystem", func() error {
		var err error
		st, err = e.api.Status(e.ctx(10 * time.Second))
		switch {
		case err != nil:
			return err
		case !st.Enabled || !st.Available:
			return fmt.Errorf("status enabled=%t available=%t: %s", st.Enabled, st.Available, st.Reason)
		case st.Gateway == nil || !st.Gateway.Healthy:
			return errors.New("the OpenShell gateway is not connected yet")
		}
		return nil
	})
	t.Logf("sandbox subsystem: gateway %s %s, ingress %s, egress %s, pack %s", st.Gateway.Name, st.Gateway.Version,
		st.IngressAddr, st.EgressAddr, st.Pack)

	// CSRF: a mutating request without the client header is refused.
	req, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:"+strconv.Itoa(e.apiPort)+sandboxapi.PathEgressUnblock,
		strings.NewReader(`{"host":"example.net","sandbox":"x"}`))
	req.Header.Set("Authorization", "Bearer "+e.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("mutating request without %s = %d, want 403", sandboxapi.ClientHeader, resp.StatusCode)
	}
	// Auth: a wrong token is refused.
	if _, err := sandboxapi.NewClient(e.api.BaseURL, "wrong").List(e.ctx(10 * time.Second)); err == nil {
		t.Fatal("a wrong token listed sandboxes")
	}
}

// ---- lifecycle ---------------------------------------------------------------

func (e *env) create() *sandboxapi.Sandbox {
	t := e.t
	e.root.Cleanup(e.restDelete) // runs before the daemon stops
	started := time.Now()
	sb, err := e.api.Create(e.ctx(40*time.Minute), sandboxapi.CreateRequest{
		Name: e.prefix, Harness: "claudecode", Project: e.project,
		Credentials: []sandboxapi.CredentialBinding{{
			Name: "ANTHROPIC_API_KEY", Value: mockKey, Host: "host.openshell.internal", Port: e.mock,
		}},
		Env: map[string]string{"ANTHROPIC_BASE_URL": "http://host.openshell.internal:" + strconv.Itoa(e.mock)},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Logf("created %s in %s: phase=%s pack=%s profile=%s mode=%s image=%s contract=%s tier=%s",
		sb.Name, time.Since(started).Round(time.Second), sb.Phase, sb.Pack, sb.Profile, sb.WorkdirMode, sb.Image,
		sb.HookContract, sb.TamperTier)
	if sb.Phase != "ready" || sb.WorkdirMode != "mount" || sb.Workdir == "" || sb.ID == "" {
		t.Fatalf("created sandbox = %+v", sb)
	}
	if sb.Workspace == nil || !slices.Contains(sb.Workspace.Hidden, ".env") {
		t.Fatalf("workspace summary = %+v, want .env hidden", sb.Workspace)
	}
	got, err := e.gw.GetSandbox(e.ctx(30*time.Second), sb.Name)
	if err != nil {
		t.Fatalf("OpenShell has no sandbox %s: %v", sb.Name, err)
	}
	if got.Labels[manager.LabelManaged] != "true" || got.Labels[manager.LabelOwner] == "" || got.Labels[manager.LabelHarness] != "claudecode" {
		t.Fatalf("sandbox labels = %v, want the io.defenseclaw/* management labels", got.Labels)
	}
	if n := len(e.prefixedProviders(e.ctx(30 * time.Second))); n < 2 {
		t.Fatalf("providers named after the sandbox = %d, want the ingress and the credential binding", n)
	}
	list, err := e.api.List(e.ctx(30 * time.Second))
	if err != nil || !slices.ContainsFunc(list, func(s sandboxapi.Sandbox) bool { return s.Name == sb.Name }) {
		t.Fatalf("list = %v, %v", names(list), err)
	}
	// A probe exec first: OpenShell 0.1.1 can hang the first exec after a
	// start, and the harness run must not be the one retried.
	e.exec(sb, 30*time.Second, true, "true")
	return sb
}

func (e *env) hookReachesIngress(sb *sandboxapi.Sandbox) {
	t := e.t
	before := e.get(sb.Name).Hooks
	out := e.harness(sb, "Write the allowed marker file.")
	if got := e.exec(sb, 30*time.Second, true, "cat", allowedMarkerFile); strings.TrimSpace(got.stdout) != "dce2e-allowed" {
		t.Fatalf("allowed tool call left %q in %s (harness said %q)", got.stdout, allowedMarkerFile, out)
	}
	after := e.waitHooks(sb.Name, func(h sandboxapi.HookCoverage) bool {
		return h.HookRequests > before.HookRequests && h.ToolCalls > before.ToolCalls && !h.LastHookAt.IsZero()
	})
	t.Logf("hooks: requests %d, tool calls %d, last hook %s, last OTLP %s", after.HookRequests, after.ToolCalls,
		after.LastHookAt.Format(time.RFC3339), after.LastOTLPAt.Format(time.RFC3339))
	messages, substituted, placeholder := mockAuth(filepath.Join(e.work, "logs", "mock.jsonl"))
	if messages == 0 || substituted == 0 || placeholder != 0 {
		t.Fatalf("mock model: %d Messages calls, %d with the key substituted, %d with a placeholder", messages, substituted, placeholder)
	}
	t.Logf("mock model: %d Messages calls, every key substituted by OpenShell", messages)
}

func (e *env) blockedToolCall(sb *sandboxapi.Sandbox) {
	t := e.t
	var (
		mu      sync.Mutex
		stream  []sandboxapi.ActivityEvent
		ctx, cn = context.WithCancel(context.Background())
		done    = make(chan struct{})
	)
	go func() { // the SSE feed, followed live
		defer close(done)
		_ = e.api.Activity(ctx, sandboxapi.ActivityQuery{Sandbox: sb.Name, Follow: true}, func(ev sandboxapi.ActivityEvent) error {
			mu.Lock()
			stream = append(stream, ev)
			mu.Unlock()
			return nil
		})
	}()
	defer func() { cn(); <-done }()

	before := e.get(sb.Name).Hooks
	out := e.harness(sb, "Run the DCE2E-DENY scenario.")
	if res := e.exec(sb, 30*time.Second, true, "test", "-e", blockedMarkerFile); res.code == 0 {
		t.Fatalf("the blocked command ran: %s exists (harness said %q)", blockedMarkerFile, out)
	}
	after := e.waitHooks(sb.Name, func(h sandboxapi.HookCoverage) bool { return h.ToolBlocked > before.ToolBlocked })
	// LastBlocked is the plain reason: the rule, its title and what to do
	// instead, never a redaction placeholder.
	if !strings.HasPrefix(after.LastBlocked, blockedReason) || strings.Contains(after.LastBlocked, "<redacted") {
		t.Fatalf("last blocked reason = %q, want it to start with %q", after.LastBlocked, blockedReason)
	}
	var blocked sandboxapi.ActivityEvent
	waitFor(t, 30*time.Second, "tool.blocked on the SSE feed", func() error {
		mu.Lock()
		defer mu.Unlock()
		for _, ev := range stream {
			if ev.Kind == sandboxapi.ActivityToolBlocked && ev.Tool == "Bash" {
				blocked = ev
				return nil
			}
		}
		return fmt.Errorf("%d events so far", len(stream))
	})
	if !strings.HasPrefix(blocked.Reason, blockedReason) || !strings.Contains(blocked.Message, blockedReason) {
		t.Fatalf("tool.blocked event = %+v, want the plain reason", blocked)
	}
	// The model was told the same reason in the tool result.
	var told string
	for _, r := range mockToolResults(filepath.Join(e.work, "logs", "mock.jsonl")) {
		if strings.Contains(r, "E2E-SANDBOX-MARKER") {
			told = r
		}
	}
	if !strings.Contains(told, blockedReason) || strings.Contains(told, "<redacted") {
		t.Fatalf("the model's tool result for the denial = %q, want %q", told, blockedReason)
	}
	t.Logf("blocked: tool_blocked %d → %d; the model was told %q; harness said %q",
		before.ToolBlocked, after.ToolBlocked, truncate(told, 200), out)
}

// tamperAlert: in the open pack (hooks.on_tamper: alert) a tool call whose
// PreToolUse never reached DefenseClaw raises a hook_tamper finding on the
// activity feed and leaves the sandbox running.
func (e *env) tamperAlert(sb *sandboxapi.Sandbox) {
	t := e.t
	before := e.get(sb.Name).Hooks
	// The harness's own calls so far (an allowed one, a denied one) paired
	// up: none of them was taken for tamper.
	if before.Tampered != 0 {
		t.Fatalf("real harness traffic raised hook tamper: %+v", before)
	}
	id := e.tamperHook(sb)
	ev := e.waitActivity(sb.Name, "hook_tamper on the feed", func(ev sandboxapi.ActivityEvent) bool {
		return ev.Kind == sandboxapi.ActivityFinding && ev.Reason == "hook_tamper" && ev.Tool == "Bash"
	})
	if ev.Severity != "HIGH" || !strings.Contains(ev.Message, "keeps running") {
		t.Fatalf("hook_tamper event = %+v, want a HIGH alert that keeps the sandbox running", ev)
	}
	after := e.waitHooks(sb.Name, func(h sandboxapi.HookCoverage) bool { return h.Tampered > before.Tampered })
	// Give a wrong stop time to happen, then prove the sandbox still works.
	time.Sleep(5 * time.Second)
	if got := e.get(sb.Name); got.Phase != "ready" {
		t.Fatalf("the open pack stopped the sandbox on hook tamper: phase %s", got.Phase)
	}
	e.exec(sb, 30*time.Second, true, "true")
	e.noTamperTelemetryErrors()
	t.Logf("hook tamper (alert): %s, tampered %d → %d, %q", id, before.Tampered, after.Tampered, ev.Message)
}

// tamperStop: a sandbox whose pack sets hooks.on_tamper: stop is stopped on
// hook tamper.
func (e *env) tamperStop() {
	t := e.t
	// The first sandbox's later harness runs (after a restart, an edit)
	// raised no tamper of their own.
	if h := e.get(e.prefix).Hooks; h.Tampered != 1 {
		t.Fatalf("%s hook coverage = %+v, want exactly the one simulated tamper", e.prefix, h)
	}
	name := e.prefix + stopSuffix
	e.root.Cleanup(func() { e.restDeleteName(name) })
	sb, err := e.api.Create(e.ctx(20*time.Minute), sandboxapi.CreateRequest{
		Name: name, Harness: "claudecode", Project: e.stopProject, Pack: name,
	})
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	if sb.Phase != "ready" || sb.Pack != name {
		t.Fatalf("created %s = phase %s pack %s", name, sb.Phase, sb.Pack)
	}
	e.exec(sb, 30*time.Second, true, "true")
	id := e.tamperHook(sb)
	ev := e.waitActivity(name, "hook_tamper on the feed", func(ev sandboxapi.ActivityEvent) bool {
		return ev.Kind == sandboxapi.ActivityFinding && ev.Reason == "hook_tamper" && ev.Tool == "Bash"
	})
	if !strings.Contains(ev.Message, "stopping the sandbox") {
		t.Fatalf("hook_tamper event = %+v, want the stop", ev)
	}
	waitFor(t, 5*time.Minute, "DefenseClaw to stop "+name, func() error {
		if got := e.get(name); got.Phase != "stopped" {
			return fmt.Errorf("phase %s", got.Phase)
		}
		return nil
	})
	if log := e.daemonLog(); !strings.Contains(log, "hook tamper: stopped "+name) {
		t.Fatalf("the daemon log does not record the tamper stop of %s", name)
	}
	e.noTamperTelemetryErrors()
	if res, err := e.api.Delete(e.ctx(5*time.Minute), name, sandboxapi.DeleteRequest{}); err != nil || !res.Deleted {
		t.Fatalf("delete %s = %+v, %v", name, res, err)
	}
	waitFor(t, 3*time.Minute, "OpenShell to forget "+name, func() error {
		_, err := e.gw.GetSandbox(e.ctx(20*time.Second), name)
		if openshell.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("get sandbox: %v", err)
	})
	t.Logf("hook tamper (stop): %s stopped %s", id, name)
}

// tamperHook runs the sandbox's Claude Code hook by hand with a PostToolUse
// for a harmless marker call that never had a PreToolUse: what DefenseClaw
// sees when a workload kills the PreToolUse hook and the tool runs anyway.
// It returns the call's tool_use_id.
func (e *env) tamperHook(sb *sandboxapi.Sandbox) string {
	t := e.t
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	id := "toolu_dce2e_tamper_" + hex.EncodeToString(raw[:])
	payload, err := json.Marshal(map[string]any{
		"session_id": "dce2e-tamper-" + hex.EncodeToString(raw[:4]), "transcript_path": "/tmp/dce2e-tamper.jsonl",
		"cwd": sb.Workdir, "hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_use_id": id,
		"tool_input":    map[string]any{"command": "echo DCE2E-TAMPER-MARKER", "description": "Harmless tamper marker"},
		"tool_response": map[string]any{"stdout": "DCE2E-TAMPER-MARKER\n", "stderr": "", "interrupted": false, "isImage": false},
	})
	if err != nil {
		t.Fatal(err)
	}
	// The payload travels as an argument: exec stdin must stay closed.
	script := `printf '%s' "$1" > /tmp/dce2e-tamper.json && "$2" < /tmp/dce2e-tamper.json`
	res := e.exec(sb, time.Minute, false, "sh", "-c", script, "sh", string(payload), path.Join(connector.SandboxHookDir, "claude-code-hook.sh"))
	if res.code != 0 {
		t.Fatalf("the PostToolUse hook exited %d: %s", res.code, truncate(res.stdout, 300))
	}
	return id
}

// noTamperTelemetryErrors fails when the daemon could not record a
// hook_tamper finding.
func (e *env) noTamperTelemetryErrors() {
	if log := e.daemonLog(); strings.Contains(log, "hook tamper: record the finding") {
		e.t.Fatal("the daemon failed to record a hook_tamper finding (see logs/daemon.log)")
	}
}

func (e *env) daemonLog() string {
	raw, err := os.ReadFile(filepath.Join(e.work, "logs", "daemon.log"))
	if err != nil {
		e.t.Fatal(err)
	}
	return string(raw)
}

func (e *env) egressThroughProxy(sb *sandboxapi.Sandbox) {
	t := e.t
	before := e.get(sb.Name).Egress
	if c := e.proxyCurl(sb, "https://"+allowedHost+"/"); c.connect != "200" || c.code != "200" {
		t.Fatalf("%s through the proxy = %+v, want 200", allowedHost, c)
	}
	// The harness itself routes through the proxy too (its launcher exports
	// the proxy settings OpenShell strips from the environment).
	e.harness(sb, "Run the DCE2E-FETCH scenario.")
	if got := e.exec(sb, 30*time.Second, true, "cat", "/tmp/dce2e-fetch.txt"); strings.TrimSpace(got.stdout) != "200" {
		t.Fatalf("the harness's fetch of %s = %q, want 200", allowedHost, got.stdout)
	}

	if c := e.proxyCurl(sb, "https://"+blockedHost+"/dce2e"); c.connect == "200" {
		t.Fatalf("%s through the proxy = %+v, want a refusal", blockedHost, c)
	}
	e.waitActivity(sb.Name, "egress.blocked "+blockedHost, func(ev sandboxapi.ActivityEvent) bool {
		return ev.Kind == sandboxapi.ActivityEgressBlocked && ev.Host == blockedHost && ev.Source == sandboxapi.SourceProxy
	})
	res, err := e.api.Unblock(e.ctx(time.Minute), sandboxapi.UnblockRequest{Host: blockedHost, Sandbox: sb.Name})
	if err != nil || res.Scope != "sandbox" {
		t.Fatalf("unblock = %+v, %v", res, err)
	}
	if c := e.proxyCurl(sb, "https://"+blockedHost+"/dce2e"); c.connect != "200" {
		t.Fatalf("%s after the unblock = %+v, want the tunnel to open", blockedHost, c)
	}
	after := e.get(sb.Name).Egress
	if after.Blocked <= before.Blocked || after.Destinations < 2 || after.BytesUp == 0 {
		t.Fatalf("egress stats %+v → %+v", before, after)
	}
	t.Logf("egress: %+v", after)
}

func (e *env) directConnection(sb *sandboxapi.Sandbox) {
	t := e.t
	script := "curl -sS -o /dev/null --noproxy '*' --max-time 10 -w '%{http_code}' https://" + directHost + "/; echo \" $?\""
	first := e.exec(sb, 40*time.Second, false, "sh", "-c", script)
	if strings.HasPrefix(first.stdout, "200") {
		t.Fatalf("a direct connection to %s went through before any approval", directHost)
	}
	var last string
	waitFor(t, 5*time.Minute, "OpenShell to allow the approved direct connection", func() error {
		last = e.exec(sb, 40*time.Second, false, "sh", "-c", script).stdout
		if strings.HasPrefix(last, "200") {
			return nil
		}
		return fmt.Errorf("direct connection: %q", last)
	})
	e.waitActivity(sb.Name, "approval.resolved "+directHost, func(ev sandboxapi.ActivityEvent) bool {
		return ev.Kind == sandboxapi.ActivityApprovalResolved && ev.Host == directHost
	})
	t.Logf("direct connection: before %q, after %q", strings.TrimSpace(first.stdout), strings.TrimSpace(last))
}

func (e *env) stopStart(sb *sandboxapi.Sandbox) {
	t := e.t
	stopped, err := e.api.Stop(e.ctx(5*time.Minute), sb.Name)
	if err != nil || stopped.Phase != "stopped" {
		t.Fatalf("stop = %+v, %v", stopped, err)
	}
	started, err := e.api.Start(e.ctx(10*time.Minute), sb.Name, sandboxapi.StartRequest{})
	if err != nil || started.Phase != "ready" {
		t.Fatalf("start = %+v, %v", started, err)
	}
	// Hooks authenticate with the binding minted at start; a stale token
	// would fail closed and deny the tool call.
	e.exec(started, 30*time.Second, true, "rm", "-f", allowedMarkerFile)
	before := e.get(sb.Name).Hooks
	e.harness(started, "Write the allowed marker file again.")
	if got := e.exec(started, 30*time.Second, true, "cat", allowedMarkerFile); strings.TrimSpace(got.stdout) != "dce2e-allowed" {
		t.Fatalf("allowed tool call after start left %q", got.stdout)
	}
	e.waitHooks(sb.Name, func(h sandboxapi.HookCoverage) bool { return h.ToolCalls > before.ToolCalls })
	*sb = *started
}

func (e *env) reviewUndo(sb *sandboxapi.Sandbox) {
	t := e.t
	e.harness(sb, "Run the DCE2E-EDIT scenario.")
	edited, err := os.ReadFile(filepath.Join(e.project, "README.md"))
	if err != nil || !strings.Contains(string(edited), "dce2e-edited") {
		t.Fatalf("the edit did not reach the mounted project: %q, %v", edited, err)
	}
	rev, err := e.api.Review(e.ctx(2*time.Minute), sb.Name, sandboxapi.ReviewRequest{})
	if err != nil || !strings.Contains(rev.Summary, "1 file changed") {
		t.Fatalf("review = %+v, %v", rev, err)
	}
	undo, err := e.api.Undo(e.ctx(5*time.Minute), sb.Name, sandboxapi.UndoRequest{Stop: true})
	if err != nil || !undo.Stopped {
		t.Fatalf("undo = %+v, %v", undo, err)
	}
	restored, err := os.ReadFile(filepath.Join(e.project, "README.md"))
	if err != nil || string(restored) != e.readme {
		t.Fatalf("README after undo = %q, %v; want %q", restored, err, e.readme)
	}
	t.Logf("review %q; undo restored README.md", rev.Summary)
}

func (e *env) deleteSandbox(sb *sandboxapi.Sandbox) {
	t := e.t
	res, err := e.api.Delete(e.ctx(5*time.Minute), sb.Name, sandboxapi.DeleteRequest{})
	if err != nil || !res.Deleted {
		t.Fatalf("delete = %+v, %v", res, err)
	}
	waitFor(t, 3*time.Minute, "OpenShell to forget the sandbox", func() error {
		_, err := e.gw.GetSandbox(e.ctx(20*time.Second), sb.Name)
		if openshell.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("get sandbox: %v", err)
	})
	if left := e.prefixedProviders(e.ctx(30 * time.Second)); len(left) > 0 {
		t.Fatalf("providers left after delete: %v", left)
	}
	list, err := e.api.List(e.ctx(30 * time.Second))
	if err != nil || len(list) != 0 {
		t.Fatalf("list after delete = %v, %v", names(list), err)
	}
	t.Logf("deleted; providers removed: %v", res.Providers)
}

// ---- helpers -----------------------------------------------------------------

type execOut struct {
	stdout string
	code   int
}

// exec runs argv in the sandbox (never through the harness).
func (e *env) exec(sb *sandboxapi.Sandbox, timeout time.Duration, idempotent bool, argv ...string) execOut {
	e.t.Helper()
	res, err := e.gw.Exec(e.ctx(timeout+time.Minute), sb.Name, argv, openshell.ExecOptions{
		WorkDir: sb.Workdir, Timeout: timeout, Idempotent: idempotent,
	})
	if err != nil {
		e.t.Fatalf("exec %q: %v", argv[0], err)
	}
	return execOut{stdout: string(res.Stdout), code: res.ExitCode}
}

// harness runs one headless Claude Code prompt through the in-image
// launcher, as `defenseclaw sandbox run -p` would.
func (e *env) harness(sb *sandboxapi.Sandbox, prompt string) string {
	e.t.Helper()
	argv, err := harness.ClaudeCode.LaunchArgv(harness.LaunchOptions{
		Mode: harness.Headless, Yolo: sb.Launch.Yolo, Prompt: prompt, CredentialProfile: sb.Launch.CredentialProfile,
	})
	if err != nil {
		e.t.Fatal(err)
	}
	res, err := e.gw.Exec(e.ctx(5*time.Minute), sb.Name, argv, openshell.ExecOptions{WorkDir: sb.Workdir, Timeout: 4 * time.Minute})
	if err != nil {
		e.t.Fatalf("harness %q: %v", prompt, err)
	}
	out := truncate(strings.TrimSpace(string(res.Stdout)), 300)
	if res.ExitCode != 0 {
		e.t.Fatalf("harness %q exited %d: %s / %s", prompt, res.ExitCode, out, truncate(string(res.Stderr), 300))
	}
	e.t.Logf("harness %q: %s", prompt, out)
	return out
}

type curlOut struct{ connect, code, rc string }

// proxyCurl fetches url through the sandbox's DefenseClaw egress proxy. The
// proxy URL (with the sandbox's proxy credential) never leaves the sandbox.
func (e *env) proxyCurl(sb *sandboxapi.Sandbox, url string) curlOut {
	e.t.Helper()
	script := `[ -n "$DEFENSECLAW_EGRESS_URL" ] || { echo "no-proxy-env"; exit 0; }; ` +
		`curl -sS -o /dev/null --max-time 20 -w '%{http_connect} %{http_code}' --proxy "$DEFENSECLAW_EGRESS_URL" '` + url + `' 2>/dev/null; echo " $?"`
	out := strings.Fields(e.exec(sb, 40*time.Second, false, "sh", "-c", script).stdout)
	if len(out) != 3 {
		e.t.Fatalf("curl %s through the proxy printed %q", url, out)
	}
	c := curlOut{connect: out[0], code: out[1], rc: out[2]}
	e.t.Logf("proxy %s: CONNECT %s, HTTP %s, curl %s", url, c.connect, c.code, c.rc)
	return c
}

func (e *env) get(name string) *sandboxapi.Sandbox {
	e.t.Helper()
	sb, err := e.api.Get(e.ctx(30*time.Second), name)
	if err != nil {
		e.t.Fatalf("get %s: %v", name, err)
	}
	return sb
}

func (e *env) waitHooks(name string, ok func(sandboxapi.HookCoverage) bool) sandboxapi.HookCoverage {
	e.t.Helper()
	var h sandboxapi.HookCoverage
	waitFor(e.t, 30*time.Second, "hook coverage", func() error {
		h = e.get(name).Hooks
		if ok(h) {
			return nil
		}
		return fmt.Errorf("hooks %+v", h)
	})
	return h
}

func (e *env) waitActivity(sandbox, what string, match func(sandboxapi.ActivityEvent) bool) sandboxapi.ActivityEvent {
	e.t.Helper()
	var got sandboxapi.ActivityEvent
	waitFor(e.t, time.Minute, what, func() error {
		found := false
		err := e.api.Activity(e.ctx(20*time.Second), sandboxapi.ActivityQuery{Sandbox: sandbox}, func(ev sandboxapi.ActivityEvent) error {
			if !found && match(ev) {
				found, got = true, ev
			}
			return nil
		})
		switch {
		case err != nil:
			return err
		case !found:
			return errors.New("not in the activity feed yet")
		}
		return nil
	})
	return got
}

func (e *env) prefixedProviders(ctx context.Context) []string {
	list, err := e.gw.ListProviders(ctx)
	if err != nil {
		e.t.Fatalf("list providers: %v", err)
	}
	var out []string
	for _, p := range list {
		if p.Name == e.prefix || strings.HasPrefix(p.Name, e.prefix+"-") {
			out = append(out, p.Name)
		}
	}
	return out
}

// restDelete deletes the sandbox through the daemon when a step failed
// before the delete step.
func (e *env) restDelete() { e.restDeleteName(e.prefix) }

func (e *env) restDeleteName(name string) {
	if e.api == nil {
		return
	}
	if _, err := e.api.Get(e.ctx(10*time.Second), name); err != nil {
		return
	}
	if _, err := e.api.Delete(e.ctx(5*time.Minute), name, sandboxapi.DeleteRequest{}); err != nil {
		e.t.Logf("cleanup: daemon delete of %s: %v", name, err)
	}
}

// sweep deletes every OpenShell sandbox and provider carrying the prefix.
func (e *env) sweep(ctx context.Context) {
	if e.gw == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	for _, name := range []string{e.prefix, e.prefix + stopSuffix} {
		if _, err := e.gw.GetSandbox(ctx, name); err == nil {
			e.t.Logf("cleanup: deleting leftover sandbox %s", name)
			if _, err := e.gw.DeleteSandbox(ctx, name); err != nil {
				e.t.Logf("cleanup: delete sandbox %s: %v", name, err)
			} else if err := e.gw.WaitDeleted(ctx, name); err != nil {
				e.t.Logf("cleanup: wait for %s: %v", name, err)
			}
		}
	}
	list, err := e.gw.ListProviders(ctx)
	if err != nil {
		e.t.Logf("cleanup: list providers: %v", err)
		return
	}
	for _, p := range list {
		if p.Name == e.prefix || strings.HasPrefix(p.Name, e.prefix+"-") {
			e.t.Logf("cleanup: deleting leftover provider %s", p.Name)
			if _, err := e.gw.DeleteProvider(ctx, p.Name); err != nil {
				e.t.Logf("cleanup: delete provider %s: %v", p.Name, err)
			}
		}
	}
}

// deleteProfiles deletes the DefenseClaw provider profiles the daemon
// imported during this run: ones that did not exist before it and that no
// remaining provider (another user's sandbox) uses.
func (e *env) deleteProfiles() {
	if e.gw == nil || e.profilesBefore == nil {
		return
	}
	ctx := e.ctx(2 * time.Minute)
	list, err := e.gw.ListProfiles(ctx)
	if err != nil {
		e.t.Logf("cleanup: list profiles: %v", err)
		return
	}
	providers, err := e.gw.ListProviders(ctx)
	if err != nil {
		e.t.Logf("cleanup: list providers: %v", err)
		return
	}
	for _, p := range list {
		ours := p.ID == profiles.IngressID || p.ID == profiles.AnthropicID || strings.HasPrefix(p.ID, "dc-cred-")
		if e.profilesBefore[p.ID] || !ours {
			continue
		}
		if slices.ContainsFunc(providers, func(pr *openshell.Provider) bool { return pr.Type == p.ID }) {
			e.t.Logf("cleanup: keeping profile %s: a provider still uses it", p.ID)
			continue
		}
		if _, err := e.gw.DeleteProfile(ctx, p.ID); err != nil {
			e.t.Logf("cleanup: delete profile %s: %v", p.ID, err)
		} else {
			e.t.Logf("cleanup: deleted profile %s", p.ID)
		}
	}
}

func sandboxImages() (map[string]bool, error) {
	out, err := exec.Command("docker", "image", "ls", "--format", "{{.Repository}}:{{.Tag}}", "defenseclaw/sandbox").Output()
	if err != nil {
		return nil, fmt.Errorf("docker image ls: %w", err)
	}
	set := map[string]bool{}
	for _, line := range strings.Fields(string(out)) {
		set[line] = true
	}
	return set, nil
}

// removeImages removes the overlay images this run built.
func (e *env) removeImages() {
	if e.imagesBefore == nil || os.Getenv("DEFENSECLAW_E2E_KEEP_IMAGE") == "1" {
		return
	}
	now, err := sandboxImages()
	if err != nil {
		e.t.Logf("cleanup: %v", err)
		return
	}
	for tag := range now {
		if e.imagesBefore[tag] {
			continue
		}
		if out, err := exec.Command("docker", "image", "rm", tag).CombinedOutput(); err != nil {
			e.t.Logf("cleanup: docker image rm %s: %v: %s", tag, err, truncate(string(out), 200))
		} else {
			e.t.Logf("cleanup: removed image %s", tag)
		}
	}
}

func (e *env) run(dir, name string, args ...string) {
	e.t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		e.t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, truncate(string(out), 2000))
	}
}

func (e *env) spawn(label, name string, args ...string) *exec.Cmd {
	return e.spawnEnv(label, os.Environ(), name, args...)
}

func (e *env) spawnEnv(label string, environ []string, name string, args ...string) *exec.Cmd {
	e.t.Helper()
	logf, err := os.Create(filepath.Join(e.work, "logs", label+".log"))
	if err != nil {
		e.t.Fatal(err)
	}
	cmd := exec.Command(name, args...)
	cmd.Dir = e.work
	cmd.Env = environ
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		_ = logf.Close()
		e.t.Fatalf("start %s: %v", label, err)
	}
	go func() { _ = cmd.Wait(); _ = logf.Close() }()
	e.t.Logf("started %s (pid %d), log %s", label, cmd.Process.Pid, logf.Name())
	return cmd
}

// stop ends a process started by spawn: SIGTERM, then SIGKILL.
func stop(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if cmd.Process.Signal(syscall.Signal(0)) != nil { // reaped by the Wait in spawnEnv
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	_ = cmd.Process.Kill()
}

func (e *env) ctx(d time.Duration) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	e.t.Cleanup(cancel)
	return ctx
}

func waitFor(t *testing.T, d time.Duration, what string, fn func() error) {
	t.Helper()
	deadline := time.Now().Add(d)
	var err error
	for {
		if err = fn(); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for %s: %v", d, what, err)
		}
		time.Sleep(2 * time.Second)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if raw, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil && bytes.HasPrefix(raw, []byte("module github.com/defenseclaw/defenseclaw")) {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("run the test inside the DefenseClaw repository")
		}
		dir = parent
	}
}

func writeFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func envInt(t *testing.T, key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1024 || n > 65000 {
		t.Fatalf("%s=%q is not a usable port", key, v)
	}
	return n
}

func names(list []sandboxapi.Sandbox) []string {
	out := make([]string, 0, len(list))
	for _, s := range list {
		out = append(out, s.Name)
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// mockAuth summarizes the mock model's request log: Messages API calls, and
// how many arrived with the ANTHROPIC_API_KEY placeholder substituted by
// OpenShell (the mock logs "[redacted]") or still a placeholder.
func mockAuth(path string) (messages, substituted, placeholder int) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, 0
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 0, 64<<10), 4<<20)
	for s.Scan() {
		var rec struct {
			Path    string            `json:"path"`
			Headers map[string]string `json:"headers"`
		}
		if json.Unmarshal(s.Bytes(), &rec) != nil || !strings.HasPrefix(rec.Path, "/v1/messages") {
			continue
		}
		messages++
		for k, v := range rec.Headers {
			if !strings.EqualFold(k, "x-api-key") {
				continue
			}
			switch v {
			case "[redacted]":
				substituted++
			case "[redacted placeholder]":
				placeholder++
			}
		}
	}
	return messages, substituted, placeholder
}

// mockToolResults returns the tool-result text of every Messages call the
// mock model logged (what the harness told the model a tool returned).
func mockToolResults(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 0, 64<<10), 4<<20)
	for s.Scan() {
		var rec struct {
			Path    string `json:"path"`
			Summary struct {
				LastToolResult string `json:"last_tool_result"`
			} `json:"summary"`
		}
		if json.Unmarshal(s.Bytes(), &rec) != nil || !strings.HasPrefix(rec.Path, "/v1/messages") || rec.Summary.LastToolResult == "" {
			continue
		}
		out = append(out, rec.Summary.LastToolResult)
	}
	return out
}
