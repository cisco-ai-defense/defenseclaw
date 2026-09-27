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

//go:build openshell_integration

package gateway

// Live end-to-end run of a hook-only harness inside an OpenShell 0.1
// sandbox, driven the way the spike launchers did (the manager and
// `sandbox run` are not wired yet): the verified overlay image from
// TestLiveOverlay, the rendered open-profile policy with the project
// bind-mounted, the DefenseClaw ingress provider profile carrying a real
// binding token, the DefenseClaw hook ingress and egress proxy in this
// process, and the E2E mock Anthropic server as the model (or, with a
// Bedrock API key, the harness's curated Bedrock Mantle profile and a real
// model).
//
//	DEFENSECLAW_E2E_DATA_DIR=<image store data dir> \
//	DEFENSECLAW_E2E_IMAGE_REPO=<repo> DEFENSECLAW_E2E_INGRESS_PORT=<baked port> \
//	DC_OPENSHELL_SMOKE_PREFIX=<name prefix> \
//	[DC_E2E_BEDROCK_API_KEY=<Bedrock API key> DC_E2E_BEDROCK_REGION=<region>] \
//	go test -tags openshell_integration ./internal/gateway/ -run TestLiveSandboxHookOnlyHarness -v -timeout 30m
//
// For each harness it proves: the hooks reach the ingress with the binding
// token and an idempotency key, an allowed tool call runs, web egress works through
// the DefenseClaw proxy, a blocklisted destination is refused by it, and a
// connection that bypasses the proxy is refused by OpenShell. Every
// OpenShell object it creates (profile, provider, sandbox) carries the
// prefix and is deleted again.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/image"
	"github.com/defenseclaw/defenseclaw/internal/openshell/policy"
	"github.com/defenseclaw/defenseclaw/internal/openshell/profiles"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// liveMockEnv points each harness at the E2E mock Anthropic server.
var liveMockEnv = map[string]func(baseURL string) map[string]string{
	"opencode": func(baseURL string) map[string]string {
		cfg, _ := json.Marshal(map[string]interface{}{
			"provider": map[string]interface{}{"e2emock": map[string]interface{}{
				"npm": "@ai-sdk/anthropic", "name": "e2emock",
				"options": map[string]string{"baseURL": baseURL + "/v1", "apiKey": "sk-ant-e2e-mock"},
				"models":  map[string]interface{}{"claude-sonnet-4-5": map[string]interface{}{"name": "E2E mock", "tool_call": true}},
			}},
			"model": "e2emock/claude-sonnet-4-5",
		})
		return map[string]string{"OPENCODE_CONFIG_CONTENT": string(cfg), "OPENCODE_DISABLE_MODELS_FETCH": "1"}
	},
	"copilot": func(baseURL string) map[string]string {
		return map[string]string{
			"COPILOT_PROVIDER_BASE_URL": baseURL, "COPILOT_PROVIDER_TYPE": "anthropic",
			"COPILOT_PROVIDER_API_KEY": "sk-ant-e2e-mock", "COPILOT_MODEL": "claude-sonnet-4.6", "COPILOT_OFFLINE": "true",
		}
	},
}

// liveMantleProfiles names each harness's Bedrock Mantle profile and the
// credential variable its provider carries.
var liveMantleProfiles = map[string]struct{ profile, credential string }{
	"opencode": {profiles.OpenCodeBedrockMantleID, "BEDROCK_MANTLE_API_KEY"},
	"copilot":  {profiles.CopilotBedrockMantleID, "COPILOT_PROVIDER_API_KEY"},
}

// liveImportMantle imports the harness's Mantle profile under a prefixed id,
// pinned to the image's network binaries, and creates its provider with the
// key (passed through the environment, never argv or logs). It returns the
// provider name.
func liveImportMantle(t *testing.T, harnessName, prefix, suffix string, binaries []string, region, key string) string {
	t.Helper()
	spec := liveMantleProfiles[harnessName]
	rendered, err := profiles.Render(spec.profile, profiles.Input{Binaries: binaries, BedrockRegion: region})
	if err != nil {
		t.Fatal(err)
	}
	id := prefix + "-mantle-" + suffix
	file := filepath.Join(t.TempDir(), "mantle.yaml")
	if err := os.WriteFile(file, bytes.Replace(rendered.YAML, []byte("id: "+spec.profile), []byte("id: "+id), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := liveOpenShell(t, 2*time.Minute, nil, "profile", "import", "-f", file, "--global"); err != nil {
		t.Fatalf("mantle profile import: %v\n%s", err, out)
	}
	t.Cleanup(func() { _, _ = liveOpenShell(t, 2*time.Minute, nil, "profile", "delete", id, "--global") })
	if out, err := liveOpenShell(t, 2*time.Minute, []string{spec.credential + "=" + key},
		"provider", "create", "--name", id, "--type", id, "--credential", spec.credential, "--global-profile"); err != nil {
		t.Fatalf("mantle provider create: %v\n%s", err, strings.ReplaceAll(out, key, "<redacted>"))
	}
	t.Cleanup(func() { _, _ = liveOpenShell(t, 2*time.Minute, nil, "provider", "delete", id) })
	return id
}

// liveHookEvent is one request the recording front of the ingress saw.
type liveHookEvent struct {
	Path, Event, Action string
	Status              int
	Authorized, Keyed   bool
}

// liveIngressRecorder fronts the real ingress on the baked port and records
// every hook with the verdict DefenseClaw returned.
type liveIngressRecorder struct {
	mu     sync.Mutex
	events []liveHookEvent
}

func (r *liveIngressRecorder) snapshot() []liveHookEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]liveHookEvent(nil), r.events...)
}

func (r *liveIngressRecorder) handler(t *testing.T, target string) http.Handler {
	upstream, err := url.Parse("http://" + target)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.ModifyResponse = func(resp *http.Response) error {
		body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		_ = resp.Body.Close()
		if err != nil {
			return err
		}
		resp.Body = io.NopCloser(bytes.NewReader(body))
		req := resp.Request
		ev := liveHookEvent{
			Path:       req.URL.Path,
			Status:     resp.StatusCode,
			Authorized: strings.HasPrefix(req.Header.Get("Authorization"), "Bearer "),
			Keyed:      req.Header.Get(SandboxHookIdempotencyHeader) != "",
		}
		if v := req.Header.Get("X-DefenseClaw-Copilot-Event"); v != "" {
			ev.Event = v
		} else if v := req.Header.Get("X-Live-Hook-Event"); v != "" {
			ev.Event = v
		}
		var verdict struct {
			Action string `json:"action"`
		}
		_ = json.Unmarshal(body, &verdict)
		ev.Action = verdict.Action
		r.mu.Lock()
		r.events = append(r.events, ev)
		r.mu.Unlock()
		return nil
	}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// The event of a body-named hook, copied to a header for the
		// response hook above.
		if req.Body != nil && strings.HasSuffix(req.URL.Path, "/hook") {
			body, _ := io.ReadAll(io.LimitReader(req.Body, 4<<20))
			_ = req.Body.Close()
			var named struct {
				Event string `json:"hook_event_name"`
			}
			if json.Unmarshal(body, &named) == nil && named.Event != "" {
				req.Header.Set("X-Live-Hook-Event", named.Event)
			}
			req.Body = io.NopCloser(bytes.NewReader(body))
			req.ContentLength = int64(len(body))
		}
		proxy.ServeHTTP(w, req)
	})
}

func liveFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func liveRandom(t *testing.T) string {
	t.Helper()
	b := make([]byte, 3)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// liveOpenShell runs the openshell CLI with stdin closed (exec and upload
// hang on an open pipe) and a hard timeout.
func liveOpenShell(t *testing.T, timeout time.Duration, env []string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "openshell", args...)
	cmd.Stdin = nil
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// liveExec runs argv in the sandbox, retrying once when the first attempt
// produced nothing (the OpenShell exec flake right after start).
func liveExec(t *testing.T, name string, timeout time.Duration, argv ...string) string {
	t.Helper()
	args := append([]string{"sandbox", "exec", "-n", name, "--no-tty", "--"}, argv...)
	var out string
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		out, err = liveOpenShell(t, timeout, nil, args...)
		if strings.TrimSpace(out) != "" {
			break
		}
	}
	if err != nil {
		// Only the program: the argv can carry the proxy credential.
		t.Logf("exec %s: %v", argv[0], err)
	}
	return out
}

func TestLiveSandboxHookOnlyHarness(t *testing.T) {
	dataDir := os.Getenv("DEFENSECLAW_E2E_DATA_DIR")
	if dataDir == "" {
		t.Skip("set DEFENSECLAW_E2E_DATA_DIR to the data dir TestLiveOverlay built the images in")
	}
	if _, err := exec.LookPath("openshell"); err != nil {
		t.Skip("openshell CLI not available")
	}
	repo := os.Getenv("DEFENSECLAW_E2E_IMAGE_REPO")
	if repo == "" {
		repo = "e-defenseclaw-sandbox"
	}
	ingressPort := 18971
	if v := os.Getenv("DEFENSECLAW_E2E_INGRESS_PORT"); v != "" {
		var err error
		if ingressPort, err = strconv.Atoi(v); err != nil {
			t.Fatal(err)
		}
	}
	prefix := os.Getenv("DC_OPENSHELL_SMOKE_PREFIX")
	if prefix == "" {
		prefix = "e-live"
	}
	scenarios, err := os.ReadFile(filepath.Join("..", "..", "test", "e2e", "openshell", "scenarios", "claude.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"opencode", "copilot"} {
		h, _ := harness.Get(name)
		t.Run(name, func(t *testing.T) {
			runLiveHookOnlyHarness(t, h, dataDir, repo, ingressPort, prefix, scenarios)
		})
	}
}

func runLiveHookOnlyHarness(t *testing.T, h *harness.Spec, dataDir, repo string, ingressPort int, prefix string, scenarios []byte) {
	builder := &image.Builder{Docker: image.CLI{}, Store: image.NewStore(dataDir)}
	spec := image.BuildSpec{Harness: h, UID: os.Getuid(), GID: os.Getgid(), IngressPort: ingressPort, DefenseClawVersion: "0.0.0-e2e", Repository: repo}
	rec, ok, err := builder.Current(spec)
	if err != nil || !ok {
		t.Skipf("no verified %s image in %s (run TestLiveOverlay first): %v", h.Name, dataDir, err)
	}
	c, err := builder.Context(spec)
	if err != nil {
		t.Fatal(err)
	}
	var networkBinaries []string
	for _, b := range rec.NetworkBinaries {
		networkBinaries = append(networkBinaries, b.Realpath)
	}
	// OpenShell 0.1.1 caps sandbox names at 19 characters.
	suffix := liveRandom(t)
	sandboxName := prefix + "-" + map[string]string{"opencode": "oc", "copilot": "cp"}[h.Name] + suffix[:4]
	if len(sandboxName) > 19 {
		t.Fatalf("sandbox name %q exceeds OpenShell's 19 characters; shorten DC_OPENSHELL_SMOKE_PREFIX", sandboxName)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// The project, bind-mounted at /work/proj as the host uid.
	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, "README.md"), []byte("live e2e\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// DefenseClaw ingress with a mount-mode binding, fronted on the baked
	// port by the recorder.
	cfg := &config.Config{DataDir: t.TempDir(), Gateway: config.GatewayConfig{Token: sandboxTestMasterToken}}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = h.Name
	api := NewAPIServer("127.0.0.1:18970", NewSidecarHealth(), nil, nil, nil, cfg)
	store, err := sandboxauth.OpenFileStore(sandboxauth.DefaultStorePath(cfg.DataDir), sandboxauth.WithRefreshInterval(0))
	if err != nil {
		t.Fatal(err)
	}
	binding, token, err := store.Mint(sandboxauth.Spec{
		SandboxName:    sandboxName,
		Connector:      h.Name,
		AgentVersion:   rec.HarnessVersion,
		HookContractID: rec.HookContract,
		PolicyProfile:  "open",
		Workdir: sandboxauth.Workdir{
			Mode:   sandboxauth.WorkdirMount,
			Mounts: []sandboxauth.Mount{{SandboxPath: "/work/proj", HostPath: project}},
		},
		HostUser: sandboxauth.HostUser{UID: strconv.Itoa(os.Getuid()), Name: liveUserName()},
	})
	if err != nil {
		t.Fatal(err)
	}
	realIngress := "127.0.0.1:" + strconv.Itoa(liveFreePort(t))
	if err := api.SetSandboxIngress(SandboxIngressConfig{Addr: realIngress, Bindings: store}); err != nil {
		t.Fatal(err)
	}
	go func() { _ = api.RunSandboxIngress(ctx) }()
	recorder := &liveIngressRecorder{}
	front, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(ingressPort))
	if err != nil {
		t.Fatalf("ingress port %d: %v", ingressPort, err)
	}
	frontSrv := &http.Server{Handler: recorder.handler(t, realIngress), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = frontSrv.Serve(front) }()
	t.Cleanup(func() { _ = frontSrv.Close() })

	// DefenseClaw egress proxy in open mode with the built-in blocklist.
	decider, err := egress.NewDecider(egress.DeciderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	creds := egress.NewCredentialStore()
	cred, err := egress.NewCredential()
	if err != nil {
		t.Fatal(err)
	}
	if err := creds.Register(cred, egress.Principal{BindingID: binding.ID, SandboxName: sandboxName, Mode: egress.ModeOpen}); err != nil {
		t.Fatal(err)
	}
	var egressMu sync.Mutex
	var egressEvents []egress.Event
	proxy, err := egress.New(egress.Options{Auth: creds, Decider: decider, Sink: egress.EventSinkFunc(func(e egress.Event) {
		egressMu.Lock()
		egressEvents = append(egressEvents, e)
		egressMu.Unlock()
	})})
	if err != nil {
		t.Fatal(err)
	}
	egressPort := liveFreePort(t)
	egressLn, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(egressPort))
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = proxy.Serve(egressLn) }()
	t.Cleanup(func() { _ = proxy.Close() })

	// The E2E mock model, with the scenarios' tool renamed to the harness's
	// bash tool.
	mockPort := liveFreePort(t)
	script := filepath.Join(t.TempDir(), "scenarios.json")
	if err := os.WriteFile(script, bytes.ReplaceAll(scenarios, []byte(`"name": "Bash"`), []byte(`"name": "bash"`)), 0o600); err != nil {
		t.Fatal(err)
	}
	mockLog := filepath.Join(t.TempDir(), "mock.jsonl")
	mock := exec.CommandContext(ctx, "python3", filepath.Join("..", "..", "test", "e2e", "openshell", "mock_anthropic.py"),
		"--host", "127.0.0.1", "--port", strconv.Itoa(mockPort), "--script", script, "--log", mockLog, "--quiet")
	if err := mock.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mock.Process.Kill(); _ = mock.Wait() })

	// Policy: open profile, project mounted, the mock reachable on a
	// consented host port for the harness's own binaries only.
	mockRule := v1.NetworkPolicyRule{
		Endpoints: []v1.PolicyNetworkEndpoint{{Host: connector.SandboxIngressHost, Port: uint32(mockPort), Protocol: "tcp", TLS: v1.NetworkTLSModeSkip}},
	}
	for _, b := range networkBinaries {
		mockRule.Binaries = append(mockRule.Binaries, v1.PolicyNetworkBinary{Path: b})
	}
	uid, gid := strconv.Itoa(os.Getuid()), strconv.Itoa(os.Getgid())
	pol, err := policy.Render(policy.Input{
		Profile: policy.ProfileOpen, Harness: h.Name, Workdir: "/work/proj", WorkdirMode: policy.WorkdirMount,
		RunAsUser: uid, RunAsGroup: gid, IngressPort: ingressPort, EgressPort: egressPort,
		HarnessReadOnly: []string{h.InstallRoot()},
		ExtraRules:      map[string]v1.NetworkPolicyRule{"e2e_mock_llm": mockRule},
		HostPorts:       []int{mockPort},
	})
	if err != nil {
		t.Fatal(err)
	}
	polYAML, err := policy.MarshalYAML(pol)
	if err != nil {
		t.Fatal(err)
	}
	policyFile := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(policyFile, polYAML, 0o600); err != nil {
		t.Fatal(err)
	}

	// The ingress provider profile under a prefixed id, and its provider.
	ingressProfile, err := profiles.Render(profiles.IngressID, profiles.Input{IngressPort: ingressPort})
	if err != nil {
		t.Fatal(err)
	}
	profileID := prefix + "-ingress-" + suffix
	profileFile := filepath.Join(t.TempDir(), "profile.yaml")
	if err := os.WriteFile(profileFile, bytes.Replace(ingressProfile.YAML, []byte("id: "+profiles.IngressID), []byte("id: "+profileID), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := liveOpenShell(t, 2*time.Minute, nil, "profile", "import", "-f", profileFile, "--global"); err != nil {
		t.Fatalf("profile import: %v\n%s", err, out)
	}
	t.Cleanup(func() { _, _ = liveOpenShell(t, 2*time.Minute, nil, "profile", "delete", profileID, "--global") })
	providerName := prefix + "-ingress-" + suffix
	if out, err := liveOpenShell(t, 2*time.Minute, []string{connector.SandboxTokenEnv + "=" + token},
		"provider", "create", "--name", providerName, "--type", profileID, "--credential", connector.SandboxTokenEnv, "--global-profile"); err != nil {
		t.Fatalf("provider create: %v\n%s", err, out)
	}
	t.Cleanup(func() { _, _ = liveOpenShell(t, 2*time.Minute, nil, "provider", "delete", providerName) })

	// The model: the E2E mock, or with a Bedrock API key in
	// DC_E2E_BEDROCK_API_KEY the harness's curated Bedrock Mantle profile,
	// imported under a prefixed id with the key as its provider credential.
	opts := harness.EnvOptions{
		Artifacts:      c.Artifacts,
		SandboxName:    sandboxName,
		EgressProxyURL: cred.ProxyURL(connector.SandboxIngressHost, egressPort),
	}
	providers := []string{providerName}
	mantleKey := os.Getenv("DC_E2E_BEDROCK_API_KEY")
	if mantleKey != "" {
		opts.CredentialProfile = liveMantleProfiles[h.Name].profile
		opts.BedrockRegion = os.Getenv("DC_E2E_BEDROCK_REGION")
		providers = append(providers, liveImportMantle(t, h.Name, prefix, suffix, networkBinaries, opts.BedrockRegion, mantleKey))
	}
	env, err := h.Env(opts)
	if err != nil {
		t.Fatal(err)
	}
	if mantleKey == "" {
		for k, v := range liveMockEnv[h.Name]("http://" + connector.SandboxIngressHost + ":" + strconv.Itoa(mockPort)) {
			env[k] = v
		}
	}
	driver, _ := json.Marshal(map[string]interface{}{"docker": map[string]interface{}{"mounts": []interface{}{
		map[string]interface{}{"type": "bind", "source": project, "target": "/work/proj", "read_only": false},
	}}})
	create := []string{"sandbox", "create", "--name", sandboxName, "--from", rec.Tag, "--policy", policyFile,
		"--driver-config-json", string(driver), "--detach", "--no-auto-providers", "--no-credential-warnings"}
	for _, p := range providers {
		create = append(create, "--provider", p)
	}
	for k, v := range env {
		create = append(create, "--env", k+"="+v)
	}
	if out, err := liveOpenShell(t, 5*time.Minute, nil, create...); err != nil {
		t.Fatalf("sandbox create: %v\n%s", err, out)
	}
	t.Cleanup(func() { _, _ = liveOpenShell(t, 3*time.Minute, nil, "sandbox", "delete", sandboxName) })
	deadline := time.Now().Add(3 * time.Minute)
	for {
		if out := liveExec(t, sandboxName, 30*time.Second, "/bin/echo", "ready"); strings.Contains(out, "ready") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("sandbox never became exec-ready")
		}
		time.Sleep(5 * time.Second)
	}
	// OpenShell drops in-flight connections at the first settings poll.
	time.Sleep(15 * time.Second)

	run := func(prompt string) string {
		argv, err := h.LaunchArgv(harness.LaunchOptions{Mode: harness.Headless, Yolo: true, Prompt: prompt})
		if err != nil {
			t.Fatal(err)
		}
		shell := append([]string{"/bin/bash", "-c", `cd /work/proj && "$@" </dev/null 2>&1; echo "::rc=$?"`, "run"}, argv...)
		return liveExec(t, sandboxName, 4*time.Minute, shell...)
	}
	preTool := map[string]string{"opencode": "tool.execute.before", "copilot": "preToolUse"}[h.Name]
	verdicts := func(from int) []liveHookEvent {
		var out []liveHookEvent
		for _, ev := range recorder.snapshot()[from:] {
			if ev.Event == preTool {
				out = append(out, ev)
			}
		}
		return out
	}

	// 1. An allowed tool call runs, its hooks reach the ingress authenticated
	//    and keyed, and DefenseClaw allows it.
	prompt := "DefenseClaw live check: run the default tool"
	if mantleKey != "" {
		prompt = "Use your shell tool to run exactly this command and nothing else: echo hello-from-tool > /tmp/tool.txt"
	}
	out := run(prompt)
	t.Logf("allow run:\n%s", liveTail(out, 1500))
	if got := liveExec(t, sandboxName, time.Minute, "/bin/cat", "/tmp/tool.txt"); !strings.Contains(got, "hello-from-tool") {
		t.Errorf("the allowed tool call did not run: %q", got)
	}
	allowed := verdicts(0)
	if len(allowed) == 0 || allowed[0].Action != "allow" || allowed[0].Status != http.StatusOK {
		t.Errorf("allowed pre-tool verdicts = %+v", allowed)
	}
	for _, ev := range recorder.snapshot() {
		if !ev.Authorized || !ev.Keyed || ev.Status == http.StatusUnauthorized {
			t.Errorf("hook %+v did not arrive authenticated with an idempotency key", ev)
		}
	}

	// 2. Egress: the proxy carries web traffic, refuses a blocklisted
	//    destination, and OpenShell refuses a connection around the proxy.
	//    Log which create-time variables an exec session sees (names only:
	//    the proxy URL holds a secret).
	t.Logf("exec session env names: %s", strings.TrimSpace(liveExec(t, sandboxName, time.Minute,
		"/bin/sh", "-c", `env | cut -d= -f1 | sort | tr '\n' ' '`)))
	proxyURL := cred.ProxyURL(connector.SandboxIngressHost, egressPort)
	curl := func(extra ...string) string {
		args := append([]string{"/usr/bin/curl", "-s", "-m", "20", "-o", "/dev/null", "-w", "%{http_code}"}, extra...)
		return strings.TrimSpace(liveExec(t, sandboxName, time.Minute, args...))
	}
	if got := curl("--proxy", proxyURL, "https://example.org/"); !strings.HasSuffix(got, "200") {
		t.Errorf("egress to example.org through the DefenseClaw proxy = %q", got)
	}
	if got := curl("--proxy", proxyURL, "https://webhook.site/defenseclaw-e2e"); strings.HasSuffix(got, "200") {
		t.Errorf("blocklisted egress to webhook.site was allowed: %q", got)
	}
	if got := curl("--noproxy", "*", "https://example.org/"); strings.HasSuffix(got, "200") {
		t.Errorf("egress around the proxy was allowed: %q", got)
	}
	egressMu.Lock()
	var sawAllowed, sawBlocked bool
	destinations := map[string]int{}
	for _, e := range egressEvents {
		sawAllowed = sawAllowed || (e.Host == "example.org" && e.Kind == egress.EventAllowed)
		sawBlocked = sawBlocked || (e.Host == "webhook.site" && e.Kind == egress.EventBlocked)
		if e.Kind == egress.EventAllowed || e.Kind == egress.EventBlocked {
			destinations[string(e.Kind)+" "+e.Host]++
		}
	}
	egressMu.Unlock()
	// Everything the harness itself sent through the proxy (the curl checks
	// above add example.org and webhook.site).
	t.Logf("%s egress through the DefenseClaw proxy: %v", h.Name, destinations)
	if !sawAllowed || !sawBlocked {
		t.Errorf("egress proxy events: allowed example.org %t, blocked webhook.site %t", sawAllowed, sawBlocked)
	}

	// Destinations OpenShell refused (the harness's own traffic that did not
	// use the proxy): the empirical stray-outbound set of this run.
	if logs, err := liveOpenShell(t, time.Minute, nil, "logs", sandboxName, "-n", "1000", "--source", "sandbox"); err == nil {
		denied := map[string]int{}
		for _, line := range strings.Split(logs, "\n") {
			if !strings.Contains(line, "DENIED") {
				continue
			}
			for _, m := range liveDestinationRE.FindAllString(line, -1) {
				denied[m]++
			}
		}
		t.Logf("%s destinations OpenShell denied: %v", h.Name, denied)
	}

	events := recorder.snapshot()
	seen := map[string]int{}
	for _, ev := range events {
		seen[ev.Event]++
	}
	t.Logf("%s hooks at the ingress: %v", h.Name, seen)
	summary, _ := json.Marshal(map[string]interface{}{"harness": h.Name, "image": rec.Tag, "hooks": seen, "allow": allowed})
	fmt.Fprintf(os.Stderr, "LIVE-SUMMARY %s\n", summary)
}

// liveDestinationRE matches host:port in OpenShell's OCSF log lines.
var liveDestinationRE = regexp.MustCompile(`[a-z0-9][a-z0-9.-]*\.[a-z]{2,}:[0-9]{1,5}`)

func liveUserName() string {
	if name := os.Getenv("USER"); name != "" {
		return name
	}
	return "e2e"
}

func liveTail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
