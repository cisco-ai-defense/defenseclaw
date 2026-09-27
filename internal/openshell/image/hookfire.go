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
	"path"
	"path/filepath"
	"runtime"
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
// image against a mock LLM and a stand-in hook ingress it serves itself on
// the image's baked port: an allowed tool call (whose side effect must
// appear), a tool call the stand-in ingress blocks (whose side effect must
// not), and, for harnesses with a hostile-settings plan, the allowed run
// again with hostile user and project settings planted, which the image's
// managed policy must neutralise. By default the probe also serves the mock
// LLM itself (mockLLM), so it needs no model, key or network access.

// ErrHooksNotFired marks a hook-fire probe that ran the harness to completion
// and proved the image does not enforce: a required hook never fired,
// arrived unauthenticated or without an idempotency key, a blocked tool call
// still ran, or an allowed one never did. Other probe errors (docker, sink
// or option failures) say nothing about the image.
var ErrHooksNotFired = errors.New("hooks did not fire as required")

// DefaultHookFireSinkHost keeps 127.0.0.1:<ingress> free for a running
// DefenseClaw in HookFireNetworkHost mode: all of 127.0.0.0/8 is loopback on
// Linux.
const DefaultHookFireSinkHost = "127.0.0.2"

// HookFireNetwork selects how the probe container reaches the stand-in
// ingress and the mock LLM.
type HookFireNetwork string

const (
	// HookFireNetworkHost (the Linux default) runs the container on the host
	// network with host.openshell.internal mapped to SinkHost (default
	// DefaultHookFireSinkHost), where the stand-in ingress listens on the
	// image's baked port.
	HookFireNetworkHost HookFireNetwork = "host"
	// HookFireNetworkRelay (the default elsewhere) serves Docker Desktop,
	// whose host networking is opt-in and whose macOS host loopback carries
	// only 127.0.0.1, where a running DefenseClaw holds the ingress port.
	// The container stays on Docker's default bridge; the stand-in ingress
	// and the mock listen on free ports of SinkHost (default 127.0.0.1,
	// which Docker Desktop forwards host.docker.internal to);
	// host.openshell.internal maps to the container's own loopback, where a
	// relay the probe starts in the container (with the image's node)
	// forwards the baked ingress port to the stand-in ingress.
	HookFireNetworkRelay HookFireNetwork = "relay"
)

// DefaultHookFireNetwork is the network mode for the current platform.
func DefaultHookFireNetwork() HookFireNetwork {
	if runtime.GOOS == "linux" {
		return HookFireNetworkHost
	}
	return HookFireNetworkRelay
}

// hookFireContract is how one harness's hooks look to the stand-in ingress.
type hookFireContract struct {
	// required hooks must each arrive, authenticated, from a clean run.
	required []string
	// preTool is the hook whose payload the block marker is matched in.
	preTool string
	// deny is the verdict that blocks the pre-tool call, in the shape the
	// harness's sandbox hook reads.
	deny func(reason string) map[string]interface{}
}

// hookFireContracts covers every harness with a sandbox hook variant. Hooks
// that a harness fires only best-effort (OpenCode's unawaited session
// events) or only at teardown of an interactive session are not required.
var hookFireContracts = map[string]hookFireContract{
	"claudecode": {required: []string{"SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop"}, preTool: "PreToolUse", deny: claudeCodexDeny},
	"codex":      {required: []string{"SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop"}, preTool: "PreToolUse", deny: claudeCodexDeny},
	"opencode": {
		required: []string{"defenseclaw.plugin.loaded", "tool.execute.before", "tool.execute.after"},
		preTool:  "tool.execute.before",
		deny: func(reason string) map[string]interface{} {
			return map[string]interface{}{"action": "block", "reason": reason, "hook_output": map[string]interface{}{"decision": "deny", "reason": reason}}
		},
	},
	"copilot": {
		required: []string{"sessionStart", "userPromptSubmitted", "preToolUse", "postToolUse", "agentStop", "sessionEnd"},
		preTool:  "preToolUse",
		deny: func(reason string) map[string]interface{} {
			return map[string]interface{}{"action": "block", "reason": reason, "hook_output": map[string]interface{}{"permissionDecision": "deny", "permissionDecisionReason": reason}}
		},
	},
	"amp": {
		required: []string{"session.start", "agent.start", "tool.call", "tool.result", "agent.end"},
		preTool:  "tool.call",
		deny: func(reason string) map[string]interface{} {
			return map[string]interface{}{"action": "block", "reason": reason}
		},
	},
}

// claudeCodexDeny is the PreToolUse deny Claude Code and Codex hooks print.
func claudeCodexDeny(reason string) map[string]interface{} {
	deny := map[string]interface{}{
		"hookSpecificOutput": map[string]interface{}{
			"hookEventName":            "PreToolUse",
			"permissionDecision":       "deny",
			"permissionDecisionReason": reason,
		},
	}
	return map[string]interface{}{
		"action":             "block",
		"reason":             reason,
		"claude_code_output": deny,
		"codex_output":       deny,
	}
}

// HookFireOptions configure a hook-fire probe. The zero value runs the
// built-in scenarios against the built-in mock LLM on the platform's
// default network; setting Prompt, Block, Env or Args switches to a
// caller-supplied mock, which must then answer Prompt (and Block.Prompt)
// with one tool call each.
type HookFireOptions struct {
	// Network defaults to DefaultHookFireNetwork().
	Network HookFireNetwork
	// SinkHost is the host address the stand-in ingress (and the built-in
	// mock) bind: a loopback address, or in relay mode also a private
	// address such as a Linux docker bridge gateway. Host mode defaults to
	// DefaultHookFireSinkHost, relay mode to 127.0.0.1.
	SinkHost string
	// Env holds the caller's mock LLM settings (ANTHROPIC_BASE_URL and
	// ANTHROPIC_API_KEY for Claude Code, OPENAI_API_KEY for Codex).
	Env map[string]string
	// Args are extra harness arguments (for example a Codex mock provider).
	Args []string
	// Prompt drives the allow scenario, and the hostile-settings scenario of
	// harnesses that have one; the mock must answer it with one tool call.
	Prompt string
	// AllowSideEffect, when set, is the absolute file the allowed tool call
	// creates; the allow and hostile-settings runs must leave it behind.
	AllowSideEffect string
	// Block adds a scenario whose tool call the hook must deny. VerifyHooks
	// requires it.
	Block *BlockScenario
	// Timeout bounds each harness run (default 3 minutes).
	Timeout time.Duration
	// ContainerPrefix names the probe containers (default
	// defenseclaw-hookfire).
	ContainerPrefix string
	// RunFiles are bind-mounted read-only into every probe container, as
	// the sandbox manager mounts a sandbox's per-run managed configuration
	// (connector.SandboxRunFiles), so the probe proves the image enforces
	// with them in place.
	RunFiles []RunFile
}

// RunFile is a host file a probe container sees read-only at Path.
type RunFile struct {
	// HostPath is the file on the Docker host.
	HostPath string
	// Path is the absolute in-container path.
	Path string
}

// builtin reports whether opts select the built-in mock LLM and scenarios.
func (o HookFireOptions) builtin() bool {
	return o.Prompt == "" && o.Block == nil && len(o.Env) == 0 && len(o.Args) == 0 && o.AllowSideEffect == ""
}

// BlockScenario is a run whose PreToolUse the stand-in ingress blocks.
type BlockScenario struct {
	Prompt string
	// Marker is matched against the PreToolUse tool input.
	Marker string
	// SideEffect is the absolute file the blocked tool would create.
	SideEffect string
}

// Built-in hook-fire scenarios. The block marker is a harmless word the
// stand-in ingress looks for in the PreToolUse tool input.
const (
	builtinAllowPrompt     = "DefenseClaw hook-fire probe: write the marker file"
	builtinAllowSideEffect = "/tmp/dc-hookfire-allowed.txt"
	builtinBlockPrompt     = "DefenseClaw hook-fire probe: BLOCKME"
	builtinBlockMarker     = "BLOCKME"
	builtinBlockSideEffect = "/tmp/dc-hookfire-blocked.txt"
)

// builtinMockScenarios script the built-in mock LLM (block first: its match
// is the more specific one).
var builtinMockScenarios = []mockScenario{
	{match: builtinBlockMarker, command: "echo " + builtinBlockMarker + " > " + builtinBlockSideEffect, done: "The command was blocked by policy."},
	{match: "write the marker file", command: "echo dc-hookfire-allowed > " + builtinAllowSideEffect, done: "Done: the marker file was written."},
}

// builtinMockLaunch points a harness at the built-in mock LLM at baseURL.
// The keys are placeholders the mock never checks.
var builtinMockLaunch = map[string]func(baseURL string) (map[string]string, []string){
	"claudecode": func(baseURL string) (map[string]string, []string) {
		return map[string]string{"ANTHROPIC_BASE_URL": baseURL, "ANTHROPIC_API_KEY": "sk-ant-dcprobe-0123456789abcdefghij"},
			[]string{"--output-format", "json"}
	},
	"codex": func(baseURL string) (map[string]string, []string) {
		return map[string]string{"OPENAI_API_KEY": "sk-dcprobe-0123456789abcdefghij"}, []string{
			"-c", `model_provider="dcprobe"`, "-c", `model_providers.dcprobe.name="dcprobe"`,
			"-c", `model_providers.dcprobe.base_url="` + baseURL + `/v1"`,
			"-c", `model_providers.dcprobe.env_key="OPENAI_API_KEY"`, "-c", `model_providers.dcprobe.wire_api="responses"`,
			// Codex sends its default model's tools in an input item the mock
			// does not read; an unknown model gets the classic tools field.
			"-m", "mock-model",
		}
	},
	// OpenCode reaches the mock through a custom provider on its bundled
	// Anthropic SDK; the model catalog is not fetched.
	"opencode": func(baseURL string) (map[string]string, []string) {
		config, _ := json.Marshal(map[string]interface{}{
			"provider": map[string]interface{}{"dcprobe": map[string]interface{}{
				"npm": "@ai-sdk/anthropic", "name": "dcprobe",
				"options": map[string]string{"baseURL": baseURL + "/v1", "apiKey": "sk-ant-dcprobe-0123456789abcdefghij"},
				"models":  map[string]interface{}{"claude-sonnet-4-5": map[string]interface{}{"name": "DefenseClaw hook-fire mock", "tool_call": true}},
			}},
			"model": "dcprobe/claude-sonnet-4-5",
		})
		return map[string]string{"OPENCODE_CONFIG_CONTENT": string(config), "OPENCODE_DISABLE_MODELS_FETCH": "1"}, nil
	},
	// Copilot CLI's bring-your-own-provider mode needs no GitHub login;
	// offline mode skips every other request.
	"copilot": func(baseURL string) (map[string]string, []string) {
		return map[string]string{
			"COPILOT_PROVIDER_BASE_URL": baseURL, "COPILOT_PROVIDER_TYPE": "anthropic",
			"COPILOT_PROVIDER_API_KEY": "sk-ant-dcprobe-0123456789abcdefghij", "COPILOT_MODEL": "claude-sonnet-4.6",
			"COPILOT_OFFLINE": "true",
		}, nil
	},
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
	Scenario     string      `json:"scenario"`
	ExitCode     int         `json:"exit_code"`
	Events       []HookEvent `json:"events"`
	OTLPRequests int         `json:"otlp_requests"`
	// SideEffectPresent reports the scenario's side effect: the blocked
	// tool's file (block) or the allowed tool's (allow, hostile-settings,
	// when AllowSideEffect is set).
	SideEffectPresent *bool `json:"side_effect_present,omitempty"`
	// PlantedRan lists the programs planted by hostile settings that ran
	// (hostile-settings scenario only; always empty for an enforcing image).
	PlantedRan []string `json:"planted_ran,omitempty"`
	// Markers reports, for scenarios that name marker files, whether each
	// exists after the run.
	Markers map[string]bool `json:"markers,omitempty"`
	// Report holds the "::report=" lines a scenario's post-run checks
	// print.
	Report []string `json:"report,omitempty"`
	// Refusals are the launcher's answers to the plantings it must refuse
	// (hostile-settings scenario of harnesses that have them).
	Refusals []HookFireRefusal `json:"refusals,omitempty"`
	Output   string            `json:"output"`
}

// HookFireRefusal is one harness start the launcher had to refuse.
type HookFireRefusal struct {
	// Label names the planting.
	Label    string `json:"label"`
	ExitCode int    `json:"exit_code"`
	// Named reports whether the refusal named the planted file.
	Named bool `json:"named"`
}

// Hook-fire scenario names, as recorded in HookFireRun.Scenario.
const (
	ScenarioAllow           = "allow"
	ScenarioBlock           = "block"
	ScenarioHostileSettings = "hostile-settings"
)

// hookFireScenario is one harness run of the probe.
type hookFireScenario struct {
	name    string
	prompt  string
	block   *BlockScenario
	hostile *hostileSettings
	// sideEffect is checked after the run; wantSideEffect says whether it
	// must exist.
	sideEffect     string
	wantSideEffect bool

	// safe launches without skip-permissions; the built-in scenarios all
	// run in skip-permissions mode.
	safe bool
	// extraArgs are appended to the launch argv as given, past the
	// harness's bypass-flag filter (a hostile passthrough flag).
	extraArgs []string
	// env overrides the harness environment.
	env map[string]string
	// workdir, when set, is a project under the work root that setup
	// creates (on a workload-owned tmpfs, as for hostile settings).
	workdir string
	// setup runs before the harness; post runs after it and reports with
	// "::report=" lines.
	setup, post string
	// markers are absolute files whose presence is reported after the run.
	markers []string
	// mounts are extra read-only files for this scenario.
	mounts []RunFile
}

// HookFireResult is the outcome of HookFireProbe.
type HookFireResult struct {
	Network HookFireNetwork `json:"network"`
	Runs    []HookFireRun   `json:"runs"`
}

// VerifyHooks runs the hook-fire probe against the recorded image of c and
// persists the verdict under the store lock: HookFireVerified is set when
// every required hook fired, the blocked tool call was denied and the
// allowed one ran, and cleared when the probe proves the image does not
// enforce (ErrHooksNotFired). A block scenario is mandatory (the built-in
// options carry one). Store.Current selects only verified images. The probe
// runs against the recorded image ID, and the verdict is stored only while
// the record still names that image, so a concurrent rebuild is never
// marked verified by a probe of its predecessor. A probe that could not run
// leaves the record unchanged. Build calls VerifyHooks for every fresh image.
func (b *Builder) VerifyHooks(ctx context.Context, c *Context, opts HookFireOptions) (Record, HookFireResult, error) {
	if !opts.builtin() && opts.Block == nil {
		return Record{}, HookFireResult{}, errors.New("openshell image: VerifyHooks needs a block scenario: an image is verified only once a denied tool call is proven not to run")
	}
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

// HookFireProbe runs the image's harness against the mock LLM and verifies
// that every required hook fires with the sandbox token and an idempotency
// key, also with hostile user and project settings planted, that a blocked
// tool call has no side effect and that an allowed one has. It only
// reports: VerifyHooks is the path that records the verdict.
func (b *Builder) HookFireProbe(ctx context.Context, c *Context, opts HookFireOptions) (HookFireResult, error) {
	return b.hookFireProbe(ctx, c, c.Tag, opts)
}

// hookFireNet is a resolved probe network.
type hookFireNet struct {
	mode HookFireNetwork
	// bindHost is the host address the sink and the mock bind.
	bindHost string
	// sinkPort is the stand-in ingress port on bindHost.
	sinkPort int
	// containerHost is how the container addresses bindHost.
	containerHost string
}

// dockerArgs are the network flags of a probe container.
func (n hookFireNet) dockerArgs() []string {
	if n.mode == HookFireNetworkRelay {
		return []string{"--add-host", connector.SandboxIngressHost + ":127.0.0.1", "--add-host", "host.docker.internal:host-gateway"}
	}
	return []string{"--network", "host", "--add-host", connector.SandboxIngressHost + ":" + n.bindHost}
}

// hookFireRelayJS forwards 127.0.0.1:<argv[1]> to <argv[2]>:<argv[3]>.
const hookFireRelayJS = `const net=require("net");const[lp,th,tp]=process.argv.slice(1);` +
	`net.createServer(c=>{const u=net.connect(+tp,th);c.pipe(u);u.pipe(c);c.on("error",()=>u.destroy());u.on("error",()=>c.destroy());})` +
	`.listen(+lp,"127.0.0.1");`

// scriptPrefix starts the in-container relay (relay mode) and waits until
// the baked ingress port accepts connections. Exit 96 means the probe could
// not run, which says nothing about the image.
func (n hookFireNet) scriptPrefix(ingressPort int) string {
	if n.mode != HookFireNetworkRelay {
		return ""
	}
	port := strconv.Itoa(ingressPort)
	return "relay_node=\"$(command -v node 2>/dev/null)\" || relay_node=\"\"\n" +
		"[ -n \"$relay_node\" ] || { echo '::relay=no-node'; exit 96; }\n" +
		"\"$relay_node\" -e " + shQuote(hookFireRelayJS) + " " + port + " host.docker.internal " + strconv.Itoa(n.sinkPort) + " >/tmp/dc-hookfire-relay.log 2>&1 &\n" +
		"relay_try=0\n" +
		"until (exec 3<>/dev/tcp/127.0.0.1/" + port + ") 2>/dev/null; do\n" +
		"  relay_try=$((relay_try + 1)); [ \"$relay_try\" -lt 100 ] || { echo '::relay=not-ready'; exit 96; }; sleep 0.1\n" +
		"done\n"
}

// resolveHookFireNet validates the network options and picks the sink
// address.
func resolveHookFireNet(opts HookFireOptions, ingressPort int) (hookFireNet, error) {
	mode := opts.Network
	if mode == "" {
		mode = DefaultHookFireNetwork()
	}
	n := hookFireNet{mode: mode, bindHost: opts.SinkHost}
	switch mode {
	case HookFireNetworkHost:
		if n.bindHost == "" {
			n.bindHost = DefaultHookFireSinkHost
		}
		if ip := net.ParseIP(n.bindHost); ip == nil || !ip.IsLoopback() {
			return n, fmt.Errorf("openshell image: hook-fire sink host %q must be a loopback address in host mode", n.bindHost)
		}
		n.sinkPort, n.containerHost = ingressPort, n.bindHost
	case HookFireNetworkRelay:
		if n.bindHost == "" {
			n.bindHost = "127.0.0.1"
		}
		if ip := net.ParseIP(n.bindHost); ip == nil || !(ip.IsLoopback() || ip.IsPrivate()) {
			return n, fmt.Errorf("openshell image: hook-fire sink host %q must be a loopback or private address in relay mode", n.bindHost)
		}
		n.containerHost = "host.docker.internal"
	default:
		return n, fmt.Errorf("openshell image: unknown hook-fire network %q", mode)
	}
	return n, nil
}

// serveHTTP serves h on a new listener at host:port and returns the bound
// port and a shutdown func.
func serveHTTP(host string, port int, h http.Handler) (int, func(), error) {
	listener, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return 0, nil, err
	}
	server := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = server.Serve(listener) }()
	stop := func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}
	return listener.Addr().(*net.TCPAddr).Port, stop, nil
}

// hookFireProbe runs the probe against image ref (a tag or image ID).
func (b *Builder) hookFireProbe(ctx context.Context, c *Context, ref string, opts HookFireOptions) (HookFireResult, error) {
	contract, ok := hookFireContracts[c.Spec.Harness.Name]
	if !ok {
		return HookFireResult{}, fmt.Errorf("openshell image: no hook-fire contract for %s", c.Spec.Harness.Name)
	}
	required := contract.required
	netw, err := resolveHookFireNet(opts, c.Spec.IngressPort)
	if err != nil {
		return HookFireResult{}, err
	}
	result := HookFireResult{Network: netw.mode}
	builtin := opts.builtin()
	if !builtin {
		if strings.TrimSpace(opts.Prompt) == "" {
			return result, errors.New("openshell image: hook-fire probe needs a prompt the mock answers with a tool call")
		}
		if opts.Block != nil && (opts.Block.Marker == "" || opts.Block.SideEffect == "" || opts.Block.Prompt == "") {
			return result, errors.New("openshell image: block scenario needs a prompt, marker and side effect")
		}
	}
	token, err := randomHex(24)
	if err != nil {
		return result, err
	}
	var launch func(baseURL string) (map[string]string, []string)
	if builtin {
		if launch, ok = builtinMockLaunch[c.Spec.Harness.Name]; !ok {
			reason := "no built-in mock LLM wiring"
			if v := c.Spec.Harness.Verification; v.Status == harness.Unverified && v.Reason != "" {
				reason += ": " + v.Reason
			}
			return result, fmt.Errorf("openshell image: %s has %s; verify it with HookFireOptions naming a model the harness can reach", c.Spec.Harness.Name, reason)
		}
	}
	// p2-render-7: in host mode, serialize probes that bind the same address
	// to prevent EADDRINUSE collisions.
	var unlock func()
	if netw.mode == HookFireNetworkHost && b.Store != nil {
		lockPath := filepath.Join(filepath.Dir(b.Store.Path()), fmt.Sprintf("hookfire-%s-%d.lock", netw.bindHost, netw.sinkPort))
		unlock, err = lockFile(lockPath)
		if err != nil {
			return result, fmt.Errorf("openshell image: hook-fire lock: %w", err)
		}
		defer unlock()
	}
	sink := &hookSink{token: "dcprobe-" + token, contract: contract}
	sinkPort, stopSink, err := serveHTTP(netw.bindHost, netw.sinkPort, sink)
	if err != nil {
		return result, fmt.Errorf("openshell image: hook-fire sink: %w", err)
	}
	defer stopSink()
	netw.sinkPort = sinkPort
	if builtin {
		mockPort, stopMock, err := serveHTTP(netw.bindHost, 0, newMockLLM(builtinMockScenarios...))
		if err != nil {
			return result, fmt.Errorf("openshell image: hook-fire mock LLM: %w", err)
		}
		defer stopMock()
		opts.Env, opts.Args = launch("http://" + net.JoinHostPort(netw.containerHost, strconv.Itoa(mockPort)))
		opts.Prompt, opts.AllowSideEffect = builtinAllowPrompt, builtinAllowSideEffect
		opts.Block = &BlockScenario{Prompt: builtinBlockPrompt, Marker: builtinBlockMarker, SideEffect: builtinBlockSideEffect}
	}

	run := func(sc hookFireScenario) (HookFireRun, error) {
		r, err := b.hookFireRun(ctx, c, ref, opts, netw, sink, sc)
		result.Runs = append(result.Runs, r)
		return r, err
	}
	var problems []string
	sideEffect := func(r HookFireRun, sc hookFireScenario, prefix string) {
		switch {
		case sc.sideEffect == "":
		case r.SideEffectPresent == nil:
			problems = append(problems, prefix+"the probe could not tell whether "+sc.sideEffect+" exists")
		case sc.wantSideEffect && !*r.SideEffectPresent:
			problems = append(problems, prefix+"the allowed tool call never ran ("+sc.sideEffect+" is missing)")
		case !sc.wantSideEffect && *r.SideEffectPresent:
			problems = append(problems, prefix+"the blocked tool call still ran ("+sc.sideEffect+" exists)")
		}
	}
	allowSc := hookFireScenario{name: ScenarioAllow, prompt: opts.Prompt, sideEffect: opts.AllowSideEffect, wantSideEffect: true}
	allow, err := run(allowSc)
	if err != nil {
		return result, err
	}
	problems = append(problems, requiredHookProblems(allow, required)...)
	sideEffect(allow, allowSc, "")
	if opts.Block != nil {
		blockSc := hookFireScenario{name: ScenarioBlock, prompt: opts.Block.Prompt, block: opts.Block, sideEffect: opts.Block.SideEffect}
		blocked, err := run(blockSc)
		if err != nil {
			return result, err
		}
		denied := false
		for _, ev := range blocked.Events {
			denied = denied || ev.Blocked
		}
		if !denied {
			problems = append(problems, "the block scenario never reached a "+contract.preTool+" carrying the marker")
		} else {
			sideEffect(blocked, blockSc, "")
		}
	}
	if plan, ok := hostileSettingsPlans[c.Spec.Harness.Name]; ok {
		hostileSc := hookFireScenario{name: ScenarioHostileSettings, prompt: opts.Prompt, hostile: &plan, sideEffect: opts.AllowSideEffect, wantSideEffect: true}
		hostile, err := run(hostileSc)
		if err != nil {
			return result, err
		}
		for _, problem := range requiredHookProblems(hostile, required) {
			problems = append(problems, "with hostile user and project settings, "+problem)
		}
		sideEffect(hostile, hostileSc, "with hostile user and project settings, ")
		if len(hostile.PlantedRan) > 0 {
			problems = append(problems, "programs planted by hostile user and project settings ran: "+strings.Join(hostile.PlantedRan, ", "))
		}
		problems = append(problems, refusalProblems(plan.refusals, hostile.Refusals)...)
	}
	if len(problems) > 0 {
		return result, fmt.Errorf("openshell image %s hook-fire probe failed: %w: %s", c.Tag, ErrHooksNotFired, strings.Join(problems, "; "))
	}
	return result, nil
}

// refusalProblems reports every planting the launcher had to refuse but
// started the harness with, refused without naming, or was never tried.
func refusalProblems(want []hostileRefusal, got []HookFireRefusal) []string {
	byLabel := map[string]HookFireRefusal{}
	for _, r := range got {
		byLabel[r.Label] = r
	}
	var problems []string
	for _, w := range want {
		r, ok := byLabel[w.label]
		switch {
		case !ok:
			problems = append(problems, "the launcher was never started with the planted "+w.label+" ("+w.file+")")
		case r.ExitCode == 0:
			problems = append(problems, "the launcher started the harness with the planted "+w.label+" ("+w.file+")")
		case !r.Named:
			problems = append(problems, fmt.Sprintf("the launcher exited %d with the planted %s without the refusal naming %s", r.ExitCode, w.label, w.file))
		}
	}
	return problems
}

// requiredHookProblems reports every hook of run that arrived without the
// sandbox token or an idempotency key, and every required hook that never
// arrived authenticated.
func requiredHookProblems(run HookFireRun, required []string) []string {
	var problems []string
	seen := map[string]bool{}
	for _, ev := range run.Events {
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
	return problems
}

func (b *Builder) hookFireRun(
	ctx context.Context, c *Context, ref string, opts HookFireOptions, netw hookFireNet, sink *hookSink, sc hookFireScenario,
) (HookFireRun, error) {
	run := HookFireRun{Scenario: sc.name}
	argv, err := c.Spec.Harness.LaunchArgv(harness.LaunchOptions{Mode: harness.Headless, Yolo: !sc.safe, Prompt: sc.prompt, Args: opts.Args})
	if err != nil {
		return run, err
	}
	argv = append(argv, sc.extraArgs...)
	for _, file := range append([]string{sc.sideEffect}, sc.markers...) {
		if file != "" && !safePathRE.MatchString(file) {
			return run, fmt.Errorf("openshell image: side effect or marker %q must be a plain absolute path", file)
		}
	}
	mounts := append(append([]RunFile(nil), opts.RunFiles...), sc.mounts...)
	for _, m := range mounts {
		if !safePathRE.MatchString(m.Path) || path.Clean(m.Path) != m.Path || !filepath.IsAbs(m.HostPath) || strings.ContainsAny(m.HostPath, ",\n") {
			return run, fmt.Errorf("openshell image: run file %q -> %q is not a plain absolute mount", m.HostPath, m.Path)
		}
	}
	var quoted []string
	if sc.hostile != nil && len(sc.hostile.env) > 0 {
		// Only the harness gets the hostile env: the probe's own shell
		// would read a planted BASH_ENV too.
		keys := make([]string, 0, len(sc.hostile.env))
		for key := range sc.hostile.env {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		quoted = append(quoted, "/usr/bin/env")
		for _, key := range keys {
			quoted = append(quoted, shQuote(key+"="+sc.hostile.env[key]))
		}
	}
	for _, a := range argv {
		quoted = append(quoted, shQuote(a))
	}
	harnessCmd := strings.Join(quoted, " ")
	workdir := connector.SandboxHomeDir
	script := netw.scriptPrefix(c.Spec.IngressPort)
	if sc.hostile != nil {
		workdir = sc.hostile.workdir
		script += sc.hostile.setup
	}
	if sc.workdir != "" {
		workdir = sc.workdir
		script += "mkdir -p " + shQuote(sc.workdir) + " || exit 97\n"
	}
	script += sc.setup
	script += "cd " + shQuote(workdir) + " || exit 97\n"
	if sc.hostile != nil {
		for _, r := range sc.hostile.refusals {
			if !refusalLabelRE.MatchString(r.label) || !safePathRE.MatchString(r.file) {
				return run, fmt.Errorf("openshell image: hostile refusal %q (%s) is not a plain label and path", r.label, r.file)
			}
			script += r.setup +
				harnessCmd + " </dev/null >/tmp/dc-hookfire-refusal.out 2>&1; rc=$?\n" +
				"if grep -qF -- " + shQuote(r.message) + " /tmp/dc-hookfire-refusal.out; then named=1; else named=0; fi\n" +
				"echo \"::refusal=" + r.label + " $rc $named\"\n" +
				"if [ \"$named\" = 0 ]; then echo '::refusal-output-begin'; head -c 800 /tmp/dc-hookfire-refusal.out; echo; echo '::refusal-output-end'; fi\n" +
				"rm -f " + shQuote(r.file) + "\n"
		}
	}
	if sc.sideEffect != "" {
		script += "rm -f " + shQuote(sc.sideEffect) + "\n"
	}
	script += harnessCmd + " </dev/null >/tmp/dc-hookfire.out 2>&1\n" +
		"echo \"::rc=$?\"\n"
	script += sc.post
	for _, marker := range sc.markers {
		script += "if [ -e " + shQuote(marker) + " ]; then echo " + shQuote("::marker="+marker+"=present") +
			"; else echo " + shQuote("::marker="+marker+"=absent") + "; fi\n"
	}
	if sc.sideEffect != "" {
		script += "if [ -e " + shQuote(sc.sideEffect) + " ]; then echo '::side-effect=present'; else echo '::side-effect=absent'; fi\n"
	}
	if sc.hostile != nil {
		script += "if [ -s " + shQuote(hostileRanLog) + " ]; then echo \"::planted-ran=$(sort -u " + shQuote(hostileRanLog) + " | tr '\\n' ' ')\"; fi\n"
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
	name := prefix + "-" + c.Spec.Harness.Name + "-" + sc.name + "-" + suffix
	args := append([]string{"run", "--rm", "--name", name}, netw.dockerArgs()...)
	args = append(args,
		"--user", strconv.Itoa(c.Spec.UID)+":"+strconv.Itoa(c.Spec.GID),
		"-e", "HOME="+connector.SandboxHomeDir,
		"-e", connector.SandboxTokenEnv+"="+sink.token,
	)
	if sc.hostile != nil || sc.workdir != "" {
		// The image's work root is root-owned; a workload-owned tmpfs lets
		// the probe create a project below it, where the pre-seeded trust
		// applies as it does to a mounted repository.
		args = append(args, "--tmpfs", fmt.Sprintf("%s:uid=%d,gid=%d,mode=0755", harness.WorkRoot, c.Spec.UID, c.Spec.GID))
	}
	for _, m := range mounts {
		args = append(args, "--mount", "type=bind,source="+m.HostPath+",target="+m.Path+",readonly")
	}
	env := map[string]string{}
	for key, value := range c.Artifacts.Env {
		env[key] = value
	}
	for key, value := range opts.Env {
		env[key] = value
	}
	for key, value := range sc.env {
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
	sink.begin(sc.block)
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
		return run, fmt.Errorf("openshell image: hook-fire %s run: %w", sc.name, err)
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
		case strings.HasPrefix(line, "::planted-ran="):
			run.PlantedRan = strings.Fields(strings.TrimPrefix(line, "::planted-ran="))
		case strings.HasPrefix(line, "::marker="):
			file, state, _ := strings.Cut(strings.TrimPrefix(line, "::marker="), "=")
			if run.Markers == nil {
				run.Markers = map[string]bool{}
			}
			run.Markers[file] = state == "present"
		case strings.HasPrefix(line, "::report="):
			run.Report = append(run.Report, strings.TrimPrefix(line, "::report="))
		case strings.HasPrefix(line, "::refusal="):
			if f := strings.Fields(strings.TrimPrefix(line, "::refusal=")); len(f) == 3 {
				code, err := strconv.Atoi(f[1])
				if err != nil {
					continue
				}
				run.Refusals = append(run.Refusals, HookFireRefusal{Label: f[0], ExitCode: code, Named: f[2] == "1"})
			}
		}
	}
	return run, nil
}

// hookSink stands in for the DefenseClaw hook ingress: it authenticates the
// bearer, records every hook, notify and OTLP request, and answers with
// DefenseClaw-shaped verdicts.
type hookSink struct {
	token string
	// contract selects the pre-tool hook and its deny verdict; the zero
	// value is Claude Code's and Codex's.
	contract hookFireContract
	mu       sync.Mutex
	events   []HookEvent
	otlp     int
	block    *BlockScenario
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
	// Codex binds its event in a header, Copilot (whose native payload has
	// no event field) in its own; everything else names it in the body.
	if name := r.Header.Get("X-DefenseClaw-Hook-Event"); name != "" {
		ev.Event = name
	} else if name := r.Header.Get("X-DefenseClaw-Copilot-Event"); name != "" {
		ev.Event = name
	} else if raw, ok := payload["hook_event_name"]; ok {
		_ = json.Unmarshal(raw, &ev.Event)
	}
	preTool, deny := s.contract.preTool, s.contract.deny
	if preTool == "" {
		preTool, deny = "PreToolUse", claudeCodexDeny
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
	// The marker is matched anywhere in the pre-tool payload: the tool input
	// is tool_input for most harnesses and toolArgs for Copilot.
	if authorized && block != nil && ev.Event == preTool && bytes.Contains(body, []byte(block.Marker)) {
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
	resp, _ := json.Marshal(deny("Blocked by the DefenseClaw hook-fire probe"))
	_, _ = w.Write(resp)
}

func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("openshell image: randomness: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
