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
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
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

// requiredHookEvents must each arrive, authenticated, from a clean run. Hooks
// that a harness fires only best-effort (OpenCode's unawaited session events)
// or only at teardown of an interactive session are not required.
var requiredHookEvents = map[string][]string{
	"amp":         {"session.start", "agent.start", "tool.call", "tool.result", "agent.end"},
	"antigravity": {"PreInvocation", "PreToolUse", "PostToolUse", "PostInvocation", "Stop"},
	"claudecode":  {"SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop"},
	"codex":       {"SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop"},
	"copilot":     {"sessionStart", "userPromptSubmitted", "preToolUse", "postToolUse", "agentStop", "sessionEnd"},
	// The events Cursor's agent-cli-local build of the pinned release fired
	// for a headless shell call; beforeSubmitPrompt and stop do not fire in
	// print mode.
	"cursor": {"sessionStart", "preToolUse", "beforeShellExecution", "afterShellExecution", "postToolUse"},
	"devin":  {"SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop"},
	"hermes": {"on_session_start", "pre_llm_call", "pre_tool_call", "post_tool_call", "on_session_end"},
	"kiro":   {"userPromptSubmit", "preToolUse", "postToolUse", "stop"},
	// OmniGent's policy phases request, llm_request, tool_call, tool_result
	// and response.
	"omnigent":  {"UserPromptSubmit", "BeforeModel", "PreToolUse", "PostToolUse", "AfterAgentResponse"},
	"opencode":  {"defenseclaw.plugin.loaded", "tool.execute.before", "tool.execute.after"},
	"openhands": {"SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop"},
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
	"hermes": func(baseURL string) (map[string]string, []string) {
		return map[string]string{
				connector.HermesSandboxProviderBaseURLEnv: baseURL + "/v1",
				connector.HermesSandboxProviderKeyEnv:     "sk-dcprobe-0123456789abcdefghij",
			},
			[]string{"--provider", connector.HermesSandboxProviderName, "-m", "mock-model"}
	},
	"openhands": func(baseURL string) (map[string]string, []string) {
		return map[string]string{"LLM_MODEL": "openai/mock-model", "LLM_BASE_URL": baseURL + "/v1", "LLM_API_KEY": "sk-dcprobe-0123456789abcdefghij"},
			[]string{"--override-with-envs"}
	},
	"antigravity": func(baseURL string) (map[string]string, []string) {
		return map[string]string{"GEMINI_API_KEY": "dcprobe-0123456789abcdefghij", "GOOGLE_GEMINI_BASE_URL": baseURL}, nil
	},
	// The image's sandbox agent on the openai-agents harness (Responses);
	// an unpinned model would route to Databricks.
	"omnigent": func(baseURL string) (map[string]string, []string) {
		return map[string]string{"OPENAI_API_KEY": "sk-dcprobe-0123456789abcdefghij", "OPENAI_BASE_URL": baseURL + "/v1"},
			[]string{connector.OmnigentSandboxAgentPath, "--model", "mock-model"}
	},
}

// scriptedMock drives a harness that replays scripted model responses from a
// file itself instead of calling a model endpoint. Before each run the probe
// writes the scenario's script into the container, so such a probe needs no
// mock server either.
type scriptedMock struct {
	// path is the in-container file the harness reads the script from.
	path string
	// launch returns the harness env and extra arguments that select the
	// scripted mode.
	launch func() (map[string]string, []string)
	// render is the script that answers the scenario's prompt with its one
	// shell call and closing text (sc nil: a plain text answer).
	render func(sc *mockScenario) ([]byte, error)
}

// scriptedMockFile is one scenario's script.
type scriptedMockFile struct {
	path string
	data []byte
}

// builtinScriptedMocks are the harnesses the built-in probe drives through
// their own scripted-response mode.
var builtinScriptedMocks = map[string]scriptedMock{
	// Kiro CLI replays KIRO_MOCK_CHAT_RESPONSE (a list of turns, each a list
	// of text and tool-use events) in place of the Kiro service; the
	// placeholder KIRO_API_KEY only has to be present, and the run needs no
	// network.
	"kiro": {
		path: "/tmp/dc-hookfire-kiro-mock.json",
		launch: func() (map[string]string, []string) {
			return map[string]string{
				"KIRO_MOCK_CHAT_RESPONSE": "/tmp/dc-hookfire-kiro-mock.json",
				"KIRO_API_KEY":            "dcprobe-kiro-0123456789abcdefghij",
			}, nil
		},
		render: func(sc *mockScenario) ([]byte, error) {
			turns := []interface{}{[]interface{}{mockAuxText}}
			if sc != nil {
				turns = []interface{}{
					[]interface{}{"Running the DefenseClaw hook-fire probe command.", map[string]interface{}{
						"tool_use_id": "dcprobe-1", "name": "shell", "args": map[string]string{"command": sc.command},
					}},
					[]interface{}{sc.done},
				}
			}
			return json.Marshal(turns)
		},
	},
}

// hookSinkAdapter is how the stand-in ingress reads one harness's hooks and
// shapes its block verdict. The zero value is the Claude Code / Codex shape.
type hookSinkAdapter struct {
	// preTool is the event whose tool input the block scenario matches
	// (default PreToolUse).
	preTool string
	// wholePayload matches the block marker anywhere in the pre-tool
	// payload instead of its tool_input field (Copilot sends toolArgs).
	wholePayload bool
	// hookOutput renders the connector's hook_output block directive.
	hookOutput func(reason string) interface{}
	// otlpAuth records an OTLP export that arrives without the sandbox
	// token as an unauthorized event, which fails the probe: the harness
	// exports OTLP to the ingress with the token its launcher hands it.
	otlpAuth bool
	// advisoryAllow answers a pre-tool call it does not block with the
	// gateway's advisory alert verdict (would_block false, the harness
	// notice in claude_code_output / codex_output) instead of a plain allow,
	// so every allowed run also proves an alert never blocks a tool.
	advisoryAllow bool
}

var hookSinkAdapters = map[string]hookSinkAdapter{
	"amp":        {preTool: "tool.call", wholePayload: true},
	"claudecode": {advisoryAllow: true},
	// The Codex launcher passes the OTLP Authorization header in
	// OTEL_EXPORTER_OTLP_*_HEADERS.
	"codex": {otlpAuth: true, advisoryAllow: true},
	"copilot": {preTool: "preToolUse", wholePayload: true, hookOutput: func(reason string) interface{} {
		return map[string]string{"permissionDecision": "deny", "permissionDecisionReason": reason}
	}},
	"cursor": {preTool: "preToolUse", wholePayload: true, hookOutput: func(reason string) interface{} {
		return map[string]string{"permission": "deny", "user_message": reason, "agent_message": reason}
	}},
	"devin": {wholePayload: true, hookOutput: func(reason string) interface{} {
		return map[string]string{"decision": "block", "reason": reason}
	}},
	"kiro": {preTool: "preToolUse", wholePayload: true, hookOutput: func(reason string) interface{} {
		return map[string]string{"decision": "block", "reason": reason}
	}},
	"opencode": {preTool: "tool.execute.before", wholePayload: true, hookOutput: func(reason string) interface{} {
		return map[string]string{"decision": "deny", "reason": reason}
	}},
	"antigravity": {wholePayload: true, hookOutput: func(reason string) interface{} {
		return map[string]string{"decision": "deny", "reason": reason}
	}},
	"hermes": {preTool: "pre_tool_call", hookOutput: func(reason string) interface{} {
		return map[string]string{"decision": "block", "reason": reason}
	}},
	// OmniGent's policy bridge maps the top-level action to DENY itself.
	"omnigent": {preTool: "PreToolUse"},
	"openhands": {preTool: "PreToolUse", hookOutput: func(reason string) interface{} {
		return map[string]string{"decision": "deny", "reason": reason}
	}},
}

// preToolEvent is the event whose tool input the block scenario matches.
func (a hookSinkAdapter) preToolEvent() string {
	if a.preTool == "" {
		return "PreToolUse"
	}
	return a.preTool
}

// hookEventName reads the event a hook request reports: the out-of-band
// event header the Codex hook (X-DefenseClaw-Hook-Event), the Copilot hook
// (whose native payload has no event field) and the Antigravity hook send,
// else the payload's hook_event_name (Claude Code, Codex, Hermes, OmniGent)
// or event_type (OpenHands).
func hookEventName(r *http.Request, payload map[string]json.RawMessage) string {
	for _, header := range []string{"X-DefenseClaw-Hook-Event", "X-DefenseClaw-Copilot-Event", "X-DefenseClaw-Antigravity-Event"} {
		if name := r.Header.Get(header); name != "" {
			return name
		}
	}
	for _, key := range []string{"hook_event_name", "event_type"} {
		var name string
		if raw, ok := payload[key]; ok && json.Unmarshal(raw, &name) == nil && name != "" {
			return name
		}
	}
	return ""
}

// blocks reports whether a hook request is the block scenario's pre-tool
// call.
func (a hookSinkAdapter) blocks(event string, body []byte, payload map[string]json.RawMessage, marker string) bool {
	if event != a.preToolEvent() {
		return false
	}
	if a.wholePayload {
		return bytes.Contains(body, []byte(marker))
	}
	return bytes.Contains(payload["tool_input"], []byte(marker))
}

// HookEvent is one request the stand-in ingress received.
type HookEvent struct {
	Path           string `json:"path"`
	Event          string `json:"event,omitempty"`
	Authorized     bool   `json:"authorized"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
	Blocked        bool   `json:"blocked,omitempty"`
	// Alerted marks a pre-tool call answered with an advisory alert.
	Alerted bool `json:"alerted,omitempty"`
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
	// hostGateway is the IPv4 address Docker mapped host.docker.internal
	// to in a relay-mode run, which the MicroVM scenario's hosts file
	// names.
	hostGateway string
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
	// ScenarioInteractive starts the harness TUI on a terminal, types the
	// allow prompt and quits (interactiveLaunches).
	ScenarioInteractive = "interactive"
	// ScenarioMicroVM runs the allow prompt again with the name resolution
	// of an OpenShell MicroVM (below). Its verdict is kept apart
	// (HookFireResult.MicroVMProblem, Record.MicroVMVerified): only a
	// driver without a hosts file (openshell.Driver.HostsFile) needs it.
	ScenarioMicroVM = "microvm"
)

// The MicroVM scenario gives the harness the name resolution OpenShell
// 0.1.1's vm driver gives a sandbox workload. The driver makes its root
// disk from a `docker export`, so Docker's init layer leaves /etc/hosts
// empty, and its guest init writes an /etc/resolv.conf for a loopback DNS
// relay that answers localhost with SERVFAIL. The scenario mounts an
// /etc/hosts without localhost or the hostname, which names only what the
// probe's own plumbing needs (the stand-in ingress, and in relay mode the
// host the relay and the mock are reached at), as a MicroVM's supervisor
// answers those, and a resolv.conf like the guest's whose resolver has no
// server: in relay mode the container's own 127.0.0.53, as in the guest;
// on the host network the probe's own sink address, whose port 53 nothing
// of the probe's listens on (127.0.0.53 there is systemd-resolved, which
// answers localhost). The image's own nsswitch.conf is kept, as the vm
// driver keeps it.

// microVMResolverOptions are the options of the guest's resolv.conf.
const microVMResolverOptions = "options timeout:2 attempts:2\n"

// microVMRelayResolver is the guest's DNS relay address, which nothing in
// a relay-mode probe container listens on.
const microVMRelayResolver = "127.0.0.53"

// interactiveLaunch is how the probe drives a harness TUI on a pseudo
// terminal: it waits for the TUI to settle, types the scenario prompt, waits
// for the mock's closing text and types quit.
type interactiveLaunch struct {
	quit string
}

// interactiveLaunches are the harnesses the probe also starts on a
// terminal, because their TUI does what their headless mode never does:
// OmniGent's first-launch theme picker runs only when a terminal is attached
// and wrote the image's root-owned configuration, which ended every session
// before the REPL started.
var interactiveLaunches = map[string]interactiveLaunch{
	"omnigent": {quit: "/exit"},
}

// interactiveDoneText is the part of the built-in mock's closing text for
// the allow prompt the pty driver waits for.
const interactiveDoneText = "marker file was written"

// ptyDriver runs argv[5:] on a pseudo terminal (120x40), logging everything
// it prints to /tmp/dc-hookfire.out: it waits (up to 45 s) until the TUI is
// quiet for two seconds, types argv[2] and Enter, waits up to argv[1]
// seconds for argv[3] (escape sequences and line breaks removed), types
// argv[4] and Enter, and exits with the harness's status (128+n for a
// signal), ending it if it does not quit (SIGTERM, then SIGKILL, 5 s
// apart). It waits for that status by the clock, not by reads: the
// terminal closes as the harness exits, a moment before the kernel lets
// its status be collected, and a closed terminal answers at once. It
// answers cursor-position requests as a terminal would.
const ptyDriver = `import fcntl, os, pty, re, select, signal, struct, sys, termios, time
limit, keys, done, quit = float(sys.argv[1]), sys.argv[2], sys.argv[3].encode(), sys.argv[4]
pid, fd = pty.fork()
if pid == 0:
    try:
        fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
        os.execv(sys.argv[5], sys.argv[5:])
    finally:
        os._exit(127)
log = open(os.environ.get("DC_HOOKFIRE_OUT", "/tmp/dc-hookfire.out"), "wb")
seen = b""
ansi = re.compile(rb"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]|[\r\n]")
def pump(seconds, until=None, quiet=None):
    global seen
    end, last = time.time() + seconds, time.time()
    while time.time() < end:
        ready, _, _ = select.select([fd], [], [], 0.2)
        if not ready:
            if quiet and seen and time.time() - last >= quiet:
                return True
            continue
        try:
            data = os.read(fd, 65536)
        except OSError:
            return False
        if not data:
            return False
        log.write(data)
        log.flush()
        seen += data
        last = time.time()
        if b"\x1b[6n" in data:
            os.write(fd, b"\x1b[1;1R")
        if until and until in ansi.sub(b"", seen):
            return True
    return True
def send(text):
    os.write(fd, text.encode())
    time.sleep(0.5)
    os.write(fd, b"\r")
if pump(45, quiet=2.0):
    send(keys)
    if pump(limit, until=done):
        pump(5, quiet=1.5)
        send(quit)
        pump(20)
code = 125
for sig in (None, signal.SIGTERM, signal.SIGKILL):
    if sig:
        try:
            os.kill(pid, sig)
        except ProcessLookupError:
            pass
    end = time.time() + 5
    while True:
        got, status = os.waitpid(pid, os.WNOHANG)
        if got or time.time() >= end:
            break
        if not pump(0.1):
            time.sleep(0.05)
    if got:
        code = os.waitstatus_to_exitcode(status)
        break
log.close()
sys.exit(128 - code if code < 0 else code)
`

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
	// mockScript, for a scripted-mock harness, is written before the run.
	mockScript *scriptedMockFile
	// interactive starts the harness TUI on a pseudo terminal and types
	// the prompt, in place of a headless run.
	interactive *interactiveLaunch
	// microVM runs with a MicroVM's name resolution (ScenarioMicroVM);
	// hostGateway is what host.docker.internal maps to in relay mode.
	microVM     bool
	hostGateway string
}

// HookFireResult is the outcome of HookFireProbe.
type HookFireResult struct {
	Network HookFireNetwork `json:"network"`
	Runs    []HookFireRun   `json:"runs"`
	// MicroVMProblem says why the harness does not work with a MicroVM's
	// name resolution (ScenarioMicroVM); empty when it does. It does not
	// fail the probe: only a MicroVM gateway refuses such an image.
	MicroVMProblem string `json:"microvm_problem,omitempty"`
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
// MicroVMVerified is set with HookFireVerified when the MicroVM scenario
// passed too, and MicroVMProblem says why it did not.
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
		r.MicroVMVerified = verified && res.MicroVMProblem == "" && ranScenario(res, ScenarioMicroVM)
		r.MicroVMProblem = res.MicroVMProblem
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

// microVMDockerArgs are the network flags of a MicroVM-scenario container:
// dockerArgs without the --add-host entries, which Docker drops once the
// container mounts its own /etc/hosts (microVMFiles names them instead).
func (n hookFireNet) microVMDockerArgs() []string {
	if n.mode == HookFireNetworkRelay {
		return nil
	}
	return []string{"--network", "host"}
}

// microVMFiles are the /etc/hosts and /etc/resolv.conf of a MicroVM
// scenario (ScenarioMicroVM): no localhost and no hostname, only the
// names the probe reaches the stand-in ingress and the mock by, and a
// resolver no server answers at. hostGateway is the address Docker maps
// host.docker.internal to, which relay mode needs.
func (n hookFireNet) microVMFiles(hostGateway string) (hosts, resolv string, err error) {
	if n.mode != HookFireNetworkRelay {
		return n.bindHost + "\t" + connector.SandboxIngressHost + "\n", "nameserver " + n.bindHost + "\n" + microVMResolverOptions, nil
	}
	if ip := net.ParseIP(hostGateway); ip == nil || ip.To4() == nil {
		return "", "", fmt.Errorf("openshell image: the hook-fire probe could not tell which address host.docker.internal maps to (%q), which its MicroVM scenario names", hostGateway)
	}
	return "127.0.0.1\t" + connector.SandboxIngressHost + "\n" + hostGateway + "\thost.docker.internal\n",
		"nameserver " + microVMRelayResolver + "\n" + microVMResolverOptions, nil
}

// scriptPrefix starts the in-container relay (relay mode) and waits until
// the baked ingress port accepts connections, after reporting the address
// Docker maps host.docker.internal to (hostGateway). Exit 96 means the
// probe could not run, which says nothing about the image.
func (n hookFireNet) scriptPrefix(ingressPort int) string {
	if n.mode != HookFireNetworkRelay {
		return ""
	}
	port := strconv.Itoa(ingressPort)
	return "relay_gw=\"$(/usr/bin/getent ahostsv4 host.docker.internal 2>/dev/null)\" && echo \"::host-gateway=${relay_gw%% *}\"\n" +
		"relay_node=\"$(command -v node 2>/dev/null)\" || relay_node=\"\"\n" +
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
	required, ok := requiredHookEvents[c.Spec.Harness.Name]
	if !ok {
		return HookFireResult{}, fmt.Errorf("openshell image: no hook-fire contract for %s", c.Spec.Harness.Name)
	}
	adapter := hookSinkAdapters[c.Spec.Harness.Name]
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
	scripted, isScripted := builtinScriptedMocks[c.Spec.Harness.Name]
	if builtin && !isScripted {
		if launch, ok = builtinMockLaunch[c.Spec.Harness.Name]; !ok {
			reason := "no built-in mock LLM wiring"
			if v := c.Spec.Harness.Verification(); v.Status == harness.Unverified && v.Note != "" {
				reason += ": " + v.Note
			}
			// The message reaches `sandbox image build` and setup: name
			// the consequence, not the Go option a caller could set.
			return result, fmt.Errorf("openshell image: %s has %s, so DefenseClaw cannot prove its hooks fire and its image stays unverified", c.Spec.Harness.Name, reason)
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
	sink := &hookSink{token: "dcprobe-" + token, adapter: adapter}
	sinkPort, stopSink, err := serveHTTP(netw.bindHost, netw.sinkPort, sink)
	if err != nil {
		return result, fmt.Errorf("openshell image: hook-fire sink: %w", err)
	}
	defer stopSink()
	netw.sinkPort = sinkPort
	if builtin {
		if isScripted {
			opts.Env, opts.Args = scripted.launch()
		} else {
			mockPort, stopMock, err := serveHTTP(netw.bindHost, 0, newMockLLM(builtinMockScenarios...))
			if err != nil {
				return result, fmt.Errorf("openshell image: hook-fire mock LLM: %w", err)
			}
			defer stopMock()
			opts.Env, opts.Args = launch("http://" + net.JoinHostPort(netw.containerHost, strconv.Itoa(mockPort)))
		}
		opts.Prompt, opts.AllowSideEffect = builtinAllowPrompt, builtinAllowSideEffect
		opts.Block = &BlockScenario{Prompt: builtinBlockPrompt, Marker: builtinBlockMarker, SideEffect: builtinBlockSideEffect}
	}

	run := func(sc hookFireScenario) (HookFireRun, error) {
		if builtin && isScripted {
			script, err := scripted.render(newMockLLM(builtinMockScenarios...).pick(sc.prompt))
			if err != nil {
				return HookFireRun{Scenario: sc.name}, err
			}
			sc.mockScript = &scriptedMockFile{path: scripted.path, data: script}
		}
		r, err := b.hookFireRun(ctx, c, ref, opts, netw, sink, sc)
		result.Runs = append(result.Runs, r)
		return r, err
	}
	var problems []string
	sideEffect := func(r HookFireRun, sc hookFireScenario, prefix string) {
		if p := sideEffectProblem(r, sc); p != "" {
			problems = append(problems, prefix+p)
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
			problems = append(problems, "the block scenario never reached a "+adapter.preToolEvent()+" carrying the marker")
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
	if il, ok := interactiveLaunches[c.Spec.Harness.Name]; ok && builtin {
		ttySc := hookFireScenario{name: ScenarioInteractive, prompt: opts.Prompt, sideEffect: opts.AllowSideEffect, wantSideEffect: true, interactive: &il}
		tty, err := run(ttySc)
		if err != nil {
			return result, err
		}
		const prefix = "in the interactive (terminal) launch, "
		if tty.ExitCode != 0 {
			problems = append(problems, fmt.Sprintf("%sthe harness exited %d", prefix, tty.ExitCode))
		}
		for _, problem := range requiredHookProblems(tty, required) {
			problems = append(problems, prefix+problem)
		}
		sideEffect(tty, ttySc, prefix)
	}
	vmSc := hookFireScenario{name: ScenarioMicroVM, prompt: opts.Prompt, sideEffect: opts.AllowSideEffect, wantSideEffect: true,
		microVM: true, hostGateway: allow.hostGateway}
	vm, err := run(vmSc)
	if err != nil {
		return result, err
	}
	result.MicroVMProblem = microVMProblem(c.Spec.Harness.DisplayName, vm, vmSc, required)
	if len(problems) > 0 {
		return result, fmt.Errorf("openshell image %s hook-fire probe failed: %w: %s", c.Tag, ErrHooksNotFired, strings.Join(problems, "; "))
	}
	return result, nil
}

// sideEffectProblem says what is wrong with the side effect a scenario
// left, or "".
func sideEffectProblem(r HookFireRun, sc hookFireScenario) string {
	switch {
	case sc.sideEffect == "":
	case r.SideEffectPresent == nil:
		return "the probe could not tell whether " + sc.sideEffect + " exists"
	case sc.wantSideEffect && !*r.SideEffectPresent:
		return "the allowed tool call never ran (" + sc.sideEffect + " is missing)"
	case !sc.wantSideEffect && *r.SideEffectPresent:
		return "the blocked tool call still ran (" + sc.sideEffect + " exists)"
	}
	return ""
}

// microVMProblem says why harness did not work in the MicroVM scenario's
// run r, or "" when it did: every required hook fired and the allowed tool
// call ran. A harness that could not resolve localhost is named as such,
// with the line it printed.
func microVMProblem(harnessName string, r HookFireRun, sc hookFireScenario, required []string) string {
	problems := requiredHookProblems(r, required)
	if p := sideEffectProblem(r, sc); p != "" {
		problems = append(problems, p)
	}
	if len(problems) == 0 {
		return ""
	}
	if line, ok := openshell.LocalhostLookupFailure(r.Output); ok {
		return fmt.Sprintf("%s cannot resolve localhost in an OpenShell MicroVM: it printed %q. A MicroVM's /etc/hosts is empty and its DNS relay "+
			"does not answer localhost; the image answers localhost there only to programs that use the system resolver (nss-myhostname)", harnessName, line)
	}
	if r.ExitCode != 0 {
		problems = append([]string{fmt.Sprintf("%s exited %d", harnessName, r.ExitCode)}, problems...)
	}
	return "with the name resolution of an OpenShell MicroVM (an empty /etc/hosts, and a DNS relay that does not answer localhost), " + strings.Join(problems, "; ")
}

// ranScenario reports whether res holds a run of scenario.
func ranScenario(res HookFireResult, scenario string) bool {
	for _, r := range res.Runs {
		if r.Scenario == scenario {
			return true
		}
	}
	return false
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
	launch := harness.LaunchOptions{Mode: harness.Headless, Yolo: !sc.safe, Prompt: sc.prompt, Args: opts.Args}
	if sc.interactive != nil {
		// The prompt is typed into the TUI instead.
		launch.Mode, launch.Prompt = harness.Interactive, ""
	}
	argv, err := c.Spec.Harness.LaunchArgv(launch)
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
	if sc.mockScript != nil {
		if !safePathRE.MatchString(sc.mockScript.path) {
			return run, fmt.Errorf("openshell image: scripted mock path %q must be a plain absolute path", sc.mockScript.path)
		}
		script += "printf '%s' " + shQuote(string(sc.mockScript.data)) + " >" + shQuote(sc.mockScript.path) + " || exit 96\n"
	}
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
				"if [ \"$named\" = 0 ]; then echo '::refusal-output-begin'; head -c 800 /tmp/dc-hookfire-refusal.out; echo; echo '::refusal-output-end'; fi\n"
			if r.cleanup != "" {
				script += r.cleanup
			} else {
				script += "rm -f " + shQuote(r.file) + "\n"
			}
		}
	}
	if sc.sideEffect != "" {
		script += "rm -f " + shQuote(sc.sideEffect) + "\n"
	}
	if sc.interactive != nil {
		// The driver owns the terminal and logs it to /tmp/dc-hookfire.out.
		script += "/usr/bin/python3 -I -S -c " + shQuote(ptyDriver) + " 75 " + shQuote(sc.prompt) + " " +
			shQuote(interactiveDoneText) + " " + shQuote(sc.interactive.quit) + " " +
			harnessCmd + " </dev/null >/tmp/dc-hookfire.driver 2>&1\n"
	} else {
		script += harnessCmd + " </dev/null >/tmp/dc-hookfire.out 2>&1\n"
	}
	script += "echo \"::rc=$?\"\n"
	if sc.interactive != nil {
		script += "if [ -s /tmp/dc-hookfire.driver ]; then echo '::driver-begin'; tail -c 1000 /tmp/dc-hookfire.driver; echo; echo '::driver-end'; fi\n"
	}
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
	netArgs := netw.dockerArgs()
	if sc.microVM {
		files, cleanup, err := b.microVMMounts(netw, sc.hostGateway)
		if err != nil {
			return run, err
		}
		defer cleanup()
		netArgs = netw.microVMDockerArgs()
		mounts = append(mounts, files...)
	}
	args := append([]string{"run", "--rm", "--name", name}, netArgs...)
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
		case strings.HasPrefix(line, "::host-gateway="):
			run.hostGateway = strings.TrimSpace(strings.TrimPrefix(line, "::host-gateway="))
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

// microVMMounts writes the MicroVM scenario's /etc/hosts and
// /etc/resolv.conf (hookFireNet.microVMFiles) to a new directory next to
// the image store (the system temp directory without one), where Docker
// Desktop's file sharing reaches them, and returns their read-only mounts
// and what removes them.
func (b *Builder) microVMMounts(netw hookFireNet, hostGateway string) ([]RunFile, func(), error) {
	hosts, resolv, err := netw.microVMFiles(hostGateway)
	if err != nil {
		return nil, nil, err
	}
	parent := ""
	if b.Store != nil {
		parent = filepath.Dir(b.Store.Path())
	}
	dir, err := os.MkdirTemp(parent, "hookfire-microvm-")
	if err != nil {
		return nil, nil, fmt.Errorf("openshell image: hook-fire MicroVM scenario: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	var mounts []RunFile
	for _, f := range []struct{ name, data, target string }{{"hosts", hosts, "/etc/hosts"}, {"resolv.conf", resolv, "/etc/resolv.conf"}} {
		p := filepath.Join(dir, f.name)
		if err := os.WriteFile(p, []byte(f.data), 0o644); err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("openshell image: hook-fire MicroVM scenario: %w", err)
		}
		if strings.ContainsAny(p, ",\n") {
			cleanup()
			return nil, nil, fmt.Errorf("openshell image: hook-fire MicroVM scenario: %q cannot be mounted", p)
		}
		mounts = append(mounts, RunFile{HostPath: p, Path: f.target})
	}
	return mounts, cleanup, nil
}

// hookSinkAlertVerdict is the gateway's answer to an advisory finding on a
// Claude Code or Codex PreToolUse (claudeCodeOutput / codexOutput).
var hookSinkAlertVerdict = func() []byte {
	notice := map[string]string{"systemMessage": "DefenseClaw hook-fire probe: an advisory finding; the tool runs"}
	b, _ := json.Marshal(map[string]interface{}{
		"action": "alert", "raw_action": "alert", "would_block": false, "severity": "HIGH",
		"reason": "DefenseClaw hook-fire probe advisory", "claude_code_output": notice, "codex_output": notice,
	})
	return b
}()

// hookSink stands in for the DefenseClaw hook ingress: it authenticates the
// bearer, records every hook, notify and OTLP request, and answers with
// DefenseClaw-shaped verdicts.
type hookSink struct {
	token   string
	adapter hookSinkAdapter
	mu      sync.Mutex
	events  []HookEvent
	otlp    int
	block   *BlockScenario
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
	ev.Event = hookEventName(r, payload)

	s.mu.Lock()
	block := s.block
	if strings.HasPrefix(r.URL.Path, "/v1/") {
		if authorized {
			s.otlp++
		} else if s.adapter.otlpAuth {
			s.events = append(s.events, HookEvent{Path: r.URL.Path, Event: "OTLP export"})
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
	if authorized && block != nil && s.adapter.blocks(ev.Event, body, payload, block.Marker) {
		ev.Blocked = true
	}
	ev.Alerted = authorized && !ev.Blocked && s.adapter.advisoryAllow && ev.Event == s.adapter.preToolEvent()
	s.events = append(s.events, ev)
	s.mu.Unlock()

	if !authorized {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if ev.Alerted {
		_, _ = w.Write(hookSinkAlertVerdict)
		return
	}
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
	verdict := map[string]interface{}{
		"action":             "block",
		"reason":             reason,
		"claude_code_output": deny,
		"codex_output":       deny,
	}
	if s.adapter.hookOutput != nil {
		verdict["hook_output"] = s.adapter.hookOutput(reason)
	}
	resp, _ := json.Marshal(verdict)
	_, _ = w.Write(resp)
}

func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("openshell image: randomness: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
