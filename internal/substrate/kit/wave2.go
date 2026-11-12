// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package kit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// Wave-2 connectors (PLAN 4.3): OpenCode, Copilot CLI, Hermes, Kiro CLI and
// Antigravity CLI. Their settings come from the same Substrate render as
// wave 1 (SubstrateArtifacts); this file turns the hook registrations into
// kit hook calls, points the model route at the gateway and sets the
// per-connector switches (E7, E8).

// Wave2Connectors are the connectors this file serves.
var Wave2Connectors = []string{"opencode", "copilot", "hermes", "kiro", "antigravity"}

// LunaModel is the Bedrock model every non-Claude connector runs in the
// live cells (lanes/t/MODELS.md).
const LunaModel = "us.openai.gpt-5.6-luna"

// bedrockOpenAIPath is the gateway route to Bedrock's OpenAI-compatible
// endpoint: /llm/bedrock/openai/v1/{responses,chat/completions}.
const bedrockOpenAIPath = "/llm/bedrock/openai/v1"

// LLMClientHeaders are the headers every model client of a wave-2 connector
// sends to the gateway: the actor placeholder (egress swaps in the actor
// JWT) and the client tag the actor listener's request log wants.
func llmHeaders(client string) [][2]string {
	return [][2]string{{PlaceholderHeader, PlaceholderValue}, {"X-DefenseClaw-Client", client}}
}

func modelOrDefault(o OverlayOptions) string {
	if o.Model != "" {
		return o.Model
	}
	return LunaModel
}

// wave2ModelEnv is the image environment that routes a wave-2 connector's
// model calls to the gateway with placeholder keys (D2, D14).
func wave2ModelEnv(name, gw string, o OverlayOptions) map[string]string {
	env := map[string]string{}
	base := gw + bedrockOpenAIPath
	switch name {
	case "copilot":
		hdr := llmHeaders("copilot-llm/1.0")
		env["COPILOT_PROVIDER_BASE_URL"] = base
		env["COPILOT_PROVIDER_TYPE"] = "openai"
		env["COPILOT_PROVIDER_WIRE_API"] = "responses"
		env["COPILOT_PROVIDER_API_KEY"] = "placeholder-not-a-secret"
		env["COPILOT_MODEL"] = modelOrDefault(o)
		env["COPILOT_PROVIDER_MODEL_ID"] = "gpt-5.4"
		env["COPILOT_PROVIDER_WIRE_MODEL"] = modelOrDefault(o)
		env["COPILOT_PROVIDER_HEADERS"] = hdr[0][0] + ": " + hdr[0][1] + "\n" + hdr[1][0] + ": " + hdr[1][1]
		env["COPILOT_PKG_CACHE_HOME"] = "/opt/defenseclaw-harness/copilot/cache"
	case "hermes":
		env["HERMES_DEFENSECLAW_BASE_URL"] = base
		env["HERMES_DEFENSECLAW_API_KEY"] = "placeholder-not-a-secret"
		env["HERMES_MANAGED_DIR"] = "/etc/hermes"
		env["HERMES_HOME"] = path.Join(o.Home, ".hermes")
	case "kiro":
		env["KIRO_SKIP_BINARY_PINNING"] = "1"
	}
	return env
}

// wave2PhoneHome are the extra phone-home and auto-update switches of the
// wave-2 connectors (E7). Each is a documented switch of the pinned
// release (see lanes/a10/HANDOFF.md for where); the actor's egress refuses
// the hosts anyway, and J39 measures that none of them makes a start wait.
var wave2PhoneHome = map[string]map[string]string{
	"opencode":    {"OPENCODE_DISABLE_AUTOUPDATE": "1", "OPENCODE_DISABLE_MODELS_FETCH": "1", "OPENCODE_DISABLE_LSP_DOWNLOAD": "1"},
	"copilot":     {"COPILOT_AUTO_UPDATE": "false"},
	"hermes":      {"HERMES_DISABLE_LAZY_INSTALLS": "1", "HERMES_ACCEPT_HOOKS": "1"},
	"kiro":        {},
	"antigravity": {},
}

// wave2Interactive and wave2Headless extend InteractiveArgv and HeadlessArgv.
// A headless run has nobody to answer the agent's own prompts, so those are
// off and the DefenseClaw hooks, closed on failure, are the check.
var wave2Interactive = map[string][]string{
	"opencode":    {"/usr/local/bin/opencode"},
	"copilot":     {"/usr/local/bin/copilot"},
	"hermes":      {"/usr/local/bin/hermes", "--cli"},
	"kiro":        {"/usr/local/bin/kiro-cli-chat", "chat", "--v2", "--agent", "defenseclaw"},
	"antigravity": {"/usr/local/bin/agy"},
}

var wave2Headless = map[string][]string{
	"opencode":    {"/usr/local/bin/opencode", "run", "{prompt}"},
	"copilot":     {"/usr/local/bin/copilot", "-p", "{prompt}", "--allow-all-tools"},
	"hermes":      {"/usr/local/bin/hermes", "chat", "-q", "{prompt}", "-Q", "--yolo", "--accept-hooks"},
	"kiro":        {"/usr/local/bin/kiro-cli-chat", "chat", "--v2", "--agent", "defenseclaw", "--no-interactive", "--trust-all-tools", "{prompt}"},
	"antigravity": {"/usr/local/bin/agy", "-p", "{prompt}", "--dangerously-skip-permissions"},
}

// wave2RelayEnv is environment only the agent process (and its tools) gets.
// Copilot's sandboxes refuse pidfd_open, so the harness image's root-owned
// fallback is preloaded for the Node launcher (the native CLI drops it at
// load) and the Node warning about env-proxy is silenced, as the OpenShell
// launcher does.
var wave2RelayEnv = map[string]map[string]string{
	"copilot": {
		"LD_PRELOAD":   "/opt/defenseclaw-harness/copilot/lib/defenseclaw-pidfd.so",
		"NODE_OPTIONS": "--disable-warning=UNDICI-EHPA",
	},
}

// hookCommandRewrites turn each wave-2 connector's shell hook command into
// the actor hook. The agent's events bind on the command line (Copilot,
// Antigravity) or in the payload (Hermes, Kiro); the actor hook takes the
// command-line event as --event.
var hookCommandRewrites = map[string][]struct {
	re   *regexp.Regexp
	repl string
}{
	// '/…/copilot-hook.sh' --event 'preToolUse'
	"copilot": {{regexp.MustCompile(`'` + regexp.QuoteMeta(connector.SandboxHookDir) + `/copilot-hook\.sh' --event `),
		`'` + HookBinary + `' --connector copilot --event `}},
	// /…/antigravity-hook.sh PreToolUse
	"antigravity": {{regexp.MustCompile(regexp.QuoteMeta(connector.SandboxHookDir) + `/antigravity-hook\.sh ([A-Za-z]+)`),
		HookBinary + ` --connector antigravity --event $1`}},
	// command: /…/hermes-hook.sh
	"hermes": {{regexp.MustCompile(regexp.QuoteMeta(connector.SandboxHookDir) + `/hermes-hook\.sh`),
		HookBinary + ` --connector hermes`}},
	// "command": "/…/kiro-hook.sh"
	"kiro": {{regexp.MustCompile(regexp.QuoteMeta(connector.SandboxHookDir) + `/kiro-hook\.sh`),
		HookBinary + ` --connector kiro`}},
}

// rewriteHookCommands applies the connector's rewrites to a rendered file
// and reports whether it changed anything. A file that still names a shell
// hook afterwards is an error: the shell hooks are not in the actor image.
func rewriteHookCommands(name string, data []byte) ([]byte, bool, error) {
	rules := hookCommandRewrites[name]
	changed := false
	for _, r := range rules {
		if r.re.Match(data) {
			data = r.re.ReplaceAll(data, []byte(r.repl))
			changed = true
		}
	}
	if bytes.Contains(data, []byte("-hook.sh")) {
		return nil, false, fmt.Errorf("actor overlay: a %s file still names a shell hook after the rewrite", name)
	}
	return data, changed, nil
}

// hermesManagedConfig adds the gateway's client headers and the default
// model to Hermes' managed layer. The provider entry the OpenShell render
// ships reads its base URL and key from the environment; the headers carry
// the actor placeholder (model calls need it for egress to inject the JWT).
func hermesManagedConfig(data []byte, o OverlayOptions) ([]byte, error) {
	s := string(data)
	anchor := "        key_env: HERMES_DEFENSECLAW_API_KEY\n"
	if !strings.Contains(s, anchor) {
		return nil, fmt.Errorf("actor overlay: the Hermes managed config has no DefenseClaw provider key_env")
	}
	hdr := llmHeaders("hermes-llm/1.0")
	extra := "        extra_headers:\n"
	for _, h := range hdr {
		extra += fmt.Sprintf("            %s: %s\n", h[0], h[1])
	}
	s = strings.Replace(s, anchor, anchor+extra, 1)
	// Luna's chat completions route rejects max_tokens, which Hermes sends
	// for a model id it does not recognise as a gpt-5 family name
	// ("us.openai.gpt-5.6-luna"); the Responses route has no such parameter.
	if !strings.Contains(s, "        api_mode: chat_completions\n") {
		return nil, fmt.Errorf("actor overlay: the Hermes managed config has no chat_completions api_mode to switch")
	}
	s = strings.Replace(s, "        api_mode: chat_completions\n", "        api_mode: codex_responses\n", 1)
	if strings.Contains(s, "\nmodel:") {
		return nil, fmt.Errorf("actor overlay: the Hermes managed config already sets a model")
	}
	s = strings.TrimRight(s, "\n") + "\nmodel:\n    default: " + modelOrDefault(o) + "\n    provider: defenseclaw\n"
	s = strings.Replace(s, "(OpenShell sandbox image, root-owned)", "(Agent Substrate actor image, root-owned)", 1)
	return []byte(s), nil
}

// opencodeManagedConfig adds the gateway model provider to OpenCode's
// root-owned managed config (the plugin registration stays as rendered).
// The AI SDK's OpenAI provider speaks the Responses API, which is the
// route Luna's Bedrock endpoint serves for tool calls.
func opencodeManagedConfig(data []byte, gw string, o OverlayOptions) ([]byte, error) {
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("actor overlay: OpenCode managed config: %w", err)
	}
	if _, has := doc["provider"]; has {
		return nil, fmt.Errorf("actor overlay: the OpenCode managed config already has a provider")
	}
	model := modelOrDefault(o)
	headers := map[string]any{}
	for _, h := range llmHeaders("opencode-llm/1.0") {
		headers[h[0]] = h[1]
	}
	doc["provider"] = map[string]any{"defenseclaw": map[string]any{
		"npm":  "@ai-sdk/openai",
		"name": "DefenseClaw gateway",
		"options": map[string]any{
			"baseURL": gw + bedrockOpenAIPath,
			"apiKey":  "placeholder-not-a-secret",
			"headers": headers,
		},
		"models": map[string]any{model: map[string]any{
			"name": "GPT-5.6 Luna (Bedrock)", "tool_call": true, "reasoning": true,
			"limit": map[string]any{"context": 400000, "output": 32000},
		}},
	}}
	doc["model"] = "defenseclaw/" + model
	doc["small_model"] = "defenseclaw/" + model
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// wave2UserFiles are first-run state files the agent would otherwise stop
// to ask about (folder trust), owned by the image USER under HOME.
func wave2UserFiles(name string, o OverlayOptions) []ImageFile {
	switch name {
	case "antigravity":
		// The launcher records the working directory here at each start;
		// the kit has no launcher, so the image carries it.
		doc := fmt.Sprintf("{\n  \"trustedWorkspaces\": [%q]\n}\n", o.Workdir)
		return []ImageFile{{Path: path.Join(o.Home, ".gemini", "antigravity-cli", "settings.json"), Mode: 0o600, User: true, Data: []byte(doc)}}
	}
	return nil
}

func init() {
	for k, v := range wave2Interactive {
		InteractiveArgv[k] = v
	}
	for k, v := range wave2Headless {
		HeadlessArgv[k] = v
	}
	for k, v := range wave2PhoneHome {
		PhoneHomeOff[k] = v
	}
}
