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
	"antigravity": {AntigravityStart},
}

var wave2Headless = map[string][]string{
	"opencode":    {"/usr/local/bin/opencode", "run", "{prompt}"},
	"copilot":     {"/usr/local/bin/copilot", "-p", "{prompt}", "--allow-all-tools"},
	"hermes":      {"/usr/local/bin/hermes", "chat", "-q", "{prompt}", "-Q", "--yolo", "--accept-hooks"},
	"kiro":        {"/usr/local/bin/kiro-cli-chat", "chat", "--v2", "--agent", "defenseclaw", "--no-interactive", "--trust-all-tools", "{prompt}"},
	"antigravity": {AntigravityStart, "-p", "{prompt}", "--dangerously-skip-permissions"},
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
	// "command": "'/…/cursor-hook.sh'" (Cursor runs the command through a
	// shell; the event is in the payload)
	"cursor": {{regexp.MustCompile(`'` + regexp.QuoteMeta(connector.SandboxHookDir) + `/cursor-hook\.sh'`),
		`'` + HookBinary + `' --connector cursor`}},
	// "command": "/…/devin-hook.sh" (the event is in the payload)
	"devin": {{regexp.MustCompile(regexp.QuoteMeta(connector.SandboxHookDir) + `/devin-hook\.sh`),
		HookBinary + ` --connector devin`}},
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

// AntigravityStart is the root-owned start wrapper of an Antigravity actor.
// Antigravity 1.2.12 has no system or managed hooks tier: it reads
// ~/.gemini/config/hooks.json (GAP-0117). The image therefore makes
// ~/.gemini and ~/.gemini/config root-owned directories (0755), the latter holding a root-owned
// hooks.json (0644), plus the user-owned entries agy writes there itself
// (.migrated, mcp_config.json, projects/), so the agent can neither rewrite
// nor delete nor replace the file. This wrapper refuses to start agy when
// the file differs from the root-owned canonical copy (a base image or a
// future change that left it writable) and otherwise execs agy.
const AntigravityStart = LibDir + "/kit/agy-start"

const antigravityStartScript = `#!/bin/sh
# DefenseClaw Agent Substrate actor start for Antigravity (root-owned).
# Refuses to start agy unless ~/.gemini/config/hooks.json is the root-owned,
# agent-unwritable copy of the canonical hooks, then starts agy.
home="${HOME:-/sandbox}"
canonical=/usr/local/lib/defenseclaw/antigravity/hooks.json
dir="$home/.gemini/config"
dst="$dir/hooks.json"
fail() { echo "defenseclaw: $1; refusing to start agy without DefenseClaw's hooks" >&2; exit 2; }
[ -f "$canonical" ] || fail "the canonical hooks file $canonical is missing"
if [ -L "$home/.gemini" ] || [ -L "$dir" ] || [ -L "$dst" ]; then fail "$dir is reached through a symbolic link"; fi
[ -f "$dst" ] || fail "$dst is missing"
cmp -s "$canonical" "$dst" || fail "$dst differs from the canonical hooks"
[ "$(stat -c %u "$dst" 2>/dev/null)" = 0 ] && [ "$(stat -c %u "$dir" 2>/dev/null)" = 0 ] || fail "$dst or its directory is not root-owned"
exec /usr/local/bin/agy "$@"
`

// wave2Harden applies the connector-specific ownership rules: Antigravity's
// hooks directory is root-owned (see AntigravityStart).
func wave2Harden(ov *Overlay, name string, o OverlayOptions) {
	if name != "antigravity" {
		return
	}
	hooks := path.Join(o.Home, ".gemini", "config", "hooks.json")
	dir := path.Dir(hooks)
	for i := range ov.Files {
		if ov.Files[i].Path == hooks {
			ov.Files[i].User, ov.Files[i].Mode = false, 0o644
		}
	}
	// What agy itself creates in the directory at its first start; with a
	// root-owned directory it could not, so the image creates them.
	ov.Files = append(ov.Files,
		ImageFile{Path: path.Join(dir, ".migrated"), Mode: 0o644, User: true, Data: []byte{}},
		ImageFile{Path: path.Join(dir, "mcp_config.json"), Mode: 0o644, User: true, Data: []byte{}})
	ov.UserDirs = append(ov.UserDirs, path.Join(dir, "projects"))
	// The parent is root-owned too: its owner could otherwise rename config
	// away and make a new one. antigravity-cli stays the agent's (tokens,
	// settings, cache).
	ov.RootDirs = append(ov.RootDirs, path.Dir(dir), dir)
}

// wave2UserFiles are first-run state files the agent would otherwise stop
// to ask about (folder trust), owned by the image USER under HOME.
func wave2UserFiles(name string, o OverlayOptions) []ImageFile {
	switch name {
	case "antigravity":
		start := ImageFile{Path: AntigravityStart, Mode: 0o755, Data: []byte(antigravityStartScript)}
		// The launcher records the working directory here at each start;
		// the kit has no launcher, so the image carries it.
		doc := fmt.Sprintf("{\n  \"trustedWorkspaces\": [%q]\n}\n", o.Workdir)
		return []ImageFile{start, {Path: path.Join(o.Home, ".gemini", "antigravity-cli", "settings.json"), Mode: 0o600, User: true, Data: []byte(doc)}}
	case "amp":
		// Amp has no "allow all" switch on the command line, only the
		// setting amp.dangerouslyAllowAll. A headless run has nobody to
		// answer a permission prompt, so it reads a root-owned settings file
		// with the setting (--settings-file in its argv); an interactive run
		// keeps Amp's own prompts.
		return []ImageFile{{Path: AmpHeadlessSettings, Mode: 0o644, Data: []byte("{\n  \"amp.dangerouslyAllowAll\": true\n}\n")}}
	}
	return nil
}

// AmpHeadlessSettings is the root-owned settings file of an Amp headless run.
const AmpHeadlessSettings = LibDir + "/amp/headless-settings.json"

// Wave-3 connectors (PLAN 4.3): Cursor Agent CLI, Amp and Devin CLI. Their
// only model route is a vendor account, so they run on a vendor API key that
// egress adds (CURSOR_API_KEY, AMP_API_KEY) where the vendor offers one, and
// otherwise on a sign-in held in the actor, which a managed deployment
// refuses and an open-source one allows with a warning (E9, package signin).
// Their argv comes from the pinned releases' --help (lanes/a10/HANDOFF.md).

// Wave3Connectors are the connectors this part serves.
var Wave3Connectors = []string{"cursor", "amp", "devin"}
var wave3Interactive = map[string][]string{
	"cursor": {"/usr/local/bin/cursor-agent"},
	"amp":    {"/usr/local/bin/amp"},
	"devin":  {"/usr/local/bin/devin"},
}

var wave3Headless = map[string][]string{
	"cursor": {"/usr/local/bin/cursor-agent", "-p", "{prompt}", "--force", "--trust"},
	// Amp has no command-line switch for "allow all": the setting
	// amp.dangerouslyAllowAll does that, and the image carries it in a
	// root-owned file that only a headless run reads.
	"amp":   {"/usr/local/bin/amp", "--settings-file", AmpHeadlessSettings, "-x", "{prompt}"},
	"devin": {"/usr/local/bin/devin", "--permission-mode", "dangerous", "--respect-workspace-trust", "false", "-p", "{prompt}"},
}

func init() {
	for k, v := range wave3Interactive {
		InteractiveArgv[k] = v
	}
	for k, v := range wave3Headless {
		HeadlessArgv[k] = v
	}
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
