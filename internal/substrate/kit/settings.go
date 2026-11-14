// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package kit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/sandboxruntime"
)

// The settings layer of an actor image is the connector's sandbox artifacts
// rendered for Agent Substrate (SubstrateArtifacts: A1's remote ingress, so
// every side transport (native OTLP, the Claude Code otelHeadersHelper, the
// Codex notify bridge) already posts to the actor listener with the
// x-defenseclaw-actor placeholder and no bearer), turned into the actor
// image's layer:
//
//   - every hook command and the Codex notify program run
//     defenseclaw-actor-hook instead of the shell hooks, so all hook traffic
//     takes the kit's kept-alive helper and carries its file facts;
//   - the OpenShell-only pieces (shell hooks, launchers, shims, the egress
//     proxy profile, the supervisor) are left out: an actor has no
//     supervisor, egress is transparent and the relay starts the agent;
//   - the kit adds its configuration, git and npm settings that hold only
//     placeholders, the model routes to the gateway's /llm with placeholder
//     keys, and the per-connector phone-home switches (E7, E8).

// ImageFile is one file of the settings layer.
type ImageFile struct {
	Path string
	Mode os.FileMode
	// User is true for files owned by the image USER (under HOME); every
	// other file is root-owned.
	User bool
	Data []byte
}

// Overlay is the settings layer for one connector.
type Overlay struct {
	Connector    string
	HookContract string
	Files        []ImageFile
	// Remove are OpenShell-only paths of the harness image the actor image
	// drops.
	Remove []string
	// Env is the image environment (ENV), sorted by Dockerfile order.
	Env map[string]string
	// UserDirs are extra directories owned by the image USER (mode 0755),
	// created before the files are copied.
	UserDirs []string
	// RootDirs are directories under HOME that end up root-owned 0755
	// after the files are copied, so the agent can neither delete nor
	// replace a root-owned file in them (Antigravity's hooks.json).
	RootDirs []string
}

// OverlayOptions are the template-build inputs of an overlay.
type OverlayOptions struct {
	Config Config
	// Home is the image USER's HOME.
	Home string
	// Workdir is the image WORKDIR.
	Workdir string
	// Provider selects the model route: "bedrock" or "anthropic" for Claude
	// Code, "bedrock" or "openai" for Codex (ModelProvider resolves ""). Every
	// route points at the gateway's /llm/<provider> with a placeholder key
	// (D2, D14).
	Provider string
	// Model is the default model id ("" leaves the connector's default).
	Model string
	// HarnessVersion is the agent version the image pins (it decides the
	// Claude Code default model, ClaudeCodeHaiku55MinVersion).
	HarnessVersion string
}

// SubstrateIngress is the remote ingress of cfg's gateway URL.
func SubstrateIngress(cfg Config) (connector.SandboxIngress, error) {
	u, err := url.Parse(cfg.GatewayURL)
	if err != nil || u.Hostname() == "" {
		return connector.SandboxIngress{}, fmt.Errorf("actor kit: gateway_url %q has no host", cfg.GatewayURL)
	}
	in := connector.SandboxIngress{Runtime: sandboxruntime.Substrate, Host: u.Hostname(), Scheme: u.Scheme, ActorHeader: true}
	switch u.Scheme {
	case "https":
		in.Port, in.CAFile = 443, TrustBundle
	case "http":
		in.Port = 80
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil {
			return connector.SandboxIngress{}, fmt.Errorf("actor kit: gateway_url port %q", p)
		}
		in.Port = n
	}
	return in, nil
}

// SubstrateArtifacts renders a connector's sandbox artifacts for an actor of
// cfg's gateway: the input of ActorOverlay.
func SubstrateArtifacts(p connector.SandboxArtifactProvider, agentVersion string, cfg Config) (connector.SandboxArtifacts, error) {
	in, err := SubstrateIngress(cfg)
	if err != nil {
		return connector.SandboxArtifacts{}, err
	}
	return p.SandboxArtifacts(connector.SandboxRenderTarget{Ingress: &in, FailMode: connector.SandboxFailMode,
		AgentVersion: agentVersion, OtelEnvironment: sandboxruntime.Substrate})
}

// openShellOnly are the harness image files an actor never uses.
var openShellOnly = []string{
	connector.SandboxHookDir + "/_hardening.sh",
	connector.SandboxHookDir + "/_sandbox.sh",
	connector.SandboxHookDir + "/inspect-request.sh",
	connector.SandboxHookDir + "/inspect-response.sh",
	connector.SandboxHookDir + "/inspect-tool-response.sh",
	connector.SandboxHookDir + "/inspect-tool.sh",
	connector.SandboxLibDir + "/bin",
	connector.SandboxLibDir + "/shims",
	"/etc/profile.d/defenseclaw-sandbox.sh",
}

// PhoneHomeOff are the per-connector environment switches that keep an agent
// from calling home or updating itself (E7). An actor's egress refuses those
// hosts anyway; the switches keep the agent from waiting on them.
//
//   - Claude Code (docs: settings, environment variables):
//     CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC (autoupdater, bug command,
//     error reporting and telemetry together), each of those four on its own,
//     DISABLE_INSTALLATION_CHECKS and DISABLE_UPDATES (the OpenShell harness
//     pins), CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL and
//     CLAUDE_CODE_IDE_SKIP_AUTO_INSTALL.
//   - Codex (docs: config reference): check_for_update_on_startup = false,
//     [analytics] enabled = false, [feedback] enabled = false and the
//     features the managed config turns off; there are no environment
//     switches. Its startup tip fetch ignores every setting and fails fast
//     because egress resolves no unlisted name.
//   - npm (both images carry node): NO_UPDATE_NOTIFIER and
//     npm_config_update_notifier, npm_config_fund, npm_config_audit.
var PhoneHomeOff = map[string]map[string]string{
	"claudecode": {
		"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC":             "1",
		"DISABLE_AUTOUPDATER":                                  "1",
		"DISABLE_BUG_COMMAND":                                  "1",
		"DISABLE_ERROR_REPORTING":                              "1",
		"DISABLE_TELEMETRY":                                    "1",
		"DISABLE_INSTALLATION_CHECKS":                          "1",
		"DISABLE_UPDATES":                                      "1",
		"CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL": "1",
		"CLAUDE_CODE_IDE_SKIP_AUTO_INSTALL":                    "1",
	},
	"codex": {},
	"npm": {
		"NO_UPDATE_NOTIFIER":         "1",
		"npm_config_update_notifier": "false",
		"npm_config_fund":            "false",
		"npm_config_audit":           "false",
	},
}

// ActorOverlay turns a connector's Substrate sandbox artifacts
// (SubstrateArtifacts) into the settings layer of its actor image.
func ActorOverlay(art connector.SandboxArtifacts, o OverlayOptions) (Overlay, error) {
	cfg := o.Config
	if err := cfg.Validate(); err != nil {
		return Overlay{}, err
	}
	if o.Home == "" || o.Workdir == "" {
		return Overlay{}, fmt.Errorf("actor overlay: home and workdir are required")
	}
	gw := strings.TrimRight(cfg.GatewayURL, "/")
	ov := Overlay{Connector: art.Connector, HookContract: art.HookContract, Env: map[string]string{}}
	hookCmd := HookBinary + " --connector " + art.Connector

	// Everything the harness rendered, rewritten or dropped.
	for _, f := range art.Files {
		if dropped(f.Path) {
			continue
		}
		data := f.Data
		var err error
		switch {
		case f.Path == connector.ClaudeCodeSandboxDropInPath:
			data, err = claudeDropIn(data, hookCmd)
		case f.Path == connector.CodexSandboxRequirementsPath:
			data, err = rewriteCodexHooks(data, art.Connector)
		case f.Path == connector.CodexSandboxManagedConfigPath:
			data, err = codexManagedConfig(data, gw, o)
		case strings.HasPrefix(f.Path, connector.SandboxHookDir+"/") && strings.HasSuffix(f.Path, ".sh"):
			// A connector shell hook (claude-code-hook.sh, codex-hook.sh,
			// codex-notify.sh): the actor hook replaces it.
			continue
		case art.Connector == "hermes" && f.Path == "/etc/hermes/config.yaml":
			data, err = hermesManagedConfig(data, o)
		case art.Connector == "opencode" && f.Path == connector.OpenCodeSandboxManagedConfigPath:
			data, err = opencodeManagedConfig(data, gw, o)
		}
		if err == nil && hookCommandRewrites[art.Connector] != nil {
			data, _, err = rewriteHookCommands(art.Connector, data)
		}
		if err != nil {
			return Overlay{}, err
		}
		if bytes.Contains(data, []byte(connector.SandboxIngressHost)) {
			return Overlay{}, fmt.Errorf("actor overlay: %s names %s: render the artifacts with SubstrateArtifacts", f.Path, connector.SandboxIngressHost)
		}
		ov.Files = append(ov.Files, ImageFile{Path: f.Path, Mode: f.Mode, User: f.Owner == connector.SandboxOwnerUser, Data: data})
	}
	ov.Remove = append(ov.Remove, openShellOnly...)
	for _, f := range art.Files {
		if strings.HasPrefix(f.Path, connector.SandboxHookDir+"/") && strings.HasSuffix(f.Path, ".sh") {
			ov.Remove = append(ov.Remove, f.Path)
		}
	}
	sort.Strings(ov.Remove)
	ov.Remove = dedupe(ov.Remove)

	// The kit's own files.
	if cfg.HookContracts == nil {
		cfg.HookContracts = map[string]string{}
	}
	cfg.HookContracts[art.Connector] = art.HookContract
	if cfg.Relay.Connector == "" {
		cfg.Relay.Connector = art.Connector
	}
	if cfg.Relay.Workdir == "" {
		cfg.Relay.Workdir = o.Workdir
	}
	if len(cfg.Relay.Interactive) == 0 {
		cfg.Relay.Interactive = InteractiveArgv[art.Connector]
	}
	if len(cfg.Relay.Headless) == 0 {
		cfg.Relay.Headless = HeadlessArgv[art.Connector]
	}
	if len(cfg.Relay.Env) == 0 {
		cfg.Relay.Env = wave2RelayEnv[art.Connector]
	}
	if cfg.LogDir == "" {
		cfg.LogDir = path.Join(o.Home, ".defenseclaw")
	}
	kitJSON, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return Overlay{}, err
	}
	ov.Files = append(ov.Files,
		ImageFile{Path: ConfigPath, Mode: 0o644, Data: append(kitJSON, '\n')},
		ImageFile{Path: "/etc/gitconfig", Mode: 0o644, Data: []byte(gitConfig())},
		ImageFile{Path: CredHelper, Mode: 0o755, Data: []byte(gitCredentialHelper)},
		ImageFile{Path: "/usr/local/etc/npmrc", Mode: 0o644, Data: []byte(npmrc)},
	)
	if art.Connector == "codex" {
		ov.Files = append(ov.Files, ImageFile{Path: path.Join(o.Home, ".codex", "config.toml"), Mode: 0o600, User: true,
			Data: []byte(fmt.Sprintf("# DefenseClaw actor image: the working directory is trusted (the TUI trusts exact paths).\n[projects.%q]\ntrust_level = \"trusted\"\n", o.Workdir))})
	}

	ov.Files = append(ov.Files, wave2UserFiles(art.Connector, o)...)
	wave2Harden(&ov, art.Connector, o)

	// The image environment.
	for k, v := range art.Env {
		ov.Env[k] = v
	}
	for _, set := range []string{art.Connector, "npm"} {
		for k, v := range PhoneHomeOff[set] {
			ov.Env[k] = v
		}
	}
	for _, k := range []string{"SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO"} {
		ov.Env[k] = TrustBundle
	}
	ov.Env["TMPDIR"] = path.Join(o.Home, ".cache", "tmp")
	ov.Env["HOME"] = o.Home
	for k, v := range modelEnv(art.Connector, gw, o) {
		ov.Env[k] = v
	}
	return ov, nil
}

func dropped(p string) bool {
	for _, d := range openShellOnly {
		if p == d || strings.HasPrefix(p, d+"/") {
			return true
		}
	}
	return false
}

func dedupe(in []string) []string {
	out := in[:0]
	for i, s := range in {
		if i == 0 || s != in[i-1] {
			out = append(out, s)
		}
	}
	return out
}

// ClaudeCodeBedrockModel is Claude Code's model on the Bedrock route of an
// actor image (owner, 2026-11-12: Claude Haiku 5.5, us-east-1 inference
// profile). Every model slot gets it: Claude Code also calls its opus and
// sonnet aliases for side tasks (substrate-1 GAP-0008), and each must be a
// model the gateway's /llm/bedrock allows.
const ClaudeCodeBedrockModel = "us.anthropic.claude-haiku-5-5"

// ClaudeCodeHaiku55MinVersion is the oldest Claude Code Bedrock serves
// Haiku 5.5 to: an older one gets "400 Claude Code <v> does not support this
// model; version 2.1.280 or newer is required" (live on E1, 2026-11-12).
const ClaudeCodeHaiku55MinVersion = "2.1.280"

// ClaudeCodeBedrockFallbackModel is the model of an image whose pinned
// Claude Code predates ClaudeCodeHaiku55MinVersion, until the harness pin
// moves (substrate-1 GAP: the OpenShell harness pins 2.1.156).
const ClaudeCodeBedrockFallbackModel = "us.anthropic.claude-haiku-4-5-20251001-v1:0"

// claudeCodeDefaultModel is the Bedrock model for a Claude Code version.
func claudeCodeDefaultModel(version string) string {
	if version == "" || versionAtLeast(version, ClaudeCodeHaiku55MinVersion) {
		return ClaudeCodeBedrockModel
	}
	return ClaudeCodeBedrockFallbackModel
}

// versionAtLeast compares dotted numeric versions.
func versionAtLeast(v, min string) bool {
	a, b := strings.Split(v, "."), strings.Split(min, ".")
	for i := 0; i < len(a) || i < len(b); i++ {
		var x, y int
		if i < len(a) {
			x, _ = strconv.Atoi(a[i])
		}
		if i < len(b) {
			y, _ = strconv.Atoi(b[i])
		}
		if x != y {
			return x > y
		}
	}
	return true
}

// claudeCodeModelSlots are the Claude Code variables that name a model.
var claudeCodeModelSlots = []string{"ANTHROPIC_MODEL", "ANTHROPIC_SMALL_FAST_MODEL", "ANTHROPIC_DEFAULT_HAIKU_MODEL",
	"ANTHROPIC_DEFAULT_SONNET_MODEL", "ANTHROPIC_DEFAULT_OPUS_MODEL", "CLAUDE_CODE_SUBAGENT_MODEL"}

// InteractiveArgv is the agent the relay starts in its tmux session.
var InteractiveArgv = map[string][]string{
	"claudecode": {"/usr/local/bin/claude"},
	// Codex's own bubblewrap/Landlock sandbox cannot nest in a gVisor or
	// microVM actor (as in OpenShell). Codex 0.168.0 no longer accepts
	// approval_policy "untrusted" (it refuses to start: "no longer
	// supported"); "on-request" is the interactive value left, and the
	// DefenseClaw hooks check each command either way (lane K1).
	"codex": {"/usr/local/bin/codex", "-c", `sandbox_mode="danger-full-access"`, "-c", `approval_policy="on-request"`},
}

// HeadlessArgv is each wave-1 connector's headless mode for --task (PLAN
// 4.4). Nobody can answer the agent's own permission prompts in an
// unattended run, so the agent's prompts are off and the DefenseClaw hooks,
// closed on failure, are the check.
var HeadlessArgv = map[string][]string{
	"claudecode": {"/usr/local/bin/claude", "-p", "{prompt}", "--output-format", "stream-json", "--verbose", "--dangerously-skip-permissions"},
	"codex":      {"/usr/local/bin/codex", "exec", "--skip-git-repo-check", "-c", `sandbox_mode="danger-full-access"`, "-c", `approval_policy="never"`, "{prompt}"},
}

// Wave1Connectors are the connectors InteractiveArgv and HeadlessArgv serve.
var Wave1Connectors = []string{"claudecode", "codex"}

// Connectors is every connector the kit builds an actor image for, waves 1
// to 3 (PLAN 4.3) in that order. Help texts list it, so they cannot drift.
func Connectors() []string {
	out := append([]string(nil), Wave1Connectors...)
	out = append(out, Wave2Connectors...)
	return append(out, Wave3Connectors...)
}

// CheckConnector refuses a connector the kit does not build an image for.
func CheckConnector(name string) error {
	for _, c := range Connectors() {
		if c == name {
			return nil
		}
	}
	return fmt.Errorf("%q is not a connector the kit builds; use %s", name, ConnectorList())
}

// ConnectorList is Connectors in words: "claudecode, codex, ... or devin".
func ConnectorList() string {
	c := Connectors()
	return strings.Join(c[:len(c)-1], ", ") + " or " + c[len(c)-1]
}

// ModelProvider resolves the model route of a template build. A named
// provider must be one the connector has a route for. Without one, Claude
// Code and Codex take Bedrock unless the install serves (substrate.llm.providers)
// their vendor API and not Bedrock: "anthropic" for Claude Code, "openai"
// for Codex. The other connectors have the Bedrock route only.
func ModelProvider(connectorName, provider string, served []string) (string, error) {
	vendor := map[string]string{"claudecode": "anthropic", "codex": "openai"}[connectorName]
	switch {
	case vendor == "":
		if provider != "" && provider != "bedrock" {
			return "", fmt.Errorf("--provider %q: %s has only the bedrock route", provider, connectorName)
		}
		return provider, nil
	case provider == "bedrock" || provider == vendor:
		return provider, nil
	case provider != "":
		return "", fmt.Errorf("--provider %q: %s routes are bedrock or %s", provider, connectorName, vendor)
	case slices.Contains(served, vendor) && !slices.Contains(served, "bedrock"):
		return vendor, nil
	}
	return "bedrock", nil
}

func modelEnv(connectorName, gw string, o OverlayOptions) map[string]string {
	env := map[string]string{}
	switch connectorName {
	case "claudecode":
		model := o.Model
		switch o.Provider {
		case "", "bedrock":
			if model == "" {
				model = claudeCodeDefaultModel(o.HarnessVersion)
			}
			env["CLAUDE_CODE_USE_BEDROCK"] = "1"
			env["ANTHROPIC_BEDROCK_BASE_URL"] = gw + "/llm/bedrock"
			env["AWS_BEARER_TOKEN_BEDROCK"] = "placeholder-not-a-secret"
			env["AWS_REGION"] = "us-east-1"
		case "anthropic":
			env["ANTHROPIC_BASE_URL"] = gw + "/llm/anthropic"
			env["ANTHROPIC_API_KEY"] = "placeholder-not-a-secret"
		}
		if model != "" {
			for _, k := range claudeCodeModelSlots {
				env[k] = model
			}
		}
	case "codex":
		env["OPENAI_API_KEY"] = "placeholder-not-a-secret"
		env["CODEX_API_KEY"] = "placeholder-not-a-secret"
	}
	for k, v := range wave2ModelEnv(connectorName, gw, o) {
		env[k] = v
	}
	return env
}

// ClaudeCodeModelHeaders are the headers Claude Code adds to every model
// call in an actor image, one per line.
const ClaudeCodeModelHeaders = PlaceholderHeader + ": " + PlaceholderValue + "\nX-DefenseClaw-Client: claudecode-llm/1.0"

// claudeDropIn points the managed hook matrix at the actor hook.
func claudeDropIn(data []byte, hookCmd string) ([]byte, error) {
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("actor overlay: Claude Code drop-in: %w", err)
	}
	n := 0
	hooks, _ := doc["hooks"].(map[string]any)
	for _, matchers := range hooks {
		list, _ := matchers.([]any)
		for _, m := range list {
			mm, _ := m.(map[string]any)
			hs, _ := mm["hooks"].([]any)
			for _, h := range hs {
				hh, _ := h.(map[string]any)
				if cmd, _ := hh["command"].(string); strings.HasPrefix(cmd, connector.SandboxHookDir+"/") {
					hh["command"] = hookCmd
					delete(hh, "args")
					n++
				}
			}
		}
	}
	if n == 0 {
		return nil, fmt.Errorf("actor overlay: the Claude Code drop-in registers no DefenseClaw hook")
	}
	if env, ok := doc["env"].(map[string]any); ok {
		env["OTEL_RESOURCE_ATTRIBUTES"] = "defenseclaw.connector=claudecode,service.name=claudecode,defenseclaw.sandbox.runtime=substrate"
		// Model calls carry the placeholder, so egress gives the gateway's
		// /llm route the actor JWT as the verified caller (D2), and
		// X-DefenseClaw-Client for the actor listener's CSRF gate
		// (GAP-0037). Claude Code splits this on newlines; it lives here,
		// not in the image ENV, because a Dockerfile ENV cannot hold a
		// newline (the "\n" stayed two characters and the second header
		// was never sent).
		env["ANTHROPIC_CUSTOM_HEADERS"] = ClaudeCodeModelHeaders
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func rewriteCodexHooks(data []byte, connectorName string) ([]byte, error) {
	old := connector.SandboxHookDir + "/codex-hook.sh "
	if !bytes.Contains(data, []byte(old)) {
		return nil, fmt.Errorf("actor overlay: the Codex requirements register no DefenseClaw hook")
	}
	out := bytes.ReplaceAll(data, []byte(old), []byte(HookBinary+" --connector "+connectorName+" "))
	out = bytes.Replace(out, []byte("(OpenShell sandbox image, root-owned)"), []byte("(Agent Substrate actor image, root-owned)"), 1)
	return out, nil
}

func codexManagedConfig(data []byte, gw string, o OverlayOptions) ([]byte, error) {
	s := string(data)
	oldNotify := "notify = ['" + connector.SandboxHookDir + "/codex-notify.sh']"
	if !strings.Contains(s, oldNotify) {
		return nil, fmt.Errorf("actor overlay: the Codex managed config has no DefenseClaw notify")
	}
	s = strings.Replace(s, oldNotify, "notify = ['"+HookBinary+"', '--connector', 'codex', '--notify']", 1)
	s = strings.Replace(s, "(OpenShell sandbox image, root-owned)", "(Agent Substrate actor image, root-owned)", 1)
	s = strings.Replace(s, "\n[analytics]\n", "\n[feedback]\nenabled = false\n\n[analytics]\n", 1)
	// The model route: a Responses route of the gateway with a placeholder
	// key (D2, D14). Top-level keys must come before the first table.
	model, base := o.Model, gw+"/llm/openai/v1"
	if o.Provider != "openai" {
		// Bedrock (the default): Bedrock Runtime's OpenAI-compatible
		// Responses API through /llm/bedrock (GAP-0187), Luna unless the
		// template names a model.
		base = gw + bedrockOpenAIPath
		if model == "" {
			model = LunaModel
		}
	}
	top := "model_provider = 'defenseclaw'\n"
	if model != "" {
		top = fmt.Sprintf("model = %q\n", model) + top
	}
	if o.Provider != "openai" {
		// Bedrock's OpenAI-family models serve function tools only (no
		// hosted web search, as the OpenShell harness's Bedrock profile).
		top += "web_search = 'disabled'\n"
		s = strings.Replace(s, "\n[features]\n", "\n[features]\nmulti_agent = false\n", 1)
	}
	if i := strings.Index(s, "\n["); i >= 0 {
		s = s[:i+1] + top + s[i+1:]
	}
	s += fmt.Sprintf("\n[model_providers.defenseclaw]\nname = 'DefenseClaw'\nbase_url = '%s'\nenv_key = 'OPENAI_API_KEY'\nwire_api = 'responses'\n"+
		"http_headers = { %s = '%s', X-DefenseClaw-Client = 'codex-llm/1.0' }\n", base, PlaceholderHeader, PlaceholderValue)
	return []byte(s), nil
}

// gitConfig is the system git configuration: SSH remotes go over HTTPS
// (egress carries no SSH), and the credential helper answers with a
// placeholder that egress swaps for the real token on the hosts the token
// is bound to (E8, D14).
func gitConfig() string {
	var b strings.Builder
	b.WriteString("# DefenseClaw actor image (root-owned): SSH remotes use HTTPS, credentials are placeholders.\n")
	b.WriteString("[url \"https://\"]\n\tinsteadOf = ssh://git@\n\tinsteadOf = git+ssh://git@\n")
	for _, host := range []string{"github.com", "gitlab.com", "bitbucket.org"} {
		fmt.Fprintf(&b, "[url \"https://%s/\"]\n\tinsteadOf = git@%s:\n", host, host)
	}
	fmt.Fprintf(&b, "[credential]\n\thelper = %s\n\tuseHttpPath = false\n", CredHelper)
	fmt.Fprintf(&b, "[http]\n\tsslCAInfo = %s\n", TrustBundle)
	return b.String()
}

const gitCredentialHelper = `#!/bin/sh
# DefenseClaw git credential helper (Agent Substrate actor images, root-owned).
# It never holds a secret: Substrate egress swaps the placeholder for the real
# token on the hosts the token is bound to, and nowhere else.
[ "${1:-}" = get ] || exit 0
while IFS= read -r line && [ -n "$line" ]; do :; done
printf 'username=x-access-token\npassword=placeholder-not-a-secret\n'
`

const npmrc = `# DefenseClaw actor image (root-owned). Registry tokens are never stored
# here: a template that binds a registry secret adds a placeholder token for
# that registry, which Substrate egress swaps on that host only.
update-notifier=false
fund=false
audit=false
`
