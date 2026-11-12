// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package kit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// The settings layer of an actor image is the connector's OpenShell sandbox
// artifacts (SandboxArtifactProvider), turned into their actor variant:
//
//   - every hook command runs defenseclaw-actor-hook instead of the sandbox
//     shell hooks, which post to host.openshell.internal with a binding token;
//   - telemetry goes to the actor listener with the x-defenseclaw-actor
//     placeholder;
//   - the OpenShell-only pieces (shell hooks, launchers, shims, the egress
//     proxy profile, the supervisor) are left out: an actor has no
//     supervisor, egress is transparent and the relay starts the agent;
//   - the kit adds its configuration, git and npm settings that hold only
//     placeholders, and the per-connector phone-home switches (E7, E8).
//
// TODO(A1): when SandboxRenderTarget takes a remote ingress, render the
// artifacts with it and drop the rewrites below.

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
}

// OverlayOptions are the template-build inputs of an overlay.
type OverlayOptions struct {
	Config Config
	// Home is the image USER's HOME.
	Home string
	// Workdir is the image WORKDIR.
	Workdir string
	// Provider selects the model route: "bedrock" or "anthropic" for Claude
	// Code, "openai" or "bedrock-mantle" for Codex. Every route points at the gateway's
	// /llm/<provider> with a placeholder key (D2, D14).
	Provider string
	// Model is the default model id ("" leaves the connector's default).
	Model string
}

const openShellIngress = "http://" + connector.SandboxIngressHost + ":"

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

// ActorOverlay turns a connector's OpenShell sandbox artifacts into the
// settings layer of its actor image.
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
			data, err = claudeDropIn(data, hookCmd, gw)
		case f.Path == connector.CodexSandboxRequirementsPath:
			data, err = rewriteCodexHooks(data, art.Connector)
		case f.Path == connector.CodexSandboxManagedConfigPath:
			data, err = codexManagedConfig(data, gw, o)
		case strings.HasSuffix(f.Path, "/otel-headers.sh"):
			data = []byte(otelHeadersHelper(art.Connector))
		case strings.HasPrefix(f.Path, connector.SandboxHookDir+"/") && strings.HasSuffix(f.Path, ".sh"):
			// A connector shell hook (claude-code-hook.sh, codex-hook.sh,
			// codex-notify.sh): the actor hook replaces it.
			continue
		}
		if err != nil {
			return Overlay{}, err
		}
		if bytes.Contains(data, []byte(connector.SandboxIngressHost)) {
			return Overlay{}, fmt.Errorf("actor overlay: %s still names %s", f.Path, connector.SandboxIngressHost)
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

// InteractiveArgv is the agent the relay starts in its tmux session.
var InteractiveArgv = map[string][]string{
	"claudecode": {"/usr/local/bin/claude"},
	// Codex's own bubblewrap/Landlock sandbox cannot nest in a gVisor or
	// microVM actor (as in OpenShell); "untrusted" asks before commands
	// outside its read-only set, and the DefenseClaw hooks check each one.
	"codex": {"/usr/local/bin/codex", "-c", `sandbox_mode="danger-full-access"`, "-c", `approval_policy="untrusted"`},
}

// HeadlessArgv is each wave-1 connector's headless mode for --task (PLAN
// 4.4). Nobody can answer the agent's own permission prompts in an
// unattended run, so the agent's prompts are off and the DefenseClaw hooks,
// closed on failure, are the check.
var HeadlessArgv = map[string][]string{
	"claudecode": {"/usr/local/bin/claude", "-p", "{prompt}", "--output-format", "stream-json", "--verbose", "--dangerously-skip-permissions"},
	"codex":      {"/usr/local/bin/codex", "exec", "--skip-git-repo-check", "-c", `sandbox_mode="danger-full-access"`, "-c", `approval_policy="never"`, "{prompt}"},
}

func modelEnv(connectorName, gw string, o OverlayOptions) map[string]string {
	env := map[string]string{}
	switch connectorName {
	case "claudecode":
		switch o.Provider {
		case "", "bedrock":
			env["CLAUDE_CODE_USE_BEDROCK"] = "1"
			env["ANTHROPIC_BEDROCK_BASE_URL"] = gw + "/llm/bedrock"
			env["AWS_BEARER_TOKEN_BEDROCK"] = "placeholder-not-a-secret"
			env["AWS_REGION"] = "us-east-1"
		case "anthropic":
			env["ANTHROPIC_BASE_URL"] = gw + "/llm/anthropic"
			env["ANTHROPIC_API_KEY"] = "placeholder-not-a-secret"
		}
		if o.Model != "" {
			for _, k := range []string{"ANTHROPIC_MODEL", "ANTHROPIC_SMALL_FAST_MODEL", "ANTHROPIC_DEFAULT_HAIKU_MODEL",
				"ANTHROPIC_DEFAULT_SONNET_MODEL", "ANTHROPIC_DEFAULT_OPUS_MODEL"} {
				env[k] = o.Model
			}
		}
	case "codex":
		env["OPENAI_API_KEY"] = "placeholder-not-a-secret"
		env["CODEX_API_KEY"] = "placeholder-not-a-secret"
	}
	return env
}

// claudeDropIn points the managed hook matrix at the actor hook and the
// managed telemetry at the actor listener.
func claudeDropIn(data []byte, hookCmd, gw string) ([]byte, error) {
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
		for k, v := range env {
			if s, ok := v.(string); ok {
				env[k] = rewriteIngress(s, gw)
			}
		}
		env["OTEL_RESOURCE_ATTRIBUTES"] = "defenseclaw.connector=claudecode,service.name=claudecode,defenseclaw.sandbox.runtime=substrate"
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

// rewriteIngress replaces the OpenShell ingress origin with the gateway's.
func rewriteIngress(s, gw string) string {
	i := strings.Index(s, openShellIngress)
	if i < 0 {
		return s
	}
	rest := s[i+len(openShellIngress):]
	j := 0
	for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
		j++
	}
	return s[:i] + gw + rest[j:]
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
	var lines []string
	for _, line := range strings.Split(s, "\n") {
		line = rewriteIngress(line, gw)
		if strings.HasPrefix(line, "environment = 'openshell'") {
			line = "environment = 'substrate'"
		}
		lines = append(lines, line)
		if line == "x-defenseclaw-source = 'codex'" {
			lines = append(lines, "x-defenseclaw-actor = '"+PlaceholderValue+"'")
		}
	}
	s = strings.Join(lines, "\n")
	s = strings.Replace(s, "(OpenShell sandbox image, root-owned)", "(Agent Substrate actor image, root-owned)", 1)
	s = strings.Replace(s, "\n[analytics]\n", "\n[feedback]\nenabled = false\n\n[analytics]\n", 1)
	// The model route: the gateway's OpenAI Responses route with a
	// placeholder key (D2, D14). Top-level keys must come before the first
	// table.
	model := ""
	if o.Model != "" {
		model = fmt.Sprintf("model = %q\n", o.Model)
	}
	top := model + "model_provider = 'defenseclaw'\n"
	if o.Provider == "bedrock-mantle" {
		// Mantle's OpenAI-compatible models serve function tools only
		// (as the OpenShell harness's Mantle profile).
		top += "web_search = 'disabled'\n"
		s = strings.Replace(s, "\n[features]\n", "\n[features]\nmulti_agent = false\n", 1)
	}
	if i := strings.Index(s, "\n["); i >= 0 {
		s = s[:i+1] + top + s[i+1:]
	}
	s += fmt.Sprintf("\n[model_providers.defenseclaw]\nname = 'DefenseClaw'\nbase_url = '%s/llm/openai/v1'\nenv_key = 'OPENAI_API_KEY'\nwire_api = 'responses'\n", gw)
	return []byte(s), nil
}

func otelHeadersHelper(connectorName string) string {
	return fmt.Sprintf(`#!/bin/sh
# defenseclaw-managed-hook v1
# DefenseClaw Claude Code otelHeadersHelper (Agent Substrate actor images).
# Substrate egress replaces the placeholder with the actor JWT.
printf '{"%s":"%s","x-defenseclaw-source":"%s","x-defenseclaw-client":"%s-otel/1.0"}\n'
`, PlaceholderHeader, PlaceholderValue, connectorName, connectorName)
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
