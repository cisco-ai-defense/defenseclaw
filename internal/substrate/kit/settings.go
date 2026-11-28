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
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
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
	// RegistryTokens are the npm registry hosts a substrate.secrets entry
	// injects the Authorization header on, with the placeholder the kit's
	// npmrc sends there (NPMRegistryTokens, GAP-0529). Build-time lines for
	// launchers older than 1.0.11, which write no start files: remove in 1.0.12, when launchers older than 1.0.11 are unsupported.
	RegistryTokens []RegistryToken
}

// RegistryToken is one npm registry host that egress injects a credential
// on, and the placeholder npm sends it in the credential's place.
// Build-time path: remove in 1.0.12, when launchers older than 1.0.11 are unsupported.
type RegistryToken struct {
	Host, Placeholder string
}

// NPMGlobalConfig is the kit's npm configuration. npm reads its global
// configuration from <prefix>/etc/npmrc, and the prefix is the base image's
// (/usr for a distribution node), so the kit names this file in
// npm_config_globalconfig (GAP-0529).
const NPMGlobalConfig = "/usr/local/etc/npmrc"

// NPMBaseConfigs are the global npm configurations a base image may carry,
// by the npm it ships: npm's global file is <prefix>/etc/npmrc, and the
// prefix is the folder above node's bin folder (/usr/local for the node
// images, /usr for a distribution node). The first npm the image has wins.
var NPMBaseConfigs = []struct{ NPM, Config string }{
	{"/usr/local/bin/npm", "/usr/local/etc/npmrc"},
	{"/usr/bin/npm", "/usr/etc/npmrc"},
}

// npmEnvReference is an npmrc value that only names an environment
// variable (${NPM_TOKEN}): no value is in the file.
var npmEnvReference = regexp.MustCompile(`^\$\{[A-Za-z_][A-Za-z0-9_]*\}$`)

// npmCredentialKey reports whether an npmrc key (also a //registry/:key)
// holds a credential or a client key.
func npmCredentialKey(k string) bool {
	k = strings.ToLower(strings.TrimSpace(k))
	if i := strings.LastIndex(k, ":"); i >= 0 {
		k = k[i+1:]
	}
	switch k {
	case "_authtoken", "_auth", "_password", "password", "otp", "cert", "key", "certfile", "keyfile":
		return true
	}
	return false
}

// NPMCredential returns the key of an npmrc line that holds a credential
// or a client key. A value that only names an environment variable
// (${NPM_TOKEN}) is not a credential; comments and blank lines hold none.
// The template build (WithBaseNPMConfig) and the agent start (the
// launcher's registry files) refuse the same lines.
func NPMCredential(line string) (string, bool) {
	line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
	if line == "" || line[0] == '#' || line[0] == ';' {
		return "", false
	}
	k, v, _ := strings.Cut(line, "=")
	k, v = strings.TrimSpace(k), strings.Trim(strings.TrimSpace(v), `"'`)
	if npmCredentialKey(k) && !npmEnvReference.MatchString(v) {
		return k, true
	}
	return "", false
}

// WithBaseNPMConfig is the kit's npmrc (kitData) with the settings of the
// base image's global npmrc (base, read from path) before the kit's own.
// npm_config_globalconfig makes npm read the kit's file instead of the
// base's (GAP-0529), so the base's registry, scope registries, cafile,
// strict-ssl and proxy settings would be lost (GAP-0576); the kit's lines
// come after them and win. A base global npmrc that holds a credential is
// refused: an actor holds no secret value (D14), and egress injects
// registry credentials (substrate.secrets). A value that only names an
// environment variable is not a credential.
func WithBaseNPMConfig(kitData, base []byte, path string) ([]byte, error) {
	var keep []string
	for _, raw := range strings.Split(string(base), "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		k, _, _ := strings.Cut(line, "=")
		k = strings.TrimSpace(k)
		if strings.EqualFold(k, "globalconfig") {
			continue
		}
		if _, ok := NPMCredential(line); ok {
			return nil, fmt.Errorf("the base image's npm configuration %s sets %s, a credential: remove it from the image and bind the registry's credential in substrate.secrets (egress injects it)", path, k)
		}
		keep = append(keep, line)
	}
	if len(keep) == 0 {
		return kitData, nil
	}
	s := string(kitData)
	i := 0
	for i < len(s) && s[i] == '#' {
		j := strings.IndexByte(s[i:], '\n')
		if j < 0 {
			i = len(s)
			break
		}
		i += j + 1
	}
	block := "# From the base image's " + path + " (npm reads this file instead):\n" + strings.Join(keep, "\n") + "\n# The kit's settings:\n"
	return []byte(s[:i] + block + s[i:]), nil
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
	if err := checkModelRoute(o.Provider, o.Model); err != nil {
		return Overlay{}, err
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
	// Golden-snapshot rule (E5): no machine id in the image (an empty
	// /etc/machine-id below, none in /var/lib/dbus).
	ov.Remove = append(ov.Remove, "/var/lib/dbus/machine-id")
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
	if art.Connector == "claudecode" && cfg.Relay.ClaudeStateFile == "" {
		// The harness preseed's ~/.claude.json (GAP-0446).
		cfg.Relay.ClaudeStateFile = path.Join(o.Home, ".claude.json")
	}
	if cfg.LogDir == "" {
		cfg.LogDir = path.Join(o.Home, ".defenseclaw")
	}
	// The kit configuration is written last: it names every root-owned file
	// of the overlay (relay.protected, GAP-0439).
	ov.Files = append(ov.Files,
		ImageFile{Path: ConfigPath, Mode: 0o644},
		ImageFile{Path: "/etc/machine-id", Mode: 0o444},
		ImageFile{Path: "/etc/gitconfig", Mode: 0o644, Data: []byte(gitConfig())},
		ImageFile{Path: CredHelper, Mode: 0o755, Data: []byte(gitCredentialHelper)},
		ImageFile{Path: NPMGlobalConfig, Mode: 0o644, Data: []byte(npmConfig(o.RegistryTokens))},
	)
	if art.Connector == "codex" {
		ov.Files = append(ov.Files, ImageFile{Path: path.Join(o.Home, ".codex", "config.toml"), Mode: 0o600, User: true,
			Data: []byte(fmt.Sprintf("# DefenseClaw actor image: the working directory is trusted (the TUI trusts exact paths).\n[projects.%q]\ntrust_level = \"trusted\"\n", o.Workdir))})
	}

	ov.Files = append(ov.Files, wave2UserFiles(art.Connector, o)...)
	wave2Harden(&ov, art.Connector, o)
	// relay.protected names every root-owned file the template build attests
	// (GAP-0507): the overlay, the hook and relay binaries, and the pinned
	// agent build the template build adds (AgentReleases).
	attested := append([]ImageFile{{Path: HookBinary}, {Path: RelayBinary}}, ov.Files...)
	if r, pinned := AgentReleases[art.Connector]; pinned {
		attested = append(attested, ImageFile{Path: r.Path})
	}
	cfg.Relay.Protected = ProtectedPaths(attested, o.Home)
	kitJSON, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return Overlay{}, err
	}
	for i := range ov.Files {
		if ov.Files[i].Path == ConfigPath {
			ov.Files[i].Data = append(kitJSON, '\n')
		}
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
	ov.Env["npm_config_globalconfig"] = NPMGlobalConfig
	for k, v := range modelEnv(art.Connector, gw, o) {
		ov.Env[k] = v
	}
	return ov, nil
}

// sharedDirs are system folders that hold other software's files too: a
// root-owned kit file directly in one of them (/etc/gitconfig,
// /usr/local/etc/npmrc) protects only itself, not the folder.
var sharedDirs = map[string]bool{
	"/": true, "/etc": true, "/opt": true, "/usr": true, "/usr/bin": true, "/usr/lib": true, "/usr/share": true,
	"/usr/local": true, "/usr/local/bin": true, "/usr/local/etc": true, "/usr/local/lib": true, "/usr/local/share": true,
	"/var": true, "/run": true, "/tmp": true, "/home": true,
}

// ProtectedPaths are the paths a mount of the actor must not touch
// (GAP-0439): every root-owned file of the overlay, and every folder above
// one up to (not including) a shared system folder or HOME, such as
// /etc/claude-code and /etc/claude-code/managed-settings.d. Sorted, without
// duplicates. kit.LibDir and /etc/defenseclaw are among them.
func ProtectedPaths(files []ImageFile, home string) []string {
	seen := map[string]bool{LibDir: true, path.Dir(ConfigPath): true}
	for _, f := range files {
		if f.User || !path.IsAbs(f.Path) {
			continue
		}
		p := path.Clean(f.Path)
		seen[p] = true
		for d := path.Dir(p); !sharedDirs[d] && d != path.Clean(home); d = path.Dir(d) {
			seen[d] = true
		}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
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

// InteractiveArgv is the agent the relay starts on its PTY.
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

// bedrockModelPrefixes start a Bedrock model or inference profile id
// (us.openai.gpt-5.6-luna, anthropic.claude-...): a vendor API names its
// models without them.
var bedrockModelPrefixes = []string{"us.", "eu.", "apac.", "global.", "anthropic.", "openai.", "amazon.", "meta.", "mistral."}

// checkModelRoute refuses a Bedrock model id on a vendor API route
// (openai, anthropic). Such a template points the agent at /llm/openai or
// /llm/anthropic, which a Bedrock install does not serve, and every model
// call is refused with provider_credential_unavailable (GAP-0413: the E1
// Codex template asked Luna on /llm/openai/v1).
func checkModelRoute(provider, model string) error {
	if provider != "openai" && provider != "anthropic" {
		return nil
	}
	for _, p := range bedrockModelPrefixes {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(model)), p) {
			return fmt.Errorf("--model %q is a Bedrock model id, and the %s route serves that vendor's API: build the template with --provider bedrock", model, provider)
		}
	}
	return nil
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
			env["AWS_BEARER_TOKEN_BEDROCK"] = PlaceholderSecret
			env["AWS_REGION"] = "us-east-1"
		case "anthropic":
			env["ANTHROPIC_BASE_URL"] = gw + "/llm/anthropic"
			env["ANTHROPIC_API_KEY"] = PlaceholderSecret
		}
		if model != "" {
			for _, k := range claudeCodeModelSlots {
				env[k] = model
			}
		}
	case "codex":
		env["OPENAI_API_KEY"] = PlaceholderSecret
		env["CODEX_API_KEY"] = PlaceholderSecret
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
	// The baked rules: the generic ssh rules, then the default map
	// (config.SubstrateGitBakedRewrites, which the launcher reads as the
	// rules git applies first). An admin's own map is written into the
	// actor user's git config at run (B2 2.5) and adds to them, so the
	// image needs no rebuild per host. Rules with one target share a
	// section.
	baked := config.SubstrateGitBakedRewrites()
	for i, r := range baked {
		if i == 0 || baked[i-1].To != r.To {
			fmt.Fprintf(&b, "[url \"%s\"]\n", r.To)
		}
		fmt.Fprintf(&b, "\tinsteadOf = %s\n", r.From)
	}
	fmt.Fprintf(&b, "[credential]\n\thelper = %s\n\tuseHttpPath = false\n", CredHelper)
	fmt.Fprintf(&b, "[http]\n\tsslCAInfo = %s\n", TrustBundle)
	return b.String()
}

// gitCredentialHelper answers get with the placeholder. On erase (git
// sends it after the host refused the placeholder: no secret of the
// person's is bound there) it prints one line on stderr that names the
// host and the command to run on the person's own computer (B1 2.2). The
// host is cut to letters, digits, dots and dashes, so the agent's remote
// cannot write terminal controls or a forged command; nothing is set from
// inside the agent.
const gitCredentialHelper = `#!/bin/sh
# DefenseClaw git credential helper (Agent Substrate actor images, root-owned).
# It never holds a secret: Substrate egress swaps the placeholder for the real
# token on the hosts the token is bound to, and nowhere else.
case "${1:-}" in
get)
	while IFS= read -r line && [ -n "$line" ]; do :; done
	printf 'username=x-access-token\npassword=placeholder-not-a-secret\n'
	;;
erase)
	host=
	while IFS= read -r line && [ -n "$line" ]; do
		case "$line" in host=*) host=${line#host=} ;; esac
	done
	host=$(printf '%s' "${host%%:*}" | LC_ALL=C tr -cd 'A-Za-z0-9.-' | cut -c1-253)
	[ -n "$host" ] || exit 0
	case "$host" in
	github.com) t=github ;;
	gitlab.com) t=gitlab ;;
	bitbucket.org) t=bitbucket ;;
	*) t=TEMPLATE ;;
	esac
	printf 'DefenseClaw: %s refused the request. On your computer run: defenseclaw substrate secrets add NAME --template %s --host %s\n' "$host" "$t" "$host" >&2
	[ "$t" = TEMPLATE ] && printf 'DefenseClaw: defenseclaw substrate secrets templates lists the templates you may use.\n' >&2
	;;
esac
exit 0
`

// npmConfig is the kit's npmrc. It holds no credential. The launcher
// writes the placeholders of the registries bound in the agent's policy in
// the agent's ~/.npmrc at each start (B1 2.6), so a registry bound after the
// build needs no template rebuild. The template build still writes a
// placeholder line for each registry bound at build time (tokens), because
// a launcher older than 1.0.11 writes no start files and its agents would
// get a 401 from a private registry without them. The new launcher skips a
// host this file already names. Build-time lines: remove in 1.0.12, when launchers older than 1.0.11 are unsupported.
func npmConfig(tokens []RegistryToken) string {
	var b strings.Builder
	b.WriteString("# DefenseClaw actor image (root-owned). Registry tokens are placeholders: Substrate\n" +
		"# egress swaps each for the real credential on its bound host only. Registries bound\n" +
		"# after the build are written at agent start in ~/.npmrc.\n" +
		"update-notifier=false\nfund=false\naudit=false\n")
	for _, t := range tokens {
		fmt.Fprintf(&b, "//%s/:_authToken=%s\n", t.Host, t.Placeholder)
	}
	return b.String()
}

// NPMRegistryTokens are the build-time registry placeholders for the kit's
// npmrc: every exact host of a secret injected in the Authorization header
// (npm sends a registry's _authToken there), with the secret's placeholder
// (else PlaceholderSecret). A host pattern (*.example.com) cannot name an
// npm registry and is left out. Sorted by host; the first secret wins a
// host. Build-time path for launchers older than 1.0.11: remove in 1.0.12, when launchers older than 1.0.11 are unsupported.
func NPMRegistryTokens(secrets []config.SubstrateSecret) []RegistryToken {
	seen := map[string]bool{}
	var out []RegistryToken
	for _, s := range secrets {
		if !strings.EqualFold(strings.TrimSpace(s.Inject.Header), "Authorization") {
			continue
		}
		ph := s.Inject.Placeholder
		if ph == "" {
			ph = PlaceholderSecret
		}
		for _, h := range s.Inject.Hosts {
			h = strings.ToLower(strings.TrimSpace(h))
			if h == "" || seen[h] || strings.ContainsAny(h, "*?[]/ ") {
				continue
			}
			seen[h] = true
			out = append(out, RegistryToken{Host: h, Placeholder: ph})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}
