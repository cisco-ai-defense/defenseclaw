// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package kit

import (
	"path"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// EnvRule is how the actor environment allowlist treats one of the kit's
// variables: Fixed means only Value is permitted; otherwise any value is
// (the kit sets it from the build's options, such as the gateway URL or the
// model).
type EnvRule struct {
	Value string
	Fixed bool
}

// ActorHome is the HOME of every kit image (the kitspec builds and the start
// wrappers use it).
const ActorHome = "/sandbox"

// PlaceholderSecret is the value of every credential variable in an actor
// image: egress puts the real credential on the wire.
const PlaceholderSecret = "placeholder-not-a-secret"

var (
	imageEnvOnce sync.Once
	imageEnv     map[string]EnvRule
)

// ImageEnv is the kit's documented actor environment: every variable the kit
// puts in an actor image of any connector (ActorOverlay's Env) or in the
// agent's environment (Relay.Env), with the exact value where the kit fixes
// one. The actor environment is an allowlist (substrate-1 GAP-0354,
// GAP-0355): the image environment and an ActorTemplate container's env may
// set these and the ordinary base-image settings, nothing else. A test
// renders every connector's overlay and checks it stays inside this table.
func ImageEnv() map[string]EnvRule {
	imageEnvOnce.Do(func() {
		fixed := func(v string) EnvRule { return EnvRule{Value: v, Fixed: true} }
		free := EnvRule{}
		m := map[string]EnvRule{
			"HOME": free,
			// npm reads the kit's npmrc wherever node's prefix is (GAP-0529).
			"npm_config_globalconfig": fixed(NPMGlobalConfig),
			"TMPDIR":                  fixed(path.Join(ActorHome, ".cache", "tmp")),
			// The agent's mode, set by the relay for a --task run.
			ModeEnv: free,
			// Claude Code's model route (modelEnv): the gateway URL and the
			// model come from the build.
			"CLAUDE_CODE_USE_BEDROCK":    fixed("1"),
			"ANTHROPIC_BEDROCK_BASE_URL": free,
			"AWS_BEARER_TOKEN_BEDROCK":   fixed(PlaceholderSecret),
			"AWS_REGION":                 free,
			"ANTHROPIC_BASE_URL":         free,
			"ANTHROPIC_API_KEY":          fixed(PlaceholderSecret),
			"OPENAI_API_KEY":             fixed(PlaceholderSecret),
			"CODEX_API_KEY":              fixed(PlaceholderSecret),
			// The wave-2 model routes (wave2ModelEnv).
			"COPILOT_PROVIDER_BASE_URL":   free,
			"COPILOT_PROVIDER_TYPE":       fixed("openai"),
			"COPILOT_PROVIDER_WIRE_API":   fixed("responses"),
			"COPILOT_PROVIDER_API_KEY":    fixed(PlaceholderSecret),
			"COPILOT_MODEL":               free,
			"COPILOT_PROVIDER_MODEL_ID":   free,
			"COPILOT_PROVIDER_WIRE_MODEL": free,
			"COPILOT_PROVIDER_HEADERS":    free,
			"COPILOT_PKG_CACHE_HOME":      fixed("/opt/defenseclaw-harness/copilot/cache"),
			"HERMES_DEFENSECLAW_BASE_URL": free,
			"HERMES_DEFENSECLAW_API_KEY":  fixed(PlaceholderSecret),
			"HERMES_MANAGED_DIR":          fixed("/etc/hermes"),
			"HERMES_HOME":                 fixed(path.Join(ActorHome, ".hermes")),
			"KIRO_SKIP_BINARY_PINNING":    fixed("1"),
			// Kiro's managed agent folder (the connector's artifacts).
			connector.KiroSandboxAgentDirEnv: fixed(connector.KiroSandboxAgentDir),
			// The connectors' own artifacts (SubstrateArtifacts' Env).
			connector.SandboxTokenEnv:              fixed(connector.SandboxSubstrateTokenPlaceholder),
			"CLAUDE_CODE_RESTRICT_PERSONAL_CONFIG": fixed("1"),
			"AMP_SKIP_UPDATE_CHECK":                fixed("1"),
			// Devin's root-owned XDG config home (wave2RelayEnv).
			"XDG_CONFIG_HOME": fixed(XDGConfigHome),
		}
		for _, k := range claudeCodeModelSlots {
			m[k] = free
		}
		for _, k := range []string{"SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO"} {
			m[k] = fixed(TrustBundle)
		}
		for _, set := range PhoneHomeOff {
			for k, v := range set {
				m[k] = fixed(v)
			}
		}
		imageEnv = m
	})
	return imageEnv
}
