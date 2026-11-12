// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package kit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
)

func overlayFor(t *testing.T, h *harness.Spec, provider string) Overlay {
	t.Helper()
	art, err := SubstrateArtifacts(h.Provider, h.DefaultVersion, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	ov, err := ActorOverlay(art, OverlayOptions{Config: DefaultConfig(), Home: "/sandbox", Workdir: "/work", Provider: provider, HarnessVersion: "2.1.300"})
	if err != nil {
		t.Fatal(err)
	}
	return ov
}

func file(ov Overlay, p string) []byte {
	for _, f := range ov.Files {
		if f.Path == p {
			return f.Data
		}
	}
	return nil
}

func TestClaudeCodeOverlay(t *testing.T) {
	ov := overlayFor(t, harness.ClaudeCode, "bedrock")
	for _, f := range ov.Files {
		if bytes.Contains(f.Data, []byte(connector.SandboxIngressHost)) || bytes.Contains(f.Data, []byte("DEFENSECLAW_SANDBOX_TOKEN")) {
			t.Fatalf("%s keeps an OpenShell transport reference", f.Path)
		}
		if strings.HasSuffix(f.Path, "-hook.sh") || strings.HasSuffix(f.Path, "_sandbox.sh") || strings.Contains(f.Path, "/shims/") {
			t.Fatalf("OpenShell-only file %s kept", f.Path)
		}
	}
	var doc struct {
		AllowManagedHooksOnly bool              `json:"allowManagedHooksOnly"`
		Env                   map[string]string `json:"env"`
		Hooks                 map[string][]struct {
			Hooks []struct {
				Command string   `json:"command"`
				Args    []string `json:"args"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(file(ov, connector.ClaudeCodeSandboxDropInPath), &doc); err != nil {
		t.Fatal(err)
	}
	if !doc.AllowManagedHooksOnly || len(doc.Hooks["PreToolUse"]) == 0 {
		t.Fatalf("drop-in %+v", doc)
	}
	for ev, ms := range doc.Hooks {
		for _, m := range ms {
			for _, h := range m.Hooks {
				if h.Command != HookBinary+" --connector claudecode" || len(h.Args) != 0 {
					t.Fatalf("%s hook %q %v", ev, h.Command, h.Args)
				}
			}
		}
	}
	if doc.Env["OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"] != DefaultGatewayURL+"/v1/logs" {
		t.Fatalf("otel %q", doc.Env["OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"])
	}
	if h := string(file(ov, "/usr/local/lib/defenseclaw/otel-headers.sh")); !strings.Contains(h, `"x-defenseclaw-actor":"defenseclaw-actor-placeholder"`) ||
		strings.Contains(h, "Authorization") {
		t.Fatalf("otel helper %q", h)
	}
	var cfg Config
	if err := json.Unmarshal(file(ov, ConfigPath), &cfg); err != nil || cfg.Validate() != nil {
		t.Fatalf("kit config %v", err)
	}
	if cfg.HookContracts["claudecode"] != "claudecode-hooks-v1" || cfg.Relay.Connector != "claudecode" ||
		cfg.Relay.Workdir != "/work" || cfg.Relay.Interactive[0] != "/usr/local/bin/claude" || cfg.Relay.Headless[2] != "{prompt}" {
		t.Fatalf("kit config %+v", cfg)
	}
	for k, want := range map[string]string{
		"DISABLE_AUTOUPDATER": "1", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1", "DISABLE_TELEMETRY": "1",
		"NODE_EXTRA_CA_CERTS": TrustBundle, "SSL_CERT_FILE": TrustBundle, "TMPDIR": "/sandbox/.cache/tmp",
		"CLAUDE_CODE_USE_BEDROCK": "1", "ANTHROPIC_BEDROCK_BASE_URL": DefaultGatewayURL + "/llm/bedrock",
		"AWS_BEARER_TOKEN_BEDROCK": "placeholder-not-a-secret", "NO_UPDATE_NOTIFIER": "1",
		"ANTHROPIC_MODEL": ClaudeCodeBedrockModel, "ANTHROPIC_SMALL_FAST_MODEL": ClaudeCodeBedrockModel,
		"ANTHROPIC_DEFAULT_OPUS_MODEL": ClaudeCodeBedrockModel, "ANTHROPIC_DEFAULT_SONNET_MODEL": ClaudeCodeBedrockModel,
		"CLAUDE_CODE_SUBAGENT_MODEL": ClaudeCodeBedrockModel,
		"ANTHROPIC_CUSTOM_HEADERS":   "x-defenseclaw-actor: defenseclaw-actor-placeholder\nX-DefenseClaw-Client: claudecode-llm/1.0",
	} {
		if ov.Env[k] != want {
			t.Errorf("env %s=%q, want %q", k, ov.Env[k], want)
		}
	}
	for _, k := range []string{"ANTHROPIC_API_KEY", "AWS_SECRET_ACCESS_KEY"} {
		if _, ok := ov.Env[k]; ok {
			t.Errorf("env carries %s", k)
		}
	}
	git := string(file(ov, "/etc/gitconfig"))
	if !strings.Contains(git, "insteadOf = git@github.com:") || !strings.Contains(git, "helper = "+CredHelper) {
		t.Fatalf("gitconfig %q", git)
	}
	if !strings.Contains(string(file(ov, CredHelper)), "password=placeholder-not-a-secret") {
		t.Fatal("credential helper")
	}
}

func TestCodexOverlay(t *testing.T) {
	ov := overlayFor(t, harness.Codex, "bedrock-mantle")
	req := string(file(ov, connector.CodexSandboxRequirementsPath))
	if strings.Contains(req, "codex-hook.sh") || !strings.Contains(req, "command = '"+HookBinary+" --connector codex --event PreToolUse --hook-contract codex-hooks-v4'") ||
		!strings.Contains(req, "managed_dir = '"+HookDir+"'") || !strings.Contains(req, "allow_managed_hooks_only = true") {
		t.Fatalf("requirements:\n%s", req)
	}
	mc := string(file(ov, connector.CodexSandboxManagedConfigPath))
	for _, want := range []string{
		"notify = ['" + HookBinary + "', '--connector', 'codex', '--notify']",
		"endpoint = '" + DefaultGatewayURL + "/v1/logs'", "x-defenseclaw-actor = 'defenseclaw-actor-placeholder'", "environment = 'substrate'",
		"check_for_update_on_startup = false", "[feedback]\nenabled = false", "model_provider = 'defenseclaw'",
		"base_url = '" + DefaultGatewayURL + "/llm/openai/v1'", "web_search = 'disabled'", "multi_agent = false",
		"http_headers = { x-defenseclaw-actor = 'defenseclaw-actor-placeholder', X-DefenseClaw-Client = 'codex-llm/1.0' }",
	} {
		if !strings.Contains(mc, want) {
			t.Errorf("managed config lacks %q:\n%s", want, mc)
		}
	}
	if strings.Index(mc, "model_provider") > strings.Index(mc, "\n[") {
		t.Fatal("model_provider is not a top-level key")
	}
	if !strings.Contains(string(file(ov, "/sandbox/.codex/config.toml")), `[projects."/work"]`) {
		t.Fatal("codex project trust")
	}
	if ov.Env["OPENAI_API_KEY"] != "placeholder-not-a-secret" {
		t.Fatal("codex placeholder key")
	}
	found := false
	for _, r := range ov.Remove {
		found = found || r == HookDir+"/codex-notify.sh"
	}
	if !found {
		t.Fatalf("remove %v", ov.Remove)
	}
}

// E5: the settings layer is the same for every build, so it holds no
// per-actor value, nonce or ID.
func TestOverlayIsDeterministic(t *testing.T) {
	for _, h := range []*harness.Spec{harness.ClaudeCode, harness.Codex} {
		a, b := overlayFor(t, h, ""), overlayFor(t, h, "")
		if len(a.Files) != len(b.Files) {
			t.Fatal("file count differs")
		}
		for i := range a.Files {
			if a.Files[i].Path != b.Files[i].Path || !bytes.Equal(a.Files[i].Data, b.Files[i].Data) {
				t.Fatalf("%s differs between two renders", a.Files[i].Path)
			}
		}
	}
}

// Bedrock serves Haiku 5.5 only to Claude Code 2.1.280 and newer.
func TestClaudeCodeModelFollowsTheHarnessVersion(t *testing.T) {
	for v, want := range map[string]string{
		"2.1.156": ClaudeCodeBedrockFallbackModel, "2.1.279": ClaudeCodeBedrockFallbackModel,
		"2.1.280": ClaudeCodeBedrockModel, "2.2.0": ClaudeCodeBedrockModel, "": ClaudeCodeBedrockModel,
	} {
		if got := claudeCodeDefaultModel(v); got != want {
			t.Errorf("%q: %s, want %s", v, got, want)
		}
	}
	env := modelEnv("claudecode", "http://gw", OverlayOptions{HarnessVersion: "2.1.156", Model: "us.anthropic.claude-haiku-5-5"})
	if env["ANTHROPIC_MODEL"] != "us.anthropic.claude-haiku-5-5" {
		t.Fatal("an explicit --model must win")
	}
}
