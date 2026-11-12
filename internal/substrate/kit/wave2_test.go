// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package kit

import (
	"bytes"
	"encoding/json"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
)

func wave2Overlay(t *testing.T, name string) Overlay {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("sandbox artifacts render on Linux and macOS hosts")
	}
	h, ok := harness.Get(name)
	if !ok {
		t.Fatalf("no harness %s", name)
	}
	cfg := DefaultConfig()
	art, err := SubstrateArtifacts(h.Provider, h.DefaultVersion, cfg)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	ov, err := ActorOverlay(art, OverlayOptions{Config: cfg, Home: "/sandbox", Workdir: "/work"})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return ov
}

func TestKitHookBinaryMatchesConnectorConstant(t *testing.T) {
	if HookBinary != connector.SandboxSubstrateHookBinary {
		t.Fatalf("kit.HookBinary %q != connector.SandboxSubstrateHookBinary %q", HookBinary, connector.SandboxSubstrateHookBinary)
	}
}

// Every wave-2 connector renders for Substrate, no file keeps a reference to
// an OpenShell shell hook or transport, the model route is the gateway's
// Bedrock OpenAI route with a placeholder key, and the argv and
// phone-home tables name the connector.
func TestWave2OverlaysCarryNoOpenShellReferences(t *testing.T) {
	for _, name := range Wave2Connectors {
		ov := wave2Overlay(t, name)
		for _, f := range ov.Files {
			if bytes.Contains(f.Data, []byte("-hook.sh")) || bytes.Contains(f.Data, []byte(connector.SandboxIngressHost)) {
				t.Errorf("%s: %s keeps an OpenShell reference", name, f.Path)
			}
			if bytes.Contains(f.Data, []byte(connector.SandboxTokenEnv)) && name == "opencode" {
				t.Errorf("opencode: %s reads the binding token", f.Path)
			}
		}
		if len(InteractiveArgv[name]) == 0 || len(HeadlessArgv[name]) == 0 {
			t.Errorf("%s: no interactive or headless argv", name)
		}
		hasPrompt := false
		for _, a := range HeadlessArgv[name] {
			hasPrompt = hasPrompt || a == "{prompt}"
		}
		if !hasPrompt {
			t.Errorf("%s: the headless argv has no {prompt}", name)
		}
		if _, ok := PhoneHomeOff[name]; !ok {
			t.Errorf("%s: no phone-home entry", name)
		}
	}
}

func TestWave2HookCommandsRunTheActorHook(t *testing.T) {
	want := map[string][]string{
		"copilot":     {"/etc/github-copilot/policy.d/50-defenseclaw.json", `"bash": "'` + HookBinary + `' --connector copilot --event 'preToolUse'"`},
		"antigravity": {"/usr/local/lib/defenseclaw/antigravity/hooks.json", `"command": "` + HookBinary + ` --connector antigravity --event PreToolUse"`},
		"hermes":      {"/etc/hermes/config.yaml", "command: " + HookBinary + " --connector hermes\n"},
		"kiro":        {"/usr/local/lib/defenseclaw/kiro/defenseclaw.json", `"command": "` + HookBinary + ` --connector kiro"`},
	}
	for name, w := range want {
		ov := wave2Overlay(t, name)
		if got := string(file(ov, w[0])); !strings.Contains(got, w[1]) {
			t.Errorf("%s: %s lacks %q:\n%s", name, w[0], w[1], got)
		}
	}
	// Antigravity has a second copy the launcher used to restore from.
	ov := wave2Overlay(t, "antigravity")
	if !bytes.Equal(file(ov, "/sandbox/.gemini/config/hooks.json"), file(ov, "/usr/local/lib/defenseclaw/antigravity/hooks.json")) {
		t.Error("antigravity: the baked and canonical hooks.json differ")
	}
}

func TestHermesProviderHeadersAndMode(t *testing.T) {
	ov := wave2Overlay(t, "hermes")
	cfg := string(file(ov, "/etc/hermes/config.yaml"))
	for _, want := range []string{"api_mode: codex_responses", "extra_headers:", PlaceholderHeader + ": " + PlaceholderValue, "default: " + LunaModel, "provider: defenseclaw"} {
		if !strings.Contains(cfg, want) {
			t.Errorf("Hermes managed config lacks %q:\n%s", want, cfg)
		}
	}
	if ov.Env["HERMES_DEFENSECLAW_BASE_URL"] != DefaultGatewayURL+"/llm/bedrock/openai/v1" || ov.Env["HERMES_DEFENSECLAW_API_KEY"] == "" {
		t.Errorf("Hermes env %v", ov.Env)
	}
}

func TestOpenCodeProviderAndPluginRegistration(t *testing.T) {
	ov := wave2Overlay(t, "opencode")
	var doc struct {
		Plugin   []string `json:"plugin"`
		Model    string   `json:"model"`
		Provider map[string]struct {
			Options struct {
				BaseURL string            `json:"baseURL"`
				APIKey  string            `json:"apiKey"`
				Headers map[string]string `json:"headers"`
			} `json:"options"`
		} `json:"provider"`
	}
	if err := json.Unmarshal(file(ov, connector.OpenCodeSandboxManagedConfigPath), &doc); err != nil {
		t.Fatal(err)
	}
	p := doc.Provider["defenseclaw"]
	if len(doc.Plugin) != 1 || p.Options.BaseURL != DefaultGatewayURL+"/llm/bedrock/openai/v1" || p.Options.APIKey == "" ||
		p.Options.Headers[PlaceholderHeader] != PlaceholderValue || doc.Model != "defenseclaw/"+LunaModel {
		t.Fatalf("managed config %+v", doc)
	}
	if plugin := string(file(ov, connector.OpenCodeSandboxPluginPath)); !strings.Contains(plugin, HookBinary) || !strings.Contains(plugin, `"hook-post"`) {
		t.Error("the OpenCode plugin does not exec the actor hook's hook-post")
	}
}

func TestCopilotModelEnv(t *testing.T) {
	ov := wave2Overlay(t, "copilot")
	for k, want := range map[string]string{
		"COPILOT_PROVIDER_BASE_URL": DefaultGatewayURL + "/llm/bedrock/openai/v1", "COPILOT_PROVIDER_WIRE_API": "responses",
		"COPILOT_PROVIDER_WIRE_MODEL": LunaModel, "COPILOT_AUTO_UPDATE": "false",
	} {
		if ov.Env[k] != want {
			t.Errorf("%s = %q, want %q", k, ov.Env[k], want)
		}
	}
	if h := ov.Env["COPILOT_PROVIDER_HEADERS"]; !strings.Contains(h, PlaceholderHeader+": "+PlaceholderValue) {
		t.Errorf("COPILOT_PROVIDER_HEADERS %q", h)
	}
}

// The gateway reads the command-line event of Copilot and Antigravity from a
// private header (the body has no event name).
func TestEventRegistrationHeaders(t *testing.T) {
	for conn, header := range map[string]string{"copilot": "X-DefenseClaw-Copilot-Event", "antigravity": "X-DefenseClaw-Antigravity-Event"} {
		_, _, _, r := run(t, conn, "preToolUse", `{"cwd":"/tmp"}`, &answer{200, `{"action":"allow"}`}, "closed")
		if r.Header[header] != "preToolUse" || r.Header["X-DefenseClaw-Hook-Event"] != "preToolUse" {
			t.Errorf("%s headers %v", conn, r.Header)
		}
	}
	_, _, _, r := run(t, "codex", "PreToolUse", `{"hook_event_name":"PreToolUse","cwd":"/tmp"}`, &answer{200, `{"action":"allow"}`}, "closed")
	if _, set := r.Header["X-DefenseClaw-Copilot-Event"]; set {
		t.Error("codex sends the Copilot event header")
	}
}

// Antigravity starts through the root-owned wrapper that restores hooks.json
// (GAP-0117), interactively and headless.
func TestAntigravityStartRestoresHooks(t *testing.T) {
	ov := wave2Overlay(t, "antigravity")
	w := string(file(ov, AntigravityStart))
	for _, want := range []string{"canonical=/usr/local/lib/defenseclaw/antigravity/hooks.json", "cmp -s", "not root-owned", "exec /usr/local/bin/agy"} {
		if !strings.Contains(w, want) {
			t.Errorf("wrapper lacks %q", want)
		}
	}
	for _, f := range ov.Files {
		if f.Path == AntigravityStart && (f.User || f.Mode != 0o755) {
			t.Errorf("wrapper must be root-owned 0755: %+v", f)
		}
	}
	// GAP-0117: the hooks file and its directory are root-owned.
	hooks := "/sandbox/.gemini/config/hooks.json"
	for _, f := range ov.Files {
		if f.Path == hooks && (f.User || f.Mode != 0o644) {
			t.Errorf("hooks.json must be root-owned 0644: %+v", f)
		}
	}
	if len(ov.RootDirs) != 2 || ov.RootDirs[0] != "/sandbox/.gemini" || ov.RootDirs[1] != "/sandbox/.gemini/config" {
		t.Errorf("RootDirs %v", ov.RootDirs)
	}
	if InteractiveArgv["antigravity"][0] != AntigravityStart || HeadlessArgv["antigravity"][0] != AntigravityStart {
		t.Error("antigravity does not start through the wrapper")
	}
}
