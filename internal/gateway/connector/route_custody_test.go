// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// A custody render (managed macOS and Windows) replaces the Claude Code key
// and login with the placeholder, restores the user values byte for byte,
// and a drift check sees the placeholder (REVIEW-code-slice4 P1-2).
func TestClaudeCodeRouteOnlyCustodyRendersAPlaceholder(t *testing.T) {
	original := "{\n  \"env\": {\n    \"ANTHROPIC_API_KEY\": \"sk-ant-user-own\"\n  },\n  \"model\": \"sonnet\"\n}"
	path, opts := routeSettingsFixture(t, original)
	c := NewClaudeCodeConnector()
	route := &RouteOnlySetup{BaseURL: "http://127.0.0.1:18970/r/claudecode", Token: "dcr1-abc", Custody: true}
	if err := c.ApplyRouteOnly(opts, route); err != nil {
		t.Fatal(err)
	}
	env := readEnv(t, path)
	if env["ANTHROPIC_AUTH_TOKEN"] != RouteOnlyPlaceholderCredential || env["ANTHROPIC_API_KEY"] != RouteOnlyPlaceholderCredential {
		t.Fatalf("custody env = %v", env)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "sk-ant-user-own") {
		t.Fatal("the user key is still in the agent settings")
	}
	if err := RouteOnlyDrift(c, opts, route); err != nil {
		t.Fatalf("fresh custody render drift = %v", err)
	}
	if err := RouteOnlyDrift(c, opts, &RouteOnlySetup{BaseURL: route.BaseURL, Token: route.Token}); err == nil {
		t.Fatal("a custody render must differ from a passthrough render")
	}
	// The user puts a real key back: drift, and the repair replaces it.
	env["ANTHROPIC_API_KEY"] = "sk-ant-again"
	writeEnvForTest(t, path, env)
	if err := RouteOnlyDrift(c, opts, route); err == nil {
		t.Fatal("a real key next to a custody render must be drift")
	}
	if err := c.ApplyRouteOnly(opts, route); err != nil {
		t.Fatal(err)
	}
	if readEnv(t, path)["ANTHROPIC_API_KEY"] != RouteOnlyPlaceholderCredential {
		t.Fatal("repair did not put the placeholder back")
	}
	if err := c.ApplyRouteOnly(opts, nil); err != nil {
		t.Fatal(err)
	}
	if env := readEnv(t, path); env["ANTHROPIC_API_KEY"] != "sk-ant-again" {
		t.Fatalf("restore puts the last user value back: %v", env)
	}

	// Bedrock: the agent skips its own AWS auth.
	bedrock := &RouteOnlySetup{BaseURL: route.BaseURL, Token: "t", Bedrock: true, Custody: true}
	if got := claudeCodeRouteEnv(bedrock); got[claudeCodeRouteSkipBedrock] != "1" || got[claudeCodeRouteAuthToken] != "" {
		t.Fatalf("custody Bedrock env = %v", got)
	}
}

func TestClaudeCodeRouteOnlyCustodyByteExactRestore(t *testing.T) {
	original := "{\n  \"model\": \"sonnet\"\n}"
	path, opts := routeSettingsFixture(t, original)
	c := NewClaudeCodeConnector()
	if err := c.ApplyRouteOnly(opts, &RouteOnlySetup{BaseURL: "http://127.0.0.1:18970/r/claudecode", Token: "x", Custody: true}); err != nil {
		t.Fatal(err)
	}
	// Lost record: only our placeholder values are removed.
	if err := os.Remove(routeBackupPath(opts.DataDir, "claudecode")); err != nil {
		t.Fatal(err)
	}
	if err := c.ApplyRouteOnly(opts, nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); !strings.Contains(string(got), "sonnet") || strings.Contains(string(got), "ANTHROPIC_") {
		t.Fatalf("lost-record restore left: %s", got)
	}
}

// The Codex custody provider drops env_key and requires_openai_auth and
// sends a placeholder bearer; restore is byte for byte.
func TestCodexRouteOnlyCustodyRendersAPlaceholderBearer(t *testing.T) {
	for name, original := range map[string]string{
		"built-in openai login": "model = \"gpt-5\"\n",
		"env_key provider":      "model_provider = \"corp\"\n\n[model_providers.corp]\nname = \"Corp\"\nbase_url = \"https://llm.corp.example/v1\"\nenv_key = \"CORP_KEY\"\nwire_api = \"responses\"\nhttp_headers = { \"Authorization\" = \"Bearer sk-in-file\", \"X-Team\" = \"blue\" }\nenv_http_headers = { \"X-Key\" = \"CORP_KEY2\" }\n",
	} {
		t.Run(name, func(t *testing.T) {
			path, opts := codexRouteFixture(t, original)
			c := NewCodexConnector()
			route := &RouteOnlySetup{BaseURL: "http://127.0.0.1:18970/r/codex", Token: "dcr1-xyz", Custody: true}
			if err := c.ApplyRouteOnly(opts, route); err != nil {
				t.Fatal(err)
			}
			raw, _ := os.ReadFile(path)
			var doc map[string]interface{}
			if err := parseCodexTOML(raw, &doc); err != nil {
				t.Fatalf("rendered config does not parse: %v\n%s", err, raw)
			}
			prov := doc["model_providers"].(map[string]interface{})["defenseclaw_route"].(map[string]interface{})
			for _, k := range []string{"env_key", "env_key_instructions", "env_http_headers"} {
				if _, ok := prov[k]; ok {
					t.Fatalf("custody provider keeps %s: %v", k, prov)
				}
			}
			if prov["requires_openai_auth"] != false {
				t.Fatalf("custody provider must not use the ChatGPT login: %v", prov)
			}
			headers := prov["http_headers"].(map[string]interface{})
			if headers["Authorization"] != "Bearer "+RouteOnlyPlaceholderCredential || headers[RouteOnlyHeader] != "dcr1-xyz" {
				t.Fatalf("custody headers = %v", headers)
			}
			if strings.Contains(original, "X-Team") && headers["X-Team"] != "blue" {
				t.Fatalf("a non-credential header was dropped: %v", headers)
			}
			if err := RouteOnlyDrift(c, opts, route); err != nil {
				t.Fatalf("fresh custody render drift = %v", err)
			}
			if err := c.ApplyRouteOnly(opts, nil); err != nil {
				t.Fatal(err)
			}
			if got, _ := os.ReadFile(path); string(got) != original {
				t.Fatalf("restore is not byte-exact:\n got %q\nwant %q", got, original)
			}
		})
	}
}

func writeEnvForTest(t *testing.T, path string, env map[string]interface{}) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var s map[string]interface{}
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	s["env"] = env
	out, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
}
