// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func codexRouteFixture(t *testing.T, content string) (string, SetupOpts) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	prev := CodexConfigPathOverride
	CodexConfigPathOverride = path
	t.Cleanup(func() { CodexConfigPathOverride = prev })
	return path, SetupOpts{DataDir: t.TempDir()}
}

func TestCodexRouteOnlyRoundTripIsByteExact(t *testing.T) {
	for name, original := range map[string]string{
		"built-in openai":     "model = \"gpt-5\"\n\n[hooks]\nenabled = true\n",
		"bedrock provider":    "# my config\nmodel = \"openai.gpt-oss\"\nmodel_provider = \"bedrock\" # Luna\n\n[model_providers.bedrock]\nname = \"Bedrock\"\nbase_url = \"https://bedrock-mantle.example/v1\"\nenv_key = \"AWS_BEARER_TOKEN_BEDROCK\"\nwire_api = \"responses\"\n",
		"no trailing newline": "model = \"gpt-5\"",
	} {
		t.Run(name, func(t *testing.T) {
			path, opts := codexRouteFixture(t, original)
			c := NewCodexConnector()
			route := &RouteOnlySetup{BaseURL: "http://127.0.0.1:18970/r/codex", Token: "dcr1-xyz"}
			if err := c.ApplyRouteOnly(opts, route); err != nil {
				t.Fatal(err)
			}
			if err := c.ApplyRouteOnly(opts, route); err != nil { // repair is idempotent
				t.Fatal(err)
			}
			raw, _ := os.ReadFile(path)
			var doc map[string]interface{}
			if err := parseCodexTOML(raw, &doc); err != nil {
				t.Fatalf("rendered config does not parse: %v\n%s", err, raw)
			}
			if doc["model_provider"] != "defenseclaw_route" || strings.Count(string(raw), "[model_providers.defenseclaw_route]") != 1 {
				t.Fatalf("rendered:\n%s", raw)
			}
			prov := doc["model_providers"].(map[string]interface{})["defenseclaw_route"].(map[string]interface{})
			if prov["base_url"] != "http://127.0.0.1:18970/r/codex" || prov["supports_websockets"] != false {
				t.Fatalf("provider = %v", prov)
			}
			if strings.Contains(original, "AWS_BEARER") && (prov["env_key"] != "AWS_BEARER_TOKEN_BEDROCK" || prov["wire_api"] != "responses") {
				t.Fatalf("wrapped provider settings not copied: %v", prov)
			}
			if !strings.Contains(original, "bedrock") && prov["requires_openai_auth"] != true {
				t.Fatalf("built-in openai keeps its login: %v", prov)
			}
			if err := c.ApplyRouteOnly(opts, nil); err != nil {
				t.Fatal(err)
			}
			got, _ := os.ReadFile(path)
			if string(got) != original {
				t.Fatalf("restore is not byte-exact:\n got %q\nwant %q", got, original)
			}
		})
	}
}

func TestCodexRouteOnlyRefusesAProfileProvider(t *testing.T) {
	_, opts := codexRouteFixture(t, "profile = \"work\"\n\n[profiles.work]\nmodel_provider = \"azure\"\n")
	err := NewCodexConnector().ApplyRouteOnly(opts, &RouteOnlySetup{BaseURL: "http://127.0.0.1:1/r/codex", Token: "t"})
	if err == nil || !strings.Contains(err.Error(), "profile") {
		t.Fatalf("err = %v", err)
	}
}
