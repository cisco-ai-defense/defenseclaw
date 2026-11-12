// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func routeSettingsFixture(t *testing.T, content string) (string, SetupOpts) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if content != "" {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	prev := ClaudeCodeSettingsPathOverride
	ClaudeCodeSettingsPathOverride = path
	t.Cleanup(func() { ClaudeCodeSettingsPathOverride = prev })
	return path, SetupOpts{DataDir: t.TempDir()}
}

func readEnv(t *testing.T, path string) map[string]interface{} {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var s map[string]interface{}
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	env, _ := s["env"].(map[string]interface{})
	return env
}

func TestClaudeCodeRouteOnlyRoundTripIsByteExact(t *testing.T) {
	for name, original := range map[string]string{
		"no env":                     "{\n  \"model\": \"sonnet\"\n}",
		"prior base url and headers": "{\n  \"env\": {\n    \"ANTHROPIC_BASE_URL\": \"https://llm.corp.example\",\n    \"ANTHROPIC_CUSTOM_HEADERS\": \"X-Team: blue\"\n  },\n  \"model\": \"sonnet\"\n}",
	} {
		t.Run(name, func(t *testing.T) {
			path, opts := routeSettingsFixture(t, original)
			c := NewClaudeCodeConnector()
			route := &RouteOnlySetup{BaseURL: "http://127.0.0.1:18970/r/claudecode", Token: "dcr1-abc"}
			if err := c.ApplyRouteOnly(opts, route); err != nil {
				t.Fatal(err)
			}
			env := readEnv(t, path)
			if env["ANTHROPIC_BASE_URL"] != route.BaseURL {
				t.Fatalf("base url = %v", env["ANTHROPIC_BASE_URL"])
			}
			headers, _ := env["ANTHROPIC_CUSTOM_HEADERS"].(string)
			if !strings.Contains(headers, "X-DC-Route-Auth: dcr1-abc") {
				t.Fatalf("headers = %q", headers)
			}
			if strings.Contains(original, "X-Team") && !strings.Contains(headers, "X-Team: blue") {
				t.Fatalf("the user header was dropped: %q", headers)
			}
			// A second apply (repair, upgrade) is idempotent.
			if err := c.ApplyRouteOnly(opts, route); err != nil {
				t.Fatal(err)
			}
			if h, _ := readEnv(t, path)["ANTHROPIC_CUSTOM_HEADERS"].(string); strings.Count(h, "X-DC-Route-Auth") != 1 {
				t.Fatalf("headers after repair = %q", h)
			}
			if err := c.ApplyRouteOnly(opts, nil); err != nil {
				t.Fatal(err)
			}
			got, _ := os.ReadFile(path)
			if string(got) != original {
				t.Fatalf("restore is not byte-exact:\n got %q\nwant %q", got, original)
			}
			if _, err := os.Stat(routeBackupPath(opts.DataDir, "claudecode")); !os.IsNotExist(err) {
				t.Fatal("the route backup must be gone after restore")
			}
		})
	}
}

func TestClaudeCodeRouteOnlyKeepsUserChangesAndBedrock(t *testing.T) {
	path, opts := routeSettingsFixture(t, "{\n  \"env\": {\n    \"CLAUDE_CODE_USE_BEDROCK\": \"1\"\n  }\n}")
	c := NewClaudeCodeConnector()
	route := &RouteOnlySetup{BaseURL: "http://127.0.0.1:4100/r/claudecode", Token: "t", Bedrock: true, GatewaySigning: true}
	if err := c.ApplyRouteOnly(opts, route); err != nil {
		t.Fatal(err)
	}
	env := readEnv(t, path)
	if env["ANTHROPIC_BEDROCK_BASE_URL"] != route.BaseURL || env["CLAUDE_CODE_SKIP_BEDROCK_AUTH"] != "1" || env["ANTHROPIC_BASE_URL"] != nil {
		t.Fatalf("bedrock env = %v", env)
	}
	// The user points Bedrock elsewhere after the render: theirs stays.
	raw, _ := os.ReadFile(path)
	edited := strings.Replace(string(raw), route.BaseURL, "https://bedrock.corp.example", 1)
	if err := os.WriteFile(path, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.ApplyRouteOnly(opts, nil); err != nil {
		t.Fatal(err)
	}
	env = readEnv(t, path)
	if env["ANTHROPIC_BEDROCK_BASE_URL"] != "https://bedrock.corp.example" || env["CLAUDE_CODE_SKIP_BEDROCK_AUTH"] != nil || env["ANTHROPIC_CUSTOM_HEADERS"] != nil || env["CLAUDE_CODE_USE_BEDROCK"] != "1" {
		t.Fatalf("restored env = %v", env)
	}
}

func TestClaudeCodeRouteOnlyNilWithoutRenderTouchesNothing(t *testing.T) {
	path, opts := routeSettingsFixture(t, "{ \"model\": \"x\" }")
	if err := NewClaudeCodeConnector().ApplyRouteOnly(opts, nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != "{ \"model\": \"x\" }" {
		t.Fatalf("an unrouted connector rewrote settings.json: %q", got)
	}
}
