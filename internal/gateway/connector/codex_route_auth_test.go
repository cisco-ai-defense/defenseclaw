// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"strings"
	"testing"
)

// rel-1-0-10 GAP-0575: a Codex provider that gets its credential from an
// [auth] command (a Bedrock short-term key minted per call) keeps that
// command through route-only; a custody render (the gateway holds the
// credential) drops it.
const codexAuthCommandConfig = "model = \"openai.gpt-oss-120b\"\nmodel_provider = \"bedrock-runtime\"\n\n" +
	"[model_providers.bedrock-runtime]\nname = \"Bedrock\"\nbase_url = \"https://bedrock-runtime.us-east-1.amazonaws.com/openai/v1\"\nwire_api = \"responses\"\n\n" +
	"experimental_bearer_token = \"fixed-bearer-test\"\n\n[model_providers.bedrock-runtime.auth]\ncommand = \"/opt/dc-bedrock/bedrock-token.py\"\nargs = [\"--region\", \"us-east-1\"]\ntimeout_ms = 5000\n"

func TestCodexRouteOnlyKeepsTheAuthCommand(t *testing.T) {
	path, opts := codexRouteFixture(t, codexAuthCommandConfig)
	c := NewCodexConnector()
	route := &RouteOnlySetup{BaseURL: "http://127.0.0.1:18970/r/codex", Token: "dcr1-xyz"}
	if err := c.ApplyRouteOnly(opts, route); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	var doc map[string]interface{}
	if err := parseCodexTOML(raw, &doc); err != nil {
		t.Fatalf("rendered config does not parse: %v\n%s", err, raw)
	}
	prov := doc["model_providers"].(map[string]interface{})["defenseclaw_route"].(map[string]interface{})
	auth, ok := prov["auth"].(map[string]interface{})
	if !ok || auth["command"] != "/opt/dc-bedrock/bedrock-token.py" || len(auth["args"].([]interface{})) != 2 || prov["experimental_bearer_token"] != "fixed-bearer-test" {
		t.Fatalf("the route provider lost the auth command: %v\n%s", prov, raw)
	}
	if err := RouteOnlyDrift(c, opts, route); err != nil {
		t.Fatalf("a fresh render is drift: %v", err)
	}
	if err := c.ApplyRouteOnly(opts, nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != codexAuthCommandConfig {
		t.Fatalf("restore is not byte exact:\n%s", got)
	}
}

func TestCodexRouteOnlyCustodyDropsTheAuthCommand(t *testing.T) {
	path, opts := codexRouteFixture(t, codexAuthCommandConfig)
	c := NewCodexConnector()
	if err := c.ApplyRouteOnly(opts, &RouteOnlySetup{BaseURL: "http://127.0.0.1:18970/r/codex", Token: "dcr1-xyz", Custody: true}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	table := string(raw)[strings.Index(string(raw), "[model_providers.defenseclaw_route]"):]
	if strings.Contains(table, "bedrock-token.py") || strings.Contains(table, "fixed-bearer-test") || !strings.Contains(table, RouteOnlyPlaceholderCredential) {
		t.Fatalf("custody render keeps the agent credential command:\n%s", table)
	}
}
