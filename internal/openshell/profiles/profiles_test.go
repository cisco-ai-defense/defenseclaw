// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package profiles

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	claudeRealpath = "/opt/defenseclaw-harness/claudecode/bin/claude"
	codexRealpath  = "/usr/lib/node_modules/@openai/codex/node_modules/@openai/codex-linux-arm64/vendor/aarch64-unknown-linux-musl/bin/codex"
)

func goldenInputs() map[string]Input {
	return map[string]Input{
		IngressID:             {IngressPort: 18971},
		AnthropicID:           {Binaries: []string{claudeRealpath}},
		ClaudeOAuthID:         {Binaries: []string{claudeRealpath}},
		ClaudeBedrockMantleID: {Binaries: []string{claudeRealpath}},
		OpenAIID:              {Binaries: []string{codexRealpath}},
		CodexBedrockMantleID:  {Binaries: []string{codexRealpath}, BedrockRegion: "us-west-2"},
	}
}

func TestRenderGolden(t *testing.T) {
	update := os.Getenv("DEFENSECLAW_UPDATE_GOLDEN") == "1"
	inputs := goldenInputs()
	if len(inputs) != len(IDs()) {
		t.Fatalf("golden inputs cover %d of %d profiles", len(inputs), len(IDs()))
	}
	for id, in := range inputs {
		t.Run(id, func(t *testing.T) {
			p, err := Render(id, in)
			if err != nil {
				t.Fatalf("Render: %v", err)
			}
			golden := filepath.Join("testdata", id+".yaml")
			if update {
				if err := os.WriteFile(golden, p.YAML, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("read golden (regenerate with DEFENSECLAW_UPDATE_GOLDEN=1): %v", err)
			}
			if !bytes.Equal(want, p.YAML) {
				t.Fatalf("%s drifted:\n%s", golden, p.YAML)
			}
		})
	}
}

func TestRenderSpecs(t *testing.T) {
	ingress, err := Render(IngressID, Input{IngressPort: 18971})
	if err != nil {
		t.Fatal(err)
	}
	s := ingress.Spec
	if s.ID != IngressID || s.InferenceCapable || len(s.Credentials) != 1 || s.Credentials[0].EnvVars[0] != "DEFENSECLAW_SANDBOX_TOKEN" ||
		s.Credentials[0].AuthStyle != "bearer" || s.Endpoints[0].Host != "host.openshell.internal" || s.Endpoints[0].Port != 18971 ||
		s.Binaries[0].Path != "/**" {
		t.Fatalf("ingress spec = %#v", s)
	}

	claude, err := Render(ClaudeBedrockMantleID, Input{Binaries: []string{claudeRealpath, claudeRealpath}})
	if err != nil {
		t.Fatal(err)
	}
	if got := claude.Spec.Endpoints[0].Host; got != "bedrock-mantle.us-east-1.api.aws" {
		t.Fatalf("default region host = %s", got)
	}
	if c := claude.Spec.Credentials[0]; c.AuthStyle != "header" || c.HeaderName != "x-api-key" || c.EnvVars[0] != "ANTHROPIC_API_KEY" {
		t.Fatalf("Claude Mantle credential = %#v", c)
	}
	if len(claude.Spec.Binaries) != 1 || claude.Spec.Binaries[0].Path != claudeRealpath {
		t.Fatalf("binaries not de-duplicated: %#v", claude.Spec.Binaries)
	}
	if !strings.Contains(claude.Spec.Description, "https://bedrock-mantle.us-east-1.api.aws/anthropic") {
		t.Fatalf("description does not name the base URL: %s", claude.Spec.Description)
	}

	codex, err := Render(CodexBedrockMantleID, Input{Binaries: []string{codexRealpath}, BedrockRegion: "eu-central-1"})
	if err != nil {
		t.Fatal(err)
	}
	if c := codex.Spec.Credentials[0]; c.AuthStyle != "bearer" || c.EnvVars[0] != "BEDROCK_MANTLE_API_KEY" || codex.Spec.Endpoints[0].Host != "bedrock-mantle.eu-central-1.api.aws" {
		t.Fatalf("Codex Mantle spec = %#v", codex.Spec)
	}
	if string(codex.Spec.Category) != "Inference" || string(ingress.Spec.Category) != "Other" {
		t.Fatal("categories do not map to the SDK values")
	}
}

func TestRenderRefusesUnsafeInput(t *testing.T) {
	cases := []struct {
		name string
		id   string
		in   Input
	}{
		{"unknown", "defenseclaw-egress", Input{}},
		{"ingress-no-port", IngressID, Input{}},
		{"ingress-bad-port", IngressID, Input{IngressPort: 70000}},
		{"llm-no-binaries", AnthropicID, Input{}},
		{"llm-glob", OpenAIID, Input{Binaries: []string{"/**"}}},
		{"llm-relative", OpenAIID, Input{Binaries: []string{"usr/bin/codex"}}},
		{"llm-unclean", OpenAIID, Input{Binaries: []string{"/usr/bin/../bin/codex"}}},
		{"llm-quote", AnthropicID, Input{Binaries: []string{"/usr/bin/cl\"aude"}}},
		{"llm-newline", AnthropicID, Input{Binaries: []string{"/usr/bin/claude\nbinaries: [/**]"}}},
		{"bad-region", ClaudeBedrockMantleID, Input{Binaries: []string{claudeRealpath}, BedrockRegion: "evil.example.com#"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Render(tc.id, tc.in); err == nil {
				t.Fatal("unsafe input rendered")
			}
		})
	}
}

func TestParseIsStrict(t *testing.T) {
	good, err := Render(OpenAIID, Input{Binaries: []string{codexRealpath}})
	if err != nil {
		t.Fatal(err)
	}
	doc := string(good.YAML)
	mutations := map[string]string{
		"unknown-key":          doc + "resource_version: 3\n",
		"bearer-wrong-header":  strings.Replace(doc, "header_name: authorization", "header_name: x-api-key", 1),
		"audit-enforcement":    strings.Replace(doc, "enforcement: enforce", "enforcement: audit", 1),
		"tcp-endpoint":         strings.Replace(doc, "protocol: rest", "protocol: tcp", 1),
		"any-binary-inference": strings.Replace(doc, `"`+codexRealpath+`"`, `"/**"`, 1),
		"optional-credential":  strings.Replace(doc, "required: true", "required: false", 1),
		"unknown-category":     strings.Replace(doc, "category: inference", "category: magic", 1),
		"second-document":      doc + "---\nid: x\n",
	}
	for name, mutated := range mutations {
		t.Run(name, func(t *testing.T) {
			if mutated == doc {
				t.Fatal("mutation did not apply")
			}
			if _, err := Parse([]byte(mutated)); err == nil {
				t.Fatal("invalid profile parsed")
			}
		})
	}
}

// TestParseAcceptsSpikeProfile loads the shape OpenShell 0.1.1 imported in
// the harness spike.
func TestParseAcceptsSpikeProfile(t *testing.T) {
	spike := `id: hs-dc-ingress
display_name: DefenseClaw harness spike ingress
description: Binds the per-sandbox DefenseClaw hook/OTLP token to the host ingress (spike)
category: other
inference_capable: false
credentials:
  - name: token
    description: DefenseClaw sandbox hook token
    env_vars: [DEFENSECLAW_SANDBOX_TOKEN]
    required: true
    auth_style: bearer
    header_name: authorization
endpoints:
  - host: host.openshell.internal
    port: 18920
    protocol: rest
    access: full
    enforcement: enforce
binaries: ["/**"]
`
	spec, err := Parse([]byte(spike))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if spec.Endpoints[0].Port != 18920 {
		t.Fatalf("spec = %#v", spec)
	}
}
