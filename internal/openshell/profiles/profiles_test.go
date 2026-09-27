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
	"strconv"
	"strings"
	"testing"
)

const (
	claudeRealpath         = "/opt/defenseclaw-harness/claudecode/bin/claude"
	codexRealpath          = "/usr/lib/node_modules/@openai/codex/node_modules/@openai/codex-linux-arm64/vendor/aarch64-unknown-linux-musl/bin/codex"
	openCodeRealpath       = "/opt/defenseclaw-harness/opencode/lib/node_modules/opencode-ai/bin/opencode.exe"
	copilotRealpath        = "/opt/defenseclaw-harness/copilot/lib/node_modules/@github/copilot/node_modules/@github/copilot-linux-arm64/copilot"
	copilotRuntimeRealpath = "/opt/defenseclaw-harness/copilot/cache/pkg/linux-arm64/1.0.88/prebuilds/linux-arm64/copilot-runtime"
	ampRealpath            = "/opt/defenseclaw-harness/amp/lib/node_modules/@ampcode/cli/bin/amp.exe"
)

func goldenInputs() map[string]Input {
	copilot := []string{copilotRealpath, copilotRuntimeRealpath}
	return map[string]Input{
		IngressID:             {IngressPort: 18971},
		AnthropicID:           {Binaries: []string{claudeRealpath}},
		ClaudeOAuthID:         {Binaries: []string{claudeRealpath}},
		ClaudeBedrockMantleID: {Binaries: []string{claudeRealpath}},
		OpenAIID:              {Binaries: []string{codexRealpath}},
		CodexBedrockMantleID:  {Binaries: []string{codexRealpath}, BedrockRegion: "us-west-2"},

		OpenCodeAnthropicID:     {Binaries: []string{openCodeRealpath}},
		OpenCodeOpenAIID:        {Binaries: []string{openCodeRealpath}},
		OpenCodeBedrockMantleID: {Binaries: []string{openCodeRealpath}},
		CopilotGitHubID:         {Binaries: copilot},
		CopilotAnthropicID:      {Binaries: copilot},
		CopilotBedrockMantleID:  {Binaries: copilot, BedrockRegion: "eu-west-1"},
		AmpID:                   {Binaries: []string{ampRealpath}},
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
	if ingress.ID != "defenseclaw-ingress-18971" || ingress.Template != IngressID || s.ID != ingress.ID {
		t.Fatalf("ingress id %q (template %q, spec %q), want the listener's own profile", ingress.ID, ingress.Template, s.ID)
	}
	if s.InferenceCapable || len(s.Credentials) != 1 || s.Credentials[0].EnvVars[0] != "DEFENSECLAW_SANDBOX_TOKEN" ||
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
	if claude.ID != "defenseclaw-claude-bedrock-mantle-us-east-1" || codex.ID != "defenseclaw-codex-bedrock-mantle-eu-central-1" ||
		claude.Template != ClaudeBedrockMantleID || codex.Template != CodexBedrockMantleID {
		t.Fatalf("Mantle ids %q (%q), %q (%q), want one profile per region", claude.ID, claude.Template, codex.ID, codex.Template)
	}
	anthropic, err := Render(AnthropicID, Input{Binaries: []string{claudeRealpath}})
	if err != nil {
		t.Fatal(err)
	}
	if anthropic.ID != AnthropicID || anthropic.Template != AnthropicID {
		t.Fatalf("anthropic id %q (%q), want the template id", anthropic.ID, anthropic.Template)
	}
}

// TestProfileIDsNameTheirEndpoints pins that no two inputs that put
// different endpoints in a profile share its gateway id: profiles are
// gateway-global, and one daemon or sandbox updating a shared profile would
// re-point every other sandbox using it.
func TestProfileIDsNameTheirEndpoints(t *testing.T) {
	seen := map[string]string{}
	add := func(id string, in Input) {
		t.Helper()
		p, err := Render(id, in)
		if err != nil {
			t.Fatal(err)
		}
		var eps []string
		for _, ep := range p.Spec.Endpoints {
			eps = append(eps, ep.Host+":"+strconv.Itoa(int(ep.Port)))
		}
		key := strings.Join(eps, ",")
		if prev, ok := seen[p.ID]; ok && prev != key {
			t.Fatalf("profile %s renders endpoints %s and %s", p.ID, prev, key)
		}
		seen[p.ID] = key
	}
	for _, port := range []int{18971, 18972, 29001, 65535, 1} {
		add(IngressID, Input{IngressPort: port})
	}
	for _, id := range []string{ClaudeBedrockMantleID, CodexBedrockMantleID} {
		for _, region := range []string{"", "us-east-1", "us-west-2", "eu-central-1", "ap-southeast-2"} {
			add(id, Input{Binaries: []string{claudeRealpath}, BedrockRegion: region})
		}
	}
	for _, id := range []string{AnthropicID, ClaudeOAuthID, OpenAIID} {
		add(id, Input{Binaries: []string{claudeRealpath}})
		add(id, Input{Binaries: []string{codexRealpath}})
	}
	if len(seen) != 5+2*4+3 {
		t.Fatalf("gateway ids = %v", seen)
	}
}

func TestProfileIDHelpers(t *testing.T) {
	if got := IngressProfileID(29001); got != "defenseclaw-ingress-29001" {
		t.Fatalf("IngressProfileID = %s", got)
	}
	if got := BedrockProfileID(ClaudeBedrockMantleID, " "); got != "defenseclaw-claude-bedrock-mantle-us-east-1" {
		t.Fatalf("BedrockProfileID default region = %s", got)
	}
	for id, want := range map[string]int{
		"defenseclaw-ingress-29001": 29001, "defenseclaw-ingress-1": 1, "defenseclaw-ingress-65535": 65535,
	} {
		if port, ok := IngressPort(id); !ok || port != want {
			t.Errorf("IngressPort(%s) = %d, %t", id, port, ok)
		}
	}
	for _, id := range []string{
		LegacyIngressID, "defenseclaw-ingress-", "defenseclaw-ingress-0", "defenseclaw-ingress-029001",
		"defenseclaw-ingress-65536", "defenseclaw-ingress-123456", "defenseclaw-ingress-x", "dc-ingress-29001",
	} {
		if _, ok := IngressPort(id); ok {
			t.Errorf("IngressPort(%s) accepted", id)
		}
	}
	for id, want := range map[string]bool{
		LegacyIngressID: true, "defenseclaw-ingress-29001": true, AnthropicID: true, ClaudeBedrockMantleID: true,
		"defenseclaw-claude-bedrock-mantle-eu-west-1": true, "defenseclaw-codex-bedrock-mantle-us-gov-west-1": true,
		"defenseclaw-openai-us-east-1": false, "defenseclaw-claude-bedrock-mantle-evil": false, "defenseclaw-egress": false,
		"defenseclaw-ingress-0": false, "dc-cred-0123456789ab": false, "user-profile": false,
	} {
		if got := IsDefenseClaw(id); got != want {
			t.Errorf("IsDefenseClaw(%s) = %t, want %t", id, got, want)
		}
	}
	for _, id := range IDs() {
		in := goldenInputs()[id]
		p, err := Render(id, in)
		if err != nil {
			t.Fatal(err)
		}
		if !IsDefenseClaw(p.ID) {
			t.Errorf("rendered %s is not recognised as DefenseClaw's", p.ID)
		}
	}
}

// TestRenderHookOnlyHarnessProfiles pins the credential, endpoints and
// binaries of the OpenCode, Copilot CLI and Amp profiles.
func TestRenderHookOnlyHarnessProfiles(t *testing.T) {
	copilot := []string{copilotRealpath, copilotRuntimeRealpath}
	cases := []struct {
		id       string
		in       Input
		env      string
		style    string
		header   string
		hosts    []string
		binaries []string
	}{
		{OpenCodeAnthropicID, Input{Binaries: []string{openCodeRealpath}}, "ANTHROPIC_API_KEY", "header", "x-api-key", []string{"api.anthropic.com"}, []string{openCodeRealpath}},
		{OpenCodeOpenAIID, Input{Binaries: []string{openCodeRealpath}}, "OPENAI_API_KEY", "bearer", "authorization", []string{"api.openai.com"}, []string{openCodeRealpath}},
		{OpenCodeBedrockMantleID, Input{Binaries: []string{openCodeRealpath}, BedrockRegion: "us-west-2"}, "BEDROCK_MANTLE_API_KEY", "header", "x-api-key", []string{"bedrock-mantle.us-west-2.api.aws"}, []string{openCodeRealpath}},
		{CopilotGitHubID, Input{Binaries: copilot}, "COPILOT_GITHUB_TOKEN", "bearer", "authorization",
			[]string{"api.github.com", "api.githubcopilot.com", "api.individual.githubcopilot.com", "api.business.githubcopilot.com", "api.enterprise.githubcopilot.com"}, []string{copilotRuntimeRealpath, copilotRealpath}},
		{CopilotAnthropicID, Input{Binaries: copilot}, "COPILOT_PROVIDER_API_KEY", "header", "x-api-key", []string{"api.anthropic.com"}, []string{copilotRuntimeRealpath, copilotRealpath}},
		{CopilotBedrockMantleID, Input{Binaries: copilot}, "COPILOT_PROVIDER_API_KEY", "header", "x-api-key", []string{"bedrock-mantle.us-east-1.api.aws"}, []string{copilotRuntimeRealpath, copilotRealpath}},
		{AmpID, Input{Binaries: []string{ampRealpath}}, "AMP_API_KEY", "bearer", "authorization", []string{"ampcode.com"}, []string{ampRealpath}},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			p, err := Render(tc.id, tc.in)
			if err != nil {
				t.Fatal(err)
			}
			s := p.Spec
			if !s.InferenceCapable || len(s.Credentials) != 1 {
				t.Fatalf("spec = %#v", s)
			}
			if c := s.Credentials[0]; len(c.EnvVars) != 1 || c.EnvVars[0] != tc.env || c.AuthStyle != tc.style || c.HeaderName != tc.header {
				t.Fatalf("credential = %#v", c)
			}
			var hosts, binaries []string
			for _, ep := range s.Endpoints {
				if ep.Port != 443 || ep.Protocol != "rest" {
					t.Fatalf("endpoint %#v", ep)
				}
				hosts = append(hosts, ep.Host)
			}
			for _, b := range s.Binaries {
				binaries = append(binaries, b.Path)
			}
			if strings.Join(hosts, ",") != strings.Join(tc.hosts, ",") || strings.Join(binaries, ",") != strings.Join(tc.binaries, ",") {
				t.Fatalf("hosts %v binaries %v", hosts, binaries)
			}
			if _, err := Render(tc.id, Input{Binaries: []string{"/**"}}); err == nil {
				t.Fatal("an inference credential rendered for every binary")
			}
		})
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
