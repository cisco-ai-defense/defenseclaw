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

package manager

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/profiles"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

func TestPlanLLM(t *testing.T) {
	spec, _ := harness.Get("claudecode")
	bins := []string{testClaudeBin}
	for _, tc := range []struct {
		name string
		req  *sandboxapi.LLMCredential
		ok   bool
	}{
		{"none", nil, true},
		{"anthropic", &sandboxapi.LLMCredential{Profile: profiles.AnthropicID, Credentials: map[string]string{"ANTHROPIC_API_KEY": "k"}}, true},
		{"oauth", &sandboxapi.LLMCredential{Profile: profiles.ClaudeOAuthID, Credentials: map[string]string{"CLAUDE_CODE_OAUTH_TOKEN": "t"}}, true},
		{"wrong harness profile", &sandboxapi.LLMCredential{Profile: profiles.OpenAIID, Credentials: map[string]string{"OPENAI_API_KEY": "k"}}, false},
		{"foreign variable", &sandboxapi.LLMCredential{Profile: profiles.AnthropicID, Credentials: map[string]string{"ANTHROPIC_API_KEY": "k", "AWS_SECRET": "x"}}, false},
		{"missing variable", &sandboxapi.LLMCredential{Profile: profiles.AnthropicID}, false},
		{"multi-line value", &sandboxapi.LLMCredential{Profile: profiles.AnthropicID, Credentials: map[string]string{"ANTHROPIC_API_KEY": "a\nb"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan, err := planLLM(spec, tc.req, bins)
			if (err == nil) != tc.ok {
				t.Fatalf("planLLM = %+v, %v", plan, err)
			}
			if tc.ok && tc.req != nil && (plan == nil || plan.profile.ID != tc.req.Profile) {
				t.Fatalf("plan = %+v", plan)
			}
		})
	}
	if _, err := planLLM(spec, &sandboxapi.LLMCredential{Profile: profiles.AnthropicID, Credentials: map[string]string{"ANTHROPIC_API_KEY": "k"}}, nil); err == nil {
		t.Fatal("planned an LLM credential with no binaries to pin")
	}
}

func TestPlanCredentials(t *testing.T) {
	cfg := &config.Config{}
	cfg.Gateway.APIPort = 18970
	eff, _, err := packs.Resolve(cfg, packs.Flags{})
	if err != nil {
		t.Fatal(err)
	}
	m := &Manager{}
	feed := m.feedMatcher()
	reserved := map[string]bool{"ANTHROPIC_API_KEY": true}
	good, err := planCredentials(eff, feed, []sandboxapi.CredentialBinding{
		{Name: "STRIPE_API_KEY", Value: "s", Host: "API.Stripe.com"},
		{Name: "MOCK_KEY", Value: "m", Host: "host.openshell.internal", Port: 18921},
	}, reserved)
	if err != nil || len(good) != 2 || good[0].binding.Port != 443 || good[0].binding.Host != "api.stripe.com" {
		t.Fatalf("plan = %+v, %v", good, err)
	}
	if good[0].profile.ID == good[1].profile.ID || good[1].profile.Spec.Endpoints[0].Port != 18921 {
		t.Fatalf("profiles = %+v %+v", good[0].profile.Spec, good[1].profile.Spec)
	}
	for name, list := range map[string][]sandboxapi.CredentialBinding{
		"duplicate":        {{Name: "A", Value: "1", Host: "a.example"}, {Name: "A", Value: "2", Host: "b.example"}},
		"reserved":         {{Name: "ANTHROPIC_API_KEY", Value: "1", Host: "a.example"}},
		"defenseclaw":      {{Name: openshell.EnvSandboxToken, Value: "1", Host: "a.example"}},
		"bad host":         {{Name: "A", Value: "1", Host: "https://a.example"}},
		"wildcard":         {{Name: "A", Value: "1", Host: "*.example.com"}},
		"blocklisted":      {{Name: "A", Value: "1", Host: "webhook.site"}},
		"metadata":         {{Name: "A", Value: "1", Host: "169.254.169.254", Port: 80}},
		"api port":         {{Name: "A", Value: "1", Host: "host.openshell.internal", Port: 18970}},
		"gateway port":     {{Name: "A", Value: "1", Host: "host.openshell.internal", Port: 17670}},
		"empty value":      {{Name: "A", Value: "", Host: "a.example"}},
		"loopback literal": {{Name: "A", Value: "1", Host: "127.0.0.1", Port: 5432}},
	} {
		if _, err := planCredentials(eff, feed, list, reserved); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestValidateExtraEnv(t *testing.T) {
	pinned := map[string]string{"DISABLE_AUTOUPDATER": "1"}
	if err := validateExtraEnv(map[string]string{"ANTHROPIC_BASE_URL": "http://host.openshell.internal:18921", "FOO": "bar"}, pinned); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []map[string]string{
		{"DISABLE_AUTOUPDATER": "0"}, {"no_proxy": "*"}, {"PATH": "/tmp"}, {"BAD-NAME": "x"}, {"X": "a\nb"},
		{"DYLD_INSERT_LIBRARIES": "x"}, {"OPENSHELL_GATEWAY": "x"},
	} {
		if err := validateExtraEnv(bad, pinned); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}

func TestEnsureProfileImportsOnceAndUpdatesOnChange(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	p, err := profiles.Render(profiles.IngressID, profiles.Input{IngressPort: testIngressPort})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := e.m.ensureProfile(ctx, e.gw, p, nil); err != nil {
			t.Fatal(err)
		}
	}
	if len(e.importer.imported) != 1 || len(e.importer.updated) != 0 {
		t.Fatalf("imported %v updated %v", e.importer.imported, e.importer.updated)
	}
	moved, _ := profiles.Render(profiles.IngressID, profiles.Input{IngressPort: 28971})
	if err := e.m.ensureProfile(ctx, e.gw, moved, nil); err != nil {
		t.Fatal(err)
	}
	if len(e.importer.updated) != 1 {
		t.Fatalf("port change not updated: %v", e.importer.updated)
	}
	got, _ := e.client.GetProfile(ctx, profiles.IngressID)
	if got.Endpoints[0].Port != 28971 {
		t.Fatalf("profile = %+v", got.Endpoints)
	}

	// LLM profiles merge network binaries from other images.
	render := func(bins []string) (profiles.Profile, error) {
		return profiles.Render(profiles.AnthropicID, profiles.Input{Binaries: bins})
	}
	first, _ := render([]string{"/opt/a/claude"})
	second, _ := render([]string{"/opt/b/claude"})
	if err := e.m.ensureProfile(ctx, e.gw, first, render); err != nil {
		t.Fatal(err)
	}
	if err := e.m.ensureProfile(ctx, e.gw, second, render); err != nil {
		t.Fatal(err)
	}
	got, _ = e.client.GetProfile(ctx, profiles.AnthropicID)
	if len(got.Binaries) != 2 {
		t.Fatalf("binaries = %+v", got.Binaries)
	}

	e.m.opts.Profiles = nil
	other, _ := profiles.Render(profiles.OpenAIID, profiles.Input{Binaries: []string{"/opt/codex"}})
	if err := e.m.ensureProfile(ctx, e.gw, other, nil); !sandboxapi.IsCode(err, sandboxapi.CodeUnavailable) {
		t.Fatalf("missing profile without importer: %v", err)
	}
}
