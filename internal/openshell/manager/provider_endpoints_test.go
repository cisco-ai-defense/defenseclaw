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
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/profiles"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// TestCredentialEndpointsFollowThePolicy pins that a --credential binding,
// whose provider rule opens its endpoint around the egress proxy, is judged
// again once the policy changes: a running sandbox's provider is detached
// (logged, recorded, on the feed) and the next start is refused, for the
// administrator's block list and the user's alike.
func TestCredentialEndpointsFollowThePolicy(t *testing.T) {
	for _, tc := range []struct {
		name   string
		edit   func(c *config.Config)
		code   string
		reason string
	}{
		{"admin block", func(c *config.Config) { c.OpenShell.Admin.EgressBlock = []string{"api.stripe.com"} },
			sandboxapi.CodeAdminViolation, policyReasonAdmin},
		{"admin allow-only", func(c *config.Config) { c.OpenShell.Admin.EgressAllowOnly = []string{"registry.example.org"} },
			sandboxapi.CodeAdminViolation, policyReasonAdmin},
		{"block list", func(c *config.Config) { c.OpenShell.Egress.Block = []string{"api.stripe.com"} },
			sandboxapi.CodePolicyViolation, policyReasonBlocklist},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, nil)
			ctx := context.Background()
			sb := e.create(sandboxapi.CreateRequest{Name: "credbox",
				Credentials: []sandboxapi.CredentialBinding{{Name: "STRIPE_API_KEY", Value: "stripe-secret", Host: "api.stripe.com"}}})
			provider := providerName(sb.Name, roleCredential, 0)
			e.setConfig(tc.edit)
			if !e.m.enforceAll(ctx) {
				t.Fatal("enforcement did not reach the gateway")
			}
			got, err := e.client.GetSandbox(ctx, sb.Name)
			if err != nil || slices.Contains(got.Spec.Providers, provider) {
				t.Fatalf("providers after enforcement = %v, %v; want %s detached", got.Spec.Providers, err, provider)
			}
			var recorded, fed bool
			e.tel.mu.Lock()
			for _, p := range e.tel.policy {
				recorded = recorded || (p.Operation == audit.SandboxPolicyRuleRemove && p.Target == provider && p.Reason == tc.reason)
			}
			e.tel.mu.Unlock()
			for _, ev := range e.m.ActivitySince(0, sb.Name) {
				fed = fed || (ev.Kind == sandboxapi.ActivityEgressBlocked && ev.Reason == tc.reason)
			}
			if !recorded || !fed {
				t.Fatalf("recorded %v, on the feed %v", recorded, fed)
			}
			if _, err := e.m.Stop(ctx, sb.Name); err != nil {
				t.Fatal(err)
			}
			_, err = e.m.Start(ctx, sb.Name, sandboxapi.StartRequest{})
			wantCode(t, err, tc.code)
		})
	}
}

// TestModelProviderEndpointsFollowTheAdminLists pins that the endpoints
// of the --llm credential's provider, which its provider rule opens around
// the egress proxy, are covered by the organization's egress_allow_only
// and egress_block: at create and on every later start.
func TestModelProviderEndpointsFollowTheAdminLists(t *testing.T) {
	llm := &sandboxapi.LLMCredential{Profile: profiles.AnthropicID, Credentials: map[string]string{"ANTHROPIC_API_KEY": "sk-test"}}
	e := newEnv(t, func(c *config.Config) { c.OpenShell.Admin.EgressAllowOnly = []string{"registry.example.org"} })
	_, err := e.m.Create(context.Background(), sandboxapi.CreateRequest{Name: "llmbox", Harness: "claudecode", Project: e.project, LLM: llm})
	if apiErr := wantCode(t, err, sandboxapi.CodeAdminViolation); apiErr.Violation == nil || apiErr.Violation.Key != "llm" ||
		apiErr.Violation.Attempted != "api.anthropic.com" {
		t.Fatalf("violation = %+v", apiErr.Violation)
	}
	assertNothingLeft(t, e)

	e = newEnv(t, nil)
	ctx := context.Background()
	sb := e.create(sandboxapi.CreateRequest{Name: "llmbox", LLM: llm})
	if _, err := e.m.Stop(ctx, sb.Name); err != nil {
		t.Fatal(err)
	}
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.EgressBlock = []string{"api.anthropic.com"} })
	_, err = e.m.Start(ctx, sb.Name, sandboxapi.StartRequest{})
	wantCode(t, err, sandboxapi.CodeAdminViolation)
}
