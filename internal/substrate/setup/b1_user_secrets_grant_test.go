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

package setup

import (
	"context"
	"strings"
	"testing"
)

// B1 S3: self-service values live in their own namespace, so the
// credential provider must be granted it on every launcher atespace while
// self-service is on, and lose it when self-service is turned off and at
// uninstall. The provider namespace keeps its own grants throughout.
func TestB1ProviderGrantsTheUserSecretsNamespace(t *testing.T) {
	api, kube := newFakeAPI(), newFakeKube()
	plan := testPlan()
	plan.CredentialProvider.UserSecretsNamespace = "defenseclaw-user-secrets"
	plan.CredentialProvider.UserSecrets = true
	key := "ate-system/k8s-credential-provider-namespace-policy"
	kube.cms[key] = &ConfigMap{Namespace: "ate-system", Name: "k8s-credential-provider-namespace-policy",
		Data: map[string]string{NamespacePolicyKey: "policies:\n- atespace: old-launcher\n  allowedNamespaces: [defenseclaw-user-secrets]\n- atespace: team-a\n  allowedNamespaces: [ns1]\n"}}
	granted := func(atespace, ns string) bool {
		t.Helper()
		pol, err := parseNamespacePolicy(kube.cms[key].Data[NamespacePolicyKey])
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range pol.Policies {
			if p.Atespace == atespace {
				for _, n := range p.AllowedNamespaces {
					if n == ns {
						return true
					}
				}
			}
		}
		return false
	}
	if _, err := Bootstrap(context.Background(), plan, api, kube); err != nil {
		t.Fatal(err)
	}
	if !granted("eng-web", "defenseclaw-user-secrets") || !granted("eng-web", "defenseclaw-actor-secrets") {
		t.Fatalf("self-service on: eng-web lacks a grant:\n%s", kube.cms[key].Data[NamespacePolicyKey])
	}
	if granted("old-launcher", "defenseclaw-user-secrets") || !granted("team-a", "ns1") {
		t.Fatalf("self-service on: stale grant kept or a foreign grant touched:\n%s", kube.cms[key].Data[NamespacePolicyKey])
	}

	plan.CredentialProvider.UserSecrets = false
	if _, err := Bootstrap(context.Background(), plan, api, kube); err != nil {
		t.Fatal(err)
	}
	if granted("eng-web", "defenseclaw-user-secrets") || !granted("eng-web", "defenseclaw-actor-secrets") {
		t.Fatalf("self-service off: the user secrets grant was not revoked:\n%s", kube.cms[key].Data[NamespacePolicyKey])
	}

	plan.CredentialProvider.UserSecrets = true
	if _, err := Bootstrap(context.Background(), plan, api, kube); err != nil {
		t.Fatal(err)
	}
	if _, err := PreDelete(context.Background(), plan, api, kube); err != nil {
		t.Fatal(err)
	}
	pol := kube.cms[key].Data[NamespacePolicyKey]
	if strings.Contains(pol, "defenseclaw-user-secrets") || strings.Contains(pol, "defenseclaw-actor-secrets") || !granted("team-a", "ns1") {
		t.Fatalf("after uninstall:\n%s", pol)
	}

	// The plan refuses a user secrets namespace that is DefenseClaw's or
	// Substrate's, the admin secrets one or a system one (RV3 P3-5).
	for _, ns := range []string{plan.Namespace, plan.SubstrateNamespace, "Bad_NS",
		testPlan().CredentialProvider.SecretsNamespace, "default", "kube-system", "kube-public", "kube-node-lease"} {
		p := testPlan()
		p.CredentialProvider.UserSecretsNamespace = ns
		if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "user_secrets_namespace") {
			t.Errorf("user_secrets_namespace %q: %v", ns, err)
		}
	}
}
