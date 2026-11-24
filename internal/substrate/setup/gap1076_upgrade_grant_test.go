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
	"slices"
	"strings"
	"testing"
)

// TestUpgradeWithoutOwnerTokenGrantsTheUserSecretsNamespaceGAP1076 is the
// e1 cluster: installed at 1.0.10 (the first bootstrap granted the admin
// secrets namespace and deleted the owner token Secret), then upgraded to a
// chart with self-service secrets on. The bootstrap hook of that upgrade has
// no owner token, so it leaves the access policies alone, but it must still
// grant the launcher atespaces the self-service namespace and restart the
// provider; otherwise every bound person secret is refused at the egress.
func TestUpgradeWithoutOwnerTokenGrantsTheUserSecretsNamespaceGAP1076(t *testing.T) {
	kube := newFakeKube()
	plan := testPlan()
	plan.CredentialProvider.UserSecretsNamespace = "defenseclaw-user-secrets"
	plan.CredentialProvider.UserSecrets = true
	key := "ate-system/k8s-credential-provider-namespace-policy"
	kube.cms[key] = &ConfigMap{Namespace: "ate-system", Name: "k8s-credential-provider-namespace-policy",
		Data: map[string]string{NamespacePolicyKey: "policies:\n- atespace: eng-web\n  allowedNamespaces: [defenseclaw-actor-secrets]\n- atespace: team-a\n  allowedNamespaces: [ns1]\n"}}
	var r StepReport
	var err error
	func() {
		defer func() {
			if p := recover(); p != nil {
				t.Fatalf("bootstrap without an owner token panicked: %v", p)
			}
		}()
		r, err = Bootstrap(context.Background(), plan, nil, kube)
	}()
	if err != nil {
		t.Fatal(err)
	}
	pol, err := parseNamespacePolicy(kube.cms[key].Data[NamespacePolicyKey])
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, p := range pol.Policies {
		got[p.Atespace] = p.AllowedNamespaces
	}
	if !slices.Contains(got["eng-web"], "defenseclaw-user-secrets") || !slices.Contains(got["eng-web"], "defenseclaw-actor-secrets") {
		t.Fatalf("eng-web lacks a grant after the upgrade: %v", got["eng-web"])
	}
	if !slices.Equal(got["team-a"], []string{"ns1"}) {
		t.Fatalf("a foreign grant changed: %v", got["team-a"])
	}
	if !slices.Contains(kube.restarts, "ate-system/k8s-credential-provider") {
		t.Fatalf("the provider was not restarted to load the grant: %v", kube.restarts)
	}
	if !strings.Contains(strings.Join(r.Notes, "\n"), "access policies were not touched") {
		t.Fatalf("the report does not say the access policies were left alone: %v", r.Notes)
	}
	// Idempotent: a second upgrade changes nothing and restarts nothing.
	before := len(kube.restarts)
	if _, err := Bootstrap(context.Background(), plan, nil, kube); err != nil || len(kube.restarts) != before {
		t.Fatalf("second upgrade: err %v, restarts %v", err, kube.restarts)
	}
}
