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

// TestRV3P34RenameRevokesTheOldUserSecretsNamespace: moving
// self_service_secrets.namespace from A to B revokes A from the launcher
// atespaces, and the next uninstall leaves nothing of either (RV3 P3-4).
func TestRV3P34RenameRevokesTheOldUserSecretsNamespace(t *testing.T) {
	api, kube := newFakeAPI(), newFakeKube()
	plan := testPlan()
	plan.CredentialProvider.UserSecrets = true
	plan.CredentialProvider.UserSecretsNamespace = "dc-users-a"
	key := "ate-system/k8s-credential-provider-namespace-policy"
	kube.cms[key] = &ConfigMap{Namespace: "ate-system", Name: "k8s-credential-provider-namespace-policy",
		Data: map[string]string{NamespacePolicyKey: "policies:\n- atespace: team-a\n  allowedNamespaces: [ns1]\n"}}
	run := func() StepReport {
		t.Helper()
		r, err := Bootstrap(context.Background(), plan, api, kube)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	run()
	if pol := kube.cms[key].Data[NamespacePolicyKey]; !strings.Contains(pol, "dc-users-a") {
		t.Fatalf("namespace A not granted:\n%s", pol)
	}
	plan.CredentialProvider.UserSecretsNamespace = "dc-users-b"
	run()
	pol := kube.cms[key].Data[NamespacePolicyKey]
	if strings.Contains(pol, "dc-users-a") || !strings.Contains(pol, "dc-users-b") || !strings.Contains(pol, "ns1") {
		t.Fatalf("after the rename A must be revoked, B granted, foreign grants kept:\n%s", pol)
	}
	if _, err := PreDelete(context.Background(), plan, api, kube); err != nil {
		t.Fatal(err)
	}
	if pol := kube.cms[key].Data[NamespacePolicyKey]; strings.Contains(pol, "dc-users") || !strings.Contains(pol, "ns1") {
		t.Fatalf("after uninstall:\n%s", pol)
	}
}

// TestRV4F7PlanRefusesALauncherAtespaceAsUserSecretsNamespace (RV4 F7).
func TestRV4F7PlanRefusesALauncherAtespaceAsUserSecretsNamespace(t *testing.T) {
	p := testPlan()
	p.CredentialProvider.UserSecretsNamespace = p.LauncherAtespaces[0]
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "user_secrets_namespace") {
		t.Errorf("launcher atespace %q as the user secrets namespace: %v", p.LauncherAtespaces[0], err)
	}
}
