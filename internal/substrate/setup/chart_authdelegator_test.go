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
	"encoding/json"
	"strings"
	"testing"
)

func clusterScoped(objs []k8sObject) []k8sObject {
	var out []k8sObject
	for _, o := range objs {
		if o.Kind == "ClusterRole" || o.Kind == "ClusterRoleBinding" {
			out = append(out, o)
		}
	}
	return out
}

func hookPlanFrom(t *testing.T, objs []k8sObject) ChartPlan {
	t.Helper()
	for _, o := range objs {
		if o.Kind != "Job" {
			continue
		}
		for _, c := range dig(o.Spec, "template", "spec", "containers").([]any) {
			for _, e := range dig(c, "env").([]any) {
				if v, ok := dig(e, "value").(string); ok && strings.HasPrefix(strings.TrimSpace(v), "{") && strings.Contains(v, "\"controller_deployment\"") {
					var p ChartPlan
					if err := json.Unmarshal([]byte(v), &p); err != nil {
						t.Fatal(err)
					}
					if _, err := ParsePlan([]byte(v)); err != nil {
						t.Fatalf("hook plan refused: %v", err)
					}
					return p
				}
			}
		}
	}
	t.Fatal("no hook plan in the render")
	return ChartPlan{}
}

// TestChartAuthDelegatorGAP0153 is the lead's GAP-0153 ruling: with the
// Kubernetes sign-in on (no OIDC issuer, not managed) the chart renders one
// cluster-scoped object, a ClusterRoleBinding of the gateway
// ServiceAccount to system:auth-delegator, named by
// gateway.authDelegatorBinding, and the uninstall plan names it; with an
// OIDC issuer, on a managed install or with --no-kube-sign-in it renders
// nothing cluster-scoped and the plan names nothing.
func TestChartAuthDelegatorGAP0153(t *testing.T) {
	helm := helmBinary(t)
	objs := decodeObjects(t, renderChart(t, helm, "kube-signin"))
	cs := clusterScoped(objs)
	if len(cs) != 1 || !authDelegatorGrant(cs[0]) || cs[0].Metadata["name"] != "defenseclaw-auth-delegator-defenseclaw-system-dc" {
		t.Fatalf("kube sign-in: cluster-scoped objects %+v", cs)
	}
	if ns := dig(cs[0].Subjects[0], "namespace"); ns != "defenseclaw-system" {
		t.Errorf("subject namespace %v", ns)
	}
	if p := hookPlanFrom(t, objs); p.AuthDelegatorBinding != "defenseclaw-auth-delegator-defenseclaw-system-dc" {
		t.Errorf("uninstall plan names %q", p.AuthDelegatorBinding)
	}

	objs = decodeObjects(t, renderChart(t, helm, "kube-signin", "--set", "gateway.authDelegatorBinding=dc-gw-tokenreview"))
	if cs := clusterScoped(objs); len(cs) != 1 || cs[0].Metadata["name"] != "dc-gw-tokenreview" || hookPlanFrom(t, objs).AuthDelegatorBinding != "dc-gw-tokenreview" {
		t.Errorf("named binding: %+v", cs)
	}

	images := "config.substrate.templates.allowed_images[0]=registry.example.com/defenseclaw/*"
	for name, extra := range map[string][]string{
		"oidc":            {"--set", "config.substrate.identity.oidc.issuer=https://idp.example", "--set", "config.substrate.identity.oidc.client_id=dc"},
		"managed":         {"--set", "config.deployment_mode=managed_enterprise", "--set", images},
		"no-kube-sign-in": {"--set", "gateway.args={serve,--substrate,--no-kube-sign-in}"},
		// A Go bool flag: =true and =1 turn the sign-in off too (R3a P3).
		"no-kube-sign-in=true": {"--set-json", `gateway.args=["serve","--substrate","--no-kube-sign-in=true"]`},
		"no-kube-sign-in=1":    {"--set-json", `gateway.args=["serve","--substrate","--no-kube-sign-in=1"]`},
		"last wins":            {"--set-json", `gateway.args=["serve","--no-kube-sign-in=false","--no-kube-sign-in"]`},
	} {
		objs := decodeObjects(t, renderChart(t, helm, "kube-signin", extra...))
		if cs := clusterScoped(objs); len(cs) != 0 {
			t.Errorf("%s: cluster-scoped objects %+v", name, cs)
		}
		if p := hookPlanFrom(t, objs); p.AuthDelegatorBinding != "" {
			t.Errorf("%s: uninstall plan names %q", name, p.AuthDelegatorBinding)
		}
	}
}

// The invariant allows the binding only under the sign-in: the same object
// in an OIDC render is cluster-wide RBAC.
func TestAuthDelegatorOnlyUnderTheSignIn(t *testing.T) {
	binding := k8sObject{Kind: "ClusterRoleBinding", Metadata: map[string]any{"name": "x"},
		RoleRef:  map[string]any{"kind": "ClusterRole", "name": "system:auth-delegator"},
		Subjects: []any{map[string]any{"kind": "ServiceAccount", "name": "defenseclaw-gateway"}}}
	if !authDelegatorGrant(binding) {
		t.Fatal("the gateway binding is not recognized")
	}
	for _, bad := range []k8sObject{
		{Kind: "ClusterRoleBinding", RoleRef: map[string]any{"kind": "ClusterRole", "name": "cluster-admin"}, Subjects: binding.Subjects},
		{Kind: "ClusterRoleBinding", RoleRef: binding.RoleRef, Subjects: []any{map[string]any{"kind": "ServiceAccount", "name": "defenseclaw-controller"}}},
		{Kind: "ClusterRoleBinding", RoleRef: binding.RoleRef, Subjects: append(append([]any{}, binding.Subjects...), map[string]any{"kind": "Group", "name": "system:authenticated"})},
		{Kind: "ClusterRole", RoleRef: binding.RoleRef, Subjects: binding.Subjects},
	} {
		if authDelegatorGrant(bad) {
			t.Errorf("allowed %+v", bad)
		}
	}
	oidc := []k8sObject{{Kind: "ConfigMap", Metadata: map[string]any{"name": "defenseclaw-config"},
		Data: map[string]any{"config.yaml": "substrate:\n  identity:\n    oidc:\n      issuer: https://idp.example\n"}}}
	if kubeSignInRendered(oidc) {
		t.Error("an OIDC render counts as the Kubernetes sign-in")
	}
}

// The uninstall names the binding in its report and its purge steps.
func TestPreDeleteNamesTheAuthDelegatorBinding(t *testing.T) {
	plan := testPlan()
	plan.AuthDelegatorBinding = "defenseclaw-auth-delegator-defenseclaw-system-dc"
	steps := strings.Join(PurgeSteps(plan), "\n")
	if !strings.Contains(steps, "kubectl delete clusterrolebinding defenseclaw-auth-delegator-defenseclaw-system-dc") {
		t.Errorf("purge steps: %s", steps)
	}
	if strings.Contains(strings.Join(PurgeSteps(testPlan()), "\n"), "clusterrolebinding") {
		t.Error("purge steps name a binding that was never rendered")
	}
}
