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
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type rbacObject struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Rules []struct {
		APIGroups []string `yaml:"apiGroups"`
		Resources []string `yaml:"resources"`
		Verbs     []string `yaml:"verbs"`
	} `yaml:"rules"`
	RoleRef struct {
		Kind string `yaml:"kind"`
		Name string `yaml:"name"`
	} `yaml:"roleRef"`
	Subjects []struct {
		Kind      string `yaml:"kind"`
		Name      string `yaml:"name"`
		Namespace string `yaml:"namespace"`
	} `yaml:"subjects"`
}

func clusterRBAC(t *testing.T, out []byte) (roles, bindings []rbacObject) {
	t.Helper()
	for _, doc := range strings.Split(string(out), "\n---") {
		var o rbacObject
		if yaml.Unmarshal([]byte(doc), &o) != nil {
			continue
		}
		switch o.Kind {
		case "ClusterRole":
			roles = append(roles, o)
		case "ClusterRoleBinding":
			bindings = append(bindings, o)
		}
	}
	return roles, bindings
}

// TestChartTokenReviewGrantGAP0153: with the Kubernetes sign-in on (no
// OIDC issuer, not managed) the gateway ServiceAccount, and only it, may
// create TokenReviews, through a ClusterRole with that one rule; with an
// OIDC issuer, on a managed install, or with --no-kube-sign-in, nothing
// cluster-scoped is rendered.
func TestChartTokenReviewGrantGAP0153(t *testing.T) {
	helm := helmBinary(t)
	roles, bindings := clusterRBAC(t, renderChart(t, helm, "kube-signin"))
	if len(roles) != 1 || len(bindings) != 1 {
		t.Fatalf("kube sign-in: %d ClusterRoles, %d ClusterRoleBindings", len(roles), len(bindings))
	}
	r, b := roles[0], bindings[0]
	if len(r.Rules) != 1 || !slices.Equal(r.Rules[0].APIGroups, []string{"authentication.k8s.io"}) ||
		!slices.Equal(r.Rules[0].Resources, []string{"tokenreviews"}) || !slices.Equal(r.Rules[0].Verbs, []string{"create"}) {
		t.Errorf("ClusterRole rules %+v", r.Rules)
	}
	if !strings.Contains(r.Metadata.Name, "defenseclaw-system") || b.RoleRef.Kind != "ClusterRole" || b.RoleRef.Name != r.Metadata.Name {
		t.Errorf("names: role %q, binding roleRef %+v", r.Metadata.Name, b.RoleRef)
	}
	if len(b.Subjects) != 1 || b.Subjects[0].Kind != "ServiceAccount" || b.Subjects[0].Name != "defenseclaw-gateway" ||
		b.Subjects[0].Namespace != "defenseclaw-system" {
		t.Errorf("subjects %+v", b.Subjects)
	}
	images := "config.substrate.templates.allowed_images[0]=registry.example.com/defenseclaw/*"
	for name, extra := range map[string][]string{
		"oidc":            {"--set", "config.substrate.identity.oidc.issuer=https://idp.example", "--set", "config.substrate.identity.oidc.client_id=dc"},
		"managed":         {"--set", "config.deployment_mode=managed_enterprise", "--set", images},
		"no-kube-sign-in": {"--set", "gateway.args={serve,--substrate,--no-kube-sign-in}"},
	} {
		if roles, bindings := clusterRBAC(t, renderChart(t, helm, "kube-signin", extra...)); len(roles)+len(bindings) != 0 {
			t.Errorf("%s: %d ClusterRoles, %d ClusterRoleBindings", name, len(roles), len(bindings))
		}
	}
}
