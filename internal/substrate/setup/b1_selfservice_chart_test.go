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
	"os/exec"
	"slices"
	"testing"
)

// B1 S3: with self-service secrets on (the default) the chart makes the
// binding store ConfigMap with no data and resource-policy keep (helm
// upgrade keeps the live bindings the chart never set), the values
// namespace, a gateway Role there for dc-b-<person> Secrets, get/update
// on the store for the gateway and get for the controller, and the hook
// plan that grants the credential provider that namespace. mode off: none
// of it, and the plan still names the namespace so its grants are revoked.
func TestB1ChartSelfServiceSecrets(t *testing.T) {
	helm := helmBinary(t)
	type found struct {
		cm, ns, valuesRole bool
		cmData             any
		cmKeep             any
		gwVerbs, ctlVerbs  []string
		plan               ChartPlan
	}
	look := func(out []byte) found {
		var f found
		for _, o := range decodeMaps(t, out) {
			name, _ := dig(o, "metadata", "name").(string)
			ns, _ := dig(o, "metadata", "namespace").(string)
			switch {
			case o["kind"] == "ConfigMap" && name == "defenseclaw-secret-bindings":
				f.cm, f.cmData, f.cmKeep = ns == "defenseclaw-system", o["data"], dig(o, "metadata", "annotations", "helm.sh/resource-policy")
			case o["kind"] == "Namespace" && name == "defenseclaw-user-secrets":
				f.ns = dig(o, "metadata", "annotations", "helm.sh/resource-policy") == "keep"
			case o["kind"] == "Role" && name == "defenseclaw-gateway-secrets" && ns == "defenseclaw-user-secrets":
				f.valuesRole = true
				for _, r := range o["rules"].([]any) {
					if dig(r, "resourceNames") != nil {
						f.valuesRole = false // dc-b-<person>: every Secret of the namespace
					}
				}
			case o["kind"] == "Role" && (name == "defenseclaw-gateway" || name == "defenseclaw-controller"):
				for _, r := range o["rules"].([]any) {
					names, _ := dig(r, "resourceNames").([]any)
					if !slices.Contains(names, any("defenseclaw-secret-bindings")) {
						continue
					}
					var verbs []string
					for _, v := range dig(r, "verbs").([]any) {
						verbs = append(verbs, v.(string))
					}
					if name == "defenseclaw-gateway" {
						f.gwVerbs = verbs
					} else {
						f.ctlVerbs = verbs
					}
				}
			}
		}
		f.plan = hookPlanFrom(t, decodeObjects(t, out))
		return f
	}

	on := look(renderChart(t, helm, "default"))
	if !on.cm || on.cmData != nil || on.cmKeep != "keep" {
		t.Fatalf("store ConfigMap: in release ns %v, data %v, resource-policy %v", on.cm, on.cmData, on.cmKeep)
	}
	if !on.ns || !on.valuesRole {
		t.Fatalf("values namespace kept %v, gateway values Role %v", on.ns, on.valuesRole)
	}
	if !slices.Equal(on.gwVerbs, []string{"get", "update"}) || !slices.Equal(on.ctlVerbs, []string{"get"}) {
		t.Fatalf("store verbs gateway %v controller %v", on.gwVerbs, on.ctlVerbs)
	}
	if cp := on.plan.CredentialProvider; !cp.UserSecrets || cp.UserSecretsNamespace != "defenseclaw-user-secrets" {
		t.Fatalf("hook plan credential provider %+v", cp)
	}

	off := look(renderChart(t, helm, "default", "--set", "config.substrate.self_service_secrets.mode=off"))
	if off.cm || off.ns || off.valuesRole || off.gwVerbs != nil || off.ctlVerbs != nil {
		t.Fatalf("mode off still renders self-service objects: %+v", off)
	}
	if cp := off.plan.CredentialProvider; cp.UserSecrets || cp.UserSecretsNamespace != "defenseclaw-user-secrets" {
		t.Fatalf("mode off hook plan %+v (must name the namespace to revoke it)", cp)
	}

	pre := look(renderChart(t, helm, "default", "--set", "substrate.credentialProvider.createUserSecretsNamespace=false"))
	if pre.ns || !pre.cm || !pre.valuesRole {
		t.Fatalf("createUserSecretsNamespace=false: %+v", pre)
	}

	for _, ns := range []string{"defenseclaw-system", "ate-system"} {
		args := []string{"template", "dc", chartDir, "--namespace", "defenseclaw-system", "--kube-version", chartKubeVersion,
			"--set", "config.substrate.self_service_secrets.namespace=" + ns}
		if err := exec.Command(helm, args...).Run(); err == nil {
			t.Errorf("self_service_secrets.namespace=%s accepted", ns)
		}
	}
}
