// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const egressReadRoleYAML = `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: defenseclaw-defenseclaw-system-egress-read
  namespace: ate-system
rules:
- apiGroups: [""]
  resources: [configmaps]
  resourceNames: [atenet-egress]
  verbs: [get]
`

const egressReadBindingYAML = `apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: defenseclaw-defenseclaw-system-egress-read
  namespace: ate-system
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: defenseclaw-defenseclaw-system-egress-read
subjects:
- kind: ServiceAccount
  name: defenseclaw-controller
  namespace: defenseclaw-system
`

const gatewaySubjectYAML = `- kind: ServiceAccount
  name: defenseclaw-gateway
  namespace: defenseclaw-system
`

// GAP-0505 (lead ruling on the RBAC exception): the Substrate namespace
// holds exactly one standing grant, get on the atenet-egress ConfigMap for
// the controller's ServiceAccount alone. At e1f0863e6c the binding also
// named the gateway's ServiceAccount and the check accepted any number of
// grants of that name and any subject list of controller and gateway.
// Every other verb, resource, resourceName, rule, subject, Role or
// RoleBinding there fails the check; hook RBAC is checked apart.
func TestSubstrateNamespaceHoldsOnlyTheControllerEgressReadGAP0505(t *testing.T) {
	role, binding := egressReadRoleYAML, egressReadBindingYAML
	sub := func(s, old, new string) string {
		t.Helper()
		if !strings.Contains(s, old) {
			t.Fatalf("mutation %q does not apply", old)
		}
		return strings.Replace(s, old, new, 1)
	}
	otherRole := strings.ReplaceAll(role, "-egress-read", "-extra")
	hookRole := sub(strings.ReplaceAll(role, "-egress-read", "-hooks"), "  namespace: ate-system\n",
		"  namespace: ate-system\n  annotations:\n    helm.sh/hook: pre-delete\n    helm.sh/hook-delete-policy: before-hook-creation,hook-succeeded\n")
	for _, tc := range []struct {
		name string
		docs []string
		ok   bool
	}{
		{"the one grant", []string{role, binding}, true},
		{"hook RBAC is not a standing grant", []string{role, binding, hookRole}, true},
		{"list too", []string{sub(role, "verbs: [get]", "verbs: [get, list]"), binding}, false},
		{"watch too", []string{sub(role, "verbs: [get]", "verbs: [get, watch]"), binding}, false},
		{"list alone", []string{sub(role, "verbs: [get]", "verbs: [list]"), binding}, false},
		{"secrets too", []string{sub(role, "resources: [configmaps]", "resources: [configmaps, secrets]"), binding}, false},
		{"another ConfigMap too", []string{sub(role, "resourceNames: [atenet-egress]", "resourceNames: [atenet-egress, other]"), binding}, false},
		{"every ConfigMap", []string{sub(role, "  resourceNames: [atenet-egress]\n", ""), binding}, false},
		{"a second rule", []string{role + "- apiGroups: [\"\"]\n  resources: [pods]\n  verbs: [get]\n", binding}, false},
		{"the gateway too", []string{role, binding + gatewaySubjectYAML}, false},
		{"the gateway instead", []string{role, sub(binding, "name: defenseclaw-controller", "name: defenseclaw-gateway")}, false},
		{"a controller of another namespace", []string{role, sub(binding, "  namespace: defenseclaw-system\n", "  namespace: other\n")}, false},
		{"a user", []string{role, sub(binding, "kind: ServiceAccount", "kind: User")}, false},
		{"a ClusterRole", []string{role, sub(binding, "  kind: Role\n", "  kind: ClusterRole\n")}, false},
		{"another Role", []string{role, binding, otherRole}, false},
		{"two egress Roles", []string{role, binding, role}, false},
		{"two egress RoleBindings", []string{role, binding, binding}, false},
		{"no RoleBinding", []string{role}, false},
		{"no grant", nil, false},
	} {
		objs := decodeObjects(t, []byte(strings.Join(tc.docs, "---\n")))
		errs := substrateNamespaceGrantErrors(objs)
		if (len(errs) == 0) != tc.ok {
			t.Errorf("%s: errors %q, want ok=%v", tc.name, errs, tc.ok)
		}
	}
}

// The checked-in goldens (16 renders) carry the one grant, bound to the
// controller alone; this needs no helm.
func TestChartGoldensHoldOnlyTheControllerEgressReadGAP0505(t *testing.T) {
	for _, c := range chartCases {
		raw, err := os.ReadFile(filepath.Join(chartDir, "tests", "golden", c+".yaml"))
		if err != nil {
			t.Fatal(err)
		}
		if errs := substrateNamespaceGrantErrors(decodeObjects(t, raw)); len(errs) != 0 {
			t.Errorf("%s: %q", c, errs)
		}
		if strings.Contains(string(raw), "-egress-read\nsubjects:\n- kind: ServiceAccount\n  name: defenseclaw-controller\n  namespace: defenseclaw-system\n- ") {
			t.Errorf("%s: the egress read binding names more than the controller", c)
		}
	}
}

// The chart README's RBAC table names the grant and why it exists.
func TestChartReadmeNamesTheEgressReadGAP0505(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(chartDir, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	var row string
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "| Role and RoleBinding `defenseclaw-<release namespace>-egress-read`") {
			row = line
		}
	}
	for _, want := range []string{"controller's ServiceAccount alone", "`get`", "`atenet-egress` ConfigMap alone", "detect a replaced egress callout (GAP-0505)"} {
		if !strings.Contains(row, want) {
			t.Errorf("README RBAC row lacks %q: %q", want, row)
		}
	}
	if strings.Contains(row, "controller and gateway") {
		t.Errorf("README RBAC row still grants the gateway: %q", row)
	}
}
