// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"errors"
	"io"
	"os/exec"
	"slices"
	"testing"

	"gopkg.in/yaml.v3"
)

// GAP-0183: the secrets admin API writes the Kubernetes sources of
// config.substrate.secrets with the gateway's token, so the gateway gets a
// Role in each source namespace: create, and get and patch by name where the
// Secret name is fixed (every Secret of the namespace when it has {person}).
// Never list, watch or delete, and never in the release namespace.
func TestGAP0183GatewayCanWriteThePersonSecrets(t *testing.T) {
	helm := helmBinary(t)
	roles, bindings := map[string]map[string]any{}, map[string]map[string]any{}
	for _, o := range decodeMaps(t, renderChart(t, helm, "person-secrets")) {
		if dig(o, "metadata", "name") != "defenseclaw-gateway-secrets" {
			continue
		}
		ns, _ := dig(o, "metadata", "namespace").(string)
		switch o["kind"] {
		case "Role":
			roles[ns] = o
		case "RoleBinding":
			bindings[ns] = o
		}
	}
	if len(roles) != 2 || len(bindings) != 2 {
		t.Fatalf("roles in %v, bindings in %v; want defenseclaw-actor-secrets and dc-people", keysOf(roles), keysOf(bindings))
	}
	rules := map[string][]any{}
	for ns, o := range roles {
		rules[ns] = asList(o["rules"])
	}
	for ns, rs := range rules {
		var verbs []any
		for _, r := range rs {
			if !slices.Contains(asList(dig(r, "resources")), any("secrets")) {
				t.Errorf("%s: a rule on %v", ns, dig(r, "resources"))
			}
			names := asList(dig(r, "resourceNames"))
			for _, v := range asList(dig(r, "verbs")) {
				verbs = append(verbs, v)
				switch v {
				case "list", "watch", "delete", "*":
					t.Errorf("%s: verb %v", ns, v)
				case "get", "patch":
					want := map[string][]any{"defenseclaw-actor-secrets": {"github-app", "pypi"}, "dc-people": nil}[ns]
					if !slices.Equal(names, want) {
						t.Errorf("%s: %v by names %v, want %v", ns, v, names, want)
					}
				}
			}
		}
		for _, v := range []any{"create", "get", "patch"} {
			if !slices.Contains(verbs, v) {
				t.Errorf("%s: no %v (verbs %v)", ns, v, verbs)
			}
		}
	}
	for ns, b := range bindings {
		subjects := asList(b["subjects"])
		if dig(b, "roleRef", "kind") != "Role" || dig(b, "roleRef", "name") != "defenseclaw-gateway-secrets" || len(subjects) != 1 ||
			dig(subjects[0], "name") != "defenseclaw-gateway" || dig(subjects[0], "namespace") != "defenseclaw-system" {
			t.Errorf("%s: binding %v %v", ns, b["roleRef"], subjects)
		}
	}
	// Without Kubernetes sources there is no such Role.
	for _, o := range decodeObjects(t, renderChart(t, helm, "launcher")) {
		if o.Metadata["name"] == "defenseclaw-gateway-secrets" {
			t.Fatalf("launcher render has %s %v", o.Kind, o.Metadata)
		}
	}
	// A Kubernetes source in the release or Substrate namespace fails the
	// render: the gateway would get patch on DefenseClaw's own Secrets.
	for _, src := range []string{
		"ate-secret://k8s.io/default/default/{person}-npm/token",
		"ate-secret://k8s.io/default/ate-system/npm/token",
	} {
		args := []string{"template", "dc", chartDir, "--kube-version", chartKubeVersion,
			"--set", "config.substrate.secrets[0].name=x", "--set", "config.substrate.secrets[0].source=" + src,
			"--set", "config.substrate.secrets[0].scope=per_person"}
		if err := exec.Command(helm, args...).Run(); err == nil {
			t.Errorf("source %s accepted", src)
		}
	}
}

func keysOf[V any](m map[string]V) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func decodeMaps(t *testing.T, out []byte) []map[string]any {
	t.Helper()
	var objs []map[string]any
	dec := yaml.NewDecoder(bytes.NewReader(out))
	for {
		var o map[string]any
		err := dec.Decode(&o)
		if errors.Is(err, io.EOF) {
			return objs
		}
		if err != nil {
			t.Fatal(err)
		}
		if o != nil {
			objs = append(objs, o)
		}
	}
}
