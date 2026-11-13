// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"fmt"
	"os/exec"
	"slices"
	"testing"

	"gopkg.in/yaml.v3"
)

// f11Pod is one Deployment's first container and pod volumes.
type f11Pod struct {
	args, mounts, volumes []string
	volume                map[string]any
}

func f11Render(t *testing.T, out []byte) (map[string]f11Pod, map[string]any, map[string]map[string]any) {
	t.Helper()
	pods, sas := map[string]f11Pod{}, map[string]map[string]any{}
	var cfg map[string]any
	for _, o := range decodeObjects(t, out) {
		name, _ := o.Metadata["name"].(string)
		switch o.Kind {
		case "Deployment":
			p := f11Pod{volume: map[string]any{}}
			if cs := asList(dig(o.Spec, "template", "spec", "containers")); len(cs) > 0 {
				for _, a := range asList(dig(cs[0], "args")) {
					p.args = append(p.args, fmt.Sprint(a))
				}
				for _, m := range asList(dig(cs[0], "volumeMounts")) {
					p.mounts = append(p.mounts, fmt.Sprint(dig(m, "name"))+"="+fmt.Sprint(dig(m, "mountPath")))
				}
			}
			for _, v := range asList(dig(o.Spec, "template", "spec", "volumes")) {
				n := fmt.Sprint(dig(v, "name"))
				p.volumes = append(p.volumes, n)
				p.volume[n] = v
			}
			pods[name] = p
		case "ServiceAccount":
			a, _ := o.Metadata["annotations"].(map[string]any)
			sas[name] = a
		case "ConfigMap":
			if name == "defenseclaw-config" {
				if err := yaml.Unmarshal([]byte(fmt.Sprint(o.Data["config.yaml"])), &cfg); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	return pods, cfg, sas
}

// GAP-0190: controller.templateRegistrySecret mounts the login file in the
// controller and the gateway only and points registry_auth.docker_config
// at it; componentAnnotations reach only the named ServiceAccounts (an
// IRSA role for ECR on gateway and controller, never the callout).
// GAP-0191: the OIDC CA can come from a Secret, and admin_groups stays in
// config.
func TestGAP0190ChartRegistryLogins(t *testing.T) {
	helm := helmBinary(t)
	pods, cfg, sas := f11Render(t, renderChart(t, helm, "private-registry"))
	gw, ctl := pods["defenseclaw-gateway"], pods["defenseclaw-controller"]

	const mount = "template-registry-auth=/etc/defenseclaw/substrate/registry-auth"
	for name, p := range map[string]f11Pod{"gateway": gw, "controller": ctl} {
		if !slices.Contains(p.mounts, mount) {
			t.Errorf("%s lacks the registry login mount: %v", name, p.mounts)
		}
		reg := p.volume["template-registry-auth"]
		items := asList(dig(reg, "secret", "items"))
		if dig(reg, "secret", "secretName") != "dc-template-registry" || len(items) != 1 ||
			dig(items[0], "key") != ".dockerconfigjson" || dig(items[0], "path") != "config.json" {
			t.Errorf("%s registry volume = %v", name, reg)
		}
	}
	for name, p := range pods {
		if name != "defenseclaw-gateway" && name != "defenseclaw-controller" && slices.Contains(p.volumes, "template-registry-auth") {
			t.Errorf("%s gets the registry logins", name)
		}
	}
	if got := dig(cfg, "substrate", "templates", "registry_auth", "docker_config"); got != "/etc/defenseclaw/substrate/registry-auth/config.json" {
		t.Errorf("registry_auth.docker_config = %v", got)
	}
	if got := asList(dig(cfg, "substrate", "templates", "registry_auth", "ecr_hosts")); len(got) != 1 {
		t.Errorf("registry_auth.ecr_hosts = %v", got)
	}
	if got := asList(dig(cfg, "substrate", "identity", "admin_groups")); len(got) != 1 || got[0] != "dc-admins" {
		t.Errorf("identity.admin_groups = %v", got)
	}
	if dig(gw.volume["oidc-ca"], "secret", "secretName") != "dc-oidc-ca" ||
		!slices.Contains(gw.args, "--oidc-ca-file=/etc/defenseclaw/oidc-ca/ca.crt") ||
		!slices.Contains(gw.mounts, "oidc-ca=/etc/defenseclaw/oidc-ca") {
		t.Errorf("OIDC CA from a Secret: volume %v, args %v", gw.volume["oidc-ca"], gw.args)
	}
	const role = "eks.amazonaws.com/role-arn"
	for sa, want := range map[string]bool{"defenseclaw-gateway": true, "defenseclaw-controller": true, "defenseclaw-callout": false} {
		if _, has := sas[sa][role]; has != want {
			t.Errorf("ServiceAccount %s IRSA annotation = %v, want %v", sa, has, want)
		}
	}

	t.Run("defaults are anonymous with no login mount", func(t *testing.T) {
		pods, cfg, _ := f11Render(t, renderChart(t, helm, "default"))
		for name, p := range pods {
			if slices.Contains(p.volumes, "template-registry-auth") {
				t.Errorf("%s mounts registry logins by default", name)
			}
		}
		if dig(cfg, "substrate", "templates", "registry_auth") != nil {
			t.Errorf("default config sets registry_auth: %v", dig(cfg, "substrate", "templates"))
		}
	})
	t.Run("a config docker_config wins over the chart mount path", func(t *testing.T) {
		_, cfg, _ := f11Render(t, renderChart(t, helm, "default", "--set",
			"controller.templateRegistrySecret=r,config.substrate.templates.registry_auth.docker_config=/own/config.json"))
		if got := dig(cfg, "substrate", "templates", "registry_auth", "docker_config"); got != "/own/config.json" {
			t.Errorf("docker_config = %v", got)
		}
	})
	t.Run("schema refuses an unknown component", func(t *testing.T) {
		args := []string{"template", "dc", chartDir, "--kube-version", chartKubeVersion, "--set", "serviceAccounts.componentAnnotations.leader.a=b"}
		if err := exec.Command(helm, args...).Run(); err == nil {
			t.Error("componentAnnotations.leader accepted")
		}
	})
}
