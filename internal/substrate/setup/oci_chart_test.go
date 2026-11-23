// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"os/exec"
	"slices"
	"testing"
)

// GAP-0437 (Preview): bundles.oci renders substrate.bundles.oci and the
// controller-only mounts for the registry login Secret and the CA file. Off
// by default, like the code.
func TestChartBundlesOCI(t *testing.T) {
	helm := helmBinary(t)

	t.Run("off by default: no oci key, no mount", func(t *testing.T) {
		for _, c := range []string{"default", "bundles"} {
			pods, cfg, _ := f11Render(t, renderChart(t, helm, c))
			if dig(cfg, "substrate", "bundles", "oci") != nil {
				t.Errorf("%s: config has bundles.oci: %v", c, dig(cfg, "substrate", "bundles"))
			}
			for name, p := range pods {
				for _, v := range []string{"bundle-oci-auth", "bundle-oci-ca"} {
					if slices.Contains(p.volumes, v) {
						t.Errorf("%s: %s mounts %s by default", c, name, v)
					}
				}
			}
		}
	})

	t.Run("on with a Secret: login mounted in the controller only", func(t *testing.T) {
		pods, cfg, _ := f11Render(t, renderChart(t, helm, "bundles-oci"))
		oci := dig(cfg, "substrate", "bundles", "oci")
		if dig(oci, "enabled") != true || dig(oci, "timeout") != "45s" ||
			dig(oci, "credentials_file") != "/etc/defenseclaw-substrate/bundle-oci-auth/config.json" ||
			dig(oci, "ca_file") != nil {
			t.Errorf("bundles.oci = %v", oci)
		}
		if h := asList(dig(oci, "auth_hosts")); len(h) != 1 || h[0] != "auth.registry.example.com" {
			t.Errorf("auth_hosts = %v", h)
		}
		st := asList(dig(oci, "stages"))
		if len(st) != 1 || dig(st[0], "stage") != "prod" || len(asList(dig(st[0], "atespaces"))) != 2 {
			t.Errorf("stages = %v", st)
		}
		ctl := pods["defenseclaw-controller"]
		if !slices.Contains(ctl.mounts, "bundle-oci-auth=/etc/defenseclaw-substrate/bundle-oci-auth") {
			t.Errorf("controller mounts = %v", ctl.mounts)
		}
		v := ctl.volume["bundle-oci-auth"]
		items := asList(dig(v, "secret", "items"))
		if dig(v, "secret", "secretName") != "dc-bundle-registry" || len(items) != 1 ||
			dig(items[0], "key") != ".dockerconfigjson" || dig(items[0], "path") != "config.json" {
			t.Errorf("login volume = %v", v)
		}
		for name, p := range pods {
			if name != "defenseclaw-controller" && (slices.Contains(p.volumes, "bundle-oci-auth") || slices.Contains(p.volumes, "bundle-oci-ca")) {
				t.Errorf("%s gets the OCI mounts", name)
			}
		}
		for _, m := range ctl.mounts {
			if m == "bundle-oci-ca=/etc/defenseclaw-substrate/bundle-oci-ca" {
				t.Error("a CA mount without a CA value")
			}
		}
	})

	t.Run("on with a CA: ConfigMap key mounted, anonymous pulls", func(t *testing.T) {
		pods, cfg, _ := f11Render(t, renderChart(t, helm, "bundles-oci-ca"))
		oci := dig(cfg, "substrate", "bundles", "oci")
		if dig(oci, "ca_file") != "/etc/defenseclaw-substrate/bundle-oci-ca/ca.crt" || dig(oci, "credentials_file") != nil {
			t.Errorf("bundles.oci = %v", oci)
		}
		ctl := pods["defenseclaw-controller"]
		if !slices.Contains(ctl.mounts, "bundle-oci-ca=/etc/defenseclaw-substrate/bundle-oci-ca") ||
			slices.Contains(ctl.volumes, "bundle-oci-auth") {
			t.Errorf("controller mounts = %v, volumes = %v", ctl.mounts, ctl.volumes)
		}
		v := ctl.volume["bundle-oci-ca"]
		items := asList(dig(v, "configMap", "items"))
		if dig(v, "configMap", "name") != "registry-ca" || len(items) != 1 ||
			dig(items[0], "key") != "registry-ca.pem" || dig(items[0], "path") != "ca.crt" {
			t.Errorf("CA volume = %v", v)
		}
	})

	t.Run("a CA from a Secret", func(t *testing.T) {
		pods, _, _ := f11Render(t, renderChart(t, helm, "bundles-oci-ca", "--set", "bundles.oci.ca.configMap=,bundles.oci.ca.secret=registry-ca-secret"))
		v := pods["defenseclaw-controller"].volume["bundle-oci-ca"]
		if dig(v, "secret", "secretName") != "registry-ca-secret" || dig(v, "configMap") != nil {
			t.Errorf("CA volume = %v", v)
		}
	})

	t.Run("config.substrate.bundles.oci wins over the values", func(t *testing.T) {
		_, cfg, _ := f11Render(t, renderChart(t, helm, "bundles-oci", "--set",
			"config.substrate.bundles.enabled=true,config.substrate.bundles.oci.enabled=false"))
		if dig(cfg, "substrate", "bundles", "oci", "enabled") != false || dig(cfg, "substrate", "bundles", "oci", "stages") != nil {
			t.Errorf("bundles.oci = %v", dig(cfg, "substrate", "bundles", "oci"))
		}
	})

	t.Run("refused values", func(t *testing.T) {
		const ref = "registry.example.com/p/b@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		for name, set := range map[string]string{
			"oci without bundle mode": "bundles.oci.enabled=true,bundles.oci.stages[0].stage=prod,bundles.oci.stages[0].ref=" + ref,
			"oci without a stage":     "bundles.enabled=true,bundles.oci.enabled=true",
			"a tag ref":               "bundles.enabled=true,bundles.oci.enabled=true,bundles.oci.stages[0].stage=prod,bundles.oci.stages[0].ref=registry.example.com/p/b:v1",
			"login without bundles":   "bundles.oci.credentialsSecret=x",
			"CA from both":            "bundles.enabled=true,bundles.oci.ca.configMap=a,bundles.oci.ca.secret=b",
			"bad timeout":             "bundles.enabled=true,bundles.oci.timeout=soon",
			"unknown oci key":         "bundles.enabled=true,bundles.oci.insecure=true",
		} {
			args := []string{"template", "dc", chartDir, "--kube-version", chartKubeVersion, "--set", set}
			if err := exec.Command(helm, args...).Run(); err == nil {
				t.Errorf("%s: accepted", name)
			}
		}
	})
}
