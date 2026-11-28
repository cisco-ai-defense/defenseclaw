// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"os/exec"
	"slices"
	"strings"
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
		for name, c := range map[string]struct{ set, msg string }{
			"oci without bundle mode": {"bundles.oci.enabled=true,bundles.oci.stages[0].stage=prod,bundles.oci.stages[0].ref=" + ref, "needs bundles.enabled=true"},
			"oci without a stage":     {"bundles.enabled=true,bundles.oci.enabled=true", "needs bundles.oci.stages"},
			"a tag ref":               {"bundles.enabled=true,bundles.oci.enabled=true,bundles.oci.stages[0].stage=prod,bundles.oci.stages[0].ref=registry.example.com/p/b:v1", "stages.0.ref"},
			"login without bundles":   {"bundles.oci.credentialsSecret=x", "need bundles.enabled=true"},
			"CA from both":            {"bundles.enabled=true,bundles.oci.ca.configMap=a,bundles.oci.ca.secret=b", "not both"},
			"bad timeout":             {"bundles.enabled=true,bundles.oci.timeout=soon", "bundles.oci.timeout"},
			"timeout below 5s":        {"bundles.enabled=true,bundles.oci.timeout=1s", "from 5s to 2m"},
			"timeout above 2m":        {"bundles.enabled=true,bundles.oci.timeout=3m", "from 5s to 2m"},
			"unknown oci key":         {"bundles.enabled=true,bundles.oci.insecure=true", "insecure"},
			"auth host with a scheme": {"bundles.enabled=true,bundles.oci.authHosts[0]=http://*.evil", "authHosts"},
			"auth host edge hyphen":   {"bundles.enabled=true,bundles.oci.authHosts[0]=-a.example.com", "authHosts"},
			"auth host without a dot": {"bundles.enabled=true,bundles.oci.authHosts[0]=localhost", "authHosts"},
		} {
			args := []string{"template", "dc", chartDir, "--kube-version", chartKubeVersion, "--set", c.set}
			out, err := exec.Command(helm, args...).CombinedOutput()
			if err == nil {
				t.Errorf("%s: accepted", name)
			} else if !strings.Contains(string(out), c.msg) {
				t.Errorf("%s: refused with the wrong message (want %q): %s", name, c.msg, out)
			}
		}
		for name, set := range map[string]string{
			"timeout 5s":    "bundles.enabled=true,bundles.oci.timeout=5s",
			"timeout 2m":    "bundles.enabled=true,bundles.oci.timeout=2m",
			"timeout 1.5m":  "bundles.enabled=true,bundles.oci.timeout=1.5m",
			"auth host":     "bundles.enabled=true,bundles.oci.authHosts[0]=auth.docker.io",
			"auth host:443": "bundles.enabled=true,bundles.oci.authHosts[0]=a-b.example.com:8443",
		} {
			args := []string{"template", "dc", chartDir, "--kube-version", chartKubeVersion, "--set", set}
			if out, err := exec.Command(helm, args...).CombinedOutput(); err != nil {
				t.Errorf("%s: refused: %s", name, out)
			}
		}
	})
}
