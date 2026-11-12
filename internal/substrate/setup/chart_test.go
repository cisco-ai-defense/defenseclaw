// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/substrate/extproc"
)

// chartDir is the chart, from this package's directory.
const chartDir = "../../../deploy/helm/defenseclaw-substrate"

// chartKubeVersion is the Kubernetes version the goldens render for:
// Substrate needs pod certificates (PodCertificateRequest), so 1.34 or later.
const chartKubeVersion = "1.34.0"

// chartCases are the golden renders: values files under
// deploy/helm/defenseclaw-substrate/tests/values (empty for the defaults).
var chartCases = []string{"default", "launcher", "minimal", "full", "expose-lb", "expose-ingress"}

func helmBinary(t *testing.T) string {
	t.Helper()
	if h := os.Getenv("DEFENSECLAW_HELM"); h != "" {
		return h
	}
	h, err := exec.LookPath("helm")
	if err != nil {
		// The CI job substrate-chart installs a pinned helm and sets this;
		// the general Go shards have no helm and skip.
		if os.Getenv("DEFENSECLAW_HELM_REQUIRED") != "" {
			t.Fatal("helm is not installed; the chart goldens need it here")
		}
		t.Skip("helm is not installed (set DEFENSECLAW_HELM)")
	}
	return h
}

func renderChart(t *testing.T, helm, values string, extra ...string) []byte {
	t.Helper()
	args := []string{"template", "dc", chartDir, "--namespace", "defenseclaw-system", "--kube-version", chartKubeVersion}
	if values != "default" {
		args = append(args, "--values", filepath.Join(chartDir, "tests", "values", values+".yaml"))
	}
	args = append(args, extra...)
	cmd := exec.Command(helm, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("helm template %s: %v\n%s", values, err, stderr.String())
	}
	return out
}

func TestChartGoldens(t *testing.T) {
	helm := helmBinary(t)
	for _, c := range chartCases {
		t.Run(c, func(t *testing.T) {
			out := renderChart(t, helm, c)
			golden(t, filepath.Join("..", chartDir, "tests", "golden", c+".yaml"), out)
			checkChartInvariants(t, c, out)
		})
	}
}

func TestChartRefusesBadValues(t *testing.T) {
	helm := helmBinary(t)
	for name, set := range map[string]string{
		"hpa below 2":             "gateway.hpa.minReplicas=1",
		"short digest":            "image.digest=sha256:abc",
		"bad atespace":            "managedAtespaces={Bad_Name}",
		"ingress no host":         "admin.expose.type=Ingress",
		"ingress no tls":          "admin.expose.type=Ingress,admin.expose.ingress.host=dc.example.com",
		"lb no source ranges":     "admin.expose.type=LoadBalancer",
		"expose nodeport":         "admin.expose.type=NodePort",
		"managed fails open":      "config.deployment_mode=managed_enterprise,config.substrate.extproc.failure_mode=open",
		"secrets ns = release ns": "substrate.credentialProvider.secretsNamespace=default",
		"unknown value":           "gateway.surprise=1",
	} {
		args := []string{"template", "dc", chartDir, "--kube-version", chartKubeVersion, "--set", set}
		if err := exec.Command(helm, args...).Run(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

type k8sObject struct {
	APIVersion string         `yaml:"apiVersion"`
	Kind       string         `yaml:"kind"`
	Metadata   map[string]any `yaml:"metadata"`
	Spec       map[string]any `yaml:"spec"`
	Data       map[string]any `yaml:"data"`
}

func decodeObjects(t *testing.T, out []byte) []k8sObject {
	t.Helper()
	dec := yaml.NewDecoder(bytes.NewReader(out))
	var objs []k8sObject
	for {
		var o k8sObject
		err := dec.Decode(&o)
		if errors.Is(err, io.EOF) {
			return objs
		}
		if err != nil {
			t.Fatalf("rendered YAML: %v", err)
		}
		if o.Kind != "" {
			objs = append(objs, o)
		}
	}
}

func dig(m any, path ...string) any {
	for _, p := range path {
		mm, ok := m.(map[string]any)
		if !ok {
			return nil
		}
		m = mm[p]
	}
	return m
}

// checkChartInvariants holds the security properties every render keeps,
// whatever the values.
func checkChartInvariants(t *testing.T, name string, out []byte) {
	t.Helper()
	objs := decodeObjects(t, out)
	byName := map[string]k8sObject{}
	for _, o := range objs {
		byName[o.Kind+"/"+o.Metadata["name"].(string)] = o
		if o.Kind == "Secret" {
			t.Errorf("%s: the chart renders a Secret (%v); DefenseClaw's secrets are never chart values", name, o.Metadata["name"])
		}
		if o.Kind == "ClusterRole" || o.Kind == "ClusterRoleBinding" {
			t.Errorf("%s: cluster-wide RBAC %v", name, o.Metadata["name"])
		}
		if o.Kind == "Deployment" || o.Kind == "Job" {
			pod := dig(o.Spec, "template", "spec")
			if dig(pod, "securityContext", "runAsNonRoot") != true {
				t.Errorf("%s: %s %v runs as root", name, o.Kind, o.Metadata["name"])
			}
			if dig(pod, "automountServiceAccountToken") != false && o.Metadata["name"] != "defenseclaw-otel-collector" {
				t.Errorf("%s: %v automounts the ServiceAccount token", name, o.Metadata["name"])
			}
			for _, c := range dig(pod, "containers").([]any) {
				sc := dig(c, "securityContext")
				if dig(sc, "allowPrivilegeEscalation") != false || dig(sc, "readOnlyRootFilesystem") != true {
					t.Errorf("%s: container of %v: %v", name, o.Metadata["name"], sc)
				}
			}
		}
	}
	// A pod no Service selects gets no servicedns serving certificate, and a
	// pod that mounts one it cannot get never starts.
	if c, ok := byName["Deployment/defenseclaw-controller"]; ok {
		raw, _ := yaml.Marshal(c.Spec)
		if strings.Contains(string(raw), "servicedns.podcert.ate.dev/identity\n            keyType") ||
			strings.Contains(string(raw), "name: servicedns\n") {
			t.Errorf("%s: the controller mounts a servicedns serving certificate but no Service selects it", name)
		}
	}
	// The callout config parses as the callout reads it (strict), and names
	// the DefenseClaw hosts it must never buffer and the egress peer.
	cm, ok := byName["ConfigMap/defenseclaw-callout"]
	if !ok {
		t.Fatalf("%s: no callout ConfigMap", name)
	}
	cc, err := extproc.ParseConfig([]byte(cm.Data["callout.yaml"].(string)))
	if err != nil {
		t.Errorf("%s: callout.yaml: %v", name, err)
	} else {
		if !slices.Contains(cc.DefenseClawHosts, "defenseclaw-actor.defenseclaw-system.svc.cluster.local") ||
			!slices.Contains(cc.DefenseClawHosts, "defenseclaw-admin.defenseclaw-system.svc") {
			t.Errorf("%s: defenseclaw_hosts %v", name, cc.DefenseClawHosts)
		}
		if len(cc.EgressPeers) != 1 || !strings.HasSuffix(cc.EgressPeers[0], "/sa/atenet-egress") || cc.FailureMode != extproc.FailureClosed {
			t.Errorf("%s: egress peers %v, failure mode %s", name, cc.EgressPeers, cc.FailureMode)
		}
		if name == "full" && (len(cc.Secrets) != 1 || cc.Secrets[0].Placeholder != "DC_SECRET_GITHUB" || len(cc.Profiles) != 2 ||
			cc.Judge.URL == "" || cc.ActorSecretsDir == "" || len(cc.MCPHosts) != 1) {
			t.Errorf("full: callout config %+v", cc)
		}
		if raw, _ := yaml.Marshal(cm.Data); strings.Contains(string(raw), "ate-secret://") {
			t.Errorf("%s: the callout config carries a secret source", name)
		}
	}
	// D15: the actor Service exposes only the actor listener; the admin
	// Service only the admin listener.
	for svc, port := range map[string]string{"defenseclaw-actor": "actor", "defenseclaw-admin": "admin"} {
		ports := dig(byName["Service/"+svc].Spec, "ports").([]any)
		if len(ports) != 1 || dig(ports[0], "targetPort") != port {
			t.Errorf("%s: Service %s ports %v", name, svc, ports)
		}
	}
	// GAP-0023: egress reaches the actor Service on an http rule, port 80.
	if p := dig(byName["Service/defenseclaw-actor"].Spec, "ports").([]any)[0]; dig(p, "port") != 80 {
		t.Errorf("%s: actor Service port %v, want 80", name, dig(p, "port"))
	}
	// GAP-0086: only the admin listener is ever exposed outside the cluster.
	for _, o := range objs {
		switch o.Kind {
		case "Service":
			if typ := dig(o.Spec, "type"); typ == "LoadBalancer" || typ == "NodePort" {
				for _, pt := range dig(o.Spec, "ports").([]any) {
					if dig(pt, "targetPort") != "admin" {
						t.Errorf("%s: %s Service %v exposes %v", name, typ, o.Metadata["name"], dig(pt, "targetPort"))
					}
				}
			}
		case "Ingress":
			raw, _ := yaml.Marshal(o.Spec)
			if strings.Contains(string(raw), "defenseclaw-actor") || dig(o.Spec, "tls") == nil {
				t.Errorf("%s: Ingress %v: %s", name, o.Metadata["name"], raw)
			}
		}
	}
	np, ok := byName["NetworkPolicy/defenseclaw-gateway"]
	if !ok {
		if name != "minimal" {
			t.Errorf("%s: no gateway NetworkPolicy", name)
		}
		return
	}
	// The actor port admits only atenet-egress; the admin port never does.
	for _, rule := range dig(np.Spec, "ingress").([]any) {
		port := dig(rule, "ports").([]any)[0]
		from, _ := yaml.Marshal(dig(rule, "from"))
		switch dig(port, "port") {
		case 8080:
			if !strings.Contains(string(from), "atenet-egress") || strings.Count(string(from), "- ") != 1 {
				t.Errorf("%s: actor port peers %s", name, from)
			}
		case 9443:
			// Never atenet-egress (actors), and the namespace peer must
			// exclude Substrate worker pods, which host actors.
			if strings.Contains(string(from), "atenet-egress") || !strings.Contains(string(from), "DoesNotExist") ||
				strings.Contains(string(from), "podSelector: {}") {
				t.Errorf("%s: admin port admits egress or actors: %s", name, from)
			}
		}
	}
	if _, ok := byName["NetworkPolicy/defenseclaw-default-deny"]; !ok {
		t.Errorf("%s: no default deny", name)
	}
	// GAP-0084: the pods that hold keys have egress limits.
	for _, c := range []string{"gateway", "leader", "callout"} {
		if _, ok := byName["NetworkPolicy/defenseclaw-"+c+"-egress"]; !ok {
			t.Errorf("%s: no egress NetworkPolicy for the %s", name, c)
		}
	}
	// The hook plan parses as the plan the hook Jobs read.
	// Hook resources are the Jobs and RBAC that exists only while the hooks
	// run (GAP-0080: deleted once they succeed; Helm keeps other hook
	// resources after an uninstall), and each Job's plan parses as the plan
	// the step reads.
	var plans []string
	for _, o := range objs {
		hook, _ := dig(o.Metadata, "annotations", "helm.sh/hook").(string)
		del, _ := dig(o.Metadata, "annotations", "helm.sh/hook-delete-policy").(string)
		if hook != "" && o.Kind != "Job" && ((o.Kind != "Role" && o.Kind != "RoleBinding") || !strings.Contains(del, "hook-succeeded")) {
			t.Errorf("%s: hook resource %s %v outlives the release", name, o.Kind, o.Metadata["name"])
		}
		if (o.Kind == "Role" || o.Kind == "RoleBinding") && dig(o.Metadata, "namespace") == "ate-system" && hook == "" {
			t.Errorf("%s: a standing grant in the Substrate namespace: %s %v", name, o.Kind, o.Metadata["name"])
		}
		if o.Kind != "Job" {
			continue
		}
		for _, c := range dig(o.Spec, "template", "spec", "containers").([]any) {
			for _, e := range dig(c, "env").([]any) {
				if dig(e, "name") == "DEFENSECLAW_CHART_PLAN" {
					plans = append(plans, dig(e, "value").(string))
				}
			}
		}
	}
	if len(plans) < 3 {
		t.Fatalf("%s: %d hook Jobs carry a plan", name, len(plans))
	}
	p, err := ParsePlan([]byte(plans[0]))
	if err != nil {
		t.Errorf("%s: plan: %v", name, err)
	}
	if p.ActorHost != "defenseclaw-actor.defenseclaw-system.svc.cluster.local" {
		t.Errorf("%s: actor host %q is not the FQDN actors can resolve through egress (GAP-0023)", name, p.ActorHost)
	}
	if !slices.Contains(p.GlobalViewers, "system:serviceaccount:defenseclaw-system:defenseclaw-hooks") {
		t.Errorf("%s: the hooks ServiceAccount cannot list actors for the uninstall", name)
	}
}
