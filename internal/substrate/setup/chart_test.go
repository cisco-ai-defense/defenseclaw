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
)

// chartDir is the chart, from this package's directory.
const chartDir = "../../../deploy/helm/defenseclaw-substrate"

// chartKubeVersion is the Kubernetes version the goldens render for:
// Substrate needs pod certificates (PodCertificateRequest), so 1.34 or later.
const chartKubeVersion = "1.34.0"

// chartCases are the golden renders: values files under
// deploy/helm/defenseclaw-substrate/tests/values (empty for the defaults).
var chartCases = []string{"default", "launcher", "minimal", "full"}

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
		"hpa below 2":     "gateway.hpa.minReplicas=1",
		"short digest":    "image.digest=sha256:abc",
		"bad atespace":    "managedAtespaces={Bad_Name}",
		"ingress no host": "adminIngress.enabled=true",
		"unknown value":   "gateway.surprise=1",
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
	// D15: the actor Service exposes only the actor listener; the admin
	// Service only the admin listener.
	for svc, port := range map[string]string{"defenseclaw-actor": "actor", "defenseclaw-admin": "admin"} {
		ports := dig(byName["Service/"+svc].Spec, "ports").([]any)
		if len(ports) != 1 || dig(ports[0], "targetPort") != port {
			t.Errorf("%s: Service %s ports %v", name, svc, ports)
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
		case 8443:
			if !strings.Contains(string(from), "atenet-egress") || strings.Count(string(from), "- ") != 1 {
				t.Errorf("%s: actor port peers %s", name, from)
			}
		case 9443:
			if strings.Contains(string(from), "atenet-egress") || strings.Contains(string(from), "worker-pool") {
				t.Errorf("%s: admin port admits egress or actors: %s", name, from)
			}
		}
	}
	if _, ok := byName["NetworkPolicy/defenseclaw-default-deny"]; !ok {
		t.Errorf("%s: no default deny", name)
	}
	// The hook plan parses as the plan the hook Jobs read.
	plan := byName["ConfigMap/defenseclaw-chart-plan"]
	p, err := ParsePlan([]byte(plan.Data["plan.json"].(string)))
	if err != nil {
		t.Errorf("%s: plan.json: %v", name, err)
	}
	if !slices.Contains(p.GlobalViewers, "system:serviceaccount:defenseclaw-system:defenseclaw-hooks") {
		t.Errorf("%s: the hooks ServiceAccount cannot list actors for the uninstall", name)
	}
}
