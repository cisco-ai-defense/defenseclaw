// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"errors"
	"fmt"
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
var chartCases = []string{"default", "launcher", "minimal", "full", "expose-lb", "expose-ingress", "bundles", "managed", "actor-secrets", "kube-signin", "ask-keys", "managed-bundles", "person-secrets", "oidc-private"}

// helmPinnedVersion is the helm release the goldens are rendered with and
// that the CI job substrate-chart installs (keep it equal to HELM_VERSION in
// .github/workflows/ci.yml). Other helm releases print the same objects with
// different YAML, so a golden compare under them is not a test of the chart.
const helmPinnedVersion = "v3.17.3"

func helmBinary(t *testing.T) string {
	t.Helper()
	required := os.Getenv("DEFENSECLAW_HELM_REQUIRED") != ""
	h := os.Getenv("DEFENSECLAW_HELM")
	if h == "" {
		var err error
		if h, err = exec.LookPath("helm"); err != nil {
			// The CI job substrate-chart installs the pinned helm and sets
			// DEFENSECLAW_HELM_REQUIRED; the general Go shards skip.
			if required {
				t.Fatal("helm is not installed; the chart goldens need it here")
			}
			t.Skip("helm is not installed (set DEFENSECLAW_HELM)")
		}
	}
	// The hosted runners ship their own helm, which is not the pinned one:
	// only the job that installs the pinned release compares the goldens.
	out, err := exec.Command(h, "version", "--template", "{{.Version}}").Output()
	if got := strings.TrimSpace(string(out)); err != nil || got != helmPinnedVersion {
		if required {
			t.Fatalf("helm %q is not the pinned %s the goldens are rendered with (%v)", got, helmPinnedVersion, err)
		}
		t.Skipf("helm %q is not the pinned %s (set DEFENSECLAW_HELM)", got, helmPinnedVersion)
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
		"hpa below 2":               "gateway.hpa.minReplicas=1",
		"short digest":              "image.digest=sha256:abc",
		"bad atespace":              "managedAtespaces={Bad_Name}",
		"ingress no host":           "admin.expose.type=Ingress",
		"ingress no tls":            "admin.expose.type=Ingress,admin.expose.ingress.host=dc.example.com",
		"lb no source ranges":       "admin.expose.type=LoadBalancer,admin.url=https://dc.example.com",
		"lb no url":                 "admin.expose.type=LoadBalancer,admin.expose.loadBalancer.sourceRanges={10.0.0.0/8}",
		"url not https":             "admin.url=http://dc.example.com",
		"expose nodeport":           "admin.expose.type=NodePort",
		"managed fails open":        "config.deployment_mode=managed_enterprise,config.substrate.extproc.failure_mode=open,config.substrate.templates.allowed_images={reg.example.com/dc/*}",
		"secrets ns = release ns":   "substrate.credentialProvider.secretsNamespace=default",
		"managed no allowed_images": "config.deployment_mode=managed_enterprise",
		"managed unattested":        "config.deployment_mode=managed_enterprise,config.substrate.require_attested_templates=false,config.substrate.templates.allowed_images={reg.example.com/dc/*}",
		"unknown value":             "gateway.surprise=1",
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
	RoleRef    map[string]any `yaml:"roleRef"`
	Subjects   []any          `yaml:"subjects"`
}

// authDelegatorGrant reports whether a cluster-scoped RBAC object is the
// chart's one allowed exception (lead ruling, GAP-0153): a
// ClusterRoleBinding of the gateway ServiceAccount alone to
// system:auth-delegator. Whether it may be rendered at all (the Kubernetes
// sign-in on) is checked by the caller.
func authDelegatorGrant(o k8sObject) bool {
	return o.Kind == "ClusterRoleBinding" && o.RoleRef["kind"] == "ClusterRole" && o.RoleRef["name"] == "system:auth-delegator" &&
		len(o.Subjects) == 1 && dig(o.Subjects[0], "kind") == "ServiceAccount" && dig(o.Subjects[0], "name") == "defenseclaw-gateway"
}

// kubeSignInRendered reports whether the render runs the Kubernetes sign-in:
// the gateway config has no OIDC issuer and the install is not managed.
func kubeSignInRendered(objs []k8sObject) bool {
	for _, o := range objs {
		if o.Kind != "ConfigMap" || o.Metadata["name"] != "defenseclaw-config" {
			continue
		}
		var cfg struct {
			DeploymentMode string `yaml:"deployment_mode"`
			Substrate      struct {
				Identity struct {
					OIDC struct {
						Issuer string `yaml:"issuer"`
					} `yaml:"oidc"`
				} `yaml:"identity"`
			} `yaml:"substrate"`
		}
		if yaml.Unmarshal([]byte(fmt.Sprint(o.Data["config.yaml"])), &cfg) != nil {
			return false
		}
		return cfg.Substrate.Identity.OIDC.Issuer == "" && !strings.HasPrefix(strings.ToLower(cfg.DeploymentMode), "managed")
	}
	return false
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
	kubeSignIn := kubeSignInRendered(objs)
	byName := map[string]k8sObject{}
	for _, o := range objs {
		byName[o.Kind+"/"+o.Metadata["name"].(string)] = o
		if o.Kind == "Secret" {
			t.Errorf("%s: the chart renders a Secret (%v); DefenseClaw's secrets are never chart values", name, o.Metadata["name"])
		}
		if (o.Kind == "ClusterRole" || o.Kind == "ClusterRoleBinding") && (!kubeSignIn || !authDelegatorGrant(o)) {
			// The one exception: the gateway bound to system:auth-delegator,
			// and only when people sign in with Kubernetes (GAP-0153).
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
		// The admin Service is never a callout-allowed host; it is refused in
		// every spelling (D15, GAP-0066).
		if !slices.Contains(cc.DefenseClawHosts, "defenseclaw-actor.defenseclaw-system.svc.cluster.local") ||
			slices.ContainsFunc(cc.DefenseClawHosts, func(h string) bool { return strings.HasPrefix(h, "defenseclaw-admin") }) {
			t.Errorf("%s: defenseclaw_hosts %v", name, cc.DefenseClawHosts)
		}
		for _, h := range []string{"defenseclaw-admin.defenseclaw-system.svc.cluster.local", "defenseclaw-admin.defenseclaw-system.svc",
			"defenseclaw-admin.defenseclaw-system", "defenseclaw-admin"} {
			if !slices.Contains(cc.InternalHosts, h) {
				t.Errorf("%s: internal_hosts %v lacks %s", name, cc.InternalHosts, h)
			}
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
	// GAP-0135: in managed mode every DefenseClaw pod reads config.yaml as one
	// read-only file (no ConfigMap directory symlinks), and its data dir is
	// its own volume that an init container gives to the gateway account
	// with 0700.
	if name == "managed" || name == "managed-bundles" {
		if !strings.Contains(fmt.Sprint(byName["ConfigMap/defenseclaw-config"].Data["config.yaml"]), "deployment_mode: managed_enterprise") {
			t.Errorf("managed: deployment_mode not in config.yaml")
		}
		for _, d := range []string{"defenseclaw-gateway", "defenseclaw-gateway-leader", "defenseclaw-controller", "defenseclaw-callout"} {
			pod := dig(byName["Deployment/"+d].Spec, "template", "spec")
			raw, _ := yaml.Marshal(pod)
			if !strings.Contains(string(raw), "subPath: config.yaml") || !strings.Contains(string(raw), "--mode=0700") ||
				!strings.Contains(string(raw), "mountPath: /var/lib/defenseclaw/data") || strings.Contains(string(raw), "mountPath: /etc/defenseclaw\n") {
				t.Errorf("managed: %s pod is not set up for the managed trust checks", d)
			}
			for _, ic := range dig(pod, "initContainers").([]any) {
				caps, _ := yaml.Marshal(dig(ic, "securityContext", "capabilities"))
				if dig(ic, "securityContext", "allowPrivilegeEscalation") != false || !strings.Contains(string(caps), "- ALL") ||
					strings.Contains(string(caps), "SYS_ADMIN") || strings.Contains(string(caps), "DAC_OVERRIDE") {
					t.Errorf("managed: %s init container: %s", d, caps)
				}
			}
		}
	} else if strings.Contains(string(out), "substrate-datadir") {
		t.Errorf("%s: a non-managed render runs the data dir init container", name)
	}
	// A pre-install hook Job cannot use a release ServiceAccount: install
	// creates those after the pre-install hooks.
	for _, o := range objs {
		hook, _ := dig(o.Metadata, "annotations", "helm.sh/hook").(string)
		if o.Kind != "Job" || !strings.Contains(hook, "pre-install") {
			continue
		}
		sa, _ := dig(o.Spec, "template", "spec", "serviceAccountName").(string)
		if s, ok := byName["ServiceAccount/"+sa]; !ok || !strings.Contains(fmt.Sprint(dig(s.Metadata, "annotations", "helm.sh/hook")), "pre-install") {
			t.Errorf("%s: pre-install Job %v runs as %q, which is not a pre-install hook resource", name, o.Metadata["name"], sa)
		}
	}
	// GAP-0143: the actor listener serves plain HTTP (egress uses an http
	// rule on port 80); --plain-http (both listeners) is never rendered.
	if gw, ok := byName["Deployment/defenseclaw-gateway"]; ok {
		raw, _ := yaml.Marshal(gw.Spec)
		if !strings.Contains(string(raw), "- --actor-plain-http") || strings.Contains(string(raw), "- --plain-http") {
			t.Errorf("%s: gateway args: actor listener not plain HTTP, or --plain-http set", name)
		}
	}
	// A13: the chain key is created by a hook (never rendered), mounted
	// into the gateway and the leader; the callout reaches the leader.
	if !strings.Contains(string(out), "- chain-key") || !strings.Contains(string(out), "secretName: defenseclaw-chain-key") {
		t.Errorf("%s: no chain-key hook or Secret mount", name)
	}
	// F4 follow-up: the relay session key is created by its own hook (never
	// rendered), with its own ServiceAccount that may read only that
	// Secret, and the gateway mounts it.
	if !strings.Contains(string(out), "- relay-session\n") || !strings.Contains(string(out), "serviceAccountName: defenseclaw-relay-key") ||
		!strings.Contains(string(out), "resourceNames: [\"defenseclaw-relay-session\"]") {
		t.Errorf("%s: no relay-session hook with its own ServiceAccount", name)
	}
	if c, ok := byName["Deployment/defenseclaw-callout"]; ok {
		raw, _ := yaml.Marshal(c.Spec)
		if name != "minimal" && !strings.Contains(string(raw), "--leader-address=defenseclaw-leader.") {
			t.Errorf("%s: the callout has no leader address", name)
		}
	}
	// GAP-0130: the launcher endpoint record names an https admin URL, and
	// the only grant to every authenticated user is reading that record.
	if cm, ok := byName["ConfigMap/defenseclaw-launcher-endpoint"]; !ok || !strings.HasPrefix(fmt.Sprint(cm.Data["admin_url"]), "https://") {
		t.Errorf("%s: launcher endpoint record = %+v", name, cm.Data)
	}
	if n := strings.Count(string(out), "name: system:authenticated"); n != 1 {
		t.Errorf("%s: %d grants to every authenticated user, want the endpoint read only", name, n)
	}
	if r, ok := byName["Role/defenseclaw-launcher-endpoint-read"]; ok {
		raw, _ := yaml.Marshal(r)
		if !strings.Contains(string(raw), "defenseclaw-launcher-endpoint") || strings.Contains(string(raw), "list") || strings.Contains(string(raw), "update") {
			t.Errorf("%s: endpoint read role: %s", name, raw)
		}
	} else {
		t.Errorf("%s: no endpoint read role", name)
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
	// GAP-0139: egress to the Substrate namespace allows the idp pod port
	// (8443 behind Service port 443), or the gateway cannot fetch the JWKS.
	if gw, ok := byName["NetworkPolicy/defenseclaw-gateway-egress"]; ok {
		raw, _ := yaml.Marshal(gw.Spec)
		if !strings.Contains(string(raw), "port: 8443") {
			t.Errorf("%s: gateway egress does not allow the idp pod port 8443", name)
		}
	}
	// GAP-0084: the pods that hold keys have egress limits.
	for _, c := range []string{"gateway", "leader", "callout", "controller"} {
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
		if hook != "" && o.Kind != "Job" && ((o.Kind != "Role" && o.Kind != "RoleBinding" && o.Kind != "ServiceAccount") || !strings.Contains(del, "hook-succeeded")) {
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
