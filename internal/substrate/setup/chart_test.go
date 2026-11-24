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
	"regexp"
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
var chartCases = []string{"default", "launcher", "minimal", "full", "expose-lb", "expose-ingress", "bundles", "managed", "actor-secrets", "kube-signin", "ask-keys", "managed-bundles", "person-secrets", "oidc-private", "private-registry", "actor-keys", "bundles-oci", "bundles-oci-ca", "substrate-sync"}

// helmPinnedVersion is the helm release the goldens are rendered with and
// that the CI job substrate-chart installs (keep it equal to HELM_VERSION in
// .github/workflows/ci.yml). Other helm releases print the same objects with
// different YAML, so a golden compare under them is not a test of the chart.
const helmPinnedVersion = "v3.17.3"

// helmVerdict is what the chart tests do with the helm they found: use it
// (path), fail the test (fail) or skip it (skip). Exactly one is set.
type helmVerdict struct{ path, fail, skip string }

// helmRequiredMessage is the sentence every helm failure or skip ends with, so
// a gate log shows how to make a missing helm fail (GAP-0882: a gate on a box
// without helm ran the chart tests as skips and looked green).
const helmRequiredMessage = "the chart tests did NOT run; set DEFENSECLAW_HELM_REQUIRED=1 in every gate run so a missing or unpinned helm fails them instead"

// resolveHelm decides from the environment. required is
// DEFENSECLAW_HELM_REQUIRED=1 (any other value, "0" included, is not
// required, as the env-var registry says); explicit is DEFENSECLAW_HELM.
func resolveHelm(required bool, explicit string, lookPath func(string) (string, error), version func(string) (string, error)) helmVerdict {
	h := explicit
	if h == "" {
		var err error
		if h, err = lookPath("helm"); err != nil {
			// The CI job substrate-chart installs the pinned helm and sets
			// DEFENSECLAW_HELM_REQUIRED; the general Go shards skip.
			if required {
				return helmVerdict{fail: "helm is not installed; the chart goldens need it here"}
			}
			return helmVerdict{skip: "helm is not installed (set DEFENSECLAW_HELM): " + helmRequiredMessage}
		}
	}
	// The hosted runners ship their own helm, which is not the pinned one:
	// only the job that installs the pinned release compares the goldens.
	out, err := version(h)
	if got := strings.TrimSpace(out); err != nil || got != helmPinnedVersion {
		if required {
			return helmVerdict{fail: fmt.Sprintf("helm %q is not the pinned %s the goldens are rendered with (%v)", got, helmPinnedVersion, err)}
		}
		return helmVerdict{skip: fmt.Sprintf("helm %q is not the pinned %s (set DEFENSECLAW_HELM): %s", got, helmPinnedVersion, helmRequiredMessage)}
	}
	return helmVerdict{path: h}
}

// helmRequiredFromEnv is DEFENSECLAW_HELM_REQUIRED=1.
func helmRequiredFromEnv() bool { return os.Getenv("DEFENSECLAW_HELM_REQUIRED") == "1" }

func helmBinary(t *testing.T) string {
	t.Helper()
	verdict := resolveHelm(helmRequiredFromEnv(), os.Getenv("DEFENSECLAW_HELM"), exec.LookPath,
		func(h string) (string, error) {
			out, err := exec.Command(h, "version", "--template", "{{.Version}}").Output()
			return string(out), err
		})
	switch {
	case verdict.fail != "":
		t.Fatal(verdict.fail)
	case verdict.skip != "":
		// Also on stderr, so a gate that keeps only failures and warnings
		// still shows that the chart tests were skipped.
		fmt.Fprintf(os.Stderr, "WARNING: %s: %s\n", t.Name(), verdict.skip)
		t.Skip(verdict.skip)
	}
	return verdict.path
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
		"budget store on cluster":   "config.routing.admin.budget_store.url=x", // the leader counts budgets; a pod store file is lost on restart
		"short digest":              "image.digest=sha256:abc",
		"empty relay secret":        "gateway.relaySessionSecret=",   // rendered secretName: "" and a hook Role naming ""
		"empty llm secret":          "gateway.llmCredentialsSecret=", // rendered secretName: "" on the llm-credentials volume (GAP-0236)
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
		// GAP-0402: the audit store's volume holds its cap twice over plus
		// the 256 MiB WAL ceiling, and the store has a cap.
		"home volume too small":         "homeSizeLimit=256Mi",
		"no audit store cap":            "config.observability.local.max_store_mb=0",
		"cap too large for the volume":  "config.observability.local.max_store_mb=4096",
		"managed data volume too small": "config.deployment_mode=managed_enterprise,config.substrate.templates.allowed_images={reg.example.com/dc/*},managed.dataSizeLimit=512Mi",
		"home medium not known":         "homeMedium=Disk",
		// GAP-0537: a memory home volume counts against the memory limit of
		// the container that writes it: every pod that mounts it needs
		// limits.memory >= homeSizeLimit + requests.memory, or the store
		// grows into an OOM kill instead of a full store.
		"memory home on the default sizes": "homeMedium=Memory", // 4Gi tmpfs, cap 1024, gateway limit 1Gi
		"memory home, no memory limit":     memoryHomeExample + ",callout.resources.limits=null",
		"memory home, no memory request":   memoryHomeExample + ",gateway.resources.requests=null",
		"memory home, limit below size":    "homeMedium=Memory,homeSizeLimit=512Mi,config.observability.local.max_store_mb=128", // controller and callout 512Mi < 512Mi + 128Mi
		"memory home, decimal limit short": memoryHomeExample + ",callout.resources.limits.memory=600M",                         // 572 MiB < 640 MiB
		"memory home, unreadable limit":    memoryHomeExample + ",leader.resources.limits.memory=lots",
		"bad namespace label":              "metrics.prometheusRule.enabled=true,metrics.prometheusRule.namespaceLabel=k8s.namespace.name",
		// substrate-1:GAP-0578 (f): the headroom is never under the chart default
		// request (controller 128Mi), so a 1Mi request does not make a 520Mi
		// limit fit a 512Mi tmpfs.
		"memory home, tiny request": memoryHomeExample + ",controller.resources.requests.memory=1Mi,controller.resources.limits.memory=520Mi",
		// RV3 P3-5: the self-service namespace is one of its own.
		"user secrets in kube-system":         "config.substrate.self_service_secrets.namespace=kube-system",
		"user secrets in default":             "config.substrate.self_service_secrets.namespace=default",
		"user secrets with the admin secrets": "config.substrate.self_service_secrets.namespace=defenseclaw-actor-secrets",
		// RV4 F7 (GAP-0782): never an atespace where actors run.
		"user secrets in a managed atespace":  "managedAtespaces={team-a},config.substrate.self_service_secrets.namespace=team-a",
		"user secrets in a launcher atespace": "config.substrate.launcher_atespaces.dev={team-b},config.substrate.self_service_secrets.namespace=team-b",
	} {
		args := []string{"template", "dc", chartDir, "--kube-version", chartKubeVersion, "--set", set}
		if err := exec.Command(helm, args...).Run(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// memoryHomeExample is the README's memory home volume (homeMedium Memory):
// a 512Mi tmpfs holds the 128 MiB cap twice over plus the 256 MiB WAL
// ceiling, and each pod's memory limit holds the tmpfs plus its memory
// request (gateway 1Gi >= 768Mi, leader 2Gi >= 1Gi, controller and callout
// 768Mi >= 640Mi) (GAP-0537).
const memoryHomeExample = "homeMedium=Memory,homeSizeLimit=512Mi,config.observability.local.max_store_mb=128," +
	"controller.resources.limits.memory=768Mi,callout.resources.limits.memory=768Mi"

// GAP-0402 (E3, 15 actors): DEFENSECLAW_HOME was a 256 MiB memory emptyDir,
// the audit write-ahead log's flood ceiling is also 256 MiB, and once the
// volume was full every audit write failed and every hook failed closed. The
// audit store of every DefenseClaw pod is now a disk emptyDir that holds the
// store's size cap (observability.local.max_store_mb) twice over plus the WAL
// ceiling, given to the gateway account (0700) by an init container, as the
// audit store's directory trust check needs. homeMedium Memory keeps a tmpfs
// and no init container.
func TestChartAuditStoreVolumeIsBoundedDisk(t *testing.T) {
	helm := helmBinary(t)
	for _, c := range []struct {
		values string
		extra  []string
		memory bool
	}{
		{values: "default"},
		{values: "minimal"},
		{values: "managed"},
		{values: "default", extra: []string{"--set", memoryHomeExample}, memory: true},
		// Decimal and byte quantities read as Kubernetes reads them: 700M is
		// 667 MiB and 805306368 is 768 MiB, both above 640 MiB (GAP-0537).
		{values: "default", extra: []string{"--set", memoryHomeExample + ",callout.resources.limits.memory=700M,controller.resources.limits.memory=805306368"}, memory: true},
	} {
		name := c.values + strings.Join(c.extra, "")
		objs := decodeObjects(t, renderChart(t, helm, c.values, c.extra...))
		capMB := 0
		for _, o := range objs {
			if o.Kind == "ConfigMap" && o.Metadata["name"] == "defenseclaw-config" {
				var cfg map[string]any
				if err := yaml.Unmarshal([]byte(fmt.Sprint(o.Data["config.yaml"])), &cfg); err != nil {
					t.Fatalf("%s: config.yaml: %v", name, err)
				}
				capMB, _ = dig(cfg, "observability", "local", "max_store_mb").(int)
			}
		}
		if capMB <= 0 {
			t.Errorf("%s: config.yaml has no observability.local.max_store_mb (the audit store has no size cap)", name)
		}
		pods := 0
		for _, o := range objs {
			if o.Kind != "Deployment" || o.Metadata["name"] == "defenseclaw-otel-collector" {
				continue
			}
			pods++
			pod := dig(o.Spec, "template", "spec")
			ctr := dig(pod, "containers").([]any)[0]
			home := ""
			for _, e := range dig(ctr, "env").([]any) {
				if dig(e, "name") == "DEFENSECLAW_HOME" {
					home, _ = dig(e, "value").(string)
				}
			}
			volName, mountPath := "", ""
			for _, m := range dig(ctr, "volumeMounts").([]any) {
				mp, _ := dig(m, "mountPath").(string)
				if home != "" && (home == mp || strings.HasPrefix(home, mp+"/")) && len(mp) > len(mountPath) {
					volName, mountPath = dig(m, "name").(string), mp
				}
			}
			var vol any
			for _, v := range dig(pod, "volumes").([]any) {
				if dig(v, "name") == volName {
					vol = v
				}
			}
			if vol == nil || dig(vol, "emptyDir") == nil {
				t.Errorf("%s: %v: DEFENSECLAW_HOME %q is not on an emptyDir volume (%v)", name, o.Metadata["name"], home, vol)
				continue
			}
			medium, _ := dig(vol, "emptyDir", "medium").(string)
			if c.memory != (medium == "Memory") {
				t.Errorf("%s: %v: the audit store volume %s has medium %q", name, o.Metadata["name"], volName, medium)
			}
			size, _ := dig(vol, "emptyDir", "sizeLimit").(string)
			sizeMB := 0
			if n, unit, ok := strings.Cut(size, "Gi"); ok && unit == "" {
				_, _ = fmt.Sscan(n, &sizeMB)
				sizeMB *= 1024
			} else if n, unit, ok := strings.Cut(size, "Mi"); ok && unit == "" {
				_, _ = fmt.Sscan(n, &sizeMB)
			}
			if sizeMB < 2*capMB+256 {
				t.Errorf("%s: %v: the audit store volume %s is %q, smaller than twice the %d MiB cap plus the 256 MiB WAL ceiling", name, o.Metadata["name"], volName, size, capMB)
			}
			// A disk volume's root is world-writable: an init container gives
			// it to the gateway account, or the trust check refuses it.
			given := false
			inits, _ := dig(pod, "initContainers").([]any)
			for _, ic := range inits {
				args, _ := yaml.Marshal(dig(ic, "args"))
				if strings.Contains(string(args), "- substrate-datadir\n") && strings.Contains(string(args), "--path="+mountPath+"\n") &&
					strings.Contains(string(args), "--mode=0700") {
					given = true
				}
			}
			if !c.memory && !given {
				t.Errorf("%s: %v: no init container gives %s to the gateway account", name, o.Metadata["name"], mountPath)
			}
			if c.memory && len(inits) != 0 {
				t.Errorf("%s: %v: a memory home volume runs init containers %v", name, o.Metadata["name"], inits)
			}
		}
		if pods < 3 {
			t.Errorf("%s: %d DefenseClaw Deployments rendered", name, pods)
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
	Rules      []any          `yaml:"rules"`
}

// egressReadGrant reports whether a Role or RoleBinding in the Substrate
// namespace is the chart's one standing grant there (GAP-0505, lead ruling
// 2026-11-17): get, and nothing else, on the atenet-egress ConfigMap alone,
// bound to the controller's ServiceAccount alone, so that it sees another
// callout replace DefenseClaw's. Any other verb, resource, resourceName,
// rule key or subject is not it.
func egressReadGrant(o k8sObject) bool {
	name, _ := o.Metadata["name"].(string)
	if !strings.HasPrefix(name, "defenseclaw-") || !strings.HasSuffix(name, "-egress-read") {
		return false
	}
	releaseNS := strings.TrimSuffix(strings.TrimPrefix(name, "defenseclaw-"), "-egress-read")
	if releaseNS == "" {
		return false
	}
	list := func(v any) string { return fmt.Sprint(v) }
	keys := func(m any) string {
		mm, _ := m.(map[string]any)
		ks := make([]string, 0, len(mm))
		for k := range mm {
			ks = append(ks, k)
		}
		slices.Sort(ks)
		return strings.Join(ks, ",")
	}
	switch o.Kind {
	case "Role":
		return len(o.Rules) == 1 && keys(o.Rules[0]) == "apiGroups,resourceNames,resources,verbs" &&
			list(dig(o.Rules[0], "apiGroups")) == "[]" && list(dig(o.Rules[0], "resources")) == "[configmaps]" &&
			list(dig(o.Rules[0], "resourceNames")) == "["+EgressConfigMap+"]" && list(dig(o.Rules[0], "verbs")) == "[get]"
	case "RoleBinding":
		if o.RoleRef["kind"] != "Role" || o.RoleRef["name"] != name || o.RoleRef["apiGroup"] != "rbac.authorization.k8s.io" {
			return false
		}
		// Exactly the controller's ServiceAccount: no gateway, no other
		// subject (the gateway reads the controller's result through the
		// leader).
		if len(o.Subjects) != 1 {
			return false
		}
		sub := o.Subjects[0]
		return keys(sub) == "kind,name,namespace" && dig(sub, "kind") == "ServiceAccount" &&
			dig(sub, "name") == "defenseclaw-controller" && dig(sub, "namespace") == releaseNS
	}
	return false
}

// substrateNamespaceGrantErrors checks the standing (not hook) RBAC of the
// Substrate namespace (GAP-0080, GAP-0505): exactly one Role and one
// RoleBinding, and both are the egress read grant. Hook RBAC there is
// deleted once the hooks succeed (checked apart).
func substrateNamespaceGrantErrors(objs []k8sObject) []string {
	var errs []string
	count := map[string]int{}
	for _, o := range objs {
		hook, _ := dig(o.Metadata, "annotations", "helm.sh/hook").(string)
		if (o.Kind != "Role" && o.Kind != "RoleBinding") || dig(o.Metadata, "namespace") != "ate-system" || hook != "" {
			continue
		}
		count[o.Kind]++
		if !egressReadGrant(o) {
			errs = append(errs, fmt.Sprintf("a standing grant in the Substrate namespace: %s %v", o.Kind, o.Metadata["name"]))
		}
	}
	if count["Role"] != 1 || count["RoleBinding"] != 1 {
		errs = append(errs, fmt.Sprintf("the Substrate namespace needs exactly one Role and one RoleBinding, the controller's get of the "+
			"atenet-egress ConfigMap (GAP-0505): %d Role, %d RoleBinding", count["Role"], count["RoleBinding"]))
	}
	return errs
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
	} else if strings.Contains(string(out), "--policies=") || strings.Contains(string(out), "mountPath: /var/lib/defenseclaw/data") {
		t.Errorf("%s: a non-managed render runs the managed data dir init container", name)
	}
	// The init container that gives a volume to the gateway account (managed
	// data, or the disk home volume, GAP-0402) has CHOWN and FOWNER, nothing else.
	for _, o := range objs {
		if o.Kind != "Deployment" {
			continue
		}
		inits, _ := dig(o.Spec, "template", "spec", "initContainers").([]any)
		for _, ic := range inits {
			add, drop := fmt.Sprint(dig(ic, "securityContext", "capabilities", "add")), fmt.Sprint(dig(ic, "securityContext", "capabilities", "drop"))
			if dig(ic, "securityContext", "allowPrivilegeEscalation") != false || dig(ic, "securityContext", "readOnlyRootFilesystem") != true ||
				add != "[CHOWN FOWNER]" || drop != "[ALL]" {
				t.Errorf("%s: %v init container: add %s, drop %s", name, o.Metadata["name"], add, drop)
			}
		}
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
	// Secret and (B3.5) the relay CA Secret the same step creates, and the
	// gateway mounts both, the relay CA as optional (a gateway upgraded
	// before setup ran again starts without it).
	if !strings.Contains(string(out), "- relay-session\n") || !strings.Contains(string(out), "serviceAccountName: defenseclaw-relay-key") ||
		!strings.Contains(string(out), "resourceNames: [\"defenseclaw-relay-session\", \"defenseclaw-relay-ca\"]") {
		t.Errorf("%s: no relay-session hook with its own ServiceAccount", name)
	}
	if !strings.Contains(string(out), "mountPath: /var/run/secrets/defenseclaw-relay-ca") ||
		!strings.Contains(string(out), "secretName: defenseclaw-relay-ca\n    optional: true") &&
			!strings.Contains(string(out), "secretName: defenseclaw-relay-ca\n          optional: true") {
		t.Errorf("%s: the gateway does not mount the relay CA Secret, or not as optional", name)
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
	for _, e := range substrateNamespaceGrantErrors(objs) {
		t.Errorf("%s: %s", name, e)
	}
	for _, o := range objs {
		hook, _ := dig(o.Metadata, "annotations", "helm.sh/hook").(string)
		del, _ := dig(o.Metadata, "annotations", "helm.sh/hook-delete-policy").(string)
		if hook != "" && o.Kind != "Job" && ((o.Kind != "Role" && o.Kind != "RoleBinding" && o.Kind != "ServiceAccount") || !strings.Contains(del, "hook-succeeded")) {
			t.Errorf("%s: hook resource %s %v outlives the release", name, o.Kind, o.Metadata["name"])
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
	// verify's openfga_grants check derives the same principals (GAP-0209).
	if !slices.Equal(p.Editors, ChartEditors(p.Namespace)) || !slices.Equal(p.GlobalViewers, ChartGlobalViewers(p.Namespace)) {
		t.Errorf("%s: plan editors %v / viewers %v differ from ChartEditors / ChartGlobalViewers", name, p.Editors, p.GlobalViewers)
	}
}

// substrate-1:GAP-0584 (review 2). The policy alerts selected
// k8s_namespace_name by default, a label a stock Prometheus OTLP receiver
// or a collector without resource_to_telemetry_conversion never writes, so
// they never fired. By default they read every release's series again;
// metrics.prometheusRule.namespaceLabel scopes them.
func TestGAP0584PolicyAlertsReadEverySeriesUnlessScoped(t *testing.T) {
	helm := helmBinary(t)
	out := string(renderChart(t, helm, "default", "--set", "metrics.prometheusRule.enabled=true"))
	for _, expr := range []string{"defenseclaw_substrate_policy_lag_seconds_bucket[5m]",
		"defenseclaw_substrate_policy_conflicts_total[10m]", "max(defenseclaw_substrate_unattested_templates) > 0"} {
		if !strings.Contains(out, expr) {
			t.Errorf("default rules: no %s", expr)
		}
	}
	if strings.Contains(out, "k8s_namespace_name") {
		t.Error("default rules select a namespace label no stock OTLP receiver writes")
	}
	scoped := string(renderChart(t, helm, "default", "--set", "metrics.prometheusRule.enabled=true",
		"--set", "metrics.prometheusRule.namespaceLabel=k8s_namespace_name"))
	if !strings.Contains(scoped, `defenseclaw_substrate_policy_conflicts_total{k8s_namespace_name="defenseclaw-system"}[10m]`) {
		t.Error("namespaceLabel set: the rules do not select the release's namespace")
	}
}

// substrate-1:GAP-0578 (f): validate.yaml floors each pod's process headroom
// at its chart default requests.memory, copied there by hand; a default that
// changes without its floor must fail here.
func TestChartMemoryHomeFloorsAreTheDefaultRequests(t *testing.T) {
	tmpl, err := os.ReadFile(filepath.Join(chartDir, "templates", "validate.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`\$floors := dict "gateway" (\d+) "leader" (\d+) "controller" (\d+) "callout" (\d+)`).FindStringSubmatch(string(tmpl))
	if m == nil {
		t.Fatal("validate.yaml has no $floors dict for gateway, leader, controller and callout")
	}
	raw, err := os.ReadFile(filepath.Join(chartDir, "values.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var values map[string]any
	if err := yaml.Unmarshal(raw, &values); err != nil {
		t.Fatal(err)
	}
	for i, pod := range []string{"gateway", "leader", "controller", "callout"} {
		request, _ := dig(values, pod, "resources", "requests", "memory").(string)
		mib, ok := strings.CutSuffix(request, "Mi")
		if !ok {
			t.Fatalf("%s.resources.requests.memory %q is not in Mi; teach this test the unit", pod, request)
		}
		if mib != m[i+1] {
			t.Errorf("validate.yaml floors %s at %s MiB, but its default request is %s", pod, m[i+1], request)
		}
	}
}

// GAP-0609, GAP-0610: setup.LeftoverHookJobs is the one list of the chart's
// hook Jobs other than pre-delete. The rendered hook Jobs (launcher renders
// bootstrap too) and the uninstall Role's resourceNames must be exactly that
// list, so a new or renamed hook Job cannot drift out of the uninstall.
func TestChartUninstallRoleDeletesLeftoverHookJobs(t *testing.T) {
	helm := helmBinary(t)
	want := strings.Join(LeftoverHookJobs, ", ")
	jobs := map[string]bool{}
	for _, values := range []string{"default", "launcher"} {
		out := string(renderChart(t, helm, values))
		var role string
		for _, doc := range strings.Split(out, "\n---") {
			name := ""
			if i := strings.Index(doc, "\nmetadata:\n  name: "); i >= 0 {
				name = strings.TrimSpace(strings.SplitN(doc[i+len("\nmetadata:\n  name: "):], "\n", 2)[0])
			}
			switch {
			// "\nkind: Role\n" at column 0: the RoleBinding's roleRef has
			// an indented "kind: Role" and the same name.
			case strings.Contains(doc, "\nkind: Role\n") && name == "defenseclaw-hooks-uninstall":
				role = doc
			case strings.Contains(doc, "\nkind: Job\n") && strings.Contains(doc, "helm.sh/hook: ") && name != "defenseclaw-pre-delete":
				jobs[name] = true
			}
		}
		if role == "" {
			t.Fatalf("%s: no Role defenseclaw-hooks-uninstall", values)
		}
		rule := "- apiGroups: [batch]\n  resources: [jobs]\n  resourceNames: [" + want + "]\n  verbs: [delete]"
		if !strings.Contains(role, rule) {
			t.Errorf("%s: the uninstall Role's Job rule is not %q (setup.LeftoverHookJobs):\n%s", values, rule, role)
		}
		if strings.Contains(role, "defenseclaw-pre-delete") {
			t.Errorf("%s: the uninstall Role must not delete its own Job:\n%s", values, role)
		}
	}
	var got []string
	for n := range jobs {
		got = append(got, n)
	}
	slices.Sort(got)
	listed := append([]string{}, LeftoverHookJobs...)
	slices.Sort(listed)
	if strings.Join(got, ",") != strings.Join(listed, ",") {
		t.Errorf("the chart's hook Jobs %v are not setup.LeftoverHookJobs %v", got, listed)
	}
}

// TestChartDefaultPricingMatchesBundle: the chart's files/default-pricing.json
// is the reviewed table of bundles/pricing, byte for byte, so the chart never
// seeds a price the bundle does not hold.
func TestChartDefaultPricingMatchesBundle(t *testing.T) {
	want, err := os.ReadFile(filepath.Join("..", "..", "..", "bundles", "pricing", "default-pricing.json"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(chartDir, "files", "default-pricing.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("deploy/helm/defenseclaw-substrate/files/default-pricing.json differs from bundles/pricing/default-pricing.json: copy it again")
	}
}
