// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"errors"
	"io"
	"path"
	"slices"
	"testing"

	"gopkg.in/yaml.v3"
)

// GAP-0135 (bundle as the second activated source, sub/a2 0f94088fa8): a
// managed gateway in bundle mode reads the bundle state ConfigMaps and the
// bundle anchors at start (bundle.Store.Activated), so its pod has what the
// controller has: get on the state ConfigMaps through the bundle Role, the
// anchors Secret at the path its config names, the Kubernetes token and
// POD_NAMESPACE.
func TestManagedBundleGatewayCanReadTheBundleState(t *testing.T) {
	out := renderChart(t, helmBinary(t), "managed-bundles")
	byName := map[string]map[string]any{}
	dec := yaml.NewDecoder(bytes.NewReader(out))
	for {
		var o map[string]any
		err := dec.Decode(&o)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if o != nil {
			byName[o["kind"].(string)+"/"+dig(o, "metadata", "name").(string)] = o
		}
	}
	role, binding := byName["Role/defenseclaw-bundles"], byName["RoleBinding/defenseclaw-bundles"]
	gw, cm := byName["Deployment/defenseclaw-gateway"], byName["ConfigMap/defenseclaw-config"]
	if role == nil || binding == nil || gw == nil || cm == nil {
		t.Fatal("the bundle Role, its binding, the gateway or the config is missing")
	}
	canGet := false
	for _, r := range asList(role["rules"]) {
		if slices.Contains(asList(dig(r, "resourceNames")), any(bundleStateConfigMap)) && slices.Contains(asList(dig(r, "verbs")), any("get")) {
			canGet = true
		}
	}
	if !canGet {
		t.Fatalf("the bundle Role grants no get on %s: %v", bundleStateConfigMap, role["rules"])
	}
	bound := false
	for _, s := range asList(binding["subjects"]) {
		if dig(s, "name") == "defenseclaw-gateway" {
			bound = true
		}
	}
	if !bound {
		t.Fatal("the gateway ServiceAccount is not bound to the bundle Role")
	}
	var conf struct {
		DeploymentMode string `yaml:"deployment_mode"`
		Substrate      struct {
			Bundles struct {
				Enabled     bool   `yaml:"enabled"`
				AnchorsFile string `yaml:"anchors_file"`
			} `yaml:"bundles"`
		} `yaml:"substrate"`
	}
	if err := yaml.Unmarshal([]byte(dig(cm, "data", "config.yaml").(string)), &conf); err != nil {
		t.Fatal(err)
	}
	if !conf.Substrate.Bundles.Enabled || conf.DeploymentMode != "managed_enterprise" || conf.Substrate.Bundles.AnchorsFile == "" {
		t.Fatalf("rendered config: %+v", conf)
	}
	c := asList(dig(gw, "spec", "template", "spec", "containers"))[0]
	mounts := map[string]string{}
	for _, m := range asList(dig(c, "volumeMounts")) {
		mounts[dig(m, "name").(string)] = dig(m, "mountPath").(string)
	}
	if mounts["bundle-anchors"] != path.Dir(conf.Substrate.Bundles.AnchorsFile) {
		t.Fatalf("anchors mounted at %q, config reads %q", mounts["bundle-anchors"], conf.Substrate.Bundles.AnchorsFile)
	}
	if mounts["kube-api-token"] == "" {
		t.Fatal("the gateway has no Kubernetes token to read the ConfigMaps")
	}
	hasNS := false
	for _, e := range asList(dig(c, "env")) {
		if dig(e, "name") == "POD_NAMESPACE" {
			hasNS = true
		}
	}
	if !hasNS {
		t.Fatal("the gateway has no POD_NAMESPACE")
	}
}

// bundleStateConfigMap is bundle.StateConfigMap (that package imports this
// one through the controller, so the test cannot import it).
const bundleStateConfigMap = "defenseclaw-bundles"
