// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"os/exec"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestChartChainEgressActionReachesTheLeaderGAP0250: the chain egress
// action the operator sets (here the alert opt-in, oidc-private) reaches the
// leader, which answers the callout's chain check with it: from the one
// config file the gateway and the leader both read (DEFENSECLAW_CONFIG from
// the defenseclaw-config ConfigMap), not from a flag on the gateway alone.
// At 448ce25c0b the alert went to gateway.extraArgs and the leader never
// got it.
func TestChartChainEgressActionReachesTheLeaderGAP0250(t *testing.T) {
	helm := helmBinary(t)
	objs := decodeMaps(t, renderChart(t, helm, "oidc-private"))
	var cfgText string
	pods := map[string]any{}
	for _, o := range objs {
		name, _ := dig(o, "metadata", "name").(string)
		switch {
		case o["kind"] == "ConfigMap" && name == "defenseclaw-config":
			cfgText, _ = dig(o, "data", "config.yaml").(string)
		case o["kind"] == "Deployment" && (name == "defenseclaw-gateway" || name == "defenseclaw-gateway-leader"):
			pods[name] = dig(o, "spec", "template", "spec")
		}
	}
	var cfg struct {
		Substrate struct {
			ChainEgressAction string `yaml:"chain_egress_action"`
		} `yaml:"substrate"`
	}
	if err := yaml.Unmarshal([]byte(cfgText), &cfg); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"defenseclaw-gateway", "defenseclaw-gateway-leader"} {
		pod := pods[name]
		if pod == nil {
			t.Fatalf("no %s Deployment", name)
		}
		c := asList(dig(pod, "containers"))[0]
		var args []string
		for _, a := range asList(dig(c, "args")) {
			args = append(args, a.(string))
		}
		flag := slices.ContainsFunc(args, func(a string) bool { return strings.HasPrefix(a, "--chain-egress-action") })
		envOK := false
		for _, e := range asList(dig(c, "env")) {
			if dig(e, "name") == "DEFENSECLAW_CONFIG" && dig(e, "value") == "/etc/defenseclaw/config.yaml" {
				envOK = true
			}
		}
		mountsConfig := false
		for _, v := range asList(dig(pod, "volumes")) {
			if dig(v, "configMap", "name") == "defenseclaw-config" {
				mountsConfig = true
			}
		}
		got := cfg.Substrate.ChainEgressAction
		if flag {
			t.Errorf("%s: the chain egress action is a flag on one Deployment (%v), not the shared config", name, args)
		}
		if got != "alert" || !envOK || !mountsConfig {
			t.Errorf("%s: reads config %v from the defenseclaw-config ConfigMap %v, whose substrate.chain_egress_action is %q; want the operator's alert there",
				name, envOK, mountsConfig, got)
		}
	}
}

// TestChartRefusesTheGatewayChainFlagGAP0250: the gateway-only flag that
// never reached the leader is refused, and so is an action that is not
// block or alert.
func TestChartRefusesTheGatewayChainFlagGAP0250(t *testing.T) {
	helm := helmBinary(t)
	for name, set := range map[string]string{
		"flag on gateway.extraArgs": "gateway.extraArgs={--chain-egress-action=alert}",
		"flag on gateway.args":      "gateway.args={serve,--substrate,--chain-egress-action=alert}",
		"unknown action":            "config.substrate.chain_egress_action=warn",
	} {
		args := []string{"template", "dc", chartDir, "--kube-version", chartKubeVersion, "--set", set}
		out, err := exec.Command(helm, args...).CombinedOutput()
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if !strings.Contains(string(out), "chain_egress_action") {
			t.Errorf("%s: refused without naming config.substrate.chain_egress_action: %s", name, out)
		}
	}
	for _, set := range []string{"config.substrate.chain_egress_action=alert", "config.substrate.chain_egress_action=block"} {
		if out, err := exec.Command(helm, "template", "dc", chartDir, "--kube-version", chartKubeVersion, "--set", set).CombinedOutput(); err != nil {
			t.Errorf("%s refused: %v\n%s", set, err, out)
		}
	}
}
