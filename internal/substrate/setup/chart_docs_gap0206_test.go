// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// eksPage is the EKS install page, from this package's directory.
const eksPage = "../../../docs-site/content/docs/substrate/eks.mdx"

// TestEKSPrivateOIDCIssuerEgressExample (substrate-1:GAP-0206): the EKS
// page's private OIDC issuer paragraph carries a networkPolicy.egress.extra
// example, and that example, rendered with the chart's defaults, is the rule
// that lets the key-holding pods (the gateway signs people in) reach the
// issuer. Without it the default NetworkPolicy blocks the issuer, as the page
// says.
func TestEKSPrivateOIDCIssuerEgressExample(t *testing.T) {
	values, rule := eksIssuerExample(t)
	ip, port := ruleTarget(t, rule)

	helm := helmBinary(t)
	file := filepath.Join(t.TempDir(), "issuer.yaml")
	if err := os.WriteFile(file, []byte(values), 0o600); err != nil {
		t.Fatal(err)
	}
	with := egressPolicies(t, renderChart(t, helm, "default", "--values", file))
	without := egressPolicies(t, renderChart(t, helm, "default"))
	if _, ok := with["defenseclaw-gateway-egress"]; !ok || len(with) != len(without) {
		t.Fatalf("egress policies with the example %v, without %v", keys(with), keys(without))
	}
	for name, rules := range without {
		if allows(rules, ip, port) {
			t.Errorf("%s: the default already allows %s:%d; the page says the issuer is blocked", name, ip, port)
		}
	}
	for name, rules := range with {
		found := false
		for _, r := range rules {
			found = found || reflect.DeepEqual(r, rule)
		}
		if !found {
			t.Errorf("%s: the page's rule is not rendered: %v", name, rules)
		}
		if !allows(rules, ip, port) {
			t.Errorf("%s: %s:%d is still blocked with the page's example", name, ip, port)
		}
	}
}

// eksIssuerExample returns the first yaml fence after the private OIDC
// issuer paragraph and its one networkPolicy.egress.extra rule.
func eksIssuerExample(t *testing.T) (string, map[string]any) {
	t.Helper()
	page, err := os.ReadFile(eksPage)
	if err != nil {
		t.Fatal(err)
	}
	_, after, ok := strings.Cut(string(page), "**A private OIDC issuer.**")
	if !ok {
		t.Fatal("eks.mdx has no private OIDC issuer paragraph")
	}
	para, rest, _ := strings.Cut(after, "\n\n")
	if !strings.Contains(para, "networkPolicy.egress.extra") {
		t.Fatal("the private OIDC issuer paragraph does not name networkPolicy.egress.extra")
	}
	_, fence, ok := strings.Cut(rest, "```yaml\n")
	if !ok || !strings.HasPrefix(rest, "```yaml\n") {
		t.Fatal("the private OIDC issuer paragraph is not followed by a yaml example")
	}
	values, _, _ := strings.Cut(fence, "```")
	var v map[string]any
	if err := yaml.Unmarshal([]byte(values), &v); err != nil {
		t.Fatalf("the page's example is not YAML: %v", err)
	}
	extra, _ := dig(v, "networkPolicy", "egress", "extra").([]any)
	if len(extra) != 1 {
		t.Fatalf("the page's example has %d networkPolicy.egress.extra rules, want 1: %v", len(extra), v)
	}
	rule, ok := extra[0].(map[string]any)
	if !ok {
		t.Fatalf("rule %v is not a mapping", extra[0])
	}
	return values, rule
}

// ruleTarget is the one ipBlock address and TCP port the rule admits.
func ruleTarget(t *testing.T, rule map[string]any) (net.IP, int) {
	t.Helper()
	to, _ := rule["to"].([]any)
	ports, _ := rule["ports"].([]any)
	if len(to) != 1 || len(ports) != 1 {
		t.Fatalf("rule %v: want one peer and one port", rule)
	}
	ip, _, err := net.ParseCIDR(dig(to[0], "ipBlock", "cidr").(string))
	if err != nil {
		t.Fatal(err)
	}
	port, ok := dig(ports[0], "port").(int)
	if !ok || dig(ports[0], "protocol") != "TCP" {
		t.Fatalf("rule port %v: want a TCP port number", ports[0])
	}
	return ip, port
}

// egressPolicies maps each NetworkPolicy with egress rules to its rules.
func egressPolicies(t *testing.T, out []byte) map[string][]map[string]any {
	t.Helper()
	got := map[string][]map[string]any{}
	for _, o := range decodeObjects(t, out) {
		if o.Kind != "NetworkPolicy" {
			continue
		}
		rules, _ := o.Spec["egress"].([]any)
		if len(rules) == 0 {
			continue
		}
		name, _ := o.Metadata["name"].(string)
		for _, r := range rules {
			m, _ := r.(map[string]any)
			got[name] = append(got[name], m)
		}
	}
	return got
}

// allows reports whether a rule admits TCP to ip:port. Pod and namespace
// selectors never match an address outside the cluster.
func allows(rules []map[string]any, ip net.IP, port int) bool {
	for _, r := range rules {
		portOK := r["ports"] == nil
		ports, _ := r["ports"].([]any)
		for _, p := range ports {
			proto := dig(p, "protocol")
			if (proto == nil || proto == "TCP") && dig(p, "port") == port {
				portOK = true
			}
		}
		peerOK := r["to"] == nil
		peers, _ := r["to"].([]any)
		for _, p := range peers {
			if c, ok := dig(p, "ipBlock", "cidr").(string); ok {
				if _, n, err := net.ParseCIDR(c); err == nil && n.Contains(ip) {
					peerOK = true
				}
			}
		}
		if portOK && peerOK {
			return true
		}
	}
	return false
}

func keys(m map[string][]map[string]any) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
