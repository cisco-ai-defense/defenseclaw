// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"slices"
	"strings"
	"testing"
)

// GAP-0157: the gateway starts with the attach router flags by default, and
// its egress NetworkPolicy reaches the router's CONNECT-TLS port; no other
// pod gets either. substrate.router.enabled=false, or no pod certificates,
// turns both off. The router admitting the gateway is the overlay's
// ingressAllowedSPIFFEIDs entry (TestOverlay*) and the
// ingress_clients row of doctor --cluster.
func TestGatewayAttachRouterFlags(t *testing.T) {
	helm := helmBinary(t)
	want := []string{"--router-address=atenet-router.ate-system.svc:8444",
		"--router-ca-file=/run/servicedns.podcert.ate.dev/trust-bundle.pem", "--relay-port=8080"}
	for _, c := range chartCases {
		t.Run(c, func(t *testing.T) {
			out := renderChart(t, helm, c)
			args, ports := routerRender(t, out)
			if c == "minimal" {
				// No pod certificates: no identity for the router, so no attach.
				if slices.ContainsFunc(args["defenseclaw-gateway"], func(s string) bool { return strings.HasPrefix(s, "--router-") }) {
					t.Errorf("router flags without pod certificates: %v", args["defenseclaw-gateway"])
				}
				return
			}
			for _, w := range want {
				if !slices.Contains(args["defenseclaw-gateway"], w) {
					t.Errorf("gateway args lack %s: %v", w, args["defenseclaw-gateway"])
				}
			}
			for name, a := range args {
				if name != "defenseclaw-gateway" && slices.ContainsFunc(a, func(s string) bool { return strings.HasPrefix(s, "--router-") }) {
					t.Errorf("%s gets router flags", name)
				}
			}
			// The router admits the SPIFFE ID the overlay writes into
			// ingressAllowedSPIFFEIDs: it must be the one the gateway presents.
			if id := "--peer-id=" + IngressClientID("defenseclaw-system"); !slices.Contains(args["defenseclaw-gateway"], id) {
				t.Errorf("the gateway does not present %s, the overlay ID", id)
			}
			if !ports["defenseclaw-gateway-egress"] {
				t.Error("the gateway egress policy does not reach the router port 8444")
			}
			for name, has := range ports {
				if has && name != "defenseclaw-gateway-egress" {
					t.Errorf("%s reaches the router port", name)
				}
			}
		})
	}
	t.Run("custom address and server name", func(t *testing.T) {
		args, _ := routerRender(t, renderChart(t, helm, "default", "--set",
			"substrate.router.address=router.example.internal:9444,substrate.router.serverName=router.example.internal,substrate.router.relayPort=8090"))
		g := args["defenseclaw-gateway"]
		for _, w := range []string{"--router-address=router.example.internal:9444", "--router-server-name=router.example.internal", "--relay-port=8090"} {
			if !slices.Contains(g, w) {
				t.Errorf("gateway args lack %s: %v", w, g)
			}
		}
	})
	for name, set := range map[string]string{"router off": "substrate.router.enabled=false", "no pod certificates": "podCertificates.enabled=false"} {
		t.Run(name, func(t *testing.T) {
			args, ports := routerRender(t, renderChart(t, helm, "default", "--set", set))
			if slices.ContainsFunc(args["defenseclaw-gateway"], func(s string) bool { return strings.HasPrefix(s, "--router-") }) {
				t.Errorf("router flags with %s: %v", set, args["defenseclaw-gateway"])
			}
			if ports["defenseclaw-gateway-egress"] {
				t.Errorf("router port open with %s", set)
			}
		})
	}
}

// routerRender returns each Deployment's first container args, and whether
// each egress NetworkPolicy names port 8444.
func routerRender(t *testing.T, out []byte) (map[string][]string, map[string]bool) {
	t.Helper()
	args, ports := map[string][]string{}, map[string]bool{}
	for _, o := range decodeObjects(t, out) {
		name, _ := o.Metadata["name"].(string)
		switch o.Kind {
		case "Deployment":
			cs := asList(dig(o.Spec, "template", "spec", "containers"))
			if len(cs) == 0 {
				continue
			}
			for _, a := range asList(dig(cs[0], "args")) {
				if s, ok := a.(string); ok {
					args[name] = append(args[name], s)
				}
			}
		case "NetworkPolicy":
			if !strings.HasSuffix(name, "-egress") {
				continue
			}
			for _, rule := range asList(dig(o.Spec, "egress")) {
				for _, p := range asList(dig(rule, "ports")) {
					if dig(p, "port") == 8444 {
						ports[name] = true
					}
				}
			}
			if _, seen := ports[name]; !seen {
				ports[name] = false
			}
		}
	}
	return args, ports
}
