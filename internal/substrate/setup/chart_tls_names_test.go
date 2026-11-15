// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
)

// podCertificateNames are the DNS names Agent Substrate's servicedns pod
// certificate carries for the chart's pods: "<service>.<namespace>.svc" for
// each Service, never the ".cluster.local" spelling (seen on the stk stack:
// defenseclaw-actor.dc.svc, defenseclaw-admin.dc.svc,
// defenseclaw-gateway-metrics.dc.svc).
func podCertificateNames(t *testing.T, out []byte, ns string) map[string]bool {
	t.Helper()
	names := map[string]bool{}
	for _, o := range decodeObjects(t, out) {
		if o.Kind == "Service" {
			names[fmt.Sprintf("%s.%s.svc", o.Metadata["name"], ns)] = true
		}
	}
	return names
}

// TestChartInClusterTLSNamesGAP0186: every in-cluster https URL the chart
// renders for a client that verifies the admin listener's pod certificate
// (the callout's judge, and the ask route built from it; the launcher
// endpoint's default) names a host that certificate carries. The
// ".svc.cluster.local" judge URL failed every TLS check, so every ask host
// and MCP verdict call failed closed with callout_error.
func TestChartInClusterTLSNamesGAP0186(t *testing.T) {
	helm := helmBinary(t)
	const ns = "defenseclaw-system"
	for _, c := range chartCases {
		t.Run(c, func(t *testing.T) {
			out := renderChart(t, helm, c)
			names := podCertificateNames(t, out, ns)
			if !names["defenseclaw-admin."+ns+".svc"] {
				t.Fatalf("no defenseclaw-admin Service rendered: %v", names)
			}
			cc := calloutConfigFrom(t, out)
			if cc.Judge.URL != "" {
				u, err := url.Parse(cc.Judge.URL)
				if err != nil || u.Scheme != "https" {
					t.Fatalf("judge.url %q", cc.Judge.URL)
				}
				if !names[u.Hostname()] {
					t.Errorf("judge.url host %q is not a pod certificate name %v", u.Hostname(), names)
				}
			}
			for _, o := range decodeObjects(t, out) {
				if o.Kind != "ConfigMap" || o.Metadata["name"] != "defenseclaw-launcher-endpoint" {
					continue
				}
				u, err := url.Parse(fmt.Sprint(o.Data["admin_url"]))
				if err != nil {
					t.Fatal(err)
				}
				// admin.url or an Ingress host is the operator's external
				// name; only the in-cluster default must be a pod name.
				if h := u.Hostname(); strings.HasSuffix(h, ".svc") || strings.HasSuffix(h, ".cluster.local") {
					if !names[h] {
						t.Errorf("launcher endpoint admin_url host %q is not a pod certificate name %v", h, names)
					}
				}
			}
		})
	}
	// The default install has a judge (the chart always mounts its token),
	// so the case above is not vacuous.
	if cc := calloutConfigFrom(t, renderChart(t, helm, "default")); cc.Judge.URL == "" {
		t.Fatal("default render has no judge.url")
	}
}
