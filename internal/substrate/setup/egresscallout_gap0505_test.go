// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// egressEnvoy is the shape of atenet-egress's envoy.yaml (Substrate 1.0.x,
// cut down): the additional callout is the additional_egress_ext_proc
// cluster, present only while a callout is registered.
func egressEnvoy(calloutHost string) string {
	doc := `node:
  id: atenet-egress
static_resources:
  listeners:
  - name: egress
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          http_filters:
          - name: envoy.filters.http.ext_proc
            typed_config:
              grpc_service:
                envoy_grpc:
                  cluster_name: egress_ext_proc
              failure_mode_allow: false
  clusters:
  - name: egress_ext_proc
    type: STATIC
    load_assignment:
      cluster_name: egress_ext_proc
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: 127.0.0.1
                port_value: 50051
`
	if calloutHost != "" {
		doc += `  - name: additional_egress_ext_proc
    type: STRICT_DNS
    transport_socket:
      name: envoy.transport_sockets.tls
      typed_config:
        sni: ` + strings.TrimSuffix(calloutHost, ".cluster.local") + `
    load_assignment:
      cluster_name: additional_egress_ext_proc
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: ` + calloutHost + `
                port_value: 9443
`
	}
	return doc
}

type cmGetter struct {
	cm  *ConfigMap
	err error
	ns  string
}

func (g *cmGetter) GetConfigMap(_ context.Context, namespace, name string) (*ConfigMap, error) {
	g.ns = namespace + "/" + name
	return g.cm, g.err
}

// GAP-0505: the slot is read from atenet-egress's live config, which names
// the callout ate-setup deployed, whatever any SubstrateInstall file says.
func TestEgressCalloutHolderGAP0505(t *testing.T) {
	for _, tc := range []struct {
		host, want string
	}{
		{"defenseclaw-callout.dc.svc.cluster.local", "dc/defenseclaw-callout:9443"},
		{"other-callout.default.svc.cluster.local", "default/other-callout:9443"},
		{"other-callout.default.svc", "default/other-callout:9443"},
		{"10.0.0.7", "10.0.0.7:9443"},
		{"", ""},
	} {
		got, err := EgressCalloutHolder([]byte(egressEnvoy(tc.host)))
		if err != nil || got != tc.want {
			t.Errorf("%q: holder %q, %v; want %q", tc.host, got, err, tc.want)
		}
	}
	if _, err := EgressCalloutHolder([]byte("{")); err == nil {
		t.Error("an unreadable config read as a slot")
	}
	if _, err := EgressCalloutHolder(nil); err == nil {
		t.Error("an empty config read as no callout")
	}
}

func TestEgressCalloutReaderGAP0505(t *testing.T) {
	ctx := context.Background()
	cm := func(host string) *ConfigMap {
		return &ConfigMap{Namespace: "ate-system", Name: EgressConfigMap, Data: map[string]string{EgressEnvoyKey: egressEnvoy(host)}}
	}
	g := &cmGetter{cm: cm("defenseclaw-callout.dc.svc.cluster.local")}
	r := &EgressCalloutReader{Kube: g, SubstrateNamespace: "ate-system", Namespace: "dc"}
	slot, err := r.ReadCalloutSlot(ctx)
	if err != nil || !slot.Ours || slot.Holder != "dc/defenseclaw-callout:9443" || g.ns != "ate-system/atenet-egress" {
		t.Fatalf("ours: %+v, %v (read %s)", slot, err, g.ns)
	}
	// Another release's DefenseClaw callout is not ours.
	r.Namespace = "dc2"
	if slot, err = r.ReadCalloutSlot(ctx); err != nil || slot.Ours {
		t.Fatalf("another namespace's callout counted as ours: %+v, %v", slot, err)
	}
	r.Namespace = "dc"
	g.cm = cm("other-callout.default.svc.cluster.local")
	if slot, err = r.ReadCalloutSlot(ctx); err != nil || slot.Ours || slot.Holder != "default/other-callout:9443" {
		t.Fatalf("other: %+v, %v", slot, err)
	}
	g.cm = cm("")
	if slot, err = r.ReadCalloutSlot(ctx); err != nil || slot.Ours || slot.Holder != "" {
		t.Fatalf("none: %+v, %v", slot, err)
	}
	// Unknown is an error, never "no callout": no ConfigMap, no key, no grant.
	for _, g2 := range []*cmGetter{{}, {cm: &ConfigMap{Data: map[string]string{}}}, {err: errors.New("kubernetes API 403: forbidden")}} {
		r.Kube = g2
		if slot, err := r.ReadCalloutSlot(ctx); err == nil {
			t.Errorf("%+v: read as %+v", g2, slot)
		}
	}
}
