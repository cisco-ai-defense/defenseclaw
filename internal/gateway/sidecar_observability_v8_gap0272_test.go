// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
)

// gap0272ClusterDNS answers every name with one Service ClusterIP, as the
// cluster DNS of the Substrate gateway pod does.
type gap0272ClusterDNS struct{}

func (gap0272ClusterDNS) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return []net.IPAddr{{IP: net.ParseIP("10.96.12.34")}}, nil
}

// GAP-0272: the Substrate gateway with an otlp destination on an in-cluster
// collector Service, which config validate accepts, crashed on start with
// only "observability v8 bootstrap failed: runtime_unavailable". It starts.
func TestGAP0272SubstrateGatewayStartsWithAnInClusterOTLPDestination(t *testing.T) {
	for name, safety := range map[string]string{
		"default":                "",
		"allow_private_networks": "      network_safety:\n        allow_private_networks: true\n",
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newSidecarV8BootstrapFixture(t, 8, "")
			fixture.sidecar.observabilityV8Resolver = gap0272ClusterDNS{}
			raw := []byte(fmt.Sprintf(
				"config_version: 8\ndata_dir: %q\nobservability:\n  destinations:\n    - name: smk-otlp\n      kind: otlp\n"+
					"      endpoint: http://opentelemetry-collector.otel-system.svc:4318\n      protocol: http/protobuf\n"+
					"      tls:\n        insecure: true\n%s",
				fixture.dataDir, safety,
			))
			bound, err := fixture.sidecar.BootstrapObservabilityRuntime(t.Context(), fixture.configPath, raw)
			if err != nil || !bound {
				t.Fatalf("bootstrap bound=%t error=%v", bound, err)
			}
		})
	}
}

// gap0272PanickingDNS fails only at start: config validate never resolves.
type gap0272PanickingDNS struct{}

func (gap0272PanickingDNS) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	panic("resolver failure")
}

// A destination that does refuse the start names itself and the cause in
// the bootstrap error, without its endpoint. (A missing secret or CA is
// refused earlier, by the config load that config validate also runs.)
func TestGAP0272BootstrapErrorNamesTheDestinationAndTheCause(t *testing.T) {
	fixture := newSidecarV8BootstrapFixture(t, 8, "")
	fixture.sidecar.observabilityV8Resolver = gap0272PanickingDNS{}
	raw := []byte(fmt.Sprintf(
		"config_version: 8\ndata_dir: %q\nobservability:\n  destinations:\n    - name: smk-otlp\n      kind: otlp\n"+
			"      endpoint: https://otlp.example.test:4318\n      protocol: http/protobuf\n",
		fixture.dataDir,
	))
	bound, err := fixture.sidecar.BootstrapObservabilityRuntime(t.Context(), fixture.configPath, raw)
	if err == nil || bound {
		t.Fatalf("a failed exporter must refuse the start: bound=%t error=%v", bound, err)
	}
	message := err.Error()
	if !strings.HasPrefix(message, `sidecar observability v8 bootstrap failed: runtime_unavailable: destination "smk-otlp": `) ||
		strings.Contains(message, "example.test") {
		t.Fatalf("bootstrap error %q", message)
	}
}
