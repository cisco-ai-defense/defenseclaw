// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package otlp

import (
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
)

// GAP-0669: the resource a defenseclaw.substrate.* metric leaves with keeps
// k8s.namespace.name, the one Kubernetes attribute the chart's
// metrics.prometheusRule.namespaceLabel and its docs tell an operator to
// promote to scope the policy alerts to one release. Before, the cut dropped
// it, so no series carried the label and the scoped rules never fired. The
// host, cluster, tenant, workspace and device attributes stay cut.
func TestGAP0669RestrictedMetricResourceKeepsTheNamespace(t *testing.T) {
	full := resource.NewWithAttributes("",
		attribute.String("service.name", "defenseclaw"),
		attribute.String("service.instance.id", "gw-1"),
		attribute.String("deployment.environment.name", "prod"),
		attribute.String("os.type", "linux"),
		attribute.String("k8s.namespace.name", "defenseclaw-substrate"),
		attribute.String("k8s.cluster.name", "east-1"),
		attribute.String("host.name", "node-7"),
		attribute.String("tenant.id", "t-1"),
		attribute.String("workspace.id", "w-1"),
		attribute.String("defenseclaw.device.public_key_fingerprint", "abc"),
	)
	got := map[string]string{}
	for iter := restrictedMetricResource(full).Iter(); iter.Next(); {
		kv := iter.Attribute()
		got[string(kv.Key)] = kv.Value.String()
	}
	if got["k8s.namespace.name"] != "defenseclaw-substrate" {
		t.Errorf("k8s.namespace.name left the restricted resource as %q (resource %v); the scoped alert rules read it", got["k8s.namespace.name"], got)
	}
	for _, cut := range []string{"k8s.cluster.name", "host.name", "tenant.id", "workspace.id", "defenseclaw.device.public_key_fingerprint"} {
		if v, ok := got[cut]; ok {
			t.Errorf("%s=%q is on the restricted metric resource; it is an identity or host label", cut, v)
		}
	}
	for _, kept := range []string{"service.name", "service.instance.id", "deployment.environment.name", "os.type"} {
		if got[kept] == "" {
			t.Errorf("%s was cut from the restricted metric resource", kept)
		}
	}
}
