// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package telemetry

import "testing"

// GAP-0454: a gateway pod on Agent Substrate names its cluster and
// namespace on the OTLP resource (k8s.cluster.name, k8s.namespace.name).
func TestGAP0454SubstrateResourceNamesTheClusterAndNamespace(t *testing.T) {
	snapshot := v8PlanForTest(t, "always_on", "", nil).Snapshot()
	identity := v8ResourceProcessIdentity{serviceInstanceID: "service-1", defenseClawInstanceID: "instance-1"}
	resource, err := newV8ResourceContext(snapshot, V8ProviderOptions{
		Version: "1.0", Environment: "test", K8sClusterName: "prod-eu", K8sNamespaceName: "defenseclaw-system",
	}, identity)
	if err != nil {
		t.Fatal(err)
	}
	if resource.values["k8s.cluster.name"] != "prod-eu" || resource.values["k8s.namespace.name"] != "defenseclaw-system" {
		t.Fatalf("resource %v", resource.values)
	}
	off, err := newV8ResourceContext(snapshot, V8ProviderOptions{Version: "1.0", Environment: "test"}, identity)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := off.values["k8s.namespace.name"]; ok {
		t.Fatalf("a host gateway names a namespace: %v", off.values)
	}
}
