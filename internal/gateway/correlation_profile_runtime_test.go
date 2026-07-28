// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

type correlationSpecPluginConnector struct {
	*stubConnector
	spec connector.CorrelationSpec
}

func (plugin *correlationSpecPluginConnector) CorrelationSpec(connector.SetupOpts) connector.CorrelationSpec {
	return plugin.spec
}

func TestCorrelationSpecForConnectorV8UsesAuthenticatedRuntimeRegistry(t *testing.T) {
	const name = "plugin-native-profile"
	spec := connector.DefaultCorrelationSpec("codex")
	spec.Connector = name
	spec.ProfileVersion = connector.CorrelationProfileVersion("plugin-native-profile/v1")
	spec.HookContractID = "plugin-native-profile-v1"

	registry := connector.NewDefaultRegistry()
	if err := registry.RegisterPlugin(&correlationSpecPluginConnector{
		stubConnector: &stubConnector{name: name},
		spec:          spec,
	}); err != nil {
		t.Fatal(err)
	}
	server := &APIServer{connectorRegistry: registry}
	resolved, err := server.correlationSpecForConnectorV8(name)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Connector != name || resolved.ProfileVersion != spec.ProfileVersion ||
		resolved.NativeTelemetry.Stability == connector.NativeTelemetryNone {
		t.Fatalf("runtime registry profile was not selected: %+v", resolved)
	}

	unknown, err := server.correlationSpecForConnectorV8("plugin-without-profile")
	if err != nil {
		t.Fatal(err)
	}
	if unknown.NativeTelemetry.Stability != connector.NativeTelemetryNone ||
		!unknown.AllowsReceiptTarget(connector.CorrelationTargetSourceEvent) {
		t.Fatalf("unknown connector did not fail closed: %+v", unknown)
	}
}

func TestCorrelationSpecForConnectorV8RejectsRegistryIdentityMismatch(t *testing.T) {
	const name = "plugin-profile-mismatch"
	spec := connector.DefaultCorrelationSpec("codex")
	spec.ProfileVersion = connector.CorrelationProfileVersion("plugin-profile-mismatch/v1")

	registry := connector.NewDefaultRegistry()
	if err := registry.RegisterPlugin(&correlationSpecPluginConnector{
		stubConnector: &stubConnector{name: name},
		spec:          spec,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := (&APIServer{connectorRegistry: registry}).correlationSpecForConnectorV8(name); err == nil {
		t.Fatal("profile for a different connector was accepted from runtime registry")
	}
}

func TestNativeOTLPRuntimeProfileNonePreventsDefaultProfileFallback(t *testing.T) {
	const name = "plugin-without-native-profile"
	registry := connector.NewDefaultRegistry()
	if err := registry.RegisterPlugin(&stubConnector{name: name}); err != nil {
		t.Fatal(err)
	}
	server := &APIServer{connectorRegistry: registry}
	result, err := server.correlateNativeOTLPLeafV8(
		context.Background(), otlpDecodedLeaf{}, observability.InboundMatch{}, name, time.Now().UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	values, resolved := nativeOTLPCorrelationValuesFromContext(result.ctx, name)
	if !resolved || len(values) != 0 {
		t.Fatalf("fail-closed native profile marker=(resolved=%v values=%+v)", resolved, values)
	}
}
