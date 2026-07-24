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

package gateway

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

type endpointInventoryCapture struct {
	mu      sync.Mutex
	records []observability.Record
}

type endpointInventoryPluginConnector struct {
	name        string
	description string
}

func (connector *endpointInventoryPluginConnector) Name() string { return connector.name }
func (connector *endpointInventoryPluginConnector) Description() string {
	return connector.description
}
func (*endpointInventoryPluginConnector) ToolInspectionMode() connector.ToolInspectionMode {
	return connector.ToolModeBoth
}
func (*endpointInventoryPluginConnector) SubprocessPolicy() connector.SubprocessPolicy {
	return connector.SubprocessNone
}
func (*endpointInventoryPluginConnector) Setup(context.Context, connector.SetupOpts) error {
	return nil
}
func (*endpointInventoryPluginConnector) Teardown(context.Context, connector.SetupOpts) error {
	return nil
}
func (*endpointInventoryPluginConnector) Authenticate(*http.Request) bool { return false }
func (*endpointInventoryPluginConnector) Route(
	*http.Request, []byte,
) (*connector.ConnectorSignals, error) {
	return &connector.ConnectorSignals{}, nil
}
func (*endpointInventoryPluginConnector) SetCredentials(string, string) {}
func (*endpointInventoryPluginConnector) VerifyClean(connector.SetupOpts) error {
	return nil
}

func (capture *endpointInventoryCapture) Emit(
	_ context.Context,
	_ router.Metadata,
	build observabilityruntime.EmitBuilder,
) (pipeline.LocalLogOutcome, error) {
	record, err := build(observabilityruntime.EmitContext{}, router.AdmissionOrdinary)
	if err == nil {
		capture.mu.Lock()
		capture.records = append(capture.records, record)
		capture.mu.Unlock()
	}
	return pipeline.LocalLogOutcome{}, err
}

func (capture *endpointInventoryCapture) snapshot() []observability.Record {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return append([]observability.Record(nil), capture.records...)
}

func (*endpointInventoryCapture) RecordGeneratedMetric(
	context.Context,
	observability.EventName,
	observabilityruntime.GeneratedMetricBuilder,
) (telemetry.V8MetricRecordResult, error) {
	return telemetry.V8MetricRecordResult{}, nil
}

func (*endpointInventoryCapture) StartAIDiscoveryTrace(
	ctx context.Context,
	_ observability.SpanAIDiscoveryInput,
) (context.Context, *observabilityruntime.AIDiscoveryTrace, error) {
	return ctx, nil, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
}

// withManagedEnterprise flips the process-wide managed gate for a serial test
// and restores it afterwards.
func withManagedEnterprise(t *testing.T, on bool) {
	t.Helper()
	previous := ManagedEnterpriseActive()
	SetManagedEnterpriseActive(on)
	t.Cleanup(func() { SetManagedEnterpriseActive(previous) })
}

func TestEmitEndpointInventoryManagedUsesCanonicalV8Snapshots(t *testing.T) {
	withManagedEnterprise(t, true)
	capture := &endpointInventoryCapture{}
	cfg := &config.Config{Claw: config.ClawConfig{Mode: config.ClawMode("omnigent")}}
	registry := connector.NewDefaultRegistry()

	if err := EmitEndpointInventory(t.Context(), cfg, registry, capture); err != nil {
		t.Fatal(err)
	}
	records := capture.snapshot()
	connectorCount := len(registry.Available())
	if got, want := len(records), connectorCount+2; got != want {
		t.Fatalf("canonical records=%d want %d connector rows + two collection summaries", got, want)
	}

	summaries := map[string]map[string]any{}
	summaryActions := map[string]string{}
	components := 0
	for _, record := range records {
		body, ok := record.Body()
		if !ok {
			t.Fatalf("record %s has no canonical body", record.EventName())
		}
		bodyMap, err := body.Object()
		if err != nil {
			t.Fatalf("record %s body: %v", record.EventName(), err)
		}
		switch record.EventName() {
		case "ai.discovery.completed":
			source, _ := bodyMap[observability.TelemetryAttributeDefenseClawAIDiscoverySource].(string)
			summaries[source] = bodyMap
			summaryActions[source] = record.Action()
		case "ai_component.observed":
			components++
			if got := bodyMap[observability.TelemetryAttributeDefenseClawAIComponentType]; got != "supported_connector" {
				t.Fatalf("component type=%v", got)
			}
			if got := bodyMap[observability.TelemetryAttributeDefenseClawAIDiscoverySource]; got != endpointConnectorInventorySource {
				t.Fatalf("connector component source=%v", got)
			}
			for _, field := range []string{
				observability.TelemetryAttributeDefenseClawInventoryItemName,
				observability.TelemetryAttributeDefenseClawInventoryItemDescription,
				observability.TelemetryAttributeDefenseClawInventoryConnectorSource,
				observability.TelemetryAttributeDefenseClawInventoryConnectorToolInspectionMode,
				observability.TelemetryAttributeDefenseClawInventoryConnectorSubprocessPolicy,
			} {
				if value, ok := bodyMap[field].(string); !ok || value == "" {
					t.Fatalf("connector inventory field %s=%T(%v)", field, bodyMap[field], bodyMap[field])
				}
			}
		default:
			t.Fatalf("legacy or unexpected event family %q", record.EventName())
		}
		encoded, err := json.Marshal(bodyMap)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(encoded), "device_id") || strings.Contains(string(encoded), "hostname") {
			t.Fatalf("endpoint resource anchor duplicated into body: %s", encoded)
		}
	}
	if components != connectorCount {
		t.Fatalf("connector components=%d want=%d", components, connectorCount)
	}
	connectorSummary := summaries[endpointConnectorInventorySource]
	if connectorSummary == nil || canonicalInt64(t, connectorSummary[observability.TelemetryAttributeDefenseClawAIDiscoverySignalsTotal]) != int64(connectorCount) {
		t.Fatalf("connector summary=%#v", connectorSummary)
	}
	if got := summaryActions[endpointConnectorInventorySource]; got != string(config.ObservabilityV8ManagedConnectorInventoryAction) {
		t.Fatalf("connector summary action=%q", got)
	}
	connectorIdentifiers := canonicalObjectArray(
		t, connectorSummary[observability.TelemetryAttributeDefenseClawInventoryConnectorIdentifiers],
	)
	connectorMetadata := canonicalObjectArray(
		t, connectorSummary[observability.TelemetryAttributeDefenseClawInventoryConnectorMetadata],
	)
	connectorContent := canonicalObjectArray(
		t, connectorSummary[observability.TelemetryAttributeDefenseClawInventoryConnectorContent],
	)
	if len(connectorIdentifiers) != connectorCount || len(connectorMetadata) != connectorCount ||
		len(connectorContent) != connectorCount {
		t.Fatalf(
			"connector carrier lengths identifiers/metadata/content=%d/%d/%d want=%d",
			len(connectorIdentifiers), len(connectorMetadata), len(connectorContent), connectorCount,
		)
	}
	for index := 1; index < len(connectorIdentifiers); index++ {
		previous, _ := connectorIdentifiers[index-1]["name"].(string)
		current, _ := connectorIdentifiers[index]["name"].(string)
		if previous > current {
			t.Fatalf("connector carrier order[%d]=%q > %q", index, previous, current)
		}
	}
	mcpSummary := summaries[endpointMCPInventorySource]
	if mcpSummary == nil || canonicalInt64(t, mcpSummary[observability.TelemetryAttributeDefenseClawAIDiscoverySignalsTotal]) != 0 {
		t.Fatalf("empty MCP collection was not represented: %#v", mcpSummary)
	}
	if got := summaryActions[endpointMCPInventorySource]; got != string(config.ObservabilityV8ManagedMCPInventoryAction) {
		t.Fatalf("MCP summary action=%q", got)
	}
	if identifiers := canonicalObjectArray(
		t, mcpSummary[observability.TelemetryAttributeDefenseClawInventoryMcpIdentifiers],
	); len(identifiers) != 0 {
		t.Fatalf("empty MCP identifiers=%#v", identifiers)
	}
	if metadata := canonicalObjectArray(
		t, mcpSummary[observability.TelemetryAttributeDefenseClawInventoryMcpMetadata],
	); len(metadata) != 0 {
		t.Fatalf("empty MCP metadata=%#v", metadata)
	}
}

func TestEmitManagedAgentInventoryUsesCompleteCanonicalSafeSnapshot(t *testing.T) {
	withManagedEnterprise(t, true)
	capture := &endpointInventoryCapture{}
	api := &APIServer{
		connectorRegistry: connector.NewDefaultRegistry(),
		observabilityV8:   capture,
	}
	report := &agentDiscoveryReport{
		Source: " CLI ", ScannedAt: "2026-07-11T00:00:00.000Z",
		Agents: map[string]agentDiscoverySignal{
			" Cursor ": {
				Installed: true, HasConfig: true, ConfigBasename: "config.json",
				ConfigPathHash: "sha256:" + strings.Repeat("a", 64),
				HasBinary:      true, BinaryBasename: "cursor",
				BinaryPathHash: "sha256:" + strings.Repeat("b", 64),
				Version:        "cursor 1.2.3", VersionProbeStatus: "ok",
			},
			"codex": {Installed: false, VersionProbeStatus: "not_probed"},
		},
	}
	if dropped, err := api.validateAgentDiscoveryReport(report); err != nil || len(dropped) != 0 {
		t.Fatalf("validate managed agent inventory dropped=%v err=%v", dropped, err)
	}
	if err := api.emitManagedAgentInventory(t.Context(), report, 1, false); err != nil {
		t.Fatal(err)
	}

	records := capture.snapshot()
	if len(records) != 3 {
		t.Fatalf("managed agent inventory records=%d, want summary + two agents", len(records))
	}
	components := map[string]map[string]any{}
	var summary map[string]any
	for _, record := range records {
		if record.Bucket() != observability.BucketAIDiscovery ||
			record.Action() != string(config.ObservabilityV8ManagedAgentInventoryAction) {
			t.Fatalf("managed agent inventory identity=(%q,%q,%q)", record.Bucket(), record.EventName(), record.Action())
		}
		body, ok := record.Body()
		if !ok {
			t.Fatalf("record %s has no body", record.EventName())
		}
		bodyMap, err := body.Object()
		if err != nil {
			t.Fatal(err)
		}
		switch record.EventName() {
		case "ai.discovery.completed":
			summary = bodyMap
			if got := bodyMap[observability.TelemetryAttributeDefenseClawAIDiscoverySource]; got != "cli" {
				t.Fatalf("summary source=%v", got)
			}
			if got := bodyMap[observability.TelemetryAttributeDefenseClawAgentDiscoveryScannedAt]; got != "2026-07-11T00:00:00Z" {
				t.Fatalf("summary scanned_at=%v", got)
			}
			if canonicalInt64(t, bodyMap[observability.TelemetryAttributeDefenseClawAIDiscoverySignalsTotal]) != 2 ||
				canonicalInt64(t, bodyMap[observability.TelemetryAttributeDefenseClawAIDiscoveryActiveSignals]) != 1 {
				t.Fatalf("summary counts=%#v", bodyMap)
			}
		case "ai_component.observed":
			name, _ := bodyMap[observability.TelemetryAttributeDefenseClawAgentDiscoveryConnector].(string)
			if got := bodyMap[observability.TelemetryAttributeDefenseClawAIDiscoverySource]; got != "cli" {
				t.Fatalf("agent component source=%v", got)
			}
			if got := bodyMap[observability.TelemetryAttributeDefenseClawAgentDiscoveryScannedAt]; got != "2026-07-11T00:00:00Z" {
				t.Fatalf("agent component scanned_at=%v", got)
			}
			components[name] = bodyMap
		default:
			t.Fatalf("unexpected managed agent inventory family %q", record.EventName())
		}
	}
	if summary == nil {
		t.Fatal("managed agent inventory summary is missing")
	}
	agentIdentifiers := canonicalObjectArray(
		t, summary[observability.TelemetryAttributeDefenseClawInventoryAgentIdentifiers],
	)
	agentMetadata := canonicalObjectArray(
		t, summary[observability.TelemetryAttributeDefenseClawInventoryAgentMetadata],
	)
	if len(agentIdentifiers) != 2 || len(agentMetadata) != 2 ||
		agentIdentifiers[0]["name"] != "codex" || agentIdentifiers[1]["name"] != "cursor" ||
		agentMetadata[0]["installed"] != false || agentMetadata[1]["installed"] != true {
		t.Fatalf("managed agent carrier identifiers=%#v metadata=%#v", agentIdentifiers, agentMetadata)
	}
	cursor := components["cursor"]
	if cursor == nil ||
		cursor[observability.TelemetryAttributeDefenseClawAIComponentType] != "coding_agent" ||
		cursor[observability.TelemetryAttributeDefenseClawAgentDiscoveryInstalled] != true ||
		cursor[observability.TelemetryAttributeDefenseClawAgentDiscoveryHasConfig] != true ||
		cursor[observability.TelemetryAttributeDefenseClawAgentDiscoveryConfigBasename] != "config.json" ||
		cursor[observability.TelemetryAttributeDefenseClawAgentDiscoveryConfigPathHash] != "sha256:"+strings.Repeat("a", 64) ||
		cursor[observability.TelemetryAttributeDefenseClawAgentDiscoveryHasBinary] != true ||
		cursor[observability.TelemetryAttributeDefenseClawAgentDiscoveryBinaryBasename] != "cursor" ||
		cursor[observability.TelemetryAttributeDefenseClawAgentDiscoveryBinaryPathHash] != "sha256:"+strings.Repeat("b", 64) ||
		cursor[observability.TelemetryAttributeDefenseClawAgentDiscoveryVersion] != "cursor 1.2.3" ||
		cursor[observability.TelemetryAttributeDefenseClawAgentDiscoveryProbeStatus] != "ok" {
		t.Fatalf("cursor managed inventory row=%#v", cursor)
	}
	if codex := components["codex"]; codex == nil ||
		codex[observability.TelemetryAttributeDefenseClawAgentDiscoveryInstalled] != false ||
		codex[observability.TelemetryAttributeDefenseClawAgentDiscoveryProbeStatus] != "not_probed" {
		t.Fatalf("codex managed inventory row=%#v", codex)
	}
	encoded, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"/Users/", `C:\\Users\\`, "config_path\"", "binary_path\""} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("managed agent inventory leaked raw path field/material %q: %s", forbidden, encoded)
		}
	}
}

func TestEmitManagedAgentInventoryOutsideManagedIsNoOp(t *testing.T) {
	withManagedEnterprise(t, false)
	capture := &endpointInventoryCapture{}
	api := &APIServer{observabilityV8: capture}
	if err := api.emitManagedAgentInventory(t.Context(), &agentDiscoveryReport{
		Source: "cli", ScannedAt: "2026-07-11T00:00:00Z",
		Agents: map[string]agentDiscoverySignal{"codex": {Installed: true}},
	}, 1, false); err != nil {
		t.Fatal(err)
	}
	if records := capture.snapshot(); len(records) != 0 {
		t.Fatalf("non-managed agent inventory emitted %d records", len(records))
	}
}

func TestInventorySnapshotCompleteEmptyCarriesTypedEmptyArrays(t *testing.T) {
	tests := []struct {
		name      string
		action    observability.ProducerKey
		source    string
		record    observability.Source
		fields    []string
		scannedAt string
		phase     string
		detector  string
	}{
		{
			name: "connector", action: config.ObservabilityV8ManagedConnectorInventoryAction,
			source: endpointConnectorInventorySource, record: observability.SourceSystem,
			fields: []string{
				observability.TelemetryAttributeDefenseClawInventoryConnectorIdentifiers,
				observability.TelemetryAttributeDefenseClawInventoryConnectorMetadata,
				observability.TelemetryAttributeDefenseClawInventoryConnectorContent,
			},
			phase: "endpoint_inventory", detector: endpointInventoryDetector,
		},
		{
			name: "mcp", action: config.ObservabilityV8ManagedMCPInventoryAction,
			source: endpointMCPInventorySource, record: observability.SourceSystem,
			fields: []string{
				observability.TelemetryAttributeDefenseClawInventoryMcpIdentifiers,
				observability.TelemetryAttributeDefenseClawInventoryMcpMetadata,
			},
			phase: "endpoint_inventory", detector: endpointInventoryDetector,
		},
		{
			name: "agent", action: config.ObservabilityV8ManagedAgentInventoryAction,
			source: "cli", record: observability.SourceCLI,
			fields: []string{
				observability.TelemetryAttributeDefenseClawInventoryAgentIdentifiers,
				observability.TelemetryAttributeDefenseClawInventoryAgentMetadata,
			},
			scannedAt: "2026-07-11T00:00:00Z", phase: "agent_inventory",
			detector: managedAgentInventoryDetector,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capture := &endpointInventoryCapture{}
			if err := emitInventorySnapshot(
				t.Context(), capture, test.source, test.scannedAt, nil, false,
				test.record, test.action, test.phase, test.detector,
			); err != nil {
				t.Fatal(err)
			}
			records := capture.snapshot()
			if len(records) != 1 || records[0].EventName() != "ai.discovery.completed" ||
				records[0].Outcome() != observability.OutcomeCompleted ||
				records[0].Action() != string(test.action) {
				t.Fatalf("complete empty %s records=%+v", test.name, records)
			}
			body := canonicalBody(t, records[0])
			if got := canonicalInt64(t, body[observability.TelemetryAttributeDefenseClawAIDiscoverySignalsTotal]); got != 0 {
				t.Fatalf("complete empty %s count=%d", test.name, got)
			}
			for _, field := range test.fields {
				if items := canonicalObjectArray(t, body[field]); len(items) != 0 {
					t.Fatalf("complete empty %s field %s=%#v", test.name, field, items)
				}
			}
		})
	}
}

func TestConnectorInventoryCarrierIsDeterministicallyAligned(t *testing.T) {
	components := []endpointInventoryComponent{
		connectorInventoryTestComponent("zeta", "plugin", "both", "none", "zeta description"),
		connectorInventoryTestComponent("alpha", "built-in", "pre-execution", "sandbox", "alpha description"),
		connectorInventoryTestComponent("middle", "built-in", "response-scan", "shims", "middle description"),
	}
	emit := func(input []endpointInventoryComponent) map[string]any {
		capture := &endpointInventoryCapture{}
		if err := emitEndpointInventorySnapshot(
			t.Context(), capture, endpointConnectorInventorySource, input, false,
			config.ObservabilityV8ManagedConnectorInventoryAction,
		); err != nil {
			t.Fatal(err)
		}
		return canonicalBody(t, capture.snapshot()[0])
	}
	forward := emit(components)
	reversed := append([]endpointInventoryComponent(nil), components...)
	for left, right := 0, len(reversed)-1; left < right; left, right = left+1, right-1 {
		reversed[left], reversed[right] = reversed[right], reversed[left]
	}
	backward := emit(reversed)
	fields := []string{
		observability.TelemetryAttributeDefenseClawInventoryConnectorIdentifiers,
		observability.TelemetryAttributeDefenseClawInventoryConnectorMetadata,
		observability.TelemetryAttributeDefenseClawInventoryConnectorContent,
	}
	for _, field := range fields {
		if !reflect.DeepEqual(forward[field], backward[field]) {
			t.Fatalf("deterministic connector carrier field %s differs: %#v / %#v", field, forward[field], backward[field])
		}
	}
	identifiers := canonicalObjectArray(t, forward[fields[0]])
	metadata := canonicalObjectArray(t, forward[fields[1]])
	content := canonicalObjectArray(t, forward[fields[2]])
	if got := []any{identifiers[0]["name"], identifiers[1]["name"], identifiers[2]["name"]}; !reflect.DeepEqual(got, []any{"alpha", "middle", "zeta"}) {
		t.Fatalf("connector carrier order=%v", got)
	}
	if metadata[0]["source"] != "built-in" || metadata[1]["tool_inspection_mode"] != "response-scan" ||
		metadata[2]["source"] != "plugin" || content[0]["description"] != "alpha description" ||
		content[2]["description"] != "zeta description" {
		t.Fatalf("connector carrier sections lost index alignment identifiers=%#v metadata=%#v content=%#v", identifiers, metadata, content)
	}
}

func TestManagedInventoryCarrierBoundsFailClosedWithoutTruncation(t *testing.T) {
	tests := []struct {
		name       string
		action     observability.ProducerKey
		source     string
		limit      int
		carrierKey string
		component  func(int) endpointInventoryComponent
	}{
		{
			name: "connector", action: config.ObservabilityV8ManagedConnectorInventoryAction,
			source: endpointConnectorInventorySource, limit: maxManagedConnectorInventory,
			carrierKey: observability.TelemetryAttributeDefenseClawInventoryConnectorIdentifiers,
			component: func(index int) endpointInventoryComponent {
				return connectorInventoryTestComponent(
					fmt.Sprintf("connector-%03d", index), "built-in", "both", "none", "",
				)
			},
		},
		{
			name: "mcp", action: config.ObservabilityV8ManagedMCPInventoryAction,
			source: endpointMCPInventorySource, limit: maxManagedMCPInventory,
			carrierKey: observability.TelemetryAttributeDefenseClawInventoryMcpIdentifiers,
			component: func(index int) endpointInventoryComponent {
				disabled := index%2 == 0
				name := fmt.Sprintf("mcp-%03d", index)
				return endpointInventoryComponent{
					id: endpointInventoryComponentID("mcp", name), componentType: "mcp_server",
					signal: "mcp_server_configured", product: name, itemName: name,
					active: !disabled, mcpTransport: "stdio", mcpCommandBasename: "mcp-server",
					mcpDisabled: &disabled,
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			components := make([]endpointInventoryComponent, 0, test.limit+1)
			for index := 0; index < test.limit+1; index++ {
				components = append(components, test.component(index))
			}
			exact := &endpointInventoryCapture{}
			if err := emitEndpointInventorySnapshot(
				t.Context(), exact, test.source, components[:test.limit], false, test.action,
			); err != nil {
				t.Fatal(err)
			}
			exactRecords := exact.snapshot()
			exactBody := canonicalBody(t, exactRecords[0])
			if exactRecords[0].Action() != string(test.action) ||
				exactRecords[0].Outcome() != observability.OutcomeCompleted ||
				len(canonicalObjectArray(t, exactBody[test.carrierKey])) != test.limit {
				t.Fatalf("exact %s bound summary action/outcome/body=%q/%q/%#v", test.name, exactRecords[0].Action(), exactRecords[0].Outcome(), exactBody)
			}

			overflow := &endpointInventoryCapture{}
			if err := emitEndpointInventorySnapshot(
				t.Context(), overflow, test.source, components, false, test.action,
			); err != nil {
				t.Fatal(err)
			}
			overflowRecords := overflow.snapshot()
			overflowBody := canonicalBody(t, overflowRecords[0])
			if got := canonicalInt64(t, overflowBody[observability.TelemetryAttributeDefenseClawAIDiscoverySignalsTotal]); got != int64(test.limit+1) {
				t.Fatalf("overflow %s count=%d want=%d", test.name, got, test.limit+1)
			}
			if overflowRecords[0].Action() != string(config.ObservabilityV8LocalInventoryDiagnosticAction) ||
				overflowRecords[0].Outcome() != observability.OutcomePartial {
				t.Fatalf("overflow %s summary action/outcome=%q/%q", test.name, overflowRecords[0].Action(), overflowRecords[0].Outcome())
			}
			if _, present := overflowBody[test.carrierKey]; present {
				t.Fatalf("overflow %s emitted truncated authoritative carrier: %#v", test.name, overflowBody[test.carrierKey])
			}
			for _, record := range overflowRecords {
				if record.Action() != string(config.ObservabilityV8LocalInventoryDiagnosticAction) {
					t.Fatalf("overflow %s escaped managed action on %s: %q", test.name, record.EventName(), record.Action())
				}
			}
		})
	}
}

func connectorInventoryTestComponent(
	name, source, toolMode, subprocessPolicy, description string,
) endpointInventoryComponent {
	return endpointInventoryComponent{
		id: endpointInventoryComponentID("connector", name), componentType: "supported_connector",
		signal: "supported_connector", product: name, itemName: name, itemDescription: description,
		active: true, connectorSource: source, connectorToolInspectionMode: toolMode,
		connectorSubprocessPolicy: subprocessPolicy,
	}
}

func canonicalBody(t *testing.T, record observability.Record) map[string]any {
	t.Helper()
	body, present := record.Body()
	if !present {
		t.Fatalf("record %s has no canonical body", record.EventName())
	}
	object, err := body.Object()
	if err != nil {
		t.Fatal(err)
	}
	return object
}

func TestManagedInventoryRoutingExcludesOperatorDestinations(t *testing.T) {
	disabled := false
	base, err := config.CompileObservabilityV8(&config.ObservabilityV8Source{
		Buckets: map[observability.Bucket]config.ObservabilityV8BucketPolicySource{
			observability.BucketAIDiscovery: {
				Collect: config.ObservabilityV8CollectSource{Logs: &disabled},
			},
		},
		Destinations: []config.ObservabilityV8DestinationSource{{
			Name: "operator-console", Kind: config.ObservabilityV8DestinationConsole,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := config.WithObservabilityV8ManagedAIDDestination(
		base,
		config.ObservabilityV8ManagedAIDOptions{
			DeploymentMode: "managed_enterprise", Endpoint: "https://aid.example.test",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err := router.New(plan)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerGatewayEvent,
		observability.ProducerKey("ai_discovery"),
		observability.ClassificationContext{
			Bucket: observability.BucketAIDiscovery, EventName: "ai.discovery.completed", RawSeverity: "INFO",
		},
		observability.SourceCLI,
		"",
		config.ObservabilityV8ManagedAgentInventoryAction,
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := evaluator.Evaluate(metadata, func(admission router.Admission) (observability.Record, error) {
		if admission != router.AdmissionOrdinary {
			t.Fatalf("managed inventory admission=%s", admission)
		}
		builder, buildErr := aiDiscoveryV8Builder()
		if buildErr != nil {
			return observability.Record{}, buildErr
		}
		return builder.BuildLogAIDiscoveryCompleted(observability.LogAIDiscoveryCompletedInput{
			Envelope: endpointInventoryEmitEnvelope(
				t.Context(), observabilityruntime.EmitContext{}, observability.SourceCLI,
				config.ObservabilityV8ManagedAgentInventoryAction, "agent_inventory",
			),
			Severity:                     observability.Present(observability.SeverityInfo),
			LogLevel:                     observability.Present(observability.LogLevelInfo),
			Outcome:                      observability.OutcomeCompleted,
			DefenseClawAIDiscoveryScanID: "agent-inventory-route-test",
			DefenseClawAIDiscoverySource: "cli", DefenseClawAIDiscoveryPrivacyMode: "enhanced",
			DefenseClawAIDiscoveryResult: "ok", DefenseClawAIDiscoveryDurationMs: 0,
			DefenseClawAIDiscoverySignalsTotal: 1, DefenseClawAIDiscoveryActiveSignals: 1,
			DefenseClawAIDiscoveryNewSignals: 0, DefenseClawAIDiscoveryChangedSignals: 0,
			DefenseClawAIDiscoveryGoneSignals: 0, DefenseClawAIDiscoveryFilesScanned: 0,
			DefenseClawAIDiscoveryDedupeSuppressed: 0, DefenseClawAIDiscoveryErrors: 0,
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	deliveries := result.Deliveries()
	if len(deliveries) != 2 {
		t.Fatalf("managed inventory deliveries=%+v, want local + managed", deliveries)
	}
	names := []string{deliveries[0].DestinationName, deliveries[1].DestinationName}
	sort.Strings(names)
	if strings.Join(names, ",") != strings.Join([]string{
		config.ObservabilityV8LocalDestinationName,
		config.ObservabilityV8ManagedAIDDestinationName,
	}, ",") {
		t.Fatalf("managed inventory destination names=%v", names)
	}
	for _, delivery := range deliveries {
		if delivery.DestinationName == "operator-console" {
			t.Fatalf("managed inventory escaped to operator destination: %+v", deliveries)
		}
	}
}

func TestManagedEndpointInventorySurvivesSourceDisabledAIDiscoveryLogs(t *testing.T) {
	withManagedEnterprise(t, true)
	runtime, path, adapter := newManagedAIDFailOpenRuntime(t)
	configPath := filepath.Join(t.TempDir(), "openclaw.json")
	if err := os.WriteFile(configPath, []byte(`{
  "mcp": {"servers": {"safe-mcp": {
    "command": "/opt/managed/bin/mcp-server",
    "transport": "stdio"
  }}}
}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Claw: config.ClawConfig{
		Mode: config.ClawMode("openclaw"), ConfigFile: configPath,
	}}
	registry := connector.NewRegistry()
	if err := registry.RegisterPlugin(&endpointInventoryPluginConnector{
		// Unknown plugins are deliberately not certified on Windows. Reuse a
		// supported connector identity in this empty test registry so the
		// cross-platform fixture exercises inventory routing, not presentation
		// filtering.
		name: "codex", description: "Managed connector",
	}); err != nil {
		t.Fatal(err)
	}
	if err := EmitEndpointInventory(
		t.Context(), cfg, registry, runtime,
	); err != nil {
		t.Fatal(err)
	}

	wantSources := map[string]string{
		string(config.ObservabilityV8ManagedConnectorInventoryAction): endpointConnectorInventorySource,
		string(config.ObservabilityV8ManagedMCPInventoryAction):       endpointMCPInventorySource,
	}
	for delivered := 0; delivered < 2; delivered++ {
		select {
		case item := <-adapter.delivered:
			if item.identity.Bucket != string(observability.BucketAIDiscovery) ||
				item.identity.Signal != string(observability.SignalLogs) ||
				item.identity.EventName != "ai.discovery.completed" {
				t.Fatalf("managed inventory delivery identity = %+v", item.identity)
			}
			var wire map[string]any
			if err := json.Unmarshal(item.bytes, &wire); err != nil {
				t.Fatal(err)
			}
			action, _ := wire["action"].(string)
			wantSource, ok := wantSources[action]
			if !ok {
				t.Fatalf("managed inventory action=%q", action)
			}
			body, ok := wire["body"].(map[string]any)
			if !ok || body[observability.TelemetryAttributeDefenseClawAIDiscoverySource] != wantSource {
				t.Fatalf("managed inventory body source=%#v want=%q", body, wantSource)
			}
			if action == string(config.ObservabilityV8ManagedConnectorInventoryAction) {
				if len(canonicalObjectArray(t, body[observability.TelemetryAttributeDefenseClawInventoryConnectorIdentifiers])) != 1 {
					t.Fatalf("managed connector atomic carrier=%#v", body)
				}
			} else if len(canonicalObjectArray(t, body[observability.TelemetryAttributeDefenseClawInventoryMcpIdentifiers])) != 1 {
				t.Fatalf("managed MCP atomic carrier=%#v", body)
			}
		case <-time.After(15 * time.Second):
			t.Fatalf("timed out after %d managed inventory deliveries", delivered)
		}
	}

	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var persisted int
	if err := database.QueryRow(`
		SELECT COUNT(*) FROM audit_events
		WHERE bucket = ? AND event_name = ?`,
		string(observability.BucketAIDiscovery), "ai.discovery.completed",
	).Scan(&persisted); err != nil {
		t.Fatal(err)
	}
	if persisted != 2 {
		t.Fatalf("persisted managed inventory summaries = %d, want 2", persisted)
	}
	var inventoryRows int
	if err := database.QueryRow(`
		SELECT COUNT(*) FROM audit_events
		WHERE bucket = ? AND action IN (?, ?)`,
		string(observability.BucketAIDiscovery),
		string(config.ObservabilityV8ManagedConnectorInventoryAction),
		string(config.ObservabilityV8ManagedMCPInventoryAction),
	).Scan(&inventoryRows); err != nil {
		t.Fatal(err)
	}
	if inventoryRows != 4 {
		t.Fatalf("persisted managed endpoint inventory rows=%d, want 4", inventoryRows)
	}
}

func TestManagedAgentInventoryPersistsAndExportsWhenAgentLifecycleDisabled(t *testing.T) {
	withManagedEnterprise(t, true)
	runtime, path, adapter := newManagedAIDFailOpenRuntime(t)
	api := &APIServer{
		connectorRegistry: connector.NewDefaultRegistry(),
		observabilityV8:   runtime,
	}
	request := httptest.NewRequest(
		http.MethodPost, "/api/v1/agents/discovery", strings.NewReader(validAgentDiscoveryBody()),
	)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	api.handleAgentDiscovery(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("managed agent inventory status=%d body=%s", response.Code, response.Body.String())
	}

	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	for delivered := 0; delivered < 1; {
		select {
		case item := <-adapter.delivered:
			var wire map[string]any
			if err := json.Unmarshal(item.bytes, &wire); err != nil {
				t.Fatal(err)
			}
			if wire["action"] != string(config.ObservabilityV8ManagedAgentInventoryAction) {
				continue
			}
			if item.identity.Bucket != string(observability.BucketAIDiscovery) ||
				item.identity.Signal != string(observability.SignalLogs) ||
				item.identity.EventName != "ai.discovery.completed" {
				t.Fatalf("managed agent inventory delivery identity=%+v", item.identity)
			}
			delivered++
			body, ok := wire["body"].(map[string]any)
			if !ok || body[observability.TelemetryAttributeDefenseClawAIDiscoverySource] != "cli" ||
				body[observability.TelemetryAttributeDefenseClawAgentDiscoveryScannedAt] != "2026-05-04T18:21:00Z" {
				t.Fatalf("managed agent inventory source/scanned_at body=%#v", body)
			}
			identifiers := canonicalObjectArray(t, body[observability.TelemetryAttributeDefenseClawInventoryAgentIdentifiers])
			metadata := canonicalObjectArray(t, body[observability.TelemetryAttributeDefenseClawInventoryAgentMetadata])
			if len(identifiers) != 2 || len(metadata) != 2 || identifiers[1]["name"] != "codex" ||
				identifiers[1]["config_path_hash"] != "sha256:"+strings.Repeat("a", 64) ||
				metadata[1]["installed"] != true || metadata[1]["config_basename"] != "config.toml" ||
				metadata[1]["binary_basename"] != "codex" || metadata[1]["version"] != "codex 1.2.3" ||
				metadata[1]["probe_status"] != "ok" {
				t.Fatalf("managed agent atomic carrier identifiers=%#v metadata=%#v", identifiers, metadata)
			}
		case <-deadline.C:
			t.Fatalf("timed out after %d managed agent inventory deliveries", delivered)
		}
	}
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var persisted, lifecycle, allLifecycle int
	if err := database.QueryRow(`
		SELECT COUNT(*) FROM audit_events
		WHERE bucket = ? AND action = ?`,
		string(observability.BucketAIDiscovery),
		string(config.ObservabilityV8ManagedAgentInventoryAction),
	).Scan(&persisted); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`
		SELECT COUNT(*) FROM audit_events
		WHERE bucket = ? AND action = ?`,
		string(observability.BucketAgentLifecycle),
		string(config.ObservabilityV8ManagedAgentInventoryAction),
	).Scan(&lifecycle); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`
		SELECT COUNT(*) FROM audit_events
		WHERE bucket = ?`,
		string(observability.BucketAgentLifecycle),
	).Scan(&allLifecycle); err != nil {
		t.Fatal(err)
	}
	if persisted != 3 || lifecycle != 0 || allLifecycle != 0 {
		t.Fatalf(
			"managed agent inventory persisted ai.discovery=%d agent.lifecycle action/all=%d/%d, want 3/0/0",
			persisted, lifecycle, allLifecycle,
		)
	}
}

func TestManagedPluginDescriptionUsesSensitiveProjection(t *testing.T) {
	withManagedEnterprise(t, true)
	capture := &endpointInventoryCapture{}
	registry := connector.NewRegistry()
	pathCanary := strings.Join([]string{"", "Users", "alice", ".ssh", "id_rsa"}, "/")
	description := "plugin private_key=" + pathCanary
	if err := registry.RegisterPlugin(&endpointInventoryPluginConnector{
		name: "codex", description: description,
	}); err != nil {
		t.Fatal(err)
	}
	if err := EmitEndpointInventory(t.Context(), &config.Config{}, registry, capture); err != nil {
		t.Fatal(err)
	}
	var summary observability.Record
	for _, record := range capture.snapshot() {
		body := canonicalBody(t, record)
		if record.EventName() == "ai.discovery.completed" &&
			body[observability.TelemetryAttributeDefenseClawAIDiscoverySource] == endpointConnectorInventorySource {
			summary = record
			break
		}
	}
	if summary.EventName() == "" {
		t.Fatal("managed plugin connector summary was not emitted")
	}
	engine, err := observabilityredaction.NewEngine(bytes.Repeat([]byte{0x51}, 32))
	if err != nil {
		t.Fatal(err)
	}
	profile, ok := observabilityredaction.BuiltInProfile(observabilityredaction.ProfileSensitive)
	if !ok {
		t.Fatal("sensitive profile is unavailable")
	}
	projection, _, err := engine.Project(summary, profile)
	if err != nil {
		t.Fatal(err)
	}
	body, err := projection.Payload().Object()
	if err != nil {
		t.Fatal(err)
	}
	content := canonicalObjectArray(t, body[observability.TelemetryAttributeDefenseClawInventoryConnectorContent])
	if len(content) != 1 {
		t.Fatalf("managed plugin content carrier=%#v", content)
	}
	projected, ok := content[0]["description"].(string)
	if !ok || projected == "" || projected == description || strings.Contains(projected, pathCanary) {
		t.Fatalf("managed plugin description was not redacted: %q", projected)
	}
	classes := summary.FieldClasses()
	if classes["/"+observability.TelemetryAttributeDefenseClawInventoryConnectorContent+"/0/description"] != observability.FieldClassContent ||
		classes["/"+observability.TelemetryAttributeDefenseClawInventoryConnectorIdentifiers+"/0/name"] != observability.FieldClassIdentifier ||
		classes["/"+observability.TelemetryAttributeDefenseClawInventoryConnectorMetadata+"/0/source"] != observability.FieldClassMetadata {
		t.Fatalf("managed plugin description field classes=%#v", classes)
	}
	if projection.Metadata().RedactionProfile != string(observabilityredaction.ProfileSensitive) {
		t.Fatalf("managed plugin projection metadata=%+v", projection.Metadata())
	}
}

func canonicalInt64(t *testing.T, value any) int64 {
	t.Helper()
	number, ok := value.(json.Number)
	if !ok {
		t.Fatalf("canonical numeric value=%T(%v)", value, value)
	}
	result, err := number.Int64()
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func canonicalObjectArray(t *testing.T, value any) []map[string]any {
	t.Helper()
	items, ok := value.([]any)
	if !ok {
		t.Fatalf("canonical structured array=%T(%v)", value, value)
	}
	objects := make([]map[string]any, 0, len(items))
	for index, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("canonical structured array item[%d]=%T(%v)", index, item, item)
		}
		objects = append(objects, object)
	}
	return objects
}

func TestEmitEndpointInventoryOutsideManagedIsNoOp(t *testing.T) {
	withManagedEnterprise(t, false)
	capture := &endpointInventoryCapture{}
	if err := EmitEndpointInventory(t.Context(), &config.Config{}, connector.NewDefaultRegistry(), capture); err != nil {
		t.Fatal(err)
	}
	if records := capture.snapshot(); len(records) != 0 {
		t.Fatalf("non-managed inventory emitted %d records", len(records))
	}
}

func TestContinuousAIDiscoveryV8SeenSignalIsManagedObservationOnly(t *testing.T) {
	for _, test := range []struct {
		name          string
		managed       bool
		wantEventName observability.EventName
		wantRecords   int
	}{
		{name: "managed full snapshot", managed: true, wantEventName: "ai_component.observed", wantRecords: 2},
		{name: "non-managed delta only", managed: false, wantRecords: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			withManagedEnterprise(t, test.managed)
			capture := &endpointInventoryCapture{}
			adapter := &aiDiscoveryV8Adapter{runtime: capture}
			report := inventory.AIDiscoveryReport{
				Summary: inventory.AIDiscoverySummary{
					ScanID: "scan-seen", Source: "scheduled", PrivacyMode: "enhanced", Result: "ok",
					TotalSignals: 1, ActiveSignals: 1,
				},
				Signals: []inventory.AISignal{{
					SignalID: "ai-seen-0123456789abcdef", SignatureID: "openai-python",
					Category: inventory.SignalPackageDependency, State: inventory.AIStateSeen,
					Detector: "package_manifest", Vendor: "openai", Product: "openai", Confidence: .9,
				}},
			}
			if err := adapter.EmitReport(t.Context(), report, nil); err != nil {
				t.Fatal(err)
			}
			records := capture.snapshot()
			if len(records) != test.wantRecords {
				t.Fatalf("records=%d want=%d", len(records), test.wantRecords)
			}
			if test.wantEventName != "" && records[1].EventName() != test.wantEventName {
				t.Fatalf("seen event=%q want=%q", records[1].EventName(), test.wantEventName)
			}
		})
	}
}

func TestEndpointMCPComponentsRetainOnlyBoundedIdentifiersBasenamesAndHosts(t *testing.T) {
	components := endpointMCPComponentsFromServers([]config.MCPServerEntry{
		{
			Name: "payments-mcp", Command: "/Users/alice/private/bin/mcp-server",
			Args: []string{"--token", "secret"}, CWD: "/Users/alice/private",
			URL:       "https://user:password@mcp.example.com:8443/v1?token=secret#fragment",
			Transport: "http", AuthProviderType: "oauth", Disabled: true,
		},
	})
	if len(components) != 1 {
		t.Fatalf("components=%d want=1", len(components))
	}
	component := components[0]
	if component.product != "payments-mcp" || component.itemName != "payments-mcp" ||
		component.mcpTransport != "http" || component.mcpCommandBasename != "mcp-server" ||
		component.mcpURLHost != "mcp.example.com:8443" || component.mcpAuthProviderType != "oauth" ||
		component.mcpDisabled == nil || !*component.mcpDisabled || component.active {
		t.Fatalf("sanitized component=%+v", component)
	}
	joined := strings.Join([]string{
		component.id, component.componentType, component.signal, component.product,
		component.itemName, component.mcpTransport, component.mcpCommandBasename,
		component.mcpURLHost, component.mcpAuthProviderType,
	}, " ")
	for _, forbidden := range []string{"/Users/alice", "private", "password", "token", "secret", "--token"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("canonical component leaked %q: %q", forbidden, joined)
		}
	}
}

func TestEmitEndpointInventoryPreservesPR471SafeMCPFields(t *testing.T) {
	withManagedEnterprise(t, true)
	t.Setenv("PATH", t.TempDir())
	configPath := filepath.Join(t.TempDir(), "openclaw.json")
	if err := os.WriteFile(configPath, []byte(`{
  "mcp": {"servers": {"payments-mcp": {
    "command": "/Users/alice/private/bin/mcp-server",
    "args": ["--token", "secret"],
    "cwd": "/Users/alice/private",
    "url": "https://user:password@mcp.example.com:8443/v1?token=secret#fragment",
    "transport": "http",
    "authProviderType": "oauth",
    "disabled": true
  }}}
}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Claw: config.ClawConfig{Mode: config.ClawMode("openclaw"), ConfigFile: configPath}}
	capture := &endpointInventoryCapture{}
	if err := EmitEndpointInventory(t.Context(), cfg, connector.NewDefaultRegistry(), capture); err != nil {
		t.Fatal(err)
	}

	var mcpBody map[string]any
	for _, record := range capture.snapshot() {
		body, ok := record.Body()
		if !ok || record.EventName() != "ai_component.observed" {
			continue
		}
		bodyMap, err := body.Object()
		if err != nil {
			t.Fatal(err)
		}
		if bodyMap[observability.TelemetryAttributeDefenseClawAIComponentType] == "mcp_server" {
			mcpBody = bodyMap
			break
		}
	}
	if mcpBody == nil {
		t.Fatal("no canonical MCP inventory row")
	}
	want := map[string]any{
		observability.TelemetryAttributeDefenseClawAIDiscoverySource:            endpointMCPInventorySource,
		observability.TelemetryAttributeDefenseClawInventoryItemName:            "payments-mcp",
		observability.TelemetryAttributeDefenseClawInventoryMcpTransport:        "http",
		observability.TelemetryAttributeDefenseClawInventoryMcpCommandBasename:  "mcp-server",
		observability.TelemetryAttributeDefenseClawInventoryMcpURLHost:          "mcp.example.com:8443",
		observability.TelemetryAttributeDefenseClawInventoryMcpAuthProviderType: "oauth",
		observability.TelemetryAttributeDefenseClawInventoryMcpDisabled:         true,
	}
	for field, expected := range want {
		if got := mcpBody[field]; got != expected {
			t.Fatalf("MCP field %s=%T(%v) want=%T(%v)", field, got, got, expected, expected)
		}
	}
	encoded, err := json.Marshal(mcpBody)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"/Users/alice", "private", "password", "token", "secret", "--token"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("canonical MCP row leaked %q: %s", forbidden, encoded)
		}
	}
}

func TestEndpointMCPReadFailureIsPartialNotAuthoritativeEmpty(t *testing.T) {
	withManagedEnterprise(t, true)
	t.Setenv("PATH", t.TempDir())
	dir := t.TempDir()
	cfg := &config.Config{Claw: config.ClawConfig{Mode: config.ClawMode("openclaw")}}

	cfg.Claw.ConfigFile = filepath.Join(dir, "missing.json")
	if components, partial := endpointMCPComponents(cfg); len(components) != 0 || partial {
		t.Fatalf("confirmed absent MCP config components/partial=%d/%t want=0/false", len(components), partial)
	}

	cfg.Claw.ConfigFile = filepath.Join(dir, "invalid.json")
	if err := os.WriteFile(cfg.Claw.ConfigFile, []byte(`{`), 0o600); err != nil {
		t.Fatal(err)
	}
	if components, partial := endpointMCPComponents(cfg); len(components) != 0 || !partial {
		t.Fatalf("invalid MCP config components/partial=%d/%t want=0/true", len(components), partial)
	}

	capture := &endpointInventoryCapture{}
	if err := EmitEndpointInventory(t.Context(), cfg, connector.NewDefaultRegistry(), capture); err != nil {
		t.Fatal(err)
	}
	for _, record := range capture.snapshot() {
		body, ok := record.Body()
		if !ok || record.EventName() != "ai.discovery.completed" {
			continue
		}
		bodyMap, err := body.Object()
		if err != nil {
			t.Fatal(err)
		}
		if bodyMap[observability.TelemetryAttributeDefenseClawAIDiscoverySource] != endpointMCPInventorySource {
			continue
		}
		if record.Action() != string(config.ObservabilityV8LocalInventoryDiagnosticAction) ||
			record.Outcome() != observability.OutcomePartial ||
			canonicalInt64(t, bodyMap[observability.TelemetryAttributeDefenseClawAIDiscoveryErrors]) != 1 ||
			canonicalInt64(t, bodyMap[observability.TelemetryAttributeDefenseClawAIDiscoverySignalsTotal]) != 0 {
			t.Fatalf("partial MCP summary action/outcome/body=%q/%q/%#v", record.Action(), record.Outcome(), bodyMap)
		}
		if _, present := bodyMap[observability.TelemetryAttributeDefenseClawInventoryMcpIdentifiers]; present {
			t.Fatalf("partial MCP summary carried authoritative identifiers: %#v", bodyMap)
		}
		return
	}
	t.Fatal("no partial MCP summary")
}

func TestEndpointPluginDiscoveryFailureIsPartialAndKeepsBuiltins(t *testing.T) {
	withManagedEnterprise(t, true)
	pluginRoot := filepath.Join(t.TempDir(), "configured-plugin-root")
	if err := os.WriteFile(pluginRoot, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{PluginDir: pluginRoot}
	capture := &endpointInventoryCapture{}
	makeEndpointInventoryEmitter(cfg, capture)(t.Context())

	wantBuiltins := len(connector.NewDefaultRegistry().Available())
	connectorRows := 0
	foundSummary := false
	for _, record := range capture.snapshot() {
		body, ok := record.Body()
		if !ok {
			continue
		}
		bodyMap, err := body.Object()
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(bodyMap)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(encoded), pluginRoot) {
			t.Fatalf("partial inventory leaked plugin path: %s", encoded)
		}
		switch record.EventName() {
		case "ai_component.observed":
			if bodyMap[observability.TelemetryAttributeDefenseClawAIComponentType] == "supported_connector" {
				if record.Action() != string(config.ObservabilityV8LocalInventoryDiagnosticAction) {
					t.Fatalf("partial connector component action=%q", record.Action())
				}
				connectorRows++
			}
		case "ai.discovery.completed":
			if bodyMap[observability.TelemetryAttributeDefenseClawAIDiscoverySource] != endpointConnectorInventorySource {
				continue
			}
			foundSummary = true
			if record.Action() != string(config.ObservabilityV8LocalInventoryDiagnosticAction) ||
				record.Outcome() != observability.OutcomePartial ||
				canonicalInt64(t, bodyMap[observability.TelemetryAttributeDefenseClawAIDiscoveryErrors]) != 1 ||
				canonicalInt64(t, bodyMap[observability.TelemetryAttributeDefenseClawAIDiscoverySignalsTotal]) != int64(wantBuiltins) {
				t.Fatalf("partial connector summary action/outcome/body=%q/%q/%#v", record.Action(), record.Outcome(), bodyMap)
			}
			if _, present := bodyMap[observability.TelemetryAttributeDefenseClawInventoryConnectorIdentifiers]; present {
				t.Fatalf("partial connector summary carried authoritative identifiers: %#v", bodyMap)
			}
		}
	}
	if !foundSummary || connectorRows != wantBuiltins {
		t.Fatalf(
			"plugin discovery failure summary=%t builtin rows=%d, want %d",
			foundSummary,
			connectorRows,
			wantBuiltins,
		)
	}
}

func TestEndpointInventoryHelpersRejectRawPathAndURLMaterial(t *testing.T) {
	t.Parallel()
	if got := inventorySafeBasename("/usr/local/bin/mcp-server"); got != "mcp-server" {
		t.Fatalf("inventorySafeBasename=%q", got)
	}
	if got := mcpURLHost("https://user:password@mcp.example.com:8443/v1?token=secret"); got != "mcp.example.com:8443" {
		t.Fatalf("mcpURLHost=%q", got)
	}
	if got := inventorySafeBasename(`C:\\Users\\alice\\private\\mcp.exe`); got != "mcp.exe" {
		t.Fatalf("windows inventorySafeBasename=%q", got)
	}
	for _, invalid := range []string{
		"npx -y secret", "npx;secret", "npx|secret", "npx&secret", "$(secret)",
	} {
		if got := inventorySafeBasename(invalid); got != "" {
			t.Fatalf("inventorySafeBasename(%q)=%q, want rejection", invalid, got)
		}
	}
	for _, invalid := range []string{"plugin/name", `plugin\\name`} {
		if got := inventorySafeItemName(invalid, 256); got != "" {
			t.Fatalf("inventorySafeItemName(%q)=%q, want rejection", invalid, got)
		}
	}
	if got := inventorySafeItemName("Plugin display name", 256); got != "Plugin display name" {
		t.Fatalf("inventorySafeItemName ordinary name=%q", got)
	}
	if got := inventoryStableToken("  HTTP.Stream  ", 64); got != "http.stream" {
		t.Fatalf("inventoryStableToken normalization=%q", got)
	}
	for _, invalid := range []string{"oauth/provider", "bearer credential", "shell;transport"} {
		if got := inventoryStableToken(invalid, 64); got != "" {
			t.Fatalf("inventoryStableToken(%q)=%q, want rejection", invalid, got)
		}
	}
}

var _ sidecarRuntimeEmitter = (*endpointInventoryCapture)(nil)
var _ aiDiscoveryV8Runtime = (*endpointInventoryCapture)(nil)
