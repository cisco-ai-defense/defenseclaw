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
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
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
		case "ai_component.observed":
			components++
			if got := bodyMap[observability.TelemetryAttributeDefenseClawAIComponentType]; got != "supported_connector" {
				t.Fatalf("component type=%v", got)
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
	mcpSummary := summaries[endpointMCPInventorySource]
	if mcpSummary == nil || canonicalInt64(t, mcpSummary[observability.TelemetryAttributeDefenseClawAIDiscoverySignalsTotal]) != 0 {
		t.Fatalf("empty MCP collection was not represented: %#v", mcpSummary)
	}
}

func TestManagedEndpointInventorySurvivesSourceDisabledAIDiscoveryLogs(t *testing.T) {
	withManagedEnterprise(t, true)
	runtime, path, adapter := newManagedAIDFailOpenRuntime(t)
	if err := EmitEndpointInventory(
		t.Context(), &config.Config{}, connector.NewRegistry(), runtime,
	); err != nil {
		t.Fatal(err)
	}

	for delivered := 0; delivered < 2; delivered++ {
		select {
		case item := <-adapter.delivered:
			if item.identity.Bucket != string(observability.BucketAIDiscovery) ||
				item.identity.Signal != string(observability.SignalLogs) ||
				item.identity.EventName != "ai.discovery.completed" {
				t.Fatalf("managed inventory delivery identity = %+v", item.identity)
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
}

func TestManagedPluginDescriptionUsesSensitiveProjection(t *testing.T) {
	withManagedEnterprise(t, true)
	runtime, _, adapter := newManagedAIDFailOpenRuntime(t)
	registry := connector.NewRegistry()
	pathCanary := strings.Join([]string{"", "Users", "alice", ".ssh", "id_rsa"}, "/")
	description := "plugin private_key=" + pathCanary
	if err := registry.RegisterPlugin(&endpointInventoryPluginConnector{
		name: "sensitive-plugin", description: description,
	}); err != nil {
		t.Fatal(err)
	}
	if err := EmitEndpointInventory(t.Context(), &config.Config{}, registry, runtime); err != nil {
		t.Fatal(err)
	}

	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	for delivered := 0; delivered < 3; delivered++ {
		select {
		case item := <-adapter.delivered:
			if item.identity.EventName != "ai_component.observed" {
				continue
			}
			var wire map[string]any
			if err := json.Unmarshal(item.bytes, &wire); err != nil {
				t.Fatal(err)
			}
			body, ok := wire["body"].(map[string]any)
			if !ok {
				t.Fatalf("managed plugin projection body = %T", wire["body"])
			}
			projected, ok := body[observability.TelemetryAttributeDefenseClawInventoryItemDescription].(string)
			if !ok || projected == "" || projected == description || strings.Contains(projected, pathCanary) {
				t.Fatalf("managed plugin description was not redacted: %q", projected)
			}
			classes, ok := wire["field_classes"].(map[string]any)
			if !ok || classes["/"+observability.TelemetryAttributeDefenseClawInventoryItemDescription] != "content" {
				t.Fatalf("managed plugin description field classes = %#v", classes)
			}
			projection, ok := wire["projection"].(map[string]any)
			if !ok || projection["redaction_profile"] != "sensitive" {
				t.Fatalf("managed plugin projection metadata = %#v", projection)
			}
			return
		case <-deadline.C:
			t.Fatal("timed out waiting for managed plugin inventory projection")
		}
	}
	t.Fatal("managed plugin inventory component was not delivered")
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
		if record.Outcome() != observability.OutcomePartial ||
			canonicalInt64(t, bodyMap[observability.TelemetryAttributeDefenseClawAIDiscoveryErrors]) != 1 ||
			canonicalInt64(t, bodyMap[observability.TelemetryAttributeDefenseClawAIDiscoverySignalsTotal]) != 0 {
			t.Fatalf("partial MCP summary outcome/body=%q/%#v", record.Outcome(), bodyMap)
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
				connectorRows++
			}
		case "ai.discovery.completed":
			if bodyMap[observability.TelemetryAttributeDefenseClawAIDiscoverySource] != endpointConnectorInventorySource {
				continue
			}
			foundSummary = true
			if record.Outcome() != observability.OutcomePartial ||
				canonicalInt64(t, bodyMap[observability.TelemetryAttributeDefenseClawAIDiscoveryErrors]) != 1 ||
				canonicalInt64(t, bodyMap[observability.TelemetryAttributeDefenseClawAIDiscoverySignalsTotal]) != int64(wantBuiltins) {
				t.Fatalf("partial connector summary outcome/body=%q/%#v", record.Outcome(), bodyMap)
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
