// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managedaid

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/version"
	publicschemas "github.com/defenseclaw/defenseclaw/schemas"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
)

const (
	managedEventVerdict            = "verdict"
	managedEventConnectorInventory = "connector_inventory"
	managedEventMCPInventory       = "mcp_inventory"
	managedEventAgentInventory     = "agent_inventory"
	maxManagedReasonAttributeBytes = 200
	managedGatewaySchemaURL        = "https://defenseclaw.io/schemas/gateway-event-envelope.json"
	managedScanSchemaURL           = "https://defenseclaw.io/schemas/scan-event.json"
	managedScanFindingSchemaURL    = "https://defenseclaw.io/schemas/scan-finding-event.json"
	managedActivitySchemaURL       = "https://defenseclaw.io/schemas/activity-event.json"
)

var (
	managedGatewaySchemaOnce sync.Once
	managedGatewaySchema     *jsonschema.Schema
	managedGatewaySchemaErr  error
)

// managedCompatibilityProjection is derived only from destination-projected
// canonical JSON. The central redaction engine and request SinkPolicy have
// therefore already run before any legacy-compatible field is selected here.
type managedCompatibilityProjection struct {
	body       string
	eventType  string
	attributes []*commonpb.KeyValue
}

type managedProjectedItem interface {
	Bytes() []byte
	Identity() delivery.RoutingIdentity
}

type managedCanonicalProjection struct {
	RecordID    string         `json:"record_id"`
	Timestamp   string         `json:"timestamp"`
	Bucket      string         `json:"bucket"`
	Signal      string         `json:"signal"`
	EventName   string         `json:"event_name"`
	Source      string         `json:"source"`
	Connector   string         `json:"connector"`
	Action      string         `json:"action"`
	Phase       string         `json:"phase"`
	Outcome     string         `json:"outcome"`
	Severity    string         `json:"severity"`
	LogLevel    string         `json:"log_level"`
	Body        map[string]any `json:"body"`
	Correlation map[string]any `json:"correlation"`
	Provenance  map[string]any `json:"provenance"`
}

type managedConnectorIdentifier struct {
	Name string `json:"name"`
}

type managedConnectorMetadata struct {
	Source             string `json:"source"`
	ToolInspectionMode string `json:"tool_inspection_mode"`
	SubprocessPolicy   string `json:"subprocess_policy"`
}

type managedConnectorContent struct {
	Description string `json:"description,omitempty"`
}

type managedMCPIdentifier struct {
	Name    string `json:"name"`
	URLHost string `json:"url_host,omitempty"`
}

type managedMCPMetadata struct {
	Transport        string `json:"transport,omitempty"`
	CommandBasename  string `json:"command_basename,omitempty"`
	AuthProviderType string `json:"auth_provider_type,omitempty"`
	Disabled         *bool  `json:"disabled"`
}

type managedAgentIdentifier struct {
	Name           string `json:"name"`
	ConfigPathHash string `json:"config_path_hash,omitempty"`
	BinaryPathHash string `json:"binary_path_hash,omitempty"`
}

type managedAgentMetadata struct {
	Installed      *bool  `json:"installed"`
	HasConfig      *bool  `json:"has_config"`
	ConfigBasename string `json:"config_basename,omitempty"`
	HasBinary      *bool  `json:"has_binary"`
	BinaryBasename string `json:"binary_basename,omitempty"`
	Version        string `json:"version,omitempty"`
	ProbeStatus    string `json:"probe_status"`
}

func validManagedContentHash(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if !(character >= '0' && character <= '9') && !(character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func compiledManagedGatewaySchema() (*jsonschema.Schema, error) {
	managedGatewaySchemaOnce.Do(func() {
		compiler := jsonschema.NewCompiler()
		compiler.Draft = jsonschema.Draft2020
		resources := []struct {
			url  string
			data []byte
		}{
			{managedScanSchemaURL, publicschemas.GatewayScanEventSchema()},
			{managedScanFindingSchemaURL, publicschemas.GatewayScanFindingEventSchema()},
			{managedActivitySchemaURL, publicschemas.GatewayActivityEventSchema()},
			{managedGatewaySchemaURL, publicschemas.GatewayEventEnvelopeSchema()},
		}
		for _, resource := range resources {
			if len(resource.data) == 0 {
				managedGatewaySchemaErr = errors.New("managed gateway schema unavailable")
				return
			}
			if err := compiler.AddResource(resource.url, bytes.NewReader(resource.data)); err != nil {
				managedGatewaySchemaErr = err
				return
			}
		}
		managedGatewaySchema, managedGatewaySchemaErr = compiler.Compile(managedGatewaySchemaURL)
	})
	return managedGatewaySchema, managedGatewaySchemaErr
}

func validateManagedGatewayEvent(event gatewaylog.Event) ([]byte, bool) {
	if event.PayloadHMAC == "" {
		return nil, false
	}
	encoded, err := json.Marshal(event)
	if err != nil || len(encoded) == 0 {
		return nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var document any
	if err := decoder.Decode(&document); err != nil {
		return nil, false
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, false
	}
	schema, err := compiledManagedGatewaySchema()
	if err != nil || schema == nil || schema.Validate(document) != nil {
		return nil, false
	}
	return encoded, true
}

func managedResourceSnapshot(source map[string]string) (map[string]string, string, string, bool) {
	values := make(map[string]string, len(source)+1)
	for key, value := range source {
		values[key] = value
	}
	deviceID := values["defenseclaw.device.public_key_fingerprint"]
	hostname := values["host.name"]
	if !validManagedAnchor(deviceID) || !validManagedAnchor(hostname) {
		return nil, "", "", false
	}
	// This compatibility alias is release-owned for the managed sink only. It
	// does not depend on, or mutate, the operator's global compatibility_aliases.
	values["defenseclaw.device.id"] = deviceID
	return values, deviceID, hostname, true
}

func validManagedAnchor(value string) bool {
	if value == "" || len(value) > 256 || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func projectManagedCompatibility(
	item managedProjectedItem,
	deviceID string,
	hostname string,
	contentHash string,
) (managedCompatibilityProjection, bool, bool) {
	identity := item.Identity()
	if !managedCompatibilityCandidate(identity) {
		return managedCompatibilityProjection{}, false, true
	}
	if !validManagedContentHash(contentHash) {
		return managedCompatibilityProjection{}, false, false
	}
	decoder := json.NewDecoder(bytes.NewReader(item.Bytes()))
	decoder.UseNumber()
	var wire managedCanonicalProjection
	if err := decoder.Decode(&wire); err != nil {
		return managedCompatibilityProjection{}, false, false
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return managedCompatibilityProjection{}, false, false
	}
	if wire.RecordID != identity.RecordID || wire.Bucket != identity.Bucket ||
		wire.Signal != identity.Signal || wire.EventName != identity.EventName ||
		wire.Signal != "logs" || wire.Body == nil || wire.Correlation == nil || wire.Provenance == nil {
		return managedCompatibilityProjection{}, false, false
	}
	timestamp, err := time.Parse(time.RFC3339Nano, wire.Timestamp)
	if err != nil {
		return managedCompatibilityProjection{}, false, false
	}

	event := gatewaylog.Event{
		Timestamp: timestamp.UTC(), Severity: managedGatewaySeverity(wire.Severity, wire.LogLevel),
		SchemaVersion:     version.SchemaVersion,
		BinaryVersion:     managedString(wire.Provenance, "binary_version", 256),
		ContentHash:       contentHash,
		Connector:         managedToken(wire.Connector, 256),
		RunID:             managedString(wire.Correlation, "run_id", 512),
		RequestID:         managedString(wire.Correlation, "request_id", 512),
		SessionID:         managedString(wire.Correlation, "session_id", 512),
		TurnID:            managedString(wire.Correlation, "turn_id", 512),
		TraceID:           managedString(wire.Correlation, "trace_id", 512),
		AgentID:           managedString(wire.Correlation, "agent_id", 512),
		AgentInstanceID:   managedString(wire.Correlation, "agent_instance_id", 512),
		SidecarInstanceID: managedString(wire.Correlation, "sidecar_instance_id", 512),
		PolicyID:          managedString(wire.Correlation, "policy_id", 512),
	}
	if generation, ok := managedInt64(wire.Provenance, "config_generation"); ok && generation >= 0 {
		event.Generation = uint64(generation)
	}

	projection := managedCompatibilityProjection{}
	switch {
	case wire.Bucket == "guardrail.evaluation" && wire.EventName == "guardrail.evaluation.completed":
		if !projectManagedVerdict(&event, wire.Body, &projection) {
			return managedCompatibilityProjection{}, false, false
		}
	case wire.Bucket == "ai.discovery" &&
		wire.Action == string(config.ObservabilityV8ManagedConnectorInventoryAction):
		if !projectManagedConnectorInventory(&event, wire.EventName, wire.Body, deviceID, hostname, &projection) {
			return managedCompatibilityProjection{}, false, false
		}
	case wire.Bucket == "ai.discovery" &&
		wire.Action == string(config.ObservabilityV8ManagedMCPInventoryAction):
		if !projectManagedMCPInventory(&event, wire.EventName, wire.Body, deviceID, hostname, &projection) {
			return managedCompatibilityProjection{}, false, false
		}
	case wire.Bucket == "ai.discovery" &&
		wire.Action == string(config.ObservabilityV8ManagedAgentInventoryAction):
		if !projectManagedAgentInventory(&event, wire.EventName, wire.Body, deviceID, hostname, &projection) {
			return managedCompatibilityProjection{}, false, false
		}
	default:
		return managedCompatibilityProjection{}, false, false
	}

	event.StampPayloadHMAC()
	encoded, valid := validateManagedGatewayEvent(event)
	if !valid {
		return managedCompatibilityProjection{}, false, false
	}
	projection.body = string(encoded)
	projection.attributes = append(projection.attributes,
		managedStringAttribute("event.name", "defenseclaw.gateway."+projection.eventType),
		managedStringAttribute("event.domain", "defenseclaw.gateway"),
		managedStringAttribute("defenseclaw.gateway.event_type", projection.eventType),
		managedStringAttribute("defenseclaw.device.id", deviceID),
		managedStringAttribute("host.name", hostname),
	)
	return projection, true, true
}

func managedCompatibilityCandidate(identity delivery.RoutingIdentity) bool {
	if identity.Signal != "logs" {
		return false
	}
	return identity.Bucket == "guardrail.evaluation" && identity.EventName == "guardrail.evaluation.completed" ||
		identity.Bucket == "ai.discovery" &&
			identity.EventName == "ai.discovery.completed"
}

func projectManagedVerdict(
	event *gatewaylog.Event,
	body map[string]any,
	projection *managedCompatibilityProjection,
) bool {
	stage := managedString(body, "defenseclaw.guardrail.stage", 256)
	action := managedString(body, "defenseclaw.guardrail.effective_action", 256)
	if event == nil || projection == nil || stage == "" || action == "" {
		return false
	}
	reason := managedString(body, "defenseclaw.guardrail.reason", 4096)
	latency, _ := managedNonnegativeInt64(body, "defenseclaw.guardrail.latency_ms")
	ruleIDs, ok := managedStrings(body, "defenseclaw.guardrail.rule_ids", 8, 256)
	if !ok {
		return false
	}
	event.EventType = gatewaylog.EventType(managedEventVerdict)
	event.Verdict = &gatewaylog.VerdictPayload{
		Stage: gatewaylog.Stage(stage), Action: action, Reason: reason,
		LatencyMs: latency, RuleIDs: ruleIDs,
		EvaluationID: managedString(body, "defenseclaw.evaluation.id", 512),
	}
	event.Model = managedString(body, "gen_ai.request.model", 512)
	if event.SessionID == "" {
		event.SessionID = managedString(body, "gen_ai.conversation.id", 512)
	}
	event.Provider = managedString(body, "gen_ai.provider.name", 256)
	if direction := managedString(body, "defenseclaw.guardrail.direction", 64); direction != "" {
		event.Direction = gatewaylog.Direction(direction)
	}
	projection.eventType = managedEventVerdict
	projection.attributes = append(projection.attributes,
		managedStringAttribute("defenseclaw.verdict.stage", stage),
		managedStringAttribute("defenseclaw.verdict.action", action),
		managedStringAttribute("defenseclaw.verdict.reason", managedTruncate(reason, maxManagedReasonAttributeBytes)),
		managedIntAttribute("defenseclaw.verdict.latency_ms", latency),
	)
	if len(ruleIDs) > 0 {
		projection.attributes = append(projection.attributes,
			managedStringAttribute("defenseclaw.verdict.rule_ids", strings.Join(ruleIDs, ",")))
	}
	return true
}

func projectManagedConnectorInventory(
	event *gatewaylog.Event, eventName string, body map[string]any,
	deviceID, hostname string, projection *managedCompatibilityProjection,
) bool {
	if event == nil || projection == nil || eventName != "ai.discovery.completed" {
		return false
	}
	count, active, ok := managedAuthoritativeInventorySummary(body, 128)
	if !ok {
		return false
	}
	identifiers, ok := decodeManagedArray[managedConnectorIdentifier](
		body, "defenseclaw.inventory.connector.identifiers", 128, true,
	)
	if !ok || len(identifiers) != count {
		return false
	}
	metadata, ok := decodeManagedArray[managedConnectorMetadata](
		body, "defenseclaw.inventory.connector.metadata", 128, true,
	)
	if !ok || len(metadata) != count {
		return false
	}
	content, ok := decodeManagedArray[managedConnectorContent](
		body, "defenseclaw.inventory.connector.content", 128, false,
	)
	_, contentPresent := body["defenseclaw.inventory.connector.content"]
	if !ok || contentPresent && len(content) != count || active != count {
		return false
	}
	payload := &gatewaylog.ConnectorInventoryPayload{
		DeviceID: deviceID, Hostname: hostname, Count: count,
		Connectors: make([]gatewaylog.ConnectorInventoryItem, 0, count),
	}
	for index := range identifiers {
		name := managedSafeString(identifiers[index].Name, 128)
		source := managedToken(metadata[index].Source, 64)
		toolMode := managedToken(metadata[index].ToolInspectionMode, 64)
		subprocess := managedToken(metadata[index].SubprocessPolicy, 64)
		if name == "" || strings.ContainsAny(name, `/\\`) || source == "" || toolMode == "" || subprocess == "" {
			return false
		}
		description := ""
		if len(content) != 0 {
			description = managedSafeString(content[index].Description, 512)
			if content[index].Description != "" && description == "" {
				return false
			}
		}
		payload.Connectors = append(payload.Connectors, gatewaylog.ConnectorInventoryItem{
			Name: name, Description: description, Source: source,
			ToolInspectionMode: toolMode, SubprocessPolicy: subprocess,
		})
	}
	event.EventType = gatewaylog.EventType(managedEventConnectorInventory)
	event.ConnectorInventory = payload
	projection.eventType = managedEventConnectorInventory
	projection.attributes = append(projection.attributes,
		managedIntAttribute("defenseclaw.inventory.connector.count", int64(payload.Count)))
	return true
}

func projectManagedMCPInventory(
	event *gatewaylog.Event, eventName string, body map[string]any,
	deviceID, hostname string, projection *managedCompatibilityProjection,
) bool {
	if event == nil || projection == nil || eventName != "ai.discovery.completed" {
		return false
	}
	count, active, ok := managedAuthoritativeInventorySummary(body, 256)
	if !ok {
		return false
	}
	identifiers, ok := decodeManagedArray[managedMCPIdentifier](
		body, "defenseclaw.inventory.mcp.identifiers", 256, true,
	)
	if !ok || len(identifiers) != count {
		return false
	}
	metadata, ok := decodeManagedArray[managedMCPMetadata](
		body, "defenseclaw.inventory.mcp.metadata", 256, true,
	)
	if !ok || len(metadata) != count {
		return false
	}
	payload := &gatewaylog.MCPInventoryPayload{
		DeviceID: deviceID, Hostname: hostname, Count: count,
		Servers: make([]gatewaylog.MCPInventoryItem, 0, count),
	}
	computedActive := 0
	for index := range identifiers {
		name := managedSafeString(identifiers[index].Name, 256)
		if name == "" || strings.ContainsAny(name, `/\\`) || metadata[index].Disabled == nil {
			return false
		}
		transport := managedOptionalToken(metadata[index].Transport, 64)
		command := managedOptionalSafeName(metadata[index].CommandBasename, 256)
		host := managedOptionalSafeHost(identifiers[index].URLHost, 256)
		auth := managedOptionalToken(metadata[index].AuthProviderType, 64)
		if transport == "\x00" || command == "\x00" || host == "\x00" || auth == "\x00" {
			return false
		}
		if !*metadata[index].Disabled {
			computedActive++
		}
		payload.Servers = append(payload.Servers, gatewaylog.MCPInventoryItem{
			Name: name, Transport: transport, Command: command, URLHost: host,
			AuthProvider: auth, Disabled: *metadata[index].Disabled,
		})
	}
	if computedActive != active {
		return false
	}
	event.EventType = gatewaylog.EventType(managedEventMCPInventory)
	event.MCPInventory = payload
	projection.eventType = managedEventMCPInventory
	projection.attributes = append(projection.attributes,
		managedIntAttribute("defenseclaw.inventory.mcp.count", int64(payload.Count)))
	return true
}

func projectManagedAgentInventory(
	event *gatewaylog.Event, eventName string, body map[string]any,
	deviceID, hostname string, projection *managedCompatibilityProjection,
) bool {
	if event == nil || projection == nil || eventName != "ai.discovery.completed" {
		return false
	}
	count, installed, ok := managedAuthoritativeInventorySummary(body, 64)
	if !ok {
		return false
	}
	identifiers, ok := decodeManagedArray[managedAgentIdentifier](
		body, "defenseclaw.inventory.agent.identifiers", 64, true,
	)
	if !ok || len(identifiers) != count {
		return false
	}
	metadata, ok := decodeManagedArray[managedAgentMetadata](
		body, "defenseclaw.inventory.agent.metadata", 64, true,
	)
	if !ok || len(metadata) != count {
		return false
	}
	scannedAt := managedString(body, "defenseclaw.agent.discovery.scanned_at", 64)
	if scannedAt != "" {
		if _, parseErr := time.Parse(time.RFC3339Nano, scannedAt); parseErr != nil {
			return false
		}
	}
	payload := &gatewaylog.AgentInventoryPayload{
		DeviceID: deviceID, Hostname: hostname,
		Source: managedString(body, "defenseclaw.ai.discovery.source", 64), ScannedAt: scannedAt,
		Count: count, Installed: installed, Agents: make([]gatewaylog.AgentInventoryItem, 0, count),
	}
	computedInstalled := 0
	for index := range identifiers {
		identifier, agentMetadata := identifiers[index], metadata[index]
		name := managedSafeString(identifier.Name, 128)
		if name == "" || agentMetadata.Installed == nil || agentMetadata.HasConfig == nil ||
			agentMetadata.HasBinary == nil || agentMetadata.ProbeStatus == "" {
			return false
		}
		configBase := managedOptionalSafeName(agentMetadata.ConfigBasename, 128)
		binaryBase := managedOptionalSafeName(agentMetadata.BinaryBasename, 128)
		versionValue := managedOptionalSafeString(agentMetadata.Version, 200)
		probe := managedToken(agentMetadata.ProbeStatus, 64)
		configHash := managedOptionalHash(identifier.ConfigPathHash)
		binaryHash := managedOptionalHash(identifier.BinaryPathHash)
		if configBase == "\x00" || binaryBase == "\x00" || versionValue == "\x00" || probe == "" ||
			configHash == "\x00" || binaryHash == "\x00" ||
			(!*agentMetadata.HasConfig && (configBase != "" || configHash != "")) ||
			(!*agentMetadata.HasBinary && (binaryBase != "" || binaryHash != "" || versionValue != "")) {
			return false
		}
		if *agentMetadata.Installed {
			computedInstalled++
		}
		payload.Agents = append(payload.Agents, gatewaylog.AgentInventoryItem{
			Name: name, Installed: *agentMetadata.Installed, HasConfig: *agentMetadata.HasConfig,
			ConfigBasename: configBase, ConfigPathHash: configHash, HasBinary: *agentMetadata.HasBinary,
			BinaryBasename: binaryBase, BinaryPathHash: binaryHash,
			Version: versionValue, VersionProbeStatus: probe,
		})
	}
	if computedInstalled != installed {
		return false
	}
	event.EventType = gatewaylog.EventType(managedEventAgentInventory)
	event.AgentInventory = payload
	projection.eventType = managedEventAgentInventory
	projection.attributes = append(projection.attributes,
		managedIntAttribute("defenseclaw.inventory.agent.count", int64(payload.Count)),
		managedIntAttribute("defenseclaw.inventory.agent.installed", int64(payload.Installed)),
	)
	return true
}

func applyManagedCompatibility(record *logspb.LogRecord, projection managedCompatibilityProjection) bool {
	if record == nil || projection.body == "" || projection.eventType == "" {
		return false
	}
	record.Body = &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: projection.body}}
	for _, attribute := range projection.attributes {
		if attribute == nil || attribute.Key == "" || attribute.Value == nil {
			return false
		}
		managedSetAttribute(record, attribute)
	}
	return true
}

func managedSetAttribute(record *logspb.LogRecord, attribute *commonpb.KeyValue) {
	for index := range record.Attributes {
		if record.Attributes[index] != nil && record.Attributes[index].Key == attribute.Key {
			record.Attributes[index] = attribute
			return
		}
	}
	record.Attributes = append(record.Attributes, attribute)
}

func managedStringAttribute(key, value string) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: key, Value: &commonpb.AnyValue{
		Value: &commonpb.AnyValue_StringValue{StringValue: value},
	}}
}

func managedIntAttribute(key string, value int64) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: key, Value: &commonpb.AnyValue{
		Value: &commonpb.AnyValue_IntValue{IntValue: value},
	}}
}

func managedAuthoritativeInventorySummary(body map[string]any, max int) (int, int, bool) {
	if body == nil || max < 0 || managedString(body, "defenseclaw.ai.discovery.result", 64) != "completed" ||
		managedString(body, "defenseclaw.ai.discovery.source", 256) == "" {
		return 0, 0, false
	}
	count, ok := managedNonnegativeInt(body, "defenseclaw.ai.discovery.signals_total")
	if !ok || count > max {
		return 0, 0, false
	}
	active, ok := managedNonnegativeInt(body, "defenseclaw.ai.discovery.active_signals")
	if !ok || active > count {
		return 0, 0, false
	}
	errorsTotal, ok := managedNonnegativeInt(body, "defenseclaw.ai.discovery.errors")
	if !ok || errorsTotal != 0 {
		return 0, 0, false
	}
	return count, active, true
}

func decodeManagedArray[T any](
	body map[string]any,
	key string,
	max int,
	required bool,
) ([]T, bool) {
	raw, present := body[key]
	if !present {
		return nil, !required
	}
	items, ok := raw.([]any)
	if !ok || len(items) > max {
		return nil, false
	}
	encoded, err := json.Marshal(items)
	if err != nil {
		return nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var result []T
	if err := decoder.Decode(&result); err != nil || len(result) != len(items) {
		return nil, false
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, false
	}
	return result, true
}

func managedSafeString(value string, max int) string {
	return managedString(map[string]any{"value": value}, "value", max)
}

func managedOptionalSafeString(value string, max int) string {
	if value == "" {
		return ""
	}
	if safe := managedSafeString(value, max); safe != "" {
		return safe
	}
	return "\x00"
}

func managedOptionalToken(value string, max int) string {
	if value == "" {
		return ""
	}
	if safe := managedToken(value, max); safe != "" {
		return safe
	}
	return "\x00"
}

func managedOptionalSafeName(value string, max int) string {
	if value == "" {
		return ""
	}
	safe := managedSafeString(value, max)
	if safe == "" || strings.ContainsAny(safe, `/\\`) {
		return "\x00"
	}
	return safe
}

func managedOptionalSafeHost(value string, max int) string {
	if value == "" {
		return ""
	}
	safe := managedSafeString(value, max)
	if safe == "" || strings.ContainsAny(safe, `/\\?#@`) {
		return "\x00"
	}
	return safe
}

func managedOptionalHash(value string) string {
	if value == "" {
		return ""
	}
	prefix := "sha256:"
	if strings.HasPrefix(value, "hmac-sha256:") {
		prefix = "hmac-sha256:"
	}
	if len(value) != len(prefix)+64 || !strings.HasPrefix(value, prefix) {
		return "\x00"
	}
	for _, character := range value[len(prefix):] {
		if !(character >= '0' && character <= '9') && !(character >= 'a' && character <= 'f') {
			return "\x00"
		}
	}
	return value
}

func managedString(values map[string]any, key string, max int) string {
	value, ok := values[key].(string)
	if !ok || value == "" || len(value) > max || !utf8.ValidString(value) {
		return ""
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return ""
		}
	}
	return value
}

func managedToken(value string, max int) string {
	if value == "" || len(value) > max || !utf8.ValidString(value) {
		return ""
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z') && !(character >= 'A' && character <= 'Z') &&
			!(character >= '0' && character <= '9') && !strings.ContainsRune("._:/-", character) {
			return ""
		}
	}
	return value
}

func managedTokenValue(values map[string]any, key string, max int) string {
	return managedToken(managedString(values, key, max), max)
}

func managedSafeName(values map[string]any, key string, max int) string {
	value := managedString(values, key, max)
	if strings.ContainsAny(value, `/\\`) {
		return ""
	}
	return value
}

func managedSafeHost(values map[string]any, key string, max int) string {
	value := managedString(values, key, max)
	if strings.ContainsAny(value, `/\\?#@`) {
		return ""
	}
	return value
}

func managedHash(values map[string]any, key string) string {
	value := managedString(values, key, 71)
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return ""
	}
	for _, character := range value[len("sha256:"):] {
		if !(character >= '0' && character <= '9') && !(character >= 'a' && character <= 'f') {
			return ""
		}
	}
	return value
}

func managedStrings(values map[string]any, key string, maxItems, maxItem int) ([]string, bool) {
	raw, present := values[key]
	if !present {
		return nil, true
	}
	items, ok := raw.([]any)
	if !ok || len(items) > maxItems {
		return nil, false
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		value, ok := item.(string)
		if !ok || managedString(map[string]any{"item": value}, "item", maxItem) == "" {
			return nil, false
		}
		result = append(result, value)
	}
	return result, true
}

func managedBool(values map[string]any, key string) (bool, bool) {
	value, ok := values[key].(bool)
	return value, ok
}

func managedNonnegativeInt(values map[string]any, key string) (int, bool) {
	value, ok := managedNonnegativeInt64(values, key)
	if !ok || value > int64(int(^uint(0)>>1)) {
		return 0, false
	}
	return int(value), true
}

func managedNonnegativeInt64(values map[string]any, key string) (int64, bool) {
	value, ok := managedInt64(values, key)
	return value, ok && value >= 0
}

func managedInt64(values map[string]any, key string) (int64, bool) {
	switch value := values[key].(type) {
	case json.Number:
		if integer, err := value.Int64(); err == nil {
			return integer, true
		}
		floating, err := strconv.ParseFloat(string(value), 64)
		if err != nil || math.IsNaN(floating) || math.IsInf(floating, 0) || math.Trunc(floating) != floating ||
			floating < math.MinInt64 || floating > math.MaxInt64 {
			return 0, false
		}
		return int64(floating), true
	case float64:
		if math.IsNaN(value) || math.IsInf(value, 0) || math.Trunc(value) != value ||
			value < math.MinInt64 || value > math.MaxInt64 {
			return 0, false
		}
		return int64(value), true
	default:
		return 0, false
	}
}

func managedGatewaySeverity(severity, logLevel string) gatewaylog.Severity {
	value := strings.ToUpper(strings.TrimSpace(severity))
	if value == "" {
		value = strings.ToUpper(strings.TrimSpace(logLevel))
	}
	switch value {
	case "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL", "WARN":
		return gatewaylog.Severity(value)
	case "WARNING":
		return gatewaylog.SeverityWarn
	case "ERROR", "FATAL":
		return gatewaylog.SeverityHigh
	default:
		return gatewaylog.SeverityInfo
	}
}

func managedTruncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	cut := max
	for cut > 0 && value[cut]&0xc0 == 0x80 {
		cut--
	}
	return value[:cut] + "…"
}
