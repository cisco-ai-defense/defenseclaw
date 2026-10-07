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

func managedResourceSnapshot(
	source map[string]string,
	deploymentAliases bool,
) (map[string]string, string, string, bool) {
	values := make(map[string]string, len(source)+1)
	for key, value := range source {
		values[key] = value
	}
	deviceID := values["defenseclaw.device.public_key_fingerprint"]
	hostname := values["host.name"]
	if !validManagedAnchor(deviceID) || !validManagedAnchor(hostname) {
		return nil, "", "", false
	}
	// The managed AI Defense wire contract is the resource the sink sent
	// before telemetry dropped its alias attributes, and no other destination
	// carries them. The sink always added defenseclaw.device.id itself.
	// deployment.environment and deployment.mode came from the provider
	// while trace_policy.compatibility_aliases was on, so they follow that
	// switch. Drop this when the managed backend keys only on the canonical
	// names.
	values["defenseclaw.device.id"] = deviceID
	if deploymentAliases {
		for canonical, wire := range map[string]string{
			"deployment.environment.name": "deployment.environment",
			"defenseclaw.deployment.mode": "deployment.mode",
		} {
			if value := values[canonical]; value != "" {
				values[wire] = value
			}
		}
	}
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
	default:
		// v8-ONLY managed-inventory contract (Vineet's [P1] on this
		// file). Every ai.discovery record — agent, connector, MCP,
		// skill, and plugin inventories, plus the ai_discovery scan
		// summary — flows through as its original v8 OTLP log with
		// no legacy gatewaylog.Event wrapping. The schema-v7
		// agent / connector / MCP inventory projectors are gone.
		//
		// Every ai.discovery action is now v8-passthrough. Records
		// outside guardrail.evaluation.completed remain fail-closed
		// here so an unknown record shape can't silently leak.
		if wire.Bucket == "ai.discovery" && isV8PassThroughAction(wire.Action) {
			return managedCompatibilityProjection{}, false, true
		}
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

// isV8PassThroughAction reports whether the given routing action names a v8
// discovery/inventory record that should flow through the managed AID
// adapter unprojected. Under the v8-only contract this covers EVERY
// ai.discovery action — agent, connector, MCP, skill, and plugin
// per-item inventories, plus the ai_discovery scan summary. Diagnostic
// actions like local_inventory_diagnostic are intentionally NOT here —
// those never reach the managed egress route (see
// reserveObservabilityV8ManagedInventory) so the compatibility projector
// never sees them.
func isV8PassThroughAction(action string) bool {
	switch action {
	case string(config.ObservabilityV8ManagedAgentInventoryAction),
		string(config.ObservabilityV8ManagedConnectorInventoryAction),
		string(config.ObservabilityV8ManagedMCPInventoryAction),
		string(config.ObservabilityV8ManagedSkillInventoryAction),
		string(config.ObservabilityV8ManagedPluginInventoryAction),
		"ai_discovery":
		return true
	}
	return false
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
