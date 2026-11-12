// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managedaid

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

const endpointHealthReportID = "0f8fad5b-d9cb-469f-a165-70867728950e"

func endpointHealthReportInput() observability.LogEndpointHealthReportedInput {
	return observability.LogEndpointHealthReportedInput{
		Envelope: observability.FamilyEnvelopeInput{
			Source: observability.SourceGateway,
			Action: string(config.ObservabilityV8ManagedEndpointHealthAction),
			Phase:  "report",
			Provenance: observability.FamilyProvenanceInput{
				Producer: "endpoint-health-test", BinaryVersion: "1.0.9", ConfigGeneration: 7,
				ConfigDigest: strings.Repeat("c", 64),
			},
		},
		Severity:                         observability.Present(observability.SeverityMedium),
		LogLevel:                         observability.Present(observability.LogLevelWarn),
		Outcome:                          observability.OutcomeCompleted,
		DefenseClawHealthReportID:        endpointHealthReportID,
		DefenseClawHealthSequence:        1234,
		DefenseClawHealthTrigger:         "scheduled",
		DefenseClawHealthObservedAt:      "2026-07-11T00:00:00Z",
		DefenseClawHealthReportIntervalS: 1800,
		DefenseClawHealthStatus:          "degraded",
		DefenseClawHealthReasons: observability.Present(observability.TelemetryStructuredDefenseClawHealthReasons{
			Items: []observability.TelemetryStructuredDefenseClawHealthReason{
				{Code: "HOOKS_PARTIAL", Component: "hooks", Severity: "degraded", Connector: observability.Present("codex")},
				{Code: "FAIL_OPEN_OCCURRED", Component: "inspection", Severity: "degraded"},
			},
		}),
		DefenseClawHealthReasonsTruncated:     observability.Present(false),
		DefenseClawHealthVersionProduct:       observability.Present("1.0.9"),
		DefenseClawHealthVersionPolicyBundle:  observability.Present("42"),
		DefenseClawHealthVersionAvc:           observability.Present("5.1.21.4204"),
		DefenseClawHealthOsVersion:            observability.Present("10.0.26100"),
		DefenseClawHealthGatewayStartedAt:     observability.Present("2026-07-10T00:00:00Z"),
		DefenseClawHealthGatewayUptimeS:       observability.Present(int64(86400)),
		DefenseClawHealthGatewayConfiguration: observability.Present("ready"),
		DefenseClawHealthSubsystems: observability.Present(observability.TelemetryStructuredDefenseClawHealthSubsystems{
			Items: []observability.TelemetryStructuredDefenseClawHealthSubsystemItem{
				{Name: "guardrail", State: "running", Since: observability.Present("2026-07-10T00:00:01Z")},
				{Name: "ai_discovery", State: "error", ErrorClass: observability.Present("SCAN_TIMEOUT")},
			},
		}),
		DefenseClawHealthSubsystemsTruncated:      observability.Present(false),
		DefenseClawHealthHooksConnectorsTruncated: observability.Present(false),
		DefenseClawHealthGuardianState:            observability.Present("running"),
		DefenseClawHealthGuardianLastPassAt:       observability.Present("2026-07-10T23:59:00Z"),
		DefenseClawHealthHooksTargets:             observability.Present(int64(12)),
		DefenseClawHealthHooksOk:                  observability.Present(int64(10)),
		DefenseClawHealthHooksFailed:              observability.Present(int64(1)),
		DefenseClawHealthHooksPending:             observability.Present(int64(1)),
		DefenseClawHealthHooksConnectors: observability.Present(observability.TelemetryStructuredDefenseClawHealthHookConnectors{
			Items: []observability.TelemetryStructuredDefenseClawHealthHookConnector{{
				Connector: "claude_code", Targets: 4, Ok: 4, Failed: 0, Pending: 0,
				LastActivityAt: observability.Present("2026-07-10T23:00:00Z"), ToolInspectionMode: observability.Present("enforce"),
			}},
		}),
		DefenseClawHealthHooksFailingTargets: observability.Present(observability.TelemetryStructuredDefenseClawHealthFailingTargets{
			Items: []observability.TelemetryStructuredDefenseClawHealthFailingTarget{{
				Connector: "codex", UserID: observability.Present("S-1-5-21-1004336348-1177238915-682003330-1001"),
				UserIDKind: observability.Present("windows_sid"), ErrorClass: "CONFIG_WRITE_DENIED", Pending: false,
			}},
		}),
		DefenseClawHealthHooksFailingTargetsTruncated:     observability.Present(false),
		DefenseClawHealthInspectionAIDefense:              observability.Present("ok"),
		DefenseClawHealthInspectionCmidToken:              observability.Present("ok"),
		DefenseClawHealthInspectionCmidLastSuccessAt:      observability.Present("2026-07-10T23:30:00Z"),
		DefenseClawHealthInspectionFailOpenSinceLast:      observability.Present(int64(2)),
		DefenseClawHealthCloudDeliveryState:               observability.Present("healthy"),
		DefenseClawHealthCloudDeliveryCircuit:             observability.Present("closed"),
		DefenseClawHealthCloudDeliveryConsecutiveFailures: observability.Present(int64(0)),
		DefenseClawHealthCloudDeliveryLastSuccessAt:       observability.Present("2026-07-10T23:59:30Z"),
		DefenseClawHealthCloudDeliveryLastFailureClass:    observability.Present("transient"),
		DefenseClawHealthCloudDeliveryDroppedSinceLast:    observability.Present(int64(0)),
		DefenseClawHealthLocalStoreAuditStore:             observability.Present("ok"),
	}
}

// TestEndpointHealthReportReachesManagedAIDIntactUnderSensitiveProfile builds
// the report with the generated builder, routes it through the managed
// plan, projects it with the profile the managed route selects, and sends it
// through the managed adapter. Every body field must arrive unchanged, the
// record must not be wrapped in a legacy gateway event, and no operator
// destination may receive it.
func TestEndpointHealthReportReachesManagedAIDIntactUnderSensitiveProfile(t *testing.T) {
	base, err := config.CompileObservabilityV8(&config.ObservabilityV8Source{
		Destinations: []config.ObservabilityV8DestinationSource{{
			Name: "operator-console", Kind: config.ObservabilityV8DestinationConsole,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := config.WithObservabilityV8ManagedAIDDestination(base, config.ObservabilityV8ManagedAIDOptions{
		DeploymentMode: "managed_enterprise", Endpoint: "https://aid.example.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err := router.New(plan)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerGatewayEvent,
		observability.ProducerKey("endpoint_health"),
		observability.ClassificationContext{
			Bucket: observability.BucketPlatformHealth, EventName: "endpoint.health_reported", RawSeverity: "MEDIUM",
		},
		observability.SourceGateway, "", config.ObservabilityV8ManagedEndpointHealthAction,
	)
	if err != nil {
		t.Fatalf("classify endpoint health report: %v", err)
	}
	builder, err := observability.NewFamilyBuilder(
		observability.ClockFunc(func() time.Time { return time.Date(2026, 7, 11, 0, 0, 1, 0, time.UTC) }),
		observability.TimeOrderedOccurrenceIDs,
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := evaluator.Evaluate(metadata, func(router.Admission) (observability.Record, error) {
		return builder.BuildLogEndpointHealthReported(endpointHealthReportInput())
	})
	if err != nil {
		t.Fatalf("evaluate endpoint health report: %v", err)
	}
	if result.Admission() != router.AdmissionOrdinary {
		t.Fatalf("admission = %s", result.Admission())
	}
	record, ok := result.Record()
	if !ok {
		t.Fatal("no record built")
	}
	var managedRoute router.Delivery
	destinations := map[string]bool{}
	for _, route := range result.Deliveries() {
		destinations[route.DestinationName] = true
		if route.DestinationName == config.ObservabilityV8ManagedAIDDestinationName {
			managedRoute = route
		}
	}
	if destinations["operator-console"] {
		t.Fatalf("operator destination received the endpoint health report: %+v", result.Deliveries())
	}
	if managedRoute.DestinationName == "" || managedRoute.RedactionProfile != string(redaction.ProfileSensitive) {
		t.Fatalf("managed route = %+v (deliveries %+v)", managedRoute, result.Deliveries())
	}
	profile, ok := redaction.BuiltInProfile(redaction.ProfileName(managedRoute.RedactionProfile))
	if !ok {
		t.Fatal("managed redaction profile is not built in")
	}
	original := endpointHealthCanonicalBody(t, record)

	keyed, err := redaction.NewEngine(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	for name, engine := range map[string]*redaction.Engine{
		"keyed":                     keyed,
		"personal-identifiers-kept": keyed.WithPersonalIdentifiersKept(),
	} {
		t.Run(name, func(t *testing.T) {
			projection, report, err := engine.Project(record, profile)
			if err != nil {
				t.Fatalf("project: %v (report %+v)", err, report.Entries())
			}
			if len(report.Entries()) != 0 {
				t.Fatalf("sensitive projection reported failures: %+v", report.Entries())
			}
			encoded, err := projection.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			wire := endpointHealthSendThroughManagedAdapter(t, record, encoded)
			if wire.eventName != "endpoint.health_reported" || wire.bucket != "platform.health" {
				t.Fatalf("OTLP identity attributes = %q/%q", wire.eventName, wire.bucket)
			}
			if wire.canonical["event_name"] != "endpoint.health_reported" ||
				wire.canonical["action"] != string(config.ObservabilityV8ManagedEndpointHealthAction) ||
				wire.canonical["bucket"] != "platform.health" {
				t.Fatalf("canonical identity = %v/%v/%v", wire.canonical["event_name"], wire.canonical["action"], wire.canonical["bucket"])
			}
			if _, legacy := wire.canonical["event_type"]; legacy {
				t.Fatal("endpoint health report was wrapped as a legacy gateway event")
			}
			body, _ := wire.canonical["body"].(map[string]any)
			if !reflect.DeepEqual(body, original) {
				got, _ := json.Marshal(body)
				want, _ := json.Marshal(original)
				t.Fatalf("managed body changed under the sensitive profile\n got: %s\nwant: %s", got, want)
			}
			if body["defenseclaw.health.report_id"] != endpointHealthReportID ||
				body["defenseclaw.health.version.avc"] != "5.1.21.4204" {
				t.Fatalf("report id / avc version changed: %v / %v",
					body["defenseclaw.health.report_id"], body["defenseclaw.health.version.avc"])
			}
			failing, _ := body["defenseclaw.health.hooks.failing_targets"].([]any)
			if len(failing) != 1 || failing[0].(map[string]any)["user.id"] != "S-1-5-21-1004336348-1177238915-682003330-1001" {
				t.Fatalf("failing target user.id changed: %v", failing)
			}
			reasons, _ := body["defenseclaw.health.reasons"].([]any)
			if len(reasons) != 2 || reasons[0].(map[string]any)["code"] != "HOOKS_PARTIAL" {
				t.Fatalf("reason codes changed: %v", reasons)
			}
		})
	}
}

func TestManagedCompatibilityEndpointHealthIsV8Passthrough(t *testing.T) {
	payload := managedGoldenPayload(t, "health-record", "platform.health", "endpoint.health_reported",
		string(config.ObservabilityV8ManagedEndpointHealthAction), map[string]any{
			"defenseclaw.health.report_id": endpointHealthReportID,
		})
	if managedCompatibilityCandidate(payload.Identity()) {
		t.Fatal("endpoint health report is a compatibility projection candidate")
	}
	if _, useProjection, valid := projectManagedCompatibility(
		payload, "sha256:managed-device", "managed-host", strings.Repeat("a", 64),
	); !valid || useProjection {
		t.Fatalf("endpoint health compat valid/use=%t/%t, want v8 passthrough", valid, useProjection)
	}
}

func endpointHealthCanonicalBody(t *testing.T, record observability.Record) map[string]any {
	t.Helper()
	encoded, err := record.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatal(err)
	}
	body, ok := wire["body"].(map[string]any)
	if !ok || len(body) != 38 {
		t.Fatalf("canonical endpoint health body has %d keys: %s", len(body), encoded)
	}
	return body
}

type endpointHealthWire struct {
	raw       []byte
	eventName string
	bucket    string
	canonical map[string]any
}

func endpointHealthSendThroughManagedAdapter(t *testing.T, record observability.Record, projected []byte) endpointHealthWire {
	t.Helper()
	var (
		mu       sync.Mutex
		captured []byte
	)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		mu.Lock()
		captured = body
		mu.Unlock()
		writer.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	source := testConfig(server.URL + config.ObservabilityV8ManagedAIDIngestPath)
	source.Network.AllowPrivateNetworks = true
	adapter, err := New(t.Context(), source, &testResolver{provider: &testProvider{token: "health-token"}})
	if err != nil {
		t.Fatal(err)
	}
	adapter.client = server.Client()
	dispatcher := testDispatcher(t, adapter)
	identity := record.Identity()
	payload, err := delivery.NewPayload(projected, delivery.RoutingIdentity{
		RecordID: record.RecordID(), Bucket: string(identity.Bucket),
		Signal: string(identity.Signal), EventName: string(identity.Name),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result := dispatcher.Enqueue(payload); !result.Accepted() {
		t.Fatalf("enqueue = %+v", result)
	}
	flushAndClose(t, dispatcher)
	if counters := dispatcher.Counters(); counters.Delivered != 1 {
		t.Fatalf("managed delivery counters = %+v", counters)
	}
	mu.Lock()
	body := append([]byte(nil), captured...)
	mu.Unlock()
	var envelope struct {
		Payload struct {
			ResourceLogs []struct {
				ScopeLogs []struct {
					LogRecords []struct {
						Body       map[string]any `json:"body"`
						Attributes []struct {
							Key   string         `json:"key"`
							Value map[string]any `json:"value"`
						} `json:"attributes"`
					} `json:"logRecords"`
				} `json:"scopeLogs"`
			} `json:"resourceLogs"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("decode managed request: %v: %s", err, body)
	}
	if len(envelope.Payload.ResourceLogs) != 1 || len(envelope.Payload.ResourceLogs[0].ScopeLogs) != 1 ||
		len(envelope.Payload.ResourceLogs[0].ScopeLogs[0].LogRecords) != 1 {
		t.Fatalf("managed request shape: %s", body)
	}
	logRecord := envelope.Payload.ResourceLogs[0].ScopeLogs[0].LogRecords[0]
	attributes := managedGoldenAttributeValues(logRecord.Attributes)
	text, _ := logRecord.Body["stringValue"].(string)
	var canonical map[string]any
	if err := json.Unmarshal([]byte(text), &canonical); err != nil {
		t.Fatalf("managed log body is not canonical JSON: %v: %q", err, text)
	}
	eventName, _ := attributes["defenseclaw.event.name"].(string)
	bucket, _ := attributes["defenseclaw.bucket"].(string)
	return endpointHealthWire{raw: body, eventName: eventName, bucket: bucket, canonical: canonical}
}

// TestEndpointHealthManagedRequestGolden pins the exact ingest request body a
// managed endpoint sends for one health report. The cloud ingest service
// tests its parser against a copy of this file, so a change here is a wire
// contract change. Values that differ per run (record and occurrence ids,
// timestamps, host identity) are replaced with fixed markers.
// Regenerate with DEFENSECLAW_UPDATE_GOLDEN=1 and review the diff.
func TestEndpointHealthManagedRequestGolden(t *testing.T) {
	base, err := config.CompileObservabilityV8(&config.ObservabilityV8Source{})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := config.WithObservabilityV8ManagedAIDDestination(base, config.ObservabilityV8ManagedAIDOptions{
		DeploymentMode: "managed_enterprise", Endpoint: "https://aid.example.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err := router.New(plan)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerGatewayEvent,
		observability.ProducerKey("endpoint_health"),
		observability.ClassificationContext{
			Bucket: observability.BucketPlatformHealth, EventName: "endpoint.health_reported", RawSeverity: "MEDIUM",
		},
		observability.SourceGateway, "", config.ObservabilityV8ManagedEndpointHealthAction,
	)
	if err != nil {
		t.Fatal(err)
	}
	builder, err := observability.NewFamilyBuilder(
		observability.ClockFunc(func() time.Time { return time.Date(2026, 7, 11, 0, 0, 1, 0, time.UTC) }),
		observability.TimeOrderedOccurrenceIDs,
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := evaluator.Evaluate(metadata, func(router.Admission) (observability.Record, error) {
		return builder.BuildLogEndpointHealthReported(endpointHealthReportInput())
	})
	if err != nil {
		t.Fatal(err)
	}
	record, ok := result.Record()
	if !ok {
		t.Fatal("no record built")
	}
	profile, _ := redaction.BuiltInProfile(redaction.ProfileSensitive)
	engine, err := redaction.NewEngine(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	projection, _, err := engine.Project(record, profile)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := projection.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	wire := endpointHealthSendThroughManagedAdapter(t, record, encoded)
	got := endpointHealthNormalizeRequest(t, wire.raw)

	golden := filepath.Join("testdata", "endpoint_health_ingest_request.golden.json")
	if os.Getenv("DEFENSECLAW_UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (regenerate with DEFENSECLAW_UPDATE_GOLDEN=1): %v", err)
	}
	// A Windows checkout may convert the golden to CRLF.
	want = bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))
	if !bytes.Equal(want, got) {
		gotLines, wantLines := strings.Split(string(got), "\n"), strings.Split(string(want), "\n")
		for index := 0; index < len(gotLines) || index < len(wantLines); index++ {
			var gotLine, wantLine string
			if index < len(gotLines) {
				gotLine = gotLines[index]
			}
			if index < len(wantLines) {
				wantLine = wantLines[index]
			}
			if gotLine != wantLine {
				t.Fatalf("managed endpoint health request changed at line %d:\n got: %q\nwant: %q\n(regenerate with DEFENSECLAW_UPDATE_GOLDEN=1 and review)",
					index+1, gotLine, wantLine)
			}
		}
	}
}

// endpointHealthVolatileKeys are request values that differ per run.
var endpointHealthVolatileKeys = map[string]bool{
	"timeUnixNano": true, "observedTimeUnixNano": true,
	"defenseclaw.record.id": true, "defenseclaw.occurrence.id": true, "record_id": true, "occurrence_id": true,
	"timestamp": true, "observed_at": true, "emitted_at": true,
	"host.name": true, "host.arch": true, "os.type": true, "os.version": true,
	"service.version": true, "service.instance.id": true, "defenseclaw.device.id": true,
	"defenseclaw.instance.id": true, "binary_version": true, "run_id": true, "sidecar_instance_id": true,
}

// endpointHealthNormalizeRequest replaces volatile values, including inside
// the canonical JSON string body, and indents the result.
func endpointHealthNormalizeRequest(t *testing.T, raw []byte) []byte {
	t.Helper()
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	var walk func(any) any
	walk = func(node any) any {
		switch typed := node.(type) {
		case map[string]any:
			// An OTLP attribute {key, value}: normalize by its key.
			if key, ok := typed["key"].(string); ok && endpointHealthVolatileKeys[key] {
				typed["value"] = map[string]any{"stringValue": "<volatile>"}
				return typed
			}
			for key, child := range typed {
				if endpointHealthVolatileKeys[key] {
					typed[key] = "<volatile>"
					continue
				}
				if key == "stringValue" {
					if text, ok := child.(string); ok && strings.HasPrefix(text, "{") {
						var inner any
						if json.Unmarshal([]byte(text), &inner) == nil {
							// Keep the wire shape: the body stays a JSON string.
							var compact bytes.Buffer
							encoder := json.NewEncoder(&compact)
							encoder.SetEscapeHTML(false)
							if err := encoder.Encode(walk(inner)); err != nil {
								t.Fatal(err)
							}
							typed[key] = strings.TrimSuffix(compact.String(), "\n")
							continue
						}
					}
				}
				typed[key] = walk(child)
			}
			return typed
		case []any:
			for index := range typed {
				typed[index] = walk(typed[index])
			}
			return typed
		default:
			return node
		}
	}
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(walk(value)); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}
