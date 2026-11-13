// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package observability

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"
)

const endpointHealthTestTimestamp = "2026-07-11T00:00:00.123456789+05:30"

func endpointHealthTestBuilder(t *testing.T) *FamilyBuilder {
	t.Helper()
	builder, err := NewFamilyBuilder(
		ClockFunc(func() time.Time { return time.Date(2026, 7, 11, 0, 0, 0, 0, time.UTC) }),
		TimeOrderedOccurrenceIDs,
	)
	if err != nil {
		t.Fatal(err)
	}
	return builder
}

func endpointHealthTestEnvelope() FamilyEnvelopeInput {
	return FamilyEnvelopeInput{
		Source: SourceGateway, Action: "endpoint_health", Phase: "report",
		Provenance: FamilyProvenanceInput{Producer: "endpoint-health-test", BinaryVersion: "1.0.9"},
	}
}

// endpointHealthMaximalInput fills every field and every list to its cap with
// values at their byte limits, so the encoded body is the largest the
// registry admits.
func endpointHealthMaximalInput() LogEndpointHealthReportedInput {
	pad := func(prefix string, length int) string {
		return prefix + strings.Repeat("A", length-len(prefix))
	}
	lower := func(prefix string, length int) string {
		return prefix + strings.Repeat("a", length-len(prefix))
	}
	timestamp := endpointHealthTestTimestamp
	reasons := make([]TelemetryStructuredDefenseClawHealthReason, 32)
	for index := range reasons {
		reasons[index] = TelemetryStructuredDefenseClawHealthReason{
			Code: pad("R"+strconv.Itoa(index), 64), Component: lower("c", 64), Severity: "unhealthy",
			Connector: Present(lower("x", 64)),
		}
	}
	subsystems := make([]TelemetryStructuredDefenseClawHealthSubsystemItem, 16)
	for index := range subsystems {
		subsystems[index] = TelemetryStructuredDefenseClawHealthSubsystemItem{
			Name: lower("s", 64), State: lower("r", 32), Since: Present(timestamp),
			ErrorClass: Present(pad("E", 64)),
		}
	}
	connectors := make([]TelemetryStructuredDefenseClawHealthHookConnector, 16)
	for index := range connectors {
		connectors[index] = TelemetryStructuredDefenseClawHealthHookConnector{
			Connector: lower("c", 64), Targets: 1_000_000, Ok: 1_000_000, Failed: 1_000_000, Pending: 1_000_000,
			LastActivityAt: Present(timestamp), ToolInspectionMode: Present(lower("e", 32)),
		}
	}
	failing := make([]TelemetryStructuredDefenseClawHealthFailingTarget, 16)
	for index := range failing {
		failing[index] = TelemetryStructuredDefenseClawHealthFailingTarget{
			Connector: lower("c", 64), UserID: Present(pad("S-1-5-21-", 192)), UserIDKind: Present("windows_sid"),
			ErrorClass: pad("E", 64), Pending: false,
		}
	}
	maxInt := int64(9_223_372_036_854_775_807)
	return LogEndpointHealthReportedInput{
		Envelope: endpointHealthTestEnvelope(),
		Severity: Present(SeverityHigh), LogLevel: Present(LogLevelError), Outcome: OutcomeCompleted,
		DefenseClawHealthReportID:                         "0f8fad5b-d9cb-469f-a165-70867728950e",
		DefenseClawHealthSequence:                         maxInt,
		DefenseClawHealthTrigger:                          "config_reload",
		DefenseClawHealthObservedAt:                       timestamp,
		DefenseClawHealthReportIntervalS:                  86_400,
		DefenseClawHealthStatus:                           "unhealthy",
		DefenseClawHealthReasons:                          Present(TelemetryStructuredDefenseClawHealthReasons{Items: reasons}),
		DefenseClawHealthReasonsTruncated:                 Present(true),
		DefenseClawHealthVersionProduct:                   Present(pad("1", 64)),
		DefenseClawHealthVersionPolicyBundle:              Present(pad("1", 64)),
		DefenseClawHealthVersionAvc:                       Present(pad("5", 64)),
		DefenseClawHealthOsVersion:                        Present(pad("1", 64)),
		DefenseClawHealthGatewayStartedAt:                 Present(timestamp),
		DefenseClawHealthGatewayUptimeS:                   Present(maxInt),
		DefenseClawHealthGatewayConfiguration:             Present(lower("w", 32)),
		DefenseClawHealthSubsystems:                       Present(TelemetryStructuredDefenseClawHealthSubsystems{Items: subsystems}),
		DefenseClawHealthSubsystemsTruncated:              Present(true),
		DefenseClawHealthHooksConnectorsTruncated:         Present(true),
		DefenseClawHealthGuardianState:                    Present("absent"),
		DefenseClawHealthGuardianLastPassAt:               Present(timestamp),
		DefenseClawHealthHooksTargets:                     Present(maxInt),
		DefenseClawHealthHooksOk:                          Present(maxInt),
		DefenseClawHealthHooksFailed:                      Present(maxInt),
		DefenseClawHealthHooksPending:                     Present(maxInt),
		DefenseClawHealthHooksConnectors:                  Present(TelemetryStructuredDefenseClawHealthHookConnectors{Items: connectors}),
		DefenseClawHealthHooksFailingTargets:              Present(TelemetryStructuredDefenseClawHealthFailingTargets{Items: failing}),
		DefenseClawHealthHooksFailingTargetsTruncated:     Present(true),
		DefenseClawHealthInspectionAIDefense:              Present("unavailable"),
		DefenseClawHealthInspectionUnavailableCode:        Present(pad("a", 64)),
		DefenseClawHealthInspectionCmidToken:              Present("unavailable"),
		DefenseClawHealthInspectionCmidLastSuccessAt:      Present(timestamp),
		DefenseClawHealthInspectionFailOpenSinceLast:      Present(maxInt),
		DefenseClawHealthCloudDeliveryState:               Present(lower("f", 32)),
		DefenseClawHealthCloudDeliveryCircuit:             Present(lower("h", 32)),
		DefenseClawHealthCloudDeliveryConsecutiveFailures: Present(maxInt),
		DefenseClawHealthCloudDeliveryLastSuccessAt:       Present(timestamp),
		DefenseClawHealthCloudDeliveryLastFailureClass:    Present(lower("p", 64)),
		DefenseClawHealthCloudDeliveryDroppedSinceLast:    Present(maxInt),
		DefenseClawHealthLocalStoreAuditStore:             Present(lower("u", 32)),
	}
}

func TestEndpointHealthReportMaximalBodyFitsTheWireBudget(t *testing.T) {
	record, err := endpointHealthTestBuilder(t).BuildLogEndpointHealthReported(endpointHealthMaximalInput())
	if err != nil {
		t.Fatalf("maximal endpoint health report rejected: %v", err)
	}
	if record.Identity() != (EventIdentity{Bucket: BucketPlatformHealth, Signal: SignalLogs, Name: "endpoint.health_reported"}) ||
		record.Action() != "endpoint_health" || record.Outcome() != OutcomeCompleted {
		t.Fatalf("endpoint health identity = %+v action=%q outcome=%q", record.Identity(), record.Action(), record.Outcome())
	}
	body, present := record.Body()
	if !present {
		t.Fatal("endpoint health report has no body")
	}
	object, err := body.Object()
	if err != nil {
		t.Fatal(err)
	}
	if len(object) != 39 {
		t.Fatalf("endpoint health body has %d keys, want 39", len(object))
	}
	for key := range object {
		if !strings.HasPrefix(key, "defenseclaw.health.") {
			t.Errorf("endpoint health body key %q is outside defenseclaw.health.*", key)
		}
	}
	for pointer, class := range record.FieldClasses() {
		if class != FieldClassMetadata && class != FieldClassIdentifier {
			t.Errorf("endpoint health field %s has class %s; only metadata and identifier survive every profile", pointer, class)
		}
	}
	encoded, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("maximal endpoint health body: %d bytes", len(encoded))
	if len(encoded) > 32*1024 {
		t.Fatalf("maximal endpoint health body is %d bytes, over the 32 KiB budget", len(encoded))
	}
}

func TestEndpointHealthReportRejectsUnknownBodyKeys(t *testing.T) {
	input := endpointHealthMaximalInput()
	_, err := endpointHealthTestBuilder(t).buildGeneratedResolvedLog(
		generatedLogEndpointHealthReportedDescriptor{}, resolveGeneratedLogMandatory(false),
		familyLogBuildInput{
			envelope: input.Envelope, severity: input.Severity, logLevel: input.LogLevel,
			outcome: Present(OutcomeCompleted),
			values: familyFieldValues{
				{key: "defenseclaw.health.report_id", value: input.DefenseClawHealthReportID, present: true},
				{key: "defenseclaw.health.sequence", value: int64(1), present: true},
				{key: "defenseclaw.health.trigger", value: "scheduled", present: true},
				{key: "defenseclaw.health.observed_at", value: endpointHealthTestTimestamp, present: true},
				{key: "defenseclaw.health.report_interval_s", value: int64(1800), present: true},
				{key: "defenseclaw.health.status", value: "healthy", present: true},
				{key: "defenseclaw.health.config_path", value: "/etc/defenseclaw/config.yaml", present: true},
			},
		},
	)
	if !IsFamilyBuildError(err, FamilyBuildUnknownField) {
		t.Fatalf("unknown endpoint health body key error = %v", err)
	}
}

func TestEndpointHealthReportRequiresItsIdentityFields(t *testing.T) {
	builder := endpointHealthTestBuilder(t)
	minimal := LogEndpointHealthReportedInput{
		Envelope: endpointHealthTestEnvelope(), Outcome: OutcomeCompleted,
		DefenseClawHealthReportID: "0f8fad5b-d9cb-469f-a165-70867728950e", DefenseClawHealthSequence: 0,
		DefenseClawHealthTrigger: "startup", DefenseClawHealthObservedAt: "2026-07-11T00:00:00Z",
		DefenseClawHealthReportIntervalS: 1800, DefenseClawHealthStatus: "starting",
	}
	if _, err := builder.BuildLogEndpointHealthReported(minimal); err != nil {
		t.Fatalf("minimal endpoint health report rejected: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*LogEndpointHealthReportedInput)
	}{
		{"empty report id", func(input *LogEndpointHealthReportedInput) { input.DefenseClawHealthReportID = "" }},
		{"non-uuid report id", func(input *LogEndpointHealthReportedInput) { input.DefenseClawHealthReportID = "report-1" }},
		{"negative sequence", func(input *LogEndpointHealthReportedInput) { input.DefenseClawHealthSequence = -1 }},
		{"unknown trigger", func(input *LogEndpointHealthReportedInput) { input.DefenseClawHealthTrigger = "manual" }},
		{"non-RFC3339 observed_at", func(input *LogEndpointHealthReportedInput) { input.DefenseClawHealthObservedAt = "yesterday" }},
		{"interval below one minute", func(input *LogEndpointHealthReportedInput) { input.DefenseClawHealthReportIntervalS = 59 }},
		{"interval above one day", func(input *LogEndpointHealthReportedInput) { input.DefenseClawHealthReportIntervalS = 86_401 }},
		{"unknown status", func(input *LogEndpointHealthReportedInput) { input.DefenseClawHealthStatus = "ok" }},
		{"missing outcome", func(input *LogEndpointHealthReportedInput) { input.Outcome = "" }},
		{"failed outcome", func(input *LogEndpointHealthReportedInput) { input.Outcome = OutcomeFailed }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := minimal
			test.mutate(&input)
			if _, err := builder.BuildLogEndpointHealthReported(input); err == nil {
				t.Fatal("invalid endpoint health report was accepted")
			}
		})
	}

	_, err := builder.buildGeneratedResolvedLog(
		generatedLogEndpointHealthReportedDescriptor{}, resolveGeneratedLogMandatory(false),
		familyLogBuildInput{
			envelope: minimal.Envelope, outcome: Present(OutcomeCompleted),
			values: familyFieldValues{
				{key: "defenseclaw.health.sequence", value: int64(1), present: true},
				{key: "defenseclaw.health.trigger", value: "scheduled", present: true},
				{key: "defenseclaw.health.observed_at", value: endpointHealthTestTimestamp, present: true},
				{key: "defenseclaw.health.report_interval_s", value: int64(1800), present: true},
				{key: "defenseclaw.health.status", value: "healthy", present: true},
			},
		},
	)
	if !IsFamilyBuildError(err, FamilyBuildMissingRequired) {
		t.Fatalf("missing report_id error = %v", err)
	}
}

func TestEndpointHealthReportListsEnforceTheirCaps(t *testing.T) {
	builder := endpointHealthTestBuilder(t)
	tests := []struct {
		name   string
		mutate func(*LogEndpointHealthReportedInput)
	}{
		{"33 reasons", func(input *LogEndpointHealthReportedInput) {
			reasons, _ := input.DefenseClawHealthReasons.Get()
			reasons.Items = append(reasons.Items, reasons.Items[0])
			input.DefenseClawHealthReasons = Present(reasons)
		}},
		{"17 subsystems", func(input *LogEndpointHealthReportedInput) {
			subsystems, _ := input.DefenseClawHealthSubsystems.Get()
			subsystems.Items = append(subsystems.Items, subsystems.Items[0])
			input.DefenseClawHealthSubsystems = Present(subsystems)
		}},
		{"17 hook connectors", func(input *LogEndpointHealthReportedInput) {
			connectors, _ := input.DefenseClawHealthHooksConnectors.Get()
			connectors.Items = append(connectors.Items, connectors.Items[0])
			input.DefenseClawHealthHooksConnectors = Present(connectors)
		}},
		{"17 failing targets", func(input *LogEndpointHealthReportedInput) {
			failing, _ := input.DefenseClawHealthHooksFailingTargets.Get()
			failing.Items = append(failing.Items, failing.Items[0])
			input.DefenseClawHealthHooksFailingTargets = Present(failing)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := endpointHealthMaximalInput()
			test.mutate(&input)
			if _, err := builder.BuildLogEndpointHealthReported(input); !IsFamilyBuildError(err, FamilyBuildConstraint) {
				t.Fatalf("over-cap endpoint health list error = %v", err)
			}
		})
	}
}

// Every free string in the report is a bounded token, a version or a
// timestamp; none of them can carry a path, a URL or free-form error text.
func TestEndpointHealthReportRejectsPathLikeAndFreeFormStrings(t *testing.T) {
	builder := endpointHealthTestBuilder(t)
	values := []string{"/etc/passwd", `C:\Users\alice`, `a\b`, "a/b", "user@example.com", "permission denied", ""}
	scalar := map[string]func(*LogEndpointHealthReportedInput, string){
		"version.product": func(input *LogEndpointHealthReportedInput, v string) {
			input.DefenseClawHealthVersionProduct = Present(v)
		},
		"version.policy_bundle": func(input *LogEndpointHealthReportedInput, v string) {
			input.DefenseClawHealthVersionPolicyBundle = Present(v)
		},
		"version.avc": func(input *LogEndpointHealthReportedInput, v string) { input.DefenseClawHealthVersionAvc = Present(v) },
		"os.version":  func(input *LogEndpointHealthReportedInput, v string) { input.DefenseClawHealthOsVersion = Present(v) },
		"gateway.started_at": func(input *LogEndpointHealthReportedInput, v string) {
			input.DefenseClawHealthGatewayStartedAt = Present(v)
		},
		"gateway.configuration": func(input *LogEndpointHealthReportedInput, v string) {
			input.DefenseClawHealthGatewayConfiguration = Present(v)
		},
		"guardian.last_pass_at": func(input *LogEndpointHealthReportedInput, v string) {
			input.DefenseClawHealthGuardianLastPassAt = Present(v)
		},
		"inspection.unavailable_code": func(input *LogEndpointHealthReportedInput, v string) {
			input.DefenseClawHealthInspectionUnavailableCode = Present(v)
		},
		"cloud_delivery.state": func(input *LogEndpointHealthReportedInput, v string) {
			input.DefenseClawHealthCloudDeliveryState = Present(v)
		},
		"cloud_delivery.last_failure_class": func(input *LogEndpointHealthReportedInput, v string) {
			input.DefenseClawHealthCloudDeliveryLastFailureClass = Present(v)
		},
		"local_store.audit_store": func(input *LogEndpointHealthReportedInput, v string) {
			input.DefenseClawHealthLocalStoreAuditStore = Present(v)
		},
		"reasons.code": func(input *LogEndpointHealthReportedInput, v string) {
			input.DefenseClawHealthReasons = Present(TelemetryStructuredDefenseClawHealthReasons{Items: []TelemetryStructuredDefenseClawHealthReason{{
				Code: v, Component: "hooks", Severity: "degraded",
			}}})
		},
		"reasons.connector": func(input *LogEndpointHealthReportedInput, v string) {
			input.DefenseClawHealthReasons = Present(TelemetryStructuredDefenseClawHealthReasons{Items: []TelemetryStructuredDefenseClawHealthReason{{
				Code: "HOOKS_PARTIAL", Component: "hooks", Severity: "degraded", Connector: Present(v),
			}}})
		},
		"subsystems.error_class": func(input *LogEndpointHealthReportedInput, v string) {
			input.DefenseClawHealthSubsystems = Present(TelemetryStructuredDefenseClawHealthSubsystems{Items: []TelemetryStructuredDefenseClawHealthSubsystemItem{{
				Name: "guardrail", State: "error", ErrorClass: Present(v),
			}}})
		},
		"hooks.connectors.tool_inspection_mode": func(input *LogEndpointHealthReportedInput, v string) {
			input.DefenseClawHealthHooksConnectors = Present(TelemetryStructuredDefenseClawHealthHookConnectors{Items: []TelemetryStructuredDefenseClawHealthHookConnector{{
				Connector: "codex", ToolInspectionMode: Present(v),
			}}})
		},
		"hooks.failing_targets.user.id": func(input *LogEndpointHealthReportedInput, v string) {
			input.DefenseClawHealthHooksFailingTargets = Present(TelemetryStructuredDefenseClawHealthFailingTargets{Items: []TelemetryStructuredDefenseClawHealthFailingTarget{{
				Connector: "codex", UserID: Present(v), ErrorClass: "CONFIG_WRITE_DENIED",
			}}})
		},
		"hooks.failing_targets.error_class": func(input *LogEndpointHealthReportedInput, v string) {
			input.DefenseClawHealthHooksFailingTargets = Present(TelemetryStructuredDefenseClawHealthFailingTargets{Items: []TelemetryStructuredDefenseClawHealthFailingTarget{{
				Connector: "codex", ErrorClass: v,
			}}})
		},
	}
	for name, set := range scalar {
		for _, value := range values {
			input := endpointHealthMaximalInput()
			set(&input, value)
			if _, err := builder.BuildLogEndpointHealthReported(input); err == nil {
				t.Errorf("%s accepted %q", name, value)
			}
		}
	}
	input := endpointHealthMaximalInput()
	input.DefenseClawHealthHooksFailingTargets = Present(TelemetryStructuredDefenseClawHealthFailingTargets{Items: []TelemetryStructuredDefenseClawHealthFailingTarget{{
		Connector: "codex", UserID: Present("S-1-5-21-1-2-3-1001"), UserIDKind: Present("email"), ErrorClass: "CONFIG_WRITE_DENIED",
	}}})
	if _, err := builder.BuildLogEndpointHealthReported(input); err == nil {
		t.Error("failing target accepted an unregistered user.id_kind")
	}
}
