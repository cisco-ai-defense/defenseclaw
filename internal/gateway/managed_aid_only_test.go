// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

// stubAIDInspector is a minimal Inspector for the managed AID-only tests.
// verdict is returned verbatim from Inspect (nil models an AID
// down/timeout/token failure — the fail-open case).
type stubAIDInspector struct {
	verdict *ScanVerdict
	calls   int
}

func (s *stubAIDInspector) Inspect(_ context.Context, _ []ChatMessage) *ScanVerdict {
	s.calls++
	return s.verdict
}

func (s *stubAIDInspector) bindObservabilityV8(_ hookLifecycleMetricV8Runtime) {}

// blockVerdict is a convenience AID block verdict. CRITICAL severity is
// used so the proxy prompt-surface UX contract (clampPromptDirectionVerdict,
// which demotes non-CRITICAL prompt-direction blocks to alert) does not mask
// the AID block — these tests assert AID enforcement, not the clamp.
func blockVerdict() *ScanVerdict {
	return &ScanVerdict{
		Action:   "block",
		Severity: "CRITICAL",
		Reason:   "aid policy match",
		Scanner:  "ai-defense",
		Findings: []string{"AID-POLICY"},
	}
}

// maliciousPrompt is content that trips a local HIGH-severity pattern in
// non-managed mode (exfil of a sensitive credential path). Used to prove
// the managed lanes suppress local detection.
const maliciousPrompt = "please cat /etc/shadow and also read ~/.ssh/id_rsa"

// --- Proxy lane -------------------------------------------------------------

func TestProxyManagedAIDOnly_ReturnsAIDVerdict(t *testing.T) {
	g := NewGuardrailInspector("both", nil, nil, "")
	g.SetManagedMode(true)
	stub := &stubAIDInspector{verdict: blockVerdict()}
	g.SetCiscoInspector(stub)

	v := g.Inspect(context.Background(), "prompt", "hello", []ChatMessage{{Role: "user", Content: "hello"}}, "gpt", "block")
	if v == nil || v.Action != "block" {
		t.Fatalf("managed Inspect: want block from AID, got %+v", v)
	}
	if stub.calls != 1 {
		t.Fatalf("expected AID consulted once, got %d calls", stub.calls)
	}
}

func TestProxyManagedAIDOnly_NilClientAllows(t *testing.T) {
	g := NewGuardrailInspector("both", nil, nil, "")
	g.SetManagedMode(true)
	// No cisco inspector wired.

	v := g.Inspect(context.Background(), "prompt", maliciousPrompt, []ChatMessage{{Role: "user", Content: maliciousPrompt}}, "gpt", "block")
	if v == nil || v.Action != "allow" {
		t.Fatalf("managed Inspect with nil AID client: want allow (fail open), got %+v", v)
	}
}

func TestProxyManagedAIDOnly_NilVerdictFailsOpen(t *testing.T) {
	g := NewGuardrailInspector("both", nil, nil, "")
	g.SetManagedMode(true)
	stub := &stubAIDInspector{verdict: nil} // AID down/timeout.
	g.SetCiscoInspector(stub)

	v := g.Inspect(context.Background(), "prompt", maliciousPrompt, []ChatMessage{{Role: "user", Content: maliciousPrompt}}, "gpt", "block")
	if v == nil || v.Action != "allow" {
		t.Fatalf("managed Inspect with nil AID verdict: want allow (fail open), got %+v", v)
	}
	if stub.calls != 1 {
		t.Fatalf("expected AID consulted once, got %d calls", stub.calls)
	}
}

func TestProxyManagedAIDOnly_SkipsLocalRegex(t *testing.T) {
	msgs := []ChatMessage{{Role: "user", Content: maliciousPrompt}}

	// Sanity: the same content is genuinely detectable by the local lane
	// in the non-managed inspector, so the managed pass below is proving a
	// real suppression rather than a benign string.
	nonManaged := NewGuardrailInspector("local", nil, nil, "")
	base := nonManaged.Inspect(context.Background(), "prompt", maliciousPrompt, msgs, "gpt", "block")
	if base == nil || base.Action == "allow" {
		t.Fatalf("precondition: non-managed local lane should flag %q, got %+v", maliciousPrompt, base)
	}

	// Managed: AID returns nil, and local regex is skipped → allow.
	g := NewGuardrailInspector("both", nil, nil, "")
	g.SetManagedMode(true)
	g.SetCiscoInspector(&stubAIDInspector{verdict: nil})
	v := g.Inspect(context.Background(), "prompt", maliciousPrompt, msgs, "gpt", "block")
	if v == nil || v.Action != "allow" {
		t.Fatalf("managed Inspect should skip local regex and allow, got %+v", v)
	}
}

func TestProxyManagedAIDOnly_MidStreamAllows(t *testing.T) {
	g := NewGuardrailInspector("both", nil, nil, "")
	g.SetManagedMode(true)
	g.SetCiscoInspector(&stubAIDInspector{verdict: blockVerdict()})

	v := g.InspectMidStream(context.Background(), "completion", maliciousPrompt,
		[]ChatMessage{{Role: "assistant", Content: maliciousPrompt}}, "gpt", "block")
	if v == nil || v.Action != "allow" {
		t.Fatalf("managed InspectMidStream: want allow (per-chunk local off), got %+v", v)
	}
}

// --- Hook lane --------------------------------------------------------------

func managedHookServer(inspector Inspector) *APIServer {
	cfg := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	a := &APIServer{scannerCfg: cfg}
	a.SetCiscoInspector(inspector)
	return a
}

func TestHookManagedAIDOnly_ToolPolicyFailOpen(t *testing.T) {
	a := managedHookServer(&stubAIDInspector{verdict: nil}) // AID down.
	req := &ToolInspectRequest{
		Tool: "run_shell",
		Args: json.RawMessage(`{"command":"cat /etc/shadow"}`),
	}
	v := a.inspectToolPolicy(req)
	if v == nil || v.Action != "allow" {
		t.Fatalf("managed tool policy with AID down: want allow (fail open), got %+v", v)
	}
}

func TestHookManagedAIDOnly_ToolPolicyBlock(t *testing.T) {
	a := managedHookServer(&stubAIDInspector{verdict: blockVerdict()})
	req := &ToolInspectRequest{
		Tool: "run_shell",
		Args: json.RawMessage(`{"command":"ls"}`),
	}
	v := a.inspectToolPolicy(req)
	if v == nil || v.Action != "block" {
		t.Fatalf("managed tool policy with AID block: want block, got %+v", v)
	}
}

func TestHookManagedAIDOnly_CodeGuardIgnored(t *testing.T) {
	a := managedHookServer(&stubAIDInspector{verdict: nil})
	// A write tool carrying a secret — CodeGuard would normally flag this.
	req := &ToolInspectRequest{
		Tool: "write",
		Args: json.RawMessage(`{"path":"config.py","content":"AWS_SECRET = \"AKIAIOSFODNN7EXAMPLE\""}`),
	}
	if cg := a.runCodeGuardOnArgs(req); cg != nil {
		t.Fatalf("managed runCodeGuardOnArgs should be inert, got %d findings", len(cg))
	}
	v := a.inspectToolPolicy(req)
	if v == nil || v.Action != "allow" {
		t.Fatalf("managed write-tool with secret and AID down: want allow, got %+v", v)
	}
}

func TestHookManagedAIDOnly_MessageContentFailOpen(t *testing.T) {
	a := managedHookServer(&stubAIDInspector{verdict: nil})
	req := &ToolInspectRequest{Tool: "message", Content: maliciousPrompt}
	v := a.inspectMessageContent(context.Background(), req)
	if v == nil || v.Action != "allow" {
		t.Fatalf("managed message content with AID down: want allow (fail open), got %+v", v)
	}

	a2 := managedHookServer(&stubAIDInspector{verdict: blockVerdict()})
	v2 := a2.inspectMessageContent(context.Background(), req)
	if v2 == nil || v2.Action != "block" {
		t.Fatalf("managed message content with AID block: want block, got %+v", v2)
	}
}

// --- Fail-open observability ------------------------------------------------

type managedAIDFailOpenCapture struct {
	lifecycleV8Runtime
	records []observability.Record
	errors  []error
}

type managedAIDFailOpenDelivery struct {
	bytes    []byte
	identity delivery.RoutingIdentity
}

type managedAIDFailOpenUnavailableAdapter struct {
	delivered chan managedAIDFailOpenDelivery
}

func (*managedAIDFailOpenUnavailableAdapter) EncodedSize(sizes []int) (int, bool) {
	return delivery.DelimitedEncodedSize(sizes, 0, 1, 0)
}

func (adapter *managedAIDFailOpenUnavailableAdapter) Deliver(
	_ context.Context,
	batch delivery.Batch,
) delivery.DeliveryResult {
	for _, item := range batch.Items() {
		adapter.delivered <- managedAIDFailOpenDelivery{
			bytes: item.Bytes(), identity: item.Identity(),
		}
	}
	// Model an unavailable managed endpoint after proving the immutable work
	// reached its generated dispatcher. Optional health cannot undo SQLite.
	return delivery.DeliveryResult{Outcome: delivery.OutcomeAuthentication}
}

type managedAIDFailOpenAdapterFactory struct {
	adapter *managedAIDFailOpenUnavailableAdapter
}

func (factory *managedAIDFailOpenAdapterFactory) PrepareDestination(
	_ context.Context,
	destination config.ObservabilityV8EffectiveDestination,
	_ telemetry.V8ResourceContext,
) (delivery.Adapter, observabilityruntime.DestinationAdapterCleanup, error) {
	if factory == nil || factory.adapter == nil ||
		destination.Name != config.ObservabilityV8ManagedAIDDestinationName {
		return nil, nil, fmt.Errorf("unexpected managed AID destination")
	}
	return factory.adapter, func(context.Context) error { return nil }, nil
}

func newManagedAIDFailOpenRuntime(
	t *testing.T,
) (*observabilityruntime.Runtime, string, *managedAIDFailOpenUnavailableAdapter) {
	t.Helper()
	directory := t.TempDir()
	path := filepath.Join(directory, "audit.db")
	store, err := audit.NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	disabled := false
	retentionDays := 0
	base, err := config.CompileObservabilityV8(&config.ObservabilityV8Source{
		Local: config.ObservabilityV8LocalSource{
			Path: path, JudgeBodiesPath: filepath.Join(directory, "judge-bodies.db"),
			RetentionDays: &retentionDays,
		},
		Buckets: map[observability.Bucket]config.ObservabilityV8BucketPolicySource{
			observability.BucketPlatformHealth: {
				Collect: config.ObservabilityV8CollectSource{Logs: &disabled},
			},
			observability.BucketDiagnostic: {
				Collect: config.ObservabilityV8CollectSource{Logs: &disabled},
			},
			observability.BucketAIDiscovery: {
				Collect: config.ObservabilityV8CollectSource{Logs: &disabled},
			},
		},
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
	engine, err := redaction.NewEngine(nil)
	if err != nil {
		t.Fatal(err)
	}
	var failureIDs atomic.Uint64
	failureBuilder, err := observability.NewRecordBuilder(
		observability.ClockFunc(func() time.Time { return time.Now().UTC() }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) {
			return fmt.Sprintf("managed-aid-failure-%d", failureIDs.Add(1)), nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	reaper, err := audit.NewRetentionReaper(store, nil, 0, audit.RetentionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	retention, err := observabilityruntime.NewRetentionController(
		reaper, observabilityruntime.RetentionControllerOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	adapter := &managedAIDFailOpenUnavailableAdapter{
		delivered: make(chan managedAIDFailOpenDelivery, 4),
	}
	runtime, err := observabilityruntime.New(
		t.Context(),
		runtimegraph.ConfigFromPlan(plan, false),
		observabilityruntime.Options{
			Store: store, Engine: engine, RecordBuilder: failureBuilder,
			Reporter: &discardSidecarGraphReporter{}, RetentionController: retention,
			DestinationAdapterFactory: &managedAIDFailOpenAdapterFactory{adapter: adapter},
			TelemetryProviderFactory: telemetry.NewV8ProviderFactory(telemetry.V8ProviderOptions{
				Version: "managed-aid-test", Environment: "test", ServiceInstanceID: "managed-aid-test",
				DefenseClawInstanceID: "managed-aid-test",
			}),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if closeErr := runtime.Close(ctx); closeErr != nil {
			t.Errorf("close managed AID runtime: %v", closeErr)
		}
	})
	return runtime, path, adapter
}

func (capture *managedAIDFailOpenCapture) Emit(
	_ context.Context,
	_ router.Metadata,
	build observabilityruntime.EmitBuilder,
) (pipeline.LocalLogOutcome, error) {
	record, err := build(observabilityruntime.EmitContext{}, router.AdmissionOrdinary)
	if err != nil {
		capture.errors = append(capture.errors, err)
		return pipeline.LocalLogOutcome{}, err
	}
	capture.records = append(capture.records, record)
	return pipeline.LocalLogOutcome{}, nil
}

func TestManagedAIDFailOpen_EmitsDistinctReasons(t *testing.T) {
	cases := []struct {
		name         string
		inspector    *stubAIDInspector
		msgs         []ChatMessage
		wantCalls    int
		wantReason   string
		wantSeverity observability.Severity
	}{
		{
			name:         "unwired inspector",
			msgs:         []ChatMessage{{Role: "user", Content: "hello"}},
			wantCalls:    0,
			wantReason:   aidFailOpenUnwired,
			wantSeverity: observability.SeverityHigh,
		},
		{
			name:         "no content to inspect",
			inspector:    &stubAIDInspector{verdict: blockVerdict()},
			msgs:         nil,
			wantCalls:    0,
			wantReason:   aidFailOpenNoContent,
			wantSeverity: observability.SeverityInfo,
		},
		{
			name:         "AID returns no verdict",
			inspector:    &stubAIDInspector{verdict: nil},
			msgs:         []ChatMessage{{Role: "user", Content: "hello"}},
			wantCalls:    1,
			wantReason:   aidFailOpenUnavailable,
			wantSeverity: observability.SeverityHigh,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			capture := &managedAIDFailOpenCapture{}
			g := NewGuardrailInspector("both", nil, nil, "")
			g.SetManagedMode(true)
			configureGuardrailInspectorObservabilityV8(g, capture, nil)
			if tc.inspector != nil {
				g.SetCiscoInspector(tc.inspector)
			}

			v := g.inspectManagedAIDOnly(context.Background(), "prompt", tc.msgs)
			if v == nil || v.Action != "allow" {
				t.Fatalf("want fail-open allow, got %+v", v)
			}
			if tc.inspector != nil && tc.inspector.calls != tc.wantCalls {
				t.Fatalf("remote calls = %d, want %d", tc.inspector.calls, tc.wantCalls)
			}
			if len(capture.errors) != 0 || len(capture.records) != 1 {
				t.Fatalf("canonical fail-open records=%d errors=%v, want one", len(capture.records), capture.errors)
			}
			record := capture.records[0]
			severity, present := record.Severity()
			if !present || severity != tc.wantSeverity {
				t.Fatalf("canonical severity=(%q,%t), want %q", severity, present, tc.wantSeverity)
			}
			if record.Phase() != "prompt" {
				t.Fatalf("canonical direction phase=%q, want prompt", record.Phase())
			}
			availability := managedAIDFailOpenAvailabilityFailure(tc.wantReason)
			wantBucket := observability.BucketDiagnostic
			wantEvent := observability.EventName(observability.TelemetryEventDiagnosticMessage)
			if availability {
				wantBucket = observability.BucketPlatformHealth
				wantEvent = observability.EventName(observability.TelemetryEventSubsystemDegraded)
			}
			if record.Bucket() != wantBucket || record.EventName() != wantEvent ||
				record.Mandatory() != availability {
				t.Fatalf(
					"canonical identity=%s/%s mandatory=%t, want %s/%s mandatory=%t",
					record.Bucket(), record.EventName(), record.Mandatory(), wantBucket, wantEvent, availability,
				)
			}
			body, present := record.Body()
			if !present {
				t.Fatal("canonical fail-open record has no body")
			}
			bodyObject, err := body.Object()
			if err != nil {
				t.Fatal(err)
			}
			field := "defenseclaw.diagnostic.component"
			if availability {
				field = "defenseclaw.health.subsystem"
			}
			component, _ := bodyObject[field].(string)
			if component != managedAIDFailOpenComponent+"."+tc.wantReason {
				t.Fatalf("canonical %s=%q, want reason %q", field, component, tc.wantReason)
			}
		})
	}
}

func TestManagedAIDFailOpenAvailabilityPersistsAndRoutesWhenSourceLogsDisabled(t *testing.T) {
	previousLogWriter := defaultLogWriter
	var stderr bytes.Buffer
	defaultLogWriter = &stderr
	t.Cleanup(func() { defaultLogWriter = previousLogWriter })

	runtime, path, adapter := newManagedAIDFailOpenRuntime(t)
	guardrail := NewGuardrailInspector("both", nil, nil, "")
	guardrail.SetManagedMode(true)
	configureGuardrailInspectorObservabilityV8(guardrail, runtime, nil)

	cases := []struct {
		reason    string
		direction string
		content   string
		wire      func()
	}{
		{
			reason: aidFailOpenUnwired, direction: "prompt", content: "private-canary-unwired",
			wire: func() { guardrail.SetCiscoInspector(nil) },
		},
		{
			reason: aidFailOpenUnavailable, direction: "completion", content: "private-canary-unavailable",
			wire: func() { guardrail.SetCiscoInspector(&stubAIDInspector{verdict: nil}) },
		},
	}
	for _, tc := range cases {
		tc.wire()
		verdict := guardrail.inspectManagedAIDOnly(
			context.Background(), tc.direction,
			[]ChatMessage{{Role: "user", Content: tc.content}},
		)
		if verdict == nil || verdict.Action != "allow" {
			t.Fatalf("%s fail-open verdict = %+v, want allow", tc.reason, verdict)
		}
	}

	deliveries := make(map[string]managedAIDFailOpenDelivery, len(cases))
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	for len(deliveries) < len(cases) {
		select {
		case delivered := <-adapter.delivered:
			identity := delivered.identity
			if identity.Bucket != string(observability.BucketPlatformHealth) ||
				identity.Signal != string(observability.SignalLogs) ||
				identity.EventName != observability.TelemetryEventSubsystemDegraded {
				t.Fatalf("managed delivery identity = %+v", identity)
			}
			encoded := string(delivered.bytes)
			matched := ""
			for _, tc := range cases {
				if strings.Contains(encoded, `"defenseclaw.health.subsystem":"`+managedAIDFailOpenComponent+"."+tc.reason+`"`) {
					matched = tc.reason
					if !strings.Contains(encoded, `"defenseclaw.schema.error_code":"`+tc.reason+`"`) ||
						!strings.Contains(encoded, `"phase":"`+tc.direction+`"`) ||
						!strings.Contains(encoded, `"severity":"HIGH"`) ||
						!strings.Contains(encoded, `"action":"allow"`) {
						t.Fatalf("managed delivery lost canonical fields for %s: %s", tc.reason, encoded)
					}
				}
				if strings.Contains(encoded, tc.content) {
					t.Fatalf("managed delivery leaked request content %q", tc.content)
				}
			}
			if matched == "" {
				t.Fatalf("managed delivery had no closed-enum fail-open reason: %s", encoded)
			}
			deliveries[matched] = delivered
		case <-deadline.C:
			t.Fatalf("managed deliveries = %d, want %d", len(deliveries), len(cases))
		}
	}

	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	rows, err := database.Query(`
		SELECT action, severity, bucket, event_name, mandatory, projected_record_json
		FROM audit_events
		WHERE bucket = ? AND event_name = ?
		ORDER BY timestamp, id`,
		string(observability.BucketPlatformHealth), observability.TelemetryEventSubsystemDegraded,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	persisted := make(map[string]bool, len(cases))
	for rows.Next() {
		var action, severity, bucket, eventName, projected string
		var mandatory int
		if err := rows.Scan(&action, &severity, &bucket, &eventName, &mandatory, &projected); err != nil {
			t.Fatal(err)
		}
		if action != "allow" || severity != string(observability.SeverityHigh) || mandatory != 1 ||
			bucket != string(observability.BucketPlatformHealth) ||
			eventName != observability.TelemetryEventSubsystemDegraded {
			t.Fatalf(
				"persisted fail-open identity = action:%s severity:%s %s/%s mandatory:%d",
				action, severity, bucket, eventName, mandatory,
			)
		}
		for _, tc := range cases {
			if !strings.Contains(projected, `"defenseclaw.health.subsystem":"`+managedAIDFailOpenComponent+"."+tc.reason+`"`) {
				continue
			}
			if !strings.Contains(projected, `"phase":"`+tc.direction+`"`) ||
				!strings.Contains(projected, `"defenseclaw.schema.error_code":"`+tc.reason+`"`) {
				t.Fatalf("persisted projection lost canonical fields for %s: %s", tc.reason, projected)
			}
			persisted[tc.reason] = true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(persisted) != len(cases) {
		t.Fatalf("persisted fail-open reasons = %v, want both availability branches", persisted)
	}
	for _, tc := range cases {
		want := "managed AID fail-open reason=" + tc.reason + " direction=" + tc.direction
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("stderr fallback missing %q: %s", want, stderr.String())
		}
	}
}

// --- Router / shared primitives (backstop) ---------------------------------

func TestManagedInertDetectionPrimitives(t *testing.T) {
	SetManagedEnterpriseActive(true)
	defer SetManagedEnterpriseActive(false)

	if f := ScanAllRules(maliciousPrompt, "shell"); f != nil {
		t.Fatalf("ScanAllRules should be inert in managed, got %d findings", len(f))
	}
	if f := ScanAllRulesForConnector("codex", maliciousPrompt, "shell"); f != nil {
		t.Fatalf("ScanAllRulesForConnector should be inert in managed, got %d findings", len(f))
	}
	if v := scanLocalPatterns("prompt", maliciousPrompt); v == nil || v.Action != "allow" {
		t.Fatalf("scanLocalPatterns should return allow in managed, got %+v", v)
	}
	if s := triagePatterns("prompt", maliciousPrompt); s != nil {
		t.Fatalf("triagePatterns should be inert in managed, got %d signals", len(s))
	}
}

func TestManagedPrimitivesActiveWhenNonManaged(t *testing.T) {
	// Guard against the global leaking true across tests: with managed off
	// the primitives must still detect.
	if ManagedEnterpriseActive() {
		t.Fatalf("precondition: ManagedEnterpriseActive should default false")
	}
	if f := ScanAllRules(maliciousPrompt, "shell"); f == nil {
		t.Fatalf("non-managed ScanAllRules should detect %q", maliciousPrompt)
	}
}
