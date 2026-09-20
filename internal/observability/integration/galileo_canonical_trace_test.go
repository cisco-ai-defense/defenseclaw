// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/compatibility/profilemanifest"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/galileo"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	collectortracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

type galileoTraceCapture struct {
	mu       sync.Mutex
	requests []*collectortracepb.ExportTraceServiceRequest
}

type galileoCanonicalFailureCapture struct {
	mu       sync.Mutex
	failures []galileo.CanonicalFailure
}

func (capture *galileoCanonicalFailureCapture) ObserveGalileoCanonicalFailure(
	failure galileo.CanonicalFailure,
) {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	capture.failures = append(capture.failures, failure)
}

func (capture *galileoCanonicalFailureCapture) snapshot() []galileo.CanonicalFailure {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return append([]galileo.CanonicalFailure(nil), capture.failures...)
}

func (capture *galileoTraceCapture) handle(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Path != "/v1/traces" {
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	body, _ := io.ReadAll(request.Body)
	decoded := &collectortracepb.ExportTraceServiceRequest{}
	if err := proto.Unmarshal(body, decoded); err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	capture.mu.Lock()
	capture.requests = append(capture.requests, proto.Clone(decoded).(*collectortracepb.ExportTraceServiceRequest))
	capture.mu.Unlock()
	writer.Header().Set("Content-Type", "application/x-protobuf")
	writer.WriteHeader(http.StatusOK)
}

func (capture *galileoTraceCapture) snapshot() []*collectortracepb.ExportTraceServiceRequest {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return append([]*collectortracepb.ExportTraceServiceRequest(nil), capture.requests...)
}

func TestRuntimeGalileoCapabilityDefaultDropsNonMemberAndAcknowledgesEligibleGraph(t *testing.T) {
	directory := t.TempDir()
	storePath := filepath.Join(directory, "audit.db")
	judgePath := filepath.Join(directory, "judge-bodies.db")
	store, err := audit.NewStore(storePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	capture := &galileoTraceCapture{}
	server := httptest.NewServer(http.HandlerFunc(capture.handle))
	defer server.Close()
	plan, err := config.CompileObservabilityV8(observabilitySource(
		storePath, judgePath,
		[]config.ObservabilityV8DestinationSource{{
			Name: "galileo", Kind: config.ObservabilityV8DestinationOTLP, Preset: "galileo",
			Endpoint: server.URL,
			TLS:      config.ObservabilityV8TLSSource{Insecure: true},
			NetworkSafety: config.ObservabilityV8NetworkSafetySource{
				AllowPrivateNetworks: true,
			},
		}},
	))
	if err != nil {
		t.Fatal(err)
	}
	galileoDestination, ok := plan.RuntimeDestination("galileo")
	if !ok || galileoDestination.PolicyForm != config.ObservabilityV8PolicyCapabilityDefault {
		t.Fatalf("Galileo destination is not capability-default: %+v", galileoDestination)
	}
	engine, err := redaction.NewEngine(bytes.Repeat([]byte{0x61}, 32))
	if err != nil {
		t.Fatal(err)
	}
	health := &integrationDeliveryHealth{}
	failures := &galileoCanonicalFailureCapture{}
	factory, err := destinations.NewFactory(destinations.Options{
		ConsoleStream: destinations.ConsoleStderr, Stdout: io.Discard, Stderr: io.Discard,
		Secrets:  &integrationSecrets{values: map[string]string{}, calls: map[string]int{}},
		CALoader: &integrationCALoader{}, Resolver: net.DefaultResolver, Dialer: &net.Dialer{},
		Warnings: &integrationWarnings{}, RedactionEngine: engine, DeliveryObserver: health,
		GalileoObserver: failures,
	})
	if err != nil {
		t.Fatal(err)
	}
	providerFactory := telemetry.NewV8ProviderFactory(telemetry.V8ProviderOptions{
		Version: "integration-test", Environment: "test",
		ServiceInstanceID: "galileo-canary-service", DefenseClawInstanceID: "galileo-canary-instance",
		GenerationPipelines: factory.OTLPGenerationPipelineFactory(),
	})
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
	runtime, err := observabilityruntime.New(
		context.Background(), runtimegraph.ConfigFromPlan(plan, false),
		observabilityruntime.Options{
			Store: store, Engine: engine, RecordBuilder: mustRecordBuilder(t, "galileo-canary-failure"),
			Reporter: &discardReporter{}, RetentionController: retention,
			DestinationAdapterFactory: factory, DestinationObserver: health,
			TelemetryProviderFactory: providerFactory,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if closeErr := runtime.Close(ctx); closeErr != nil {
			t.Errorf("close runtime: %v", closeErr)
		}
	})

	emitGalileoRichGraph(t, runtime, galileoRichTraceID)
	assertGalileoHealthyDelivery(t, health, "galileo")
	emitGalileoNonMemberTransition(t, runtime)
	closeGalileoRichRuntime(t, runtime)
	requests := capture.snapshot()
	if len(requests) != 1 {
		t.Fatalf("Galileo requests=%d, want one exact batch", len(requests))
	}
	assertGalileoRichGraph(t, requests)
	if observed := failures.snapshot(); len(observed) != 0 {
		t.Fatalf("Galileo canonical failures=%+v", observed)
	}
}

func emitGalileoNonMemberTransition(t *testing.T, runtime *observabilityruntime.Runtime) {
	t.Helper()
	startedAt := time.Now().UTC().Add(-time.Millisecond)
	input := observability.SpanAgentTransitionInput{
		Envelope: observability.FamilyEnvelopeInput{
			Source: observability.SourceConnector, Connector: "codex", Action: "agent_transition",
			Phase: "planning", Correlation: observability.Correlation{
				RunID: "galileo-default-run", SessionID: "galileo-default-session",
				AgentID: "galileo-default-agent", ConnectorID: "codex",
			},
			Provenance: observability.FamilyProvenanceInput{Producer: "galileo-default-test"},
		},
		Outcome: observability.OutcomeCompleted, Kind: "INTERNAL",
		StartTimeUnixNano:                   uint64(startedAt.UnixNano()),
		EndTimeUnixNano:                     uint64(startedAt.Add(time.Millisecond).UnixNano()),
		Status:                              observability.NewTraceStatusOK(),
		DefenseClawConnectorSource:          observability.Present("codex"),
		DefenseClawRunID:                    observability.Present("galileo-default-run"),
		GenAIConversationID:                 "galileo-default-session",
		GenAIAgentID:                        "galileo-default-agent",
		DefenseClawAgentRootID:              "galileo-default-agent",
		DefenseClawAgentLineageProvenance:   observability.Present("reported"),
		DefenseClawSessionRootID:            "galileo-default-session",
		DefenseClawAgentLifecycleID:         "galileo-default-lifecycle",
		DefenseClawAgentExecutionID:         "galileo-default-execution",
		DefenseClawAgentLifecycleEvent:      "turn_start",
		DefenseClawAgentLifecycleState:      "active",
		DefenseClawAgentPhase:               observability.Present("planning"),
		DefenseClawAgentPhaseCode:           observability.Present[int64](2),
		DefenseClawAgentSequence:            observability.Present[int64](1),
		DefenseClawAgentReportedCostPresent: false,
		ConditionConnectorKnown:             true,
		ConditionOperationTerminal:          true,
	}
	_, span, err := runtime.StartAgentTransitionTrace(t.Context(), input)
	if err != nil || span == nil {
		t.Fatalf("start non-member transition span=%v error=%v", span, err)
	}
	defer span.Abort()
	if err := span.End(input); err != nil {
		t.Fatalf("end non-member transition: %v", err)
	}
}

// TestLiveGalileoGeneratedRichGraphConformance is intentionally opt-in. It sends
// the generated six-family graph with explicit safe synthetic messages and tool
// data through the same
// generation-owned canonical projection and guarded HTTP/protobuf transport as
// production. Run it explicitly with:
//
//	DEFENSECLAW_LIVE_GALILEO=1 \
//	DEFENSECLAW_LIVE_GALILEO_ENDPOINT=https://<tenant-endpoint> \
//	GALILEO_API_KEY=<secret> GALILEO_PROJECT=<project> GALILEO_LOGSTREAM=<stream> \
//	go test ./internal/observability/integration -run TestLiveGalileoGeneratedRichGraphConformance -count=1 -v
func TestLiveGalileoGeneratedRichGraphConformance(t *testing.T) {
	if os.Getenv("DEFENSECLAW_LIVE_GALILEO") != "1" {
		t.Skip("set DEFENSECLAW_LIVE_GALILEO=1 to run the live Galileo conformance gate")
	}
	endpoint := os.Getenv("DEFENSECLAW_LIVE_GALILEO_ENDPOINT")
	apiKey := os.Getenv("GALILEO_API_KEY")
	project := os.Getenv("GALILEO_PROJECT")
	logstream := os.Getenv("GALILEO_LOGSTREAM")
	if endpoint == "" || apiKey == "" || project == "" || logstream == "" {
		t.Fatal("live Galileo gate requires endpoint, API key, project, and logstream environment variables")
	}
	parsedEndpoint, err := url.Parse(endpoint)
	if err != nil || parsedEndpoint.Scheme != "https" || parsedEndpoint.Host == "" {
		t.Fatalf("live Galileo gate requires an absolute HTTPS endpoint")
	}
	directory := t.TempDir()
	storePath := filepath.Join(directory, "audit.db")
	judgePath := filepath.Join(directory, "judge-bodies.db")
	store, err := audit.NewStore(storePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	plan, err := config.CompileObservabilityV8(observabilitySource(
		storePath, judgePath,
		[]config.ObservabilityV8DestinationSource{{
			Name: "galileo-live", Kind: config.ObservabilityV8DestinationOTLP, Preset: "galileo",
			Endpoint: endpoint,
			Headers: map[string]config.ObservabilityV8HeaderValue{
				"Galileo-API-Key": config.ObservabilityV8EnvironmentHeader("GALILEO_API_KEY"),
				"project":         config.ObservabilityV8StaticHeader(project),
				"logstream":       config.ObservabilityV8StaticHeader(logstream),
			},
			Send: &config.ObservabilityV8SendSource{
				Signals: []observability.Signal{observability.SignalTraces},
				Buckets: []observability.Bucket{"*"}, RedactionProfile: "none",
			},
		}},
	))
	if err != nil {
		t.Fatal(err)
	}
	engine, err := redaction.NewEngine(bytes.Repeat([]byte{0x62}, 32))
	if err != nil {
		t.Fatal(err)
	}
	health := &integrationDeliveryHealth{}
	failures := &galileoCanonicalFailureCapture{}
	factory, err := destinations.NewFactory(destinations.Options{
		ConsoleStream: destinations.ConsoleStderr, Stdout: io.Discard, Stderr: io.Discard,
		Secrets: &integrationSecrets{
			values: map[string]string{"GALILEO_API_KEY": apiKey}, calls: map[string]int{},
		},
		CALoader: &integrationCALoader{}, Resolver: net.DefaultResolver, Dialer: &net.Dialer{},
		Warnings: &integrationWarnings{}, RedactionEngine: engine, DeliveryObserver: health,
		GalileoObserver: failures,
	})
	if err != nil {
		t.Fatal(err)
	}
	providerFactory := telemetry.NewV8ProviderFactory(telemetry.V8ProviderOptions{
		Version: "integration-test", Environment: "live-conformance",
		ServiceInstanceID: "galileo-live-service", DefenseClawInstanceID: "galileo-live-instance",
		GenerationPipelines: factory.OTLPGenerationPipelineFactory(),
	})
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
	runtime, err := observabilityruntime.New(
		context.Background(), runtimegraph.ConfigFromPlan(plan, false),
		observabilityruntime.Options{
			Store: store, Engine: engine, RecordBuilder: mustRecordBuilder(t, "galileo-live-failure"),
			Reporter: &discardReporter{}, RetentionController: retention,
			DestinationAdapterFactory: factory, DestinationObserver: health,
			TelemetryProviderFactory: providerFactory,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if closeErr := runtime.Close(ctx); closeErr != nil {
			t.Errorf("close runtime: %v", closeErr)
		}
	})
	traceID := newGalileoLiveTraceID(t)
	correlationSuffix := traceID[len(traceID)-12:]
	t.Logf(
		"submitted live Galileo trace_id=%s conversation_id=conversation-rich-%s",
		traceID,
		correlationSuffix,
	)
	emitGalileoRichGraph(t, runtime, traceID)
	assertGalileoHealthyDelivery(t, health, "galileo-live")
	closeGalileoRichRuntime(t, runtime)
	if observed := failures.snapshot(); len(observed) != 0 {
		t.Fatalf("live Galileo canonical failures=%+v", observed)
	}
}

const (
	galileoRichTraceID = "102030405060708090a0b0c0d0e0f001"
	galileoRichInput   = "Safe synthetic request: look up the weather in Raleigh and summarize it for Galileo validation."
	galileoRichOutput  = "Safe synthetic response: Raleigh is 72 degrees and clear; rich trace validation completed."
)

type galileoRichSpanSpec struct {
	family, targetID, spanID, parentID, kind string
	outcome                                  observability.Outcome
	native                                   bool
}

var galileoRichSpanSpecs = []galileoRichSpanSpec{
	{
		family:   observability.TelemetryFamilyWorkflowRun,
		targetID: "otlp.genai.span.operation.v1.span.workflow.run.span.workflow.run",
		spanID:   "0000000000000001", kind: "INTERNAL", outcome: observability.OutcomeCompleted,
	},
	{
		family:   observability.TelemetryFamilyAgentInvoke,
		targetID: "otlp.genai.span.operation.v1.span.agent.invoke.span.agent.invoke",
		spanID:   "0000000000000002", parentID: "0000000000000001",
		kind: "INTERNAL", outcome: observability.OutcomeCompleted,
	},
	{
		family:   observability.TelemetryFamilyModelChat,
		targetID: "otlp.genai.span.operation.v1.span.model.chat.span.model.chat",
		spanID:   "0000000000000003", parentID: "0000000000000002",
		kind: "CLIENT", outcome: observability.OutcomeCompleted,
	},
	{
		family:   observability.TelemetryFamilyToolExecute,
		targetID: "otlp.genai.span.operation.v1.span.tool.execute.span.tool.execute",
		spanID:   "0000000000000004", parentID: "0000000000000003",
		kind: "INTERNAL", outcome: observability.OutcomeCompleted,
	},
	{
		family:   observability.TelemetryFamilyRetrievalSearch,
		targetID: "otlp.genai.span.operation.v1.span.retrieval.search.span.retrieval.search",
		spanID:   "0000000000000005", parentID: "0000000000000002",
		kind: "INTERNAL", outcome: observability.OutcomeCompleted,
	},
	{
		family:   observability.TelemetryFamilyGuardrailJudge,
		targetID: "otlp.native.span.v8.span.guardrail.judge.span.guardrail.judge",
		spanID:   "0000000000000006", parentID: "0000000000000003",
		kind: "CLIENT", outcome: observability.OutcomeAllowed, native: true,
	},
}

func emitGalileoRichGraph(
	t *testing.T,
	runtime *observabilityruntime.Runtime,
	traceID string,
) {
	t.Helper()
	emitGalileoRichGraphConfigured(
		t, runtime, traceID, 1, galileoRichInput, galileoRichOutput,
	)
}

func emitGalileoRichGraphConfigured(
	t *testing.T,
	runtime *observabilityruntime.Runtime,
	traceID string,
	wantMatched int,
	inputContent string,
	outputContent string,
) {
	t.Helper()
	correlationSuffix := traceID
	if len(correlationSuffix) > 12 {
		correlationSuffix = correlationSuffix[len(correlationSuffix)-12:]
	}
	requestID := "request-rich-" + correlationSuffix
	catalog, err := observability.LoadInboundCatalog()
	if err != nil {
		t.Fatal(err)
	}
	sequence := 0
	builder, err := observability.NewInboundImportBuilder(
		observability.ClockFunc(time.Now),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) {
			sequence++
			return "galileo-rich-record-" + strconv.Itoa(sequence), nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	batch, err := runtime.BeginInboundImportBatch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer batch.Close()
	receipt := time.Now().UTC()
	for index, spec := range galileoRichSpanSpecs {
		spanID := galileoRichRuntimeSpanID(traceID, spec.spanID)
		parentSpanID := ""
		if spec.parentID != "" {
			parentSpanID = galileoRichRuntimeSpanID(traceID, spec.parentID)
		}
		target, ok := catalog.Target(spec.targetID)
		if !ok || target.Family() != spec.family || target.Signal() != observability.SignalTraces {
			t.Fatalf("generated Galileo target unavailable: family=%q target=%q", spec.family, spec.targetID)
		}
		result, importErr := batch.ImportTrace(ctx, target, "codex", func(snapshot observabilityruntime.EmitContext) (observability.Record, error) {
			provenance, available := snapshot.InboundLocalProvenance()
			if !available {
				return observability.Record{}, errGalileoRichFixture
			}
			start := receipt.Add(time.Duration(-1200+index*100) * time.Millisecond)
			end := start.Add(50 * time.Millisecond)
			input := observability.InboundImportedTraceInput{
				ReceiptTime: receipt,
				Correlation: observability.Correlation{
					RequestID: requestID, TraceID: traceID, SpanID: spanID,
				},
				Provenance: provenance,
				Import: observability.InboundImportProvenanceInput{
					AuthenticatedSource: "codex", UpstreamServiceName: "rich-fixture",
				},
				Outcome: observability.Present(spec.outcome), Kind: spec.kind,
				StartTimeUnixNano: uint64(start.UnixNano()), EndTimeUnixNano: uint64(end.UnixNano()),
				TraceState: observability.Present("dc=rich"), Flags: 1,
				Status: observability.NewTraceStatusOK(),
				Fields: galileoRichMappedFields(
					t, target, spec.family, correlationSuffix, inputContent, outputContent,
				),
			}
			if parentSpanID != "" {
				input.ParentSpanID = observability.Present(parentSpanID)
			}
			if spec.native {
				input.NativeSpanName = observability.Present("chat gpt-4o-mini")
				input.Resource.Fields = galileoRichResourceFields(t, target)
				input.Import.UpstreamInstanceID = "rich-upstream-instance"
				input.Import.UpstreamRecordID = "rich-upstream-judge"
				input.Import.UpstreamRedactionProfile = "none"
				input.Import.IngressHopCount = 1
				input.Import.LastHopInstanceID = "rich-forwarder"
				input.Import.LastHopDestination = "galileo"
			} else {
				localResource, resourceAvailable := snapshot.InboundLocalTraceResource()
				if !resourceAvailable {
					return observability.Record{}, errGalileoRichFixture
				}
				input.LocalResource = localResource
			}
			if spec.family == observability.TelemetryFamilyModelChat {
				retry, eventErr := observability.NewSpanModelChatModelRetryEvent(
					observability.SpanModelChatModelRetryEventInput{
						TimeUnixNano:               uint64(start.Add(25 * time.Millisecond).UnixNano()),
						DefenseClawModelAttempt:    observability.Present[int64](2),
						DefenseClawModelRetryCount: observability.Present[int64](1),
						ErrorType:                  observability.Present("upstream_unavailable"),
					},
				)
				if eventErr != nil {
					return observability.Record{}, eventErr
				}
				input.Events = []observability.TraceEventInput{retry}
			}
			if spec.family == observability.TelemetryFamilyRetrievalSearch {
				link, linkErr := observability.NewInboundTraceLink(
					target, observability.InboundTraceLinkDerivedFrom,
					traceID, galileoRichRuntimeSpanID(traceID, "0000000000000003"),
					observability.Present("dc=rich"),
					observability.Absent[uint32](),
				)
				if linkErr != nil {
					return observability.Record{}, linkErr
				}
				input.Links = []observability.TraceLinkInput{link}
			}
			return builder.BuildTrace(target, input)
		})
		if importErr != nil || result.Matched != wantMatched || result.Delivered != wantMatched ||
			result.Dropped != 0 || result.Failed != 0 || result.Suppressed != 0 {
			t.Fatalf("Galileo family %q delivery=%+v error=%v", spec.family, result, importErr)
		}
	}
}

func galileoRichRuntimeSpanID(traceID, fixtureSpanID string) string {
	// The fixture IDs encode the graph ordinal in their final byte. Prefixing
	// that ordinal with trace-derived bytes gives every live run a distinct set
	// of span IDs while keeping local expectations deterministic.
	return traceID[:14] + fixtureSpanID[len(fixtureSpanID)-2:]
}

func newGalileoLiveTraceID(t *testing.T) string {
	t.Helper()
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(value)
}

var errGalileoRichFixture = &galileoRichFixtureError{}

type galileoRichFixtureError struct{}

func (*galileoRichFixtureError) Error() string { return "Galileo rich fixture capability unavailable" }

func galileoRichMappedFields(
	t *testing.T,
	target observability.InboundTarget,
	family string,
	correlationSuffix string,
	inputContent string,
	outputContent string,
) []observability.InboundMappedField {
	t.Helper()
	values := map[string]any{
		"defenseclaw.connector.source":            "openai_codex",
		"defenseclaw.run.id":                      "run-rich-" + correlationSuffix,
		"defenseclaw.operation.id":                "operation-rich-" + correlationSuffix,
		"defenseclaw.request.id":                  "request-rich-" + correlationSuffix,
		"defenseclaw.turn.id":                     "turn-rich-" + correlationSuffix,
		"gen_ai.conversation.id":                  "conversation-rich-" + correlationSuffix,
		"gen_ai.agent.id":                         "agent-rich-root",
		"gen_ai.agent.name":                       "defenseclaw",
		"defenseclaw.agent.type":                  "root",
		"defenseclaw.agent.instance_id":           "agent-rich-instance",
		"defenseclaw.agent.root.id":               "agent-rich-root",
		"defenseclaw.agent.lineage.provenance":    "reported",
		"defenseclaw.session.root.id":             "conversation-rich-" + correlationSuffix,
		"defenseclaw.agent.lifecycle.id":          "lifecycle-rich-" + correlationSuffix,
		"defenseclaw.agent.execution.id":          "execution-rich-" + correlationSuffix,
		"defenseclaw.agent.depth":                 int64(0),
		"defenseclaw.agent.lifecycle.event":       "session_start",
		"defenseclaw.agent.lifecycle.state":       "active",
		"defenseclaw.agent.phase":                 "model",
		"defenseclaw.agent.phase.previous":        "planning",
		"defenseclaw.agent.phase.code":            int64(3),
		"defenseclaw.agent.sequence":              int64(7),
		"defenseclaw.session.source":              "startup",
		"defenseclaw.session.resumed":             false,
		"defenseclaw.agent.reported_cost.present": false,
		"defenseclaw.telemetry.input.reported":    true,
		"defenseclaw.content.input.state":         "preserved",
		"defenseclaw.content.input.mime_type":     "application/json",
		"defenseclaw.telemetry.output.reported":   true,
		"defenseclaw.content.output.state":        "preserved",
		"defenseclaw.content.output.mime_type":    "application/json",
		"defenseclaw.telemetry.tokens.reported":   true,
		"gen_ai.provider.name":                    "openai",
		"gen_ai.request.model":                    "gpt-4o-mini",
		"gen_ai.response.model":                   "gpt-4o-mini",
		"gen_ai.response.finish_reasons":          []string{"stop"},
		"gen_ai.usage.input_tokens":               int64(24),
		"gen_ai.usage.output_tokens":              int64(18),
		"gen_ai.operation.name":                   "chat",
		"defenseclaw.model.attempt":               int64(2),
		"defenseclaw.model.retry_count":           int64(1),
		"defenseclaw.model.streaming":             false,
		"defenseclaw.model.cancelled":             false,
		"gen_ai.tool.name":                        "lookup",
		"gen_ai.tool.type":                        "function",
		"gen_ai.tool.call.id":                     "tool-call-rich-001",
		"defenseclaw.tool.id":                     "tool-rich-001",
		"defenseclaw.tool.provider":               "builtin",
		"defenseclaw.tool.dangerous":              false,
		"defenseclaw.tool.exit_code":              int64(0),
		"defenseclaw.tool.status":                 "completed",
		"defenseclaw.tool.args_length":            int64(31),
		"defenseclaw.tool.output_length":          int64(37),
		"db.operation.name":                       "search",
		"db.collection.name":                      "knowledge",
		"defenseclaw.retrieval.source.id":         "knowledge-rich-001",
		"defenseclaw.retrieval.source.type":       "vector_store",
		"defenseclaw.retrieval.result_count":      int64(3),
		"defenseclaw.retrieval.top_k":             int64(3),
		"defenseclaw.retrieval.score.min":         0.72,
		"defenseclaw.retrieval.score.max":         0.96,
		"defenseclaw.workflow.name":               "incident_triage",
		"defenseclaw.judge.kind":                  "injection",
		"defenseclaw.guardrail.phase":             "judge",
		"defenseclaw.guardrail.direction":         "input",
		"defenseclaw.guardrail.cache_hit":         false,
		"defenseclaw.guardrail.attempt":           int64(1),
		"defenseclaw.guardrail.latency_ms":        12.5,
		"defenseclaw.guardrail.finding_count":     int64(0),
		"defenseclaw.guardrail.raw_action":        "allow",
		"defenseclaw.guardrail.effective_action":  "allow",
	}
	switch family {
	case observability.TelemetryFamilyAgentInvoke:
		values["gen_ai.operation.name"] = "invoke_agent"
	case observability.TelemetryFamilyToolExecute:
		values["gen_ai.operation.name"] = "execute_tool"
	}
	return galileoRichMapCapabilities(t, target.Fields(), values, inputContent, outputContent)
}

func galileoRichResourceFields(
	t *testing.T,
	target observability.InboundTarget,
) []observability.InboundMappedField {
	t.Helper()
	return galileoRichMapCapabilities(t, target.TraceResourceFields(), map[string]any{
		"defenseclaw.instance.id":     "galileo-rich-instance",
		"deployment.environment.name": "test",
		"host.arch":                   "amd64",
		"host.name":                   "galileo-rich-host",
		"os.type":                     "linux",
		"service.instance.id":         "galileo-rich-service",
		"service.name":                "defenseclaw",
		"service.namespace":           "defenseclaw",
	}, "", "")
}

func galileoRichMapCapabilities(
	t *testing.T,
	capabilities []observability.InboundTargetField,
	values map[string]any,
	inputContent string,
	outputContent string,
) []observability.InboundMappedField {
	t.Helper()
	result := make([]observability.InboundMappedField, 0, len(values))
	for _, field := range capabilities {
		if field.FieldRef() == "gen_ai.input.messages" {
			mapped, err := observability.NewInboundMappedGenAIInputMessages(
				field,
				observability.TelemetryStructuredGenAIInputMessages{
					Items: []observability.TelemetryStructuredGenAIChatMessage{{
						Role: "user",
						Parts: observability.TelemetryStructuredGenAIMessageParts{
							Items: []observability.TelemetryStructuredGenAIMessagePart{
								observability.TelemetryStructuredArmGenAIMessagePartText{
									Value: observability.TelemetryStructuredGenAITextPart{Content: inputContent},
								},
							},
						},
					}},
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			result = append(result, mapped)
			continue
		}
		if field.FieldRef() == "gen_ai.output.messages" {
			mapped, err := observability.NewInboundMappedGenAIOutputMessages(
				field,
				observability.TelemetryStructuredGenAIOutputMessages{
					Items: []observability.TelemetryStructuredGenAIOutputMessage{{
						Role: "assistant", FinishReason: observability.Present("stop"),
						Parts: observability.TelemetryStructuredGenAIMessageParts{
							Items: []observability.TelemetryStructuredGenAIMessagePart{
								observability.TelemetryStructuredArmGenAIMessagePartText{
									Value: observability.TelemetryStructuredGenAITextPart{Content: outputContent},
								},
							},
						},
					}},
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			result = append(result, mapped)
			continue
		}
		if field.FieldRef() == "gen_ai.tool.call.arguments" {
			query, err := observability.NewGenAIToolCallArgumentsEntryMember(
				"query", observability.TelemetryStructuredArmGenAICanonicalJSONString{Value: "weather in Raleigh"},
			)
			if err != nil {
				t.Fatal(err)
			}
			mapped, err := observability.NewInboundMappedGenAIToolCallArguments(
				field, observability.TelemetryStructuredGenAIToolCallArguments{
					Entries: []observability.GenAIToolCallArgumentsEntryMemberInput{query},
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			result = append(result, mapped)
			continue
		}
		if field.FieldRef() == "gen_ai.tool.call.result" {
			resultText, err := observability.NewGenAIToolCallResultEntryMember(
				"summary", observability.TelemetryStructuredArmGenAICanonicalJSONString{Value: "72 degrees and clear"},
			)
			if err != nil {
				t.Fatal(err)
			}
			mapped, err := observability.NewInboundMappedGenAIToolCallResult(
				field, observability.TelemetryStructuredGenAIToolCallResult{
					Entries: []observability.GenAIToolCallResultEntryMemberInput{resultText},
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			result = append(result, mapped)
			continue
		}
		value, present := values[field.FieldRef()]
		if !present {
			continue
		}
		switch typed := value.(type) {
		case string:
			result = append(result, observability.NewInboundMappedString(field, typed))
		case bool:
			result = append(result, observability.NewInboundMappedBoolean(field, typed))
		case int64:
			result = append(result, observability.NewInboundMappedInt64(field, typed))
		case uint32:
			result = append(result, observability.NewInboundMappedUint32(field, typed))
		case float64:
			result = append(result, observability.NewInboundMappedDouble(field, typed))
		case []string:
			result = append(result, observability.NewInboundMappedStringArray(field, typed))
		default:
			t.Fatalf("unsupported rich fixture value type %T for %q", value, field.FieldRef())
		}
	}
	return result
}

func closeGalileoRichRuntime(t *testing.T, runtime *observabilityruntime.Runtime) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := runtime.Close(ctx); err != nil {
		t.Fatalf("close Galileo rich runtime: %v", err)
	}
}

func assertGalileoRichGraph(
	t *testing.T,
	requests []*collectortracepb.ExportTraceServiceRequest,
) {
	t.Helper()
	manifest, err := profilemanifest.Get(observability.RuntimeGalileoCompatibilityProfile)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := observability.LoadInboundCatalog()
	if err != nil {
		t.Fatal(err)
	}
	wire := catalog.WireContract()
	wantFamilies := profilemanifest.SortedFamilyIDs(manifest, observability.SignalTraces)
	spans := make(map[string]*tracepb.Span, len(wantFamilies))
	wantTraceID := []byte{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01}
	for _, request := range requests {
		for _, resourceSpans := range request.ResourceSpans {
			if resourceSpans.SchemaUrl != wire.ResourceSchemaURL {
				t.Fatalf("resource schema URL=%q", resourceSpans.SchemaUrl)
			}
			resource := galileoProtoAttributes(resourceSpans.Resource.Attributes)
			if resource["service.name"] != "defenseclaw" || resource["service.instance.id"] == "" ||
				resource["defenseclaw.instance.id"] == "" {
				t.Fatalf("projected resource identity=%v", resource)
			}
			for _, scopeSpans := range resourceSpans.ScopeSpans {
				if scopeSpans.SchemaUrl != wire.ScopeSchemaURL || scopeSpans.Scope.Name != wire.ScopeName {
					t.Fatalf("projected scope=%+v schema=%q", scopeSpans.Scope, scopeSpans.SchemaUrl)
				}
				scope := galileoProtoAttributes(scopeSpans.Scope.Attributes)
				if scope["defenseclaw.galileo.compatibility_profile"] != observability.RuntimeGalileoCompatibilityProfile ||
					scope["defenseclaw.semantic_profile"] != observability.RuntimeSemanticProfileID ||
					scope["defenseclaw.trace.schema_version"] != observability.RuntimeTraceSchemaVersion {
					t.Fatalf("projected scope attributes=%v", scope)
				}
				for _, span := range scopeSpans.Spans {
					attributes := galileoProtoAttributes(span.Attributes)
					family, _ := attributes["defenseclaw.span.family"].(string)
					if family == "" || !bytes.Equal(span.TraceId, wantTraceID) || len(span.SpanId) != 8 {
						t.Fatalf("projected identity family=%q trace=%x span=%x", family, span.TraceId, span.SpanId)
					}
					if _, duplicate := spans[family]; duplicate {
						t.Fatalf("duplicate projected family %q", family)
					}
					spans[family] = span
				}
			}
		}
	}
	gotFamilies := make([]string, 0, len(spans))
	for family := range spans {
		gotFamilies = append(gotFamilies, family)
	}
	sort.Strings(gotFamilies)
	if len(gotFamilies) != len(wantFamilies) {
		t.Fatalf("projected families=%v, generated Galileo profile=%v", gotFamilies, wantFamilies)
	}
	for index := range wantFamilies {
		if gotFamilies[index] != string(wantFamilies[index]) {
			t.Fatalf("projected families=%v, generated Galileo profile=%v", gotFamilies, wantFamilies)
		}
	}
	wantShape := map[string]string{
		observability.TelemetryFamilyAgentInvoke:     "AGENT",
		observability.TelemetryFamilyGuardrailJudge:  "LLM",
		observability.TelemetryFamilyModelChat:       "LLM",
		observability.TelemetryFamilyRetrievalSearch: "RETRIEVER",
		observability.TelemetryFamilyToolExecute:     "TOOL",
		observability.TelemetryFamilyWorkflowRun:     "CHAIN",
	}
	wantParents := map[string]string{
		observability.TelemetryFamilyAgentInvoke: galileoRichRuntimeSpanID(
			galileoRichTraceID, "0000000000000001",
		),
		observability.TelemetryFamilyModelChat: galileoRichRuntimeSpanID(
			galileoRichTraceID, "0000000000000002",
		),
		observability.TelemetryFamilyToolExecute: galileoRichRuntimeSpanID(
			galileoRichTraceID, "0000000000000003",
		),
		observability.TelemetryFamilyRetrievalSearch: galileoRichRuntimeSpanID(
			galileoRichTraceID, "0000000000000002",
		),
		observability.TelemetryFamilyGuardrailJudge: galileoRichRuntimeSpanID(
			galileoRichTraceID, "0000000000000003",
		),
	}
	for family, span := range spans {
		attributes := galileoProtoAttributes(span.Attributes)
		if attributes["openinference.span.kind"] != wantShape[family] ||
			attributes["defenseclaw.bucket"] == "" || span.TraceState != "dc=rich" || span.Flags&1 == 0 {
			t.Fatalf("family %q projected attributes/state=%v/%q/%d", family, attributes, span.TraceState, span.Flags)
		}
		for _, direction := range []string{"input", "output"} {
			value, valueOK := attributes[direction+".value"].(string)
			if !valueOK || value == "" || value == "[]" {
				t.Fatalf("family %q Galileo UI-facing %s.value=%#v", family, direction, attributes[direction+".value"])
			}
			wantMimeType := "text/plain"
			if family == observability.TelemetryFamilyToolExecute {
				wantMimeType = "application/json"
			} else {
				wantValue := galileoRichInput
				if direction == "output" {
					wantValue = galileoRichOutput
				}
				if value != wantValue {
					t.Fatalf("family %q Galileo UI-facing %s.value=%#v, want plain text %#v", family, direction, value, wantValue)
				}
			}
			if attributes[direction+".mime_type"] != wantMimeType {
				t.Fatalf("family %q Galileo UI-facing %s.mime_type=%#v", family, direction, attributes[direction+".mime_type"])
			}
		}
		if parent, expected := wantParents[family]; expected {
			if !bytes.Equal(span.ParentSpanId, mustGalileoSpanID(t, parent)) {
				t.Fatalf("family %q parent=%x want=%s", family, span.ParentSpanId, parent)
			}
		} else if len(span.ParentSpanId) != 0 {
			t.Fatalf("root family %q has parent=%x", family, span.ParentSpanId)
		}
	}
	model := spans[observability.TelemetryFamilyModelChat]
	modelAttributes := galileoProtoAttributes(model.Attributes)
	modelInput := modelAttributes["input.value"]
	modelOutput := modelAttributes["output.value"]
	if !strings.Contains(fmt.Sprint(modelInput), galileoRichInput) ||
		!strings.Contains(fmt.Sprint(modelOutput), galileoRichOutput) {
		t.Fatalf("projected model content is not rich: input=%v output=%v attributes=%v", modelInput, modelOutput, modelAttributes)
	}
	if len(model.Events) != 1 || model.Events[0].Name != "model.retry" ||
		galileoProtoAttributes(model.Events[0].Attributes)["defenseclaw.model.attempt"] != int64(2) {
		t.Fatalf("projected model events=%+v", model.Events)
	}
	retrieval := spans[observability.TelemetryFamilyRetrievalSearch]
	if len(retrieval.Links) != 1 || !bytes.Equal(retrieval.Links[0].TraceId, wantTraceID) ||
		!bytes.Equal(
			retrieval.Links[0].SpanId,
			mustGalileoSpanID(t, galileoRichRuntimeSpanID(galileoRichTraceID, "0000000000000003")),
		) ||
		galileoProtoAttributes(retrieval.Links[0].Attributes)["defenseclaw.link.relation"] != "derived_from" {
		t.Fatalf("projected retrieval links=%+v", retrieval.Links)
	}
	toolAttributes := galileoProtoAttributes(spans[observability.TelemetryFamilyToolExecute].Attributes)
	toolInput := toolAttributes["input.value"]
	toolOutput := toolAttributes["output.value"]
	if !strings.Contains(fmt.Sprint(toolInput), "weather in Raleigh") ||
		!strings.Contains(fmt.Sprint(toolOutput), "72 degrees and clear") {
		t.Fatalf("projected tool content is not rich: input=%v output=%v attributes=%v", toolInput, toolOutput, toolAttributes)
	}
}

func assertGalileoHealthyDelivery(t *testing.T, health *integrationDeliveryHealth, destination string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		health.mu.Lock()
		transitions := append([]delivery.HealthTransition(nil), health.transitions...)
		health.mu.Unlock()
		foundHealthy := false
		for _, transition := range transitions {
			if transition.Destination != destination {
				continue
			}
			if transition.Current == delivery.HealthDegraded || transition.Current == delivery.HealthFailing {
				t.Fatalf("Galileo delivery degraded: %+v", transition)
			}
			foundHealthy = foundHealthy || transition.Current == delivery.HealthHealthy
		}
		if foundHealthy {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("Galileo delivery never acknowledged healthy: %+v", transitions)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func galileoProtoAttributes(attributes []*commonpb.KeyValue) map[string]any {
	result := make(map[string]any, len(attributes))
	for _, attribute := range attributes {
		if attribute == nil || attribute.Value == nil {
			continue
		}
		result[attribute.Key] = galileoProtoValue(attribute.Value)
	}
	return result
}

func galileoProtoValue(input *commonpb.AnyValue) any {
	if input == nil {
		return nil
	}
	switch value := input.Value.(type) {
	case *commonpb.AnyValue_StringValue:
		return value.StringValue
	case *commonpb.AnyValue_BoolValue:
		return value.BoolValue
	case *commonpb.AnyValue_IntValue:
		return value.IntValue
	case *commonpb.AnyValue_DoubleValue:
		return value.DoubleValue
	case *commonpb.AnyValue_ArrayValue:
		items := make([]any, 0, len(value.ArrayValue.Values))
		for _, item := range value.ArrayValue.Values {
			items = append(items, galileoProtoValue(item))
		}
		return items
	case *commonpb.AnyValue_KvlistValue:
		return galileoProtoAttributes(value.KvlistValue.Values)
	case *commonpb.AnyValue_BytesValue:
		return append([]byte(nil), value.BytesValue...)
	}
	return nil
}

func mustGalileoSpanID(t *testing.T, encoded string) []byte {
	t.Helper()
	result, err := hex.DecodeString(encoded)
	if err != nil || len(result) != 8 {
		t.Fatalf("invalid fixture span ID %q: %v", encoded, err)
	}
	return result
}

var _ delivery.Observer = (*integrationDeliveryHealth)(nil)
