// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityrouter "github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	legacyredaction "github.com/defenseclaw/defenseclaw/internal/redaction"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	"github.com/defenseclaw/defenseclaw/internal/version"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"
)

const proxyGuardrailV8Producer = "gateway.proxy.guardrail"

type proxyGuardrailV8Runtime interface {
	sidecarRuntimeEmitter
	inspectTraceV8Runtime
	hookLifecycleMetricV8Runtime
}

// proxyGuardrailV8Overlay carries a guardrail decision onto the nearest
// Galileo-supported GenAI span without changing the canonical ownership of
// the full evaluation. Prompt decisions belong to invoke_agent; completion
// and proposed-tool decisions belong to model.chat. The native
// span.guardrail.apply remains the complete, destination-neutral record.
type proxyGuardrailV8Overlay struct {
	agentEvents []observability.TraceEventInput
	modelEvents []observability.TraceEventInput
}

type proxyGuardrailV8Facts struct {
	connector    string
	direction    string
	targetType   string
	detector     string
	mode         string
	rawAction    string
	effective    string
	decision     string
	outcome      observability.Outcome
	severity     observability.Severity
	logLevel     observability.LogLevel
	reason       observability.Optional[string]
	evaluationID string
	scanID       string
	enforcement  string
	ruleIDs      observability.Optional[[]string]
	confidence   observability.Optional[float64]
	findingCount int64
	latencyMs    float64
	wouldBlock   bool
	enforced     bool
	ciscoMs      float64
	observedAt   time.Time
	startedAt    time.Time
	meta         llmEventMeta
	identity     AgentIdentity
}

type proxyGuardrailTraceV8Operation struct {
	trace        *observabilityruntime.GuardrailApplyTrace
	facts        proxyGuardrailV8Facts
	strategy     string
	mode         string
	evaluationID string
	enforceable  bool
	phaseMu      sync.Mutex
	phaseClosed  bool
	phases       []proxyGuardrailPhaseV8Pending
}

type proxyGuardrailPhaseV8Pending struct {
	trace *observabilityruntime.GuardrailPhaseTrace
	input observability.SpanGuardrailPhaseInput
}

type proxyGuardrailTraceV8ContextKey struct{}
type proxyGuardrailNoEnforcementContextKey struct{}

func proxyGuardrailWithoutEnforcement(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, proxyGuardrailNoEnforcementContextKey{}, true)
}

func proxyGuardrailEnforcementAvailable(ctx context.Context) bool {
	if ctx == nil {
		return true
	}
	unavailable, _ := ctx.Value(proxyGuardrailNoEnforcementContextKey{}).(bool)
	return !unavailable
}

func configureGuardrailInspectorObservabilityV8(
	inspector *GuardrailInspector,
	runtime lifecycleV8Runtime,
	connector func() string,
) {
	if inspector == nil {
		return
	}
	logRuntime, _ := runtime.(sidecarRuntimeEmitter)
	if logRuntime == nil {
		inspector.SetManagedAIDFailOpenRecorder(nil)
	} else {
		inspector.SetManagedAIDFailOpenRecorder(func(ctx context.Context, reason, direction string) {
			if err := emitManagedAIDFailOpenV8(ctx, logRuntime, reason, direction); err != nil {
				fmt.Fprintf(
					os.Stderr,
					"[guardrail] managed AID fail-open emit_status=failed reason=%s direction=%s\n",
					normalizeManagedAIDFailOpenReason(reason),
					normalizeManagedAIDFailOpenDirection(direction),
				)
			}
		})
	}
	metricRuntime, _ := runtime.(hookLifecycleMetricV8Runtime)
	if inspector.ciscoClient != nil {
		inspector.ciscoClient.bindObservabilityV8(metricRuntime)
	}
	capability, ok := runtime.(proxyGuardrailV8Runtime)
	if !ok || capability == nil {
		inspector.SetTracerFunc(nil)
		inspector.SetPhaseTracerFunc(nil)
		inspector.SetPanicRecorderFunc(nil)
		return
	}
	inspector.SetTracerFunc(func(
		ctx context.Context,
		strategy string,
		direction string,
		_ string,
		mode string,
	) (context.Context, func(*ScanVerdict, time.Duration)) {
		currentConnector := ""
		if connector != nil {
			currentConnector = connector()
		}
		return startProxyGuardrailInspectionV8(ctx, capability, currentConnector, strategy, direction, mode)
	})
	inspector.SetPhaseTracerFunc(startProxyGuardrailPhaseV8)
	inspector.SetPanicRecorderFunc(func(ctx context.Context) {
		currentConnector := ""
		if connector != nil {
			currentConnector = connector()
		}
		recordProxyGuardrailPanicV8(ctx, capability, currentConnector)
	})
}

func startProxyGuardrailInspectionV8(
	ctx context.Context,
	runtime proxyGuardrailV8Runtime,
	connector string,
	strategy string,
	direction string,
	mode string,
) (context.Context, func(*ScanVerdict, time.Duration)) {
	if ctx == nil {
		ctx = context.Background()
	}
	evaluationID := uuid.NewString()
	placeholder := &ScanVerdict{Action: "allow", Severity: "NONE", EvaluationID: evaluationID}
	facts, valid := proxyGuardrailV8FactsFrom(ctx, connector, direction, placeholder, 0, mode, false)
	operation := &proxyGuardrailTraceV8Operation{
		facts: facts, strategy: normalizeProxyGuardrailStrategy(strategy),
		mode: mode, evaluationID: evaluationID, enforceable: proxyGuardrailEnforcementAvailable(ctx),
	}
	startedCtx := ctx
	if valid {
		input, inputOK := facts.traceInput(ctx)
		if inputOK {
			input.DefenseClawGuardrailStrategy = hookV8OptionalText(operation.strategy, 4096)
			started, span, err := runtime.StartGuardrailApplyTrace(ctx, input)
			if err == nil {
				operation.trace = span
				if started != nil {
					startedCtx = started
				}
			} else {
				fmt.Fprintf(os.Stderr, "[guardrail] generated inspection trace start failed: %v\n", err)
			}
		}
	}
	startedCtx = context.WithValue(startedCtx, proxyGuardrailTraceV8ContextKey{}, operation)
	return startedCtx, func(verdict *ScanVerdict, elapsed time.Duration) {
		operation.finish(startedCtx, verdict, elapsed)
	}
}

func (operation *proxyGuardrailTraceV8Operation) finish(
	ctx context.Context,
	verdict *ScanVerdict,
	elapsed time.Duration,
) {
	if operation == nil {
		return
	}
	if verdict == nil {
		pendingPhases := operation.closePendingPhases()
		abortProxyGuardrailPendingPhases(pendingPhases)
		if operation.trace != nil {
			operation.trace.Abort()
		}
		return
	}
	verdict.GeneratedTraceOwned = true
	if verdict.EvaluationID == "" {
		verdict.EvaluationID = operation.evaluationID
	}
	if normalized := NormalizeScanVerdict(verdict); len(normalized) > 0 {
		if verdict.ScanID == "" {
			verdict.ScanID = uuid.NewString()
		}
		if len(verdict.RuleIDs) == 0 {
			verdict.RuleIDs = scanner.TopRuleIDs(normalizedFindingsToInspect(normalized, verdict.Severity), 8)
		}
	}
	if operation.trace == nil {
		abortProxyGuardrailPendingPhases(operation.closePendingPhases())
		return
	}
	defer operation.trace.Abort()
	projectionPolicy := proxyGuardrailTraceProjectionPolicy(ctx, verdict.RedactionEnabled)
	pendingPhases := operation.closePendingPhases()
	defer abortProxyGuardrailPendingPhases(pendingPhases)
	traceCtx := operation.trace.Context()
	if traceCtx == nil {
		traceCtx = ctx
	}
	enforced := verdict.Action == "block" && hookDecisionV8Mode(operation.mode) == "enforce" &&
		operation.enforceable
	facts, valid := proxyGuardrailV8FactsFrom(
		traceCtx, operation.facts.connector, operation.facts.targetType, verdict, elapsed, operation.mode, enforced,
	)
	if !valid {
		return
	}
	verdict.EnforcementID = facts.enforcement
	input, inputOK := facts.traceInput(traceCtx)
	if !inputOK {
		return
	}
	input.Envelope.ProjectionPolicy = projectionPolicy
	input.DefenseClawGuardrailStrategy = hookV8OptionalText(operation.strategy, 4096)
	for _, pending := range pendingPhases {
		pending.input.Envelope.ProjectionPolicy = projectionPolicy
		if err := pending.trace.End(pending.input); err != nil {
			fmt.Fprintf(os.Stderr, "[guardrail] generated inspection phase end failed: %v\n", err)
			return
		}
	}
	spanContext := trace.SpanContextFromContext(traceCtx)
	if err := operation.trace.End(input); err == nil && spanContext.IsValid() {
		verdict.TraceContext = spanContext
	} else if err != nil {
		fmt.Fprintf(os.Stderr, "[guardrail] generated inspection trace end failed: %v\n", err)
	}
}

func startProxyGuardrailPhaseV8(
	ctx context.Context,
	phase string,
) (context.Context, func(string, string, time.Duration)) {
	operation, _ := ctx.Value(proxyGuardrailTraceV8ContextKey{}).(*proxyGuardrailTraceV8Operation)
	canonicalPhase := normalizeProxyGuardrailPhase(phase)
	if operation == nil || operation.trace == nil || canonicalPhase == "" {
		return ctx, func(string, string, time.Duration) {}
	}
	startedAt := time.Now().UTC()
	input := operation.phaseInput(ctx, canonicalPhase, startedAt, 0, "", "")
	phaseTrace, err := operation.trace.StartPhase(input)
	if err != nil || phaseTrace == nil {
		if err != nil {
			fmt.Fprintf(os.Stderr, "[guardrail] generated inspection phase start failed: %v\n", err)
		}
		return ctx, func(string, string, time.Duration) {}
	}
	phaseCtx := phaseTrace.Context()
	if phaseCtx == nil {
		phaseCtx = ctx
	}
	if canonicalPhase == "ai_defense" {
		phaseCtx = context.WithValue(
			phaseCtx, ciscoInspectMetricRuntimeContextKey{}, hookLifecycleMetricV8Runtime(phaseTrace),
		)
	}
	var once sync.Once
	return phaseCtx, func(action, severity string, elapsed time.Duration) {
		once.Do(func() {
			endInput := operation.phaseInput(phaseCtx, canonicalPhase, startedAt, elapsed, action, severity)
			if !operation.deferPhaseEnd(phaseTrace, endInput) {
				// The root already finished or aborted. Abort is idempotent and
				// guarantees a late phase cannot escape without releasing its lease.
				phaseTrace.Abort()
			}
		})
	}
}

func (operation *proxyGuardrailTraceV8Operation) deferPhaseEnd(
	phase *observabilityruntime.GuardrailPhaseTrace,
	input observability.SpanGuardrailPhaseInput,
) bool {
	if operation == nil || phase == nil {
		return false
	}
	operation.phaseMu.Lock()
	defer operation.phaseMu.Unlock()
	if operation.phaseClosed {
		return false
	}
	operation.phases = append(operation.phases, proxyGuardrailPhaseV8Pending{trace: phase, input: input})
	return true
}

func (operation *proxyGuardrailTraceV8Operation) closePendingPhases() []proxyGuardrailPhaseV8Pending {
	if operation == nil {
		return nil
	}
	operation.phaseMu.Lock()
	defer operation.phaseMu.Unlock()
	operation.phaseClosed = true
	result := append([]proxyGuardrailPhaseV8Pending(nil), operation.phases...)
	operation.phases = nil
	return result
}

func abortProxyGuardrailPendingPhases(phases []proxyGuardrailPhaseV8Pending) {
	for _, pending := range phases {
		if pending.trace != nil {
			pending.trace.Abort()
		}
	}
}

func proxyGuardrailTraceProjectionPolicy(
	ctx context.Context,
	directive *bool,
) observability.ProjectionPolicy {
	switch sinkPolicyFor(ctx, directive) {
	case legacyredaction.SinkPolicyRaw:
		return observability.RawProjectionPolicy()
	case legacyredaction.SinkPolicyRedact:
		return observability.RedactProjectionPolicy()
	default:
		return observability.DefaultProjectionPolicy()
	}
}

func (operation *proxyGuardrailTraceV8Operation) phaseInput(
	ctx context.Context,
	phase string,
	startedAt time.Time,
	elapsed time.Duration,
	action string,
	severity string,
) observability.SpanGuardrailPhaseInput {
	if elapsed < 0 {
		elapsed = 0
	}
	rawAction := normalizeHookActionLabel(action)
	if rawAction == "none" {
		rawAction = "allow"
	}
	effective := rawAction
	wouldBlock := rawAction == "block" &&
		(hookDecisionV8Mode(operation.mode) != "enforce" || !operation.enforceable)
	if wouldBlock {
		effective = "allow"
	}
	normalizedSeverity := observability.NormalizeSeverity(firstNonEmpty(severity, "NONE"))
	if !normalizedSeverity.Valid || !normalizedSeverity.Present {
		normalizedSeverity = observability.NormalizeSeverity("NONE")
	}
	connector := operation.facts.connector
	connectorKnown := connector != "unknown"
	if !connectorKnown {
		connector = ""
	}
	correlation := operation.facts.correlation(ctx)
	correlation.ConnectorID = connector
	return observability.SpanGuardrailPhaseInput{
		Envelope: observability.FamilyEnvelopeInput{
			ObservedAt: observability.Present(startedAt.Add(elapsed)), Source: observability.SourceGateway,
			Connector: connector, Action: string(audit.ActionGuardrailVerdict), Phase: phase,
			Correlation: correlation,
			Provenance:  observability.FamilyProvenanceInput{Producer: proxyGuardrailV8Producer},
		},
		Outcome: proxyGuardrailV8Outcome(effective), Kind: proxyGuardrailPhaseKind(phase),
		StartTimeUnixNano: uint64(startedAt.UnixNano()), EndTimeUnixNano: uint64(startedAt.Add(elapsed).UnixNano()),
		Status:                              observability.NewTraceStatusOK(),
		DefenseClawConnectorSource:          optionalJudgeMetricText(connector),
		DefenseClawRunID:                    optionalJudgeMetricText(operation.facts.meta.RunID),
		DefenseClawEvaluationID:             observability.Present(operation.evaluationID),
		DefenseClawPolicyID:                 optionalJudgeMetricText(operation.facts.meta.PolicyID),
		DefenseClawGuardrailName:            observability.Present("proxy-guardrail"),
		DefenseClawGuardrailStrategy:        hookV8OptionalText(operation.strategy, 4096),
		DefenseClawGuardrailStage:           observability.Present(operation.facts.direction),
		DefenseClawGuardrailPhase:           phase,
		DefenseClawGuardrailDirection:       observability.Present(operation.facts.direction),
		DefenseClawGuardrailTargetType:      observability.Present(operation.facts.targetType),
		DefenseClawGuardrailLatencyMs:       observability.Present(float64(elapsed) / float64(time.Millisecond)),
		DefenseClawGuardrailDecision:        observability.Present(inspectTraceV8Decision(rawAction)),
		DefenseClawGuardrailRawAction:       observability.Present(rawAction),
		DefenseClawGuardrailEffectiveAction: observability.Present(effective),
		DefenseClawGuardrailMode:            observability.Present(hookDecisionV8Mode(operation.mode)),
		DefenseClawGuardrailWouldBlock:      observability.Present(wouldBlock),
		DefenseClawSecuritySeverity:         observability.Present(string(normalizedSeverity.Severity)),
		ConditionConnectorKnown:             connectorKnown,
		ConditionOperationTerminal:          true,
	}
}

func normalizeProxyGuardrailStrategy(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "regex_only", "regex_judge", "judge_first":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "regex_only"
	}
}

func normalizeProxyGuardrailPhase(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch {
	case value == "regex" || strings.HasPrefix(value, "regex."):
		return "regex"
	case value == "cisco_ai_defense" || value == "ai_defense":
		return "ai_defense"
	case value == "judge" || strings.HasPrefix(value, "judge."):
		return "judge"
	case value == "opa" || value == "policy":
		return "policy"
	case value == "finalize":
		return "finalize"
	default:
		return ""
	}
}

func proxyGuardrailPhaseKind(phase string) string {
	if phase == "ai_defense" {
		return "CLIENT"
	}
	return "INTERNAL"
}

func recordProxyGuardrailPanicV8(
	ctx context.Context,
	runtime hookLifecycleMetricV8Runtime,
	connector string,
) {
	if runtime == nil || ctx == nil {
		return
	}
	observedAt := time.Now().UTC()
	meta := hookDecisionMetricMeta(ctx, hookDecisionMetricConnector(connector))
	item := newHookV8MetricBatchItemForProducer(
		ctx, observedAt, meta, proxyGuardrailV8Producer,
		observability.EventName(observability.TelemetryInstrumentDefenseClawPanicsTotal),
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			return builder.BuildMetricDefenseClawPanicsTotal(observability.MetricDefenseClawPanicsTotalInput{
				Envelope: envelope, Value: 1,
				DefenseClawMetricSubsystem: observability.Present(string(gatewaylog.SubsystemGuardrail)),
			})
		},
	)
	_, _ = runtime.RecordGeneratedMetricBatch(ctx, []observabilityruntime.GeneratedMetricBatchItem{item})
}

func (p *GuardrailProxy) emitProxyGuardrailObservabilityV8(
	ctx context.Context,
	direction string,
	verdict *ScanVerdict,
	elapsed time.Duration,
	mode string,
	enforced bool,
) proxyGuardrailV8Overlay {
	if p == nil || ctx == nil || verdict == nil {
		return proxyGuardrailV8Overlay{}
	}
	runtime, ok := p.observabilityV8TraceRuntime().(proxyGuardrailV8Runtime)
	if !ok || runtime == nil {
		return proxyGuardrailV8Overlay{}
	}
	signalCtx := ctx
	if verdict.TraceContext.IsValid() {
		signalCtx = trace.ContextWithSpanContext(ctx, verdict.TraceContext)
	}
	facts, ok := proxyGuardrailV8FactsFrom(signalCtx, p.connectorName(), direction, verdict, elapsed, mode, enforced)
	if !ok {
		return proxyGuardrailV8Overlay{}
	}
	overlay := facts.overlay()

	input, inputOK := facts.traceInput(signalCtx)
	var guardrailTrace *observabilityruntime.GuardrailApplyTrace
	if inputOK && !verdict.GeneratedTraceOwned {
		input.Envelope.ProjectionPolicy = proxyGuardrailTraceProjectionPolicy(
			signalCtx, verdict.RedactionEnabled,
		)
		started, span, err := runtime.StartGuardrailApplyTrace(signalCtx, input)
		if err == nil {
			guardrailTrace = span
			if started != nil {
				signalCtx = started
			}
		}
	}
	if guardrailTrace != nil {
		defer guardrailTrace.Abort()
	}

	if err := facts.emitEvaluationLog(signalCtx, runtime); err != nil {
		fmt.Fprintf(os.Stderr, "[guardrail] generated proxy evaluation log failed: %v\n", err)
	}
	if facts.enforced {
		if err := facts.emitEnforcementLog(signalCtx, runtime); err != nil {
			fmt.Fprintf(os.Stderr, "[guardrail] generated proxy enforcement log failed: %v\n", err)
		}
	}
	facts.recordMetrics(signalCtx, runtime)
	if guardrailTrace != nil {
		_ = guardrailTrace.End(input)
	}
	return overlay
}

func (facts proxyGuardrailV8Facts) overlay() proxyGuardrailV8Overlay {
	timestamp := uint64(facts.observedAt.UnixNano())
	evaluationID := observability.Present(facts.evaluationID)
	decision := observability.Present(facts.decision)
	effective := observability.Present(facts.effective)
	severity := observability.Present(string(facts.severity))
	wouldBlock := observability.Present(facts.wouldBlock)
	enforced := observability.Present(facts.enforced)
	switch facts.targetType {
	case "prompt":
		event, err := observability.NewSpanAgentInvokeGuardrailDecisionEvent(
			observability.SpanAgentInvokeGuardrailDecisionEventInput{
				TimeUnixNano: timestamp, DefenseClawEvaluationID: evaluationID,
				DefenseClawGuardrailDecision: decision, DefenseClawGuardrailEffectiveAction: effective,
				DefenseClawSecuritySeverity: severity, DefenseClawGuardrailWouldBlock: wouldBlock,
				DefenseClawGuardrailEnforced: enforced,
			},
		)
		if err == nil {
			return proxyGuardrailV8Overlay{agentEvents: []observability.TraceEventInput{event}}
		}
	case "completion", "tool_call":
		event, err := observability.NewSpanModelChatGuardrailDecisionEvent(
			observability.SpanModelChatGuardrailDecisionEventInput{
				TimeUnixNano: timestamp, DefenseClawEvaluationID: evaluationID,
				DefenseClawGuardrailDecision: decision, DefenseClawGuardrailEffectiveAction: effective,
				DefenseClawSecuritySeverity: severity, DefenseClawGuardrailWouldBlock: wouldBlock,
				DefenseClawGuardrailEnforced: enforced,
			},
		)
		if err == nil {
			return proxyGuardrailV8Overlay{modelEvents: []observability.TraceEventInput{event}}
		}
	}
	return proxyGuardrailV8Overlay{}
}

func proxyGuardrailV8FactsFrom(
	ctx context.Context,
	connector string,
	direction string,
	verdict *ScanVerdict,
	elapsed time.Duration,
	mode string,
	enforced bool,
) (proxyGuardrailV8Facts, bool) {
	severity := observability.NormalizeSeverity(firstNonEmpty(verdict.Severity, "NONE"))
	if !severity.Valid || !severity.Present || !hookModelV8Identifier(verdict.EvaluationID) {
		return proxyGuardrailV8Facts{}, false
	}
	if elapsed < 0 {
		elapsed = 0
	}
	connector = hookDecisionMetricConnector(connector)
	rawAction := normalizeHookActionLabel(verdict.Action)
	if rawAction == "none" {
		rawAction = "allow"
	}
	enforced = enforced && rawAction == "block"
	wouldBlock := rawAction == "block" && !enforced
	effective := rawAction
	if wouldBlock {
		effective = "allow"
	}
	logLevel := severity.LogLevel
	if logLevel == "" {
		logLevel = observability.LogLevelInfo
	}
	observedAt := time.Now().UTC()
	targetType := proxyGuardrailTargetType(direction)
	detector := recordTelemetryScannerEnum(direction, verdict, elapsed)
	facts := proxyGuardrailV8Facts{
		connector: connector, direction: inspectTraceV8Direction(targetType), targetType: targetType,
		detector: detector, mode: hookDecisionV8Mode(mode), rawAction: rawAction,
		effective: effective, decision: inspectTraceV8Decision(rawAction),
		outcome: proxyGuardrailV8Outcome(effective), severity: severity.Severity, logLevel: logLevel,
		reason: hookV8OptionalText(verdict.Reason, 65536), evaluationID: verdict.EvaluationID,
		scanID: proxyV8StableID(verdict.ScanID), ruleIDs: inspectTraceV8RuleIDs(verdict.RuleIDs),
		findingCount: int64(len(verdict.Findings)), latencyMs: float64(elapsed) / float64(time.Millisecond),
		wouldBlock: wouldBlock, enforced: enforced, ciscoMs: verdict.CiscoElapsedMs,
		observedAt: observedAt, startedAt: observedAt.Add(-elapsed),
		meta: hookDecisionMetricMeta(ctx, connector), identity: AgentIdentityFromContext(ctx),
	}
	if verdict.Confidence > 0 && verdict.Confidence <= 1 &&
		!math.IsNaN(verdict.Confidence) && !math.IsInf(verdict.Confidence, 0) {
		facts.confidence = observability.Present(verdict.Confidence)
	}
	if enforced {
		facts.enforcement = proxyV8StableID(verdict.EnforcementID)
		if facts.enforcement == "" {
			facts.enforcement = uuid.NewString()
		}
	}
	return facts, true
}

func (facts proxyGuardrailV8Facts) correlation(ctx context.Context) observability.Correlation {
	correlation := observability.Correlation{
		RunID: proxyV8StableID(facts.meta.RunID), RequestID: proxyV8StableID(facts.meta.RequestID),
		SessionID: proxyV8StableID(facts.meta.SessionID), TurnID: proxyV8StableID(facts.meta.TurnID),
		AgentID: proxyV8StableID(facts.meta.AgentID), AgentInstanceID: proxyV8StableID(facts.identity.AgentInstanceID),
		PolicyID: proxyV8StableID(facts.meta.PolicyID), EvaluationID: facts.evaluationID,
		ScanID: facts.scanID, EnforcementActionID: facts.enforcement,
		ToolInvocationID: proxyV8StableID(facts.meta.ToolID), ConnectorID: proxyV8StableID(facts.connector),
		SidecarInstanceID: proxyV8StableID(facts.identity.SidecarInstanceID),
	}
	if spanContext := trace.SpanContextFromContext(ctx); spanContext.IsValid() {
		correlation.TraceID = spanContext.TraceID().String()
		correlation.SpanID = spanContext.SpanID().String()
	}
	return correlation
}

func (facts proxyGuardrailV8Facts) envelope(
	ctx context.Context,
	snapshot observabilityruntime.EmitContext,
) observability.FamilyEnvelopeInput {
	connector := facts.connector
	if connector == "unknown" {
		connector = ""
	}
	return observability.FamilyEnvelopeInput{
		ObservedAt: observability.Present(facts.observedAt),
		Source:     observability.SourceGateway, Connector: connector,
		Action: string(audit.ActionGuardrailVerdict), Phase: "finalize",
		Correlation: facts.correlation(ctx),
		Provenance: observability.FamilyProvenanceInput{
			Producer: proxyGuardrailV8Producer, BinaryVersion: version.Current().BinaryVersion,
			ConfigGeneration: int64(snapshot.Generation()), ConfigDigest: snapshot.Digest(),
		},
	}
}

func (facts proxyGuardrailV8Facts) routeConnector() string {
	if facts.connector == "unknown" {
		return ""
	}
	return facts.connector
}

func (facts proxyGuardrailV8Facts) enforcementEnvelope(
	ctx context.Context,
	snapshot observabilityruntime.EmitContext,
) observability.FamilyEnvelopeInput {
	envelope := facts.envelope(ctx, snapshot)
	envelope.Action = string(audit.ActionBlock)
	envelope.Phase = "apply"
	return envelope
}

func (facts proxyGuardrailV8Facts) traceInput(ctx context.Context) (observability.SpanGuardrailApplyInput, bool) {
	connector := facts.connector
	connectorKnown := connector != "unknown"
	if !connectorKnown {
		connector = ""
	}
	correlation := facts.correlation(ctx)
	correlation.ConnectorID = connector
	events := make([]observability.TraceEventInput, 0, len(facts.ruleIDValues())+2)
	for _, ruleID := range facts.ruleIDValues() {
		event, err := observability.NewSpanGuardrailApplySecurityFindingObservedEvent(
			observability.SpanGuardrailApplySecurityFindingObservedEventInput{
				TimeUnixNano:                uint64(facts.observedAt.UnixNano()),
				DefenseClawEvaluationID:     observability.Present(facts.evaluationID),
				DefenseClawScanID:           optionalJudgeMetricText(facts.scanID),
				DefenseClawPolicyID:         optionalJudgeMetricText(facts.meta.PolicyID),
				DefenseClawFindingRuleID:    observability.Present(ruleID),
				DefenseClawSecuritySeverity: observability.Present(string(facts.severity)),
			},
		)
		if err != nil {
			return observability.SpanGuardrailApplyInput{}, false
		}
		events = append(events, event)
	}
	decisionEvent, err := observability.NewSpanGuardrailApplyGuardrailDecisionEvent(
		observability.SpanGuardrailApplyGuardrailDecisionEventInput{
			TimeUnixNano:                        uint64(facts.observedAt.UnixNano()),
			DefenseClawEvaluationID:             observability.Present(facts.evaluationID),
			DefenseClawGuardrailDecision:        observability.Present(facts.decision),
			DefenseClawGuardrailEffectiveAction: observability.Present(facts.effective),
			DefenseClawSecuritySeverity:         observability.Present(string(facts.severity)),
			DefenseClawGuardrailWouldBlock:      observability.Present(facts.wouldBlock),
			DefenseClawGuardrailEnforced:        observability.Present(facts.enforced),
		},
	)
	if err != nil {
		return observability.SpanGuardrailApplyInput{}, false
	}
	events = append(events, decisionEvent)
	if facts.enforced {
		enforcementEvent, eventErr := observability.NewSpanGuardrailApplyEnforcementRequestedEvent(
			observability.SpanGuardrailApplyEnforcementRequestedEventInput{
				TimeUnixNano:                          uint64(facts.observedAt.UnixNano()),
				DefenseClawEnforcementID:              observability.Present(facts.enforcement),
				DefenseClawEnforcementRequestedAction: observability.Present("block"),
				DefenseClawGuardrailMode:              observability.Present(facts.mode),
			},
		)
		if eventErr != nil {
			return observability.SpanGuardrailApplyInput{}, false
		}
		events = append(events, enforcementEvent)
	}
	return observability.SpanGuardrailApplyInput{
		Envelope: observability.FamilyEnvelopeInput{
			ObservedAt: observability.Present(facts.observedAt),
			Source:     observability.SourceGateway, Connector: connector,
			Action: string(audit.ActionGuardrailVerdict), Phase: "finalize",
			Correlation: correlation,
			Provenance:  observability.FamilyProvenanceInput{Producer: proxyGuardrailV8Producer},
		},
		Outcome: facts.outcome, Kind: "INTERNAL",
		StartTimeUnixNano: uint64(facts.startedAt.UnixNano()), EndTimeUnixNano: uint64(facts.observedAt.UnixNano()),
		Status: observability.NewTraceStatusOK(), Events: events,
		DefenseClawConnectorSource:          optionalJudgeMetricText(connector),
		DefenseClawRunID:                    optionalJudgeMetricText(facts.meta.RunID),
		DefenseClawRequestID:                optionalJudgeMetricText(facts.meta.RequestID),
		DefenseClawTurnID:                   optionalJudgeMetricText(facts.meta.TurnID),
		GenAIConversationID:                 optionalJudgeMetricText(facts.meta.SessionID),
		GenAIAgentID:                        optionalJudgeMetricText(facts.meta.AgentID),
		GenAIAgentName:                      inspectTraceV8AgentName(facts.meta.AgentName),
		DefenseClawAgentType:                hookV8OptionalText(facts.identity.AgentType, 4096),
		DefenseClawAgentInstanceID:          optionalJudgeMetricText(facts.identity.AgentInstanceID),
		DefenseClawToolID:                   optionalJudgeMetricText(facts.meta.ToolID),
		GenAIToolName:                       hookV8OptionalText(facts.meta.ToolName, 4096),
		GenAIToolCallID:                     optionalJudgeMetricText(facts.meta.ToolID),
		DefenseClawDestinationApp:           optionalJudgeMetricText(facts.meta.DestinationApp),
		DefenseClawEvaluationID:             observability.Present(facts.evaluationID),
		DefenseClawScanID:                   optionalJudgeMetricText(facts.scanID),
		DefenseClawPolicyID:                 optionalJudgeMetricText(facts.meta.PolicyID),
		DefenseClawEnforcementID:            optionalJudgeMetricText(facts.enforcement),
		DefenseClawGuardrailName:            "proxy-guardrail",
		DefenseClawGuardrailStage:           observability.Present(facts.direction),
		DefenseClawGuardrailPhase:           observability.Present("finalize"),
		DefenseClawGuardrailDirection:       observability.Present(facts.direction),
		DefenseClawGuardrailTargetType:      facts.targetType,
		DefenseClawGuardrailDetectorName:    optionalJudgeMetricText(facts.detector),
		DefenseClawGuardrailLatencyMs:       observability.Present(facts.latencyMs),
		DefenseClawGuardrailRuleIds:         facts.ruleIDs,
		DefenseClawGuardrailConfidence:      facts.confidence,
		DefenseClawGuardrailFindingCount:    observability.Present(facts.findingCount),
		DefenseClawGuardrailDecision:        observability.Present(facts.decision),
		DefenseClawGuardrailRawAction:       observability.Present(facts.rawAction),
		DefenseClawGuardrailEffectiveAction: observability.Present(facts.effective),
		DefenseClawGuardrailMode:            observability.Present(facts.mode),
		DefenseClawGuardrailWouldBlock:      observability.Present(facts.wouldBlock),
		DefenseClawGuardrailEnforced:        observability.Present(facts.enforced),
		DefenseClawSecuritySeverity:         observability.Present(string(facts.severity)),
		DefenseClawGuardrailReason:          facts.reason,
		ConditionConnectorKnown:             connectorKnown, ConditionOperationTerminal: true,
	}, true
}

func (facts proxyGuardrailV8Facts) emitEvaluationLog(ctx context.Context, runtime sidecarRuntimeEmitter) error {
	classification := observability.ClassificationContext{
		Bucket:      observability.BucketGuardrailEvaluation,
		EventName:   observability.EventName(observability.TelemetryEventGuardrailEvaluationCompleted),
		RawSeverity: string(facts.severity),
	}
	producerKey := observability.ProducerKey(audit.ActionGuardrailVerdict)
	metadata, err := observabilityrouter.NewClassifiedLogMetadata(
		observability.ProducerAuditAction, producerKey, classification,
		observability.SourceGateway, facts.routeConnector(), producerKey,
	)
	if err != nil {
		return err
	}
	_, err = runtime.Emit(ctx, metadata, func(
		snapshot observabilityruntime.EmitContext,
		admission observabilityrouter.Admission,
	) (observability.Record, error) {
		if admission != observabilityrouter.AdmissionOrdinary || snapshot.Generation() > math.MaxInt64 {
			return observability.Record{}, errors.New("proxy guardrail evaluation admission is invalid")
		}
		builder, buildErr := proxyGuardrailV8Builder(facts.observedAt)
		if buildErr != nil {
			return observability.Record{}, buildErr
		}
		return builder.BuildLogGuardrailEvaluationCompleted(observability.LogGuardrailEvaluationCompletedInput{
			Envelope: facts.envelope(ctx, snapshot), Severity: observability.Present(facts.severity),
			LogLevel: observability.Present(facts.logLevel), Outcome: facts.outcome,
			GenAIConversationID:                 optionalJudgeMetricText(facts.meta.SessionID),
			GenAIAgentID:                        optionalJudgeMetricText(facts.meta.AgentID),
			GenAIAgentName:                      inspectTraceV8AgentName(facts.meta.AgentName),
			DefenseClawAgentType:                hookV8OptionalText(facts.identity.AgentType, 4096),
			DefenseClawAgentInstanceID:          optionalJudgeMetricText(facts.identity.AgentInstanceID),
			DefenseClawEvaluationID:             facts.evaluationID,
			DefenseClawScanID:                   optionalJudgeMetricText(facts.scanID),
			DefenseClawPolicyID:                 optionalJudgeMetricText(facts.meta.PolicyID),
			DefenseClawEnforcementID:            optionalJudgeMetricText(facts.enforcement),
			DefenseClawGuardrailName:            observability.Present("proxy-guardrail"),
			DefenseClawGuardrailStage:           observability.Present(facts.direction),
			DefenseClawGuardrailPhase:           observability.Present("finalize"),
			DefenseClawGuardrailDirection:       observability.Present(facts.direction),
			DefenseClawGuardrailTargetType:      observability.Present(facts.targetType),
			DefenseClawGuardrailDetectorName:    optionalJudgeMetricText(facts.detector),
			DefenseClawGuardrailLatencyMs:       observability.Present(facts.latencyMs),
			DefenseClawGuardrailRuleIds:         facts.ruleIDs,
			DefenseClawGuardrailConfidence:      facts.confidence,
			DefenseClawGuardrailFindingCount:    observability.Present(facts.findingCount),
			DefenseClawGuardrailDecision:        facts.decision,
			DefenseClawGuardrailRawAction:       observability.Present(facts.rawAction),
			DefenseClawGuardrailEffectiveAction: observability.Present(facts.effective),
			DefenseClawGuardrailMode:            observability.Present(facts.mode),
			DefenseClawGuardrailWouldBlock:      observability.Present(facts.wouldBlock),
			DefenseClawGuardrailEnforced:        observability.Present(facts.enforced),
			DefenseClawSecuritySeverity:         observability.Present(string(facts.severity)),
			DefenseClawGuardrailReason:          facts.reason,
			ConditionSecuritySeverityAvailable:  true,
		})
	})
	return err
}

func (facts proxyGuardrailV8Facts) emitEnforcementLog(ctx context.Context, runtime sidecarRuntimeEmitter) error {
	classification := observability.ClassificationContext{
		Bucket:      observability.BucketEnforcementAction,
		EventName:   observability.EventName(observability.TelemetryEventEnforcementBlockApplied),
		RawSeverity: string(facts.severity), Enforced: true,
		MandatoryFacts: observability.MandatoryFacts{EnforcedOutcome: true},
	}
	producerKey := observability.ProducerKey(audit.ActionBlock)
	metadata, err := observabilityrouter.NewClassifiedLogMetadata(
		observability.ProducerAuditAction, producerKey, classification,
		observability.SourceGateway, facts.routeConnector(), producerKey,
	)
	if err != nil {
		return err
	}
	_, err = runtime.Emit(ctx, metadata, func(
		snapshot observabilityruntime.EmitContext,
		admission observabilityrouter.Admission,
	) (observability.Record, error) {
		if snapshot.Generation() > math.MaxInt64 {
			return observability.Record{}, errors.New("proxy enforcement generation is invalid")
		}
		if admission == observabilityrouter.AdmissionFloor {
			builder, buildErr := observability.NewRecordBuilder(
				observability.ClockFunc(func() time.Time { return facts.observedAt }),
				observability.OccurrenceIDGeneratorFunc(func() (string, error) { return uuid.NewString(), nil }),
			)
			if buildErr != nil {
				return observability.Record{}, buildErr
			}
			return builder.BuildMandatoryFloorLog(observability.MandatoryFloorLogInput{
				ProducerKind: observability.ProducerAuditAction, ProducerKey: producerKey,
				ClassificationContext: classification, Source: observability.SourceGateway,
				Connector: facts.routeConnector(), Action: string(audit.ActionBlock), Phase: "apply",
				Outcome: observability.OutcomeBlocked, Correlation: facts.correlation(ctx),
				Provenance: observability.Provenance{
					Producer: proxyGuardrailV8Producer, BinaryVersion: version.Current().BinaryVersion,
					RegistrySchemaVersion: observability.CurrentRecordSchemaVersion,
					ConfigGeneration:      int64(snapshot.Generation()), ConfigDigest: snapshot.Digest(),
				},
			})
		}
		if admission != observabilityrouter.AdmissionOrdinary {
			return observability.Record{}, errors.New("proxy enforcement admission is invalid")
		}
		builder, buildErr := proxyGuardrailV8Builder(facts.observedAt)
		if buildErr != nil {
			return observability.Record{}, buildErr
		}
		return builder.BuildLogEnforcementBlockApplied(observability.LogEnforcementBlockAppliedInput{
			Envelope: facts.enforcementEnvelope(ctx, snapshot), Severity: observability.Present(facts.severity),
			LogLevel: observability.Present(facts.logLevel), Outcome: observability.OutcomeBlocked,
			DefenseClawEvaluationID:               observability.Present(facts.evaluationID),
			DefenseClawScanID:                     optionalJudgeMetricText(facts.scanID),
			DefenseClawPolicyID:                   optionalJudgeMetricText(facts.meta.PolicyID),
			DefenseClawEnforcementID:              facts.enforcement,
			DefenseClawEnforcementRequestedAction: observability.Present("block"),
			DefenseClawEnforcementEffectiveAction: "block",
			DefenseClawEnforcementInitiator:       observability.Present("guardrail-proxy"),
			MandatoryEnforcedOutcome:              true,
		})
	})
	return err
}

func (facts proxyGuardrailV8Facts) recordMetrics(ctx context.Context, runtime hookLifecycleMetricV8Runtime) {
	meta := facts.meta
	meta.Source = facts.connector
	item := func(family string, build hookV8MetricRecordBuilder) observabilityruntime.GeneratedMetricBatchItem {
		return newHookV8MetricBatchItemForProducer(
			ctx, facts.observedAt, meta, proxyGuardrailV8Producer, observability.EventName(family), build,
		)
	}
	mainScanner := telemetry.NormalizeMetricTextLabel(facts.connector + ":guardrail-proxy")
	items := []observabilityruntime.GeneratedMetricBatchItem{
		item(observability.TelemetryInstrumentDefenseClawGuardrailEvaluations,
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
				return builder.BuildMetricDefenseClawGuardrailEvaluations(observability.MetricDefenseClawGuardrailEvaluationsInput{
					Envelope: envelope, Value: 1,
					DefenseClawGuardrailEffectiveAction: observability.Present(facts.effective),
					DefenseClawConnectorSource:          observability.Present(facts.connector),
					DefenseClawMetricGuardrailScanner:   observability.Present(mainScanner),
				})
			}),
		item(observability.TelemetryInstrumentDefenseClawGuardrailLatency,
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
				return builder.BuildMetricDefenseClawGuardrailLatency(observability.MetricDefenseClawGuardrailLatencyInput{
					Envelope: envelope, Value: facts.latencyMs,
					DefenseClawConnectorSource:        observability.Present(facts.connector),
					DefenseClawMetricGuardrailScanner: observability.Present(mainScanner),
				})
			}),
	}
	if facts.ciscoMs > 0 && !math.IsNaN(facts.ciscoMs) && !math.IsInf(facts.ciscoMs, 0) {
		const ciscoScanner = "cisco-ai-defense"
		items = append(items,
			item(observability.TelemetryInstrumentDefenseClawGuardrailEvaluations,
				func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
					return builder.BuildMetricDefenseClawGuardrailEvaluations(observability.MetricDefenseClawGuardrailEvaluationsInput{
						Envelope: envelope, Value: 1,
						DefenseClawGuardrailEffectiveAction: observability.Present(facts.effective),
						DefenseClawConnectorSource:          observability.Present(facts.connector),
						DefenseClawMetricGuardrailScanner:   observability.Present(ciscoScanner),
					})
				}),
			item(observability.TelemetryInstrumentDefenseClawGuardrailLatency,
				func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
					return builder.BuildMetricDefenseClawGuardrailLatency(observability.MetricDefenseClawGuardrailLatencyInput{
						Envelope: envelope, Value: facts.ciscoMs,
						DefenseClawConnectorSource:        observability.Present(facts.connector),
						DefenseClawMetricGuardrailScanner: observability.Present(ciscoScanner),
					})
				}),
		)
	}
	_, _ = runtime.RecordGeneratedMetricBatch(ctx, items)
}

func (facts proxyGuardrailV8Facts) ruleIDValues() []string {
	values, present := facts.ruleIDs.Get()
	if !present {
		return nil
	}
	return append([]string(nil), values...)
}

func proxyGuardrailV8Builder(observedAt time.Time) (*observability.FamilyBuilder, error) {
	return observability.NewFamilyBuilder(
		observability.ClockFunc(func() time.Time { return observedAt }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) { return uuid.NewString(), nil }),
	)
}

func proxyGuardrailTargetType(direction string) string {
	switch strings.ToLower(strings.TrimSpace(direction)) {
	case "prompt":
		return "prompt"
	case "completion":
		return "completion"
	case "tool-call", "tool_call":
		return "tool_call"
	default:
		return "inspect"
	}
}

func proxyGuardrailV8Outcome(action string) observability.Outcome {
	switch action {
	case "allow":
		return observability.OutcomeAllowed
	case "block":
		return observability.OutcomeBlocked
	case "deny":
		return observability.OutcomeDenied
	case "redact":
		return observability.OutcomeRedacted
	case "confirm":
		return observability.OutcomePartial
	default:
		return observability.OutcomeCompleted
	}
}
