// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	mrand "math/rand/v2"
	"os"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/diagnostics"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// The endpoint health reporter sends one health report to Cisco AI Defense on
// the inventory full-scan cadence, so an administrator can see per device
// whether DefenseClaw is protecting it. It runs only on a managed Secure
// Client deployment, the only one with the CMID-authenticated AI Defense
// destination; elsewhere it starts no goroutine and no timer.
//
// Unlike inventory, a report is sent on every tick even when nothing
// changed: a heartbeat that is suppressed when nothing changes cannot prove
// the device is still reporting. The reporter has its own timer, so a hung or
// failing discovery scan cannot silence health; it becomes a reason code.

const (
	endpointHealthV8Producer = "gateway.endpoint_health"

	// endpointHealthStartupWait bounds how long the first report waits for
	// the configuration to become ready.
	endpointHealthStartupWait = 2 * time.Minute
	// endpointHealthReadyPoll is how often the startup wait checks readiness.
	endpointHealthReadyPoll = 2 * time.Second
	// endpointHealthEmitTimeout bounds one collection, build and emit.
	endpointHealthEmitTimeout = 30 * time.Second
	// endpointHealthJitterDivisor gives the same 10% jitter as discovery.
	endpointHealthJitterDivisor = 10
	// endpointHealthMaxInterval is the report_interval_s maximum the
	// registry accepts; a longer discovery cadence still reports daily.
	endpointHealthMaxInterval = 24 * time.Hour
	// endpointHealthMaxFileBytes caps the read of the previous report file.
	endpointHealthMaxFileBytes = diagnostics.MaxFileBytes
)

func init() {
	diagnostics.Register(diagnostics.HealthReportFile, endpointHealthV8Producer)
}

// endpointHealthReporterEnabled is the managed-only gate: a Secure Client
// profile on a managed_enterprise deployment, the only combination that
// compiles the release-owned AI Defense destination.
func endpointHealthReporterEnabled(cfg *config.Config) bool {
	return cfg != nil && managed.IsManagedEnterprise(cfg.DeploymentMode) && cfg.SecureClientIntegration()
}

// endpointHealthInterval is the report interval: the discovery full-scan
// cadence (which a managed deployment floors at 30 minutes and an operator
// can only lengthen), or the managed floor while discovery is not running.
func (s *Sidecar) endpointHealthInterval() time.Duration {
	interval := inventory.ManagedEnterpriseScanInterval
	if discovery := s.aiDiscoverySnapshot(); discovery != nil {
		if scan := discovery.FullScanInterval(); scan > interval {
			interval = scan
		}
	}
	return min(interval, endpointHealthMaxInterval)
}

// endpointHealthDestinationConfigured reports whether the managed AI Defense
// destination exists for cfg: it is compiled only with a Cisco AI Defense
// endpoint, and without it operator destinations hold no reserved drop route
// for the report. The endpoint can arrive after start through the Secure
// Client env_config overlay, so this is checked per report.
func endpointHealthDestinationConfigured(cfg *config.Config) bool {
	return cfg != nil && strings.TrimSpace(cfg.CiscoAIDefense.Endpoint) != ""
}

// endpointHealthReporter is the reporter's per-process state.
type endpointHealthReporter struct {
	sidecar  *Sidecar
	cursor   endpointHealthCursor
	sequence uint64
	// emit, write and now are replaced in tests.
	emit  func(ctx context.Context, report endpointHealthReport) (endpointHealthEmitResult, error)
	write func(dataDir string, content diagnostics.HealthReportFileContent) error
	now   func() time.Time
}

// endpointHealthEmitResult says whether the managed destination took the
// record.
type endpointHealthEmitResult struct {
	routedToManaged bool
}

func newEndpointHealthReporter(s *Sidecar) *endpointHealthReporter {
	r := &endpointHealthReporter{sidecar: s, now: func() time.Time { return time.Now().UTC() }}
	r.emit = r.emitV8
	r.write = func(dataDir string, content diagnostics.HealthReportFileContent) error {
		return diagnostics.WriteJSON(dataDir, diagnostics.HealthReportFile, content)
	}
	return r
}

// runEndpointHealthReporter sends the startup report, then one report per
// jittered interval and one after each committed config reload, until ctx
// ends. Nothing is sent at shutdown: AI Defense uses "not reporting".
func (s *Sidecar) runEndpointHealthReporter(ctx context.Context) {
	r := newEndpointHealthReporter(s)
	r.sequence = r.loadSequence()
	r.waitForStartup(ctx)
	if ctx.Err() != nil {
		return
	}
	r.report(ctx, endpointHealthTriggerStartup)

	timer := time.NewTimer(endpointHealthNextDelay(s.endpointHealthInterval()))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			r.report(ctx, endpointHealthTriggerScheduled)
		case <-s.endpointHealthReloadCh:
			r.report(ctx, endpointHealthTriggerConfigReload)
			// The interval may have changed; re-arm from now.
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		}
		timer.Reset(endpointHealthNextDelay(s.endpointHealthInterval()))
	}
}

// endpointHealthNextDelay is interval plus a uniform offset in [0, 10%), so a
// fleet that restarts together does not report together.
func endpointHealthNextDelay(interval time.Duration) time.Duration {
	if interval <= 0 {
		interval = inventory.ManagedEnterpriseScanInterval
	}
	jitter := interval / endpointHealthJitterDivisor
	if jitter <= 0 {
		return interval
	}
	return interval + time.Duration(mrand.Int64N(int64(jitter)))
}

// waitForStartup returns once the configuration is ready, after
// endpointHealthStartupWait, or when ctx ends.
func (r *endpointHealthReporter) waitForStartup(ctx context.Context) {
	deadline := time.NewTimer(endpointHealthStartupWait)
	defer deadline.Stop()
	poll := time.NewTicker(endpointHealthReadyPoll)
	defer poll.Stop()
	for !r.configurationReady() {
		select {
		case <-ctx.Done():
			return
		case <-deadline.C:
			return
		case <-poll.C:
		}
	}
}

func (r *endpointHealthReporter) configurationReady() bool {
	if r.sidecar == nil || r.sidecar.health == nil {
		return true
	}
	snapshot := r.sidecar.health.Snapshot()
	return snapshot.Configuration == nil || snapshot.Configuration.State == ConfigStateReady
}

// report collects, builds, emits and records one report. A failure at any
// step is logged and never affects the gateway.
func (r *endpointHealthReporter) report(ctx context.Context, trigger string) {
	cfg := r.sidecar.currentConfig()
	if !endpointHealthReporterEnabled(cfg) || !endpointHealthDestinationConfigured(cfg) {
		// A reload left the managed Secure Client deployment, or the Cisco AI
		// Defense endpoint is not configured yet; send nothing.
		return
	}
	ctx, cancel := context.WithTimeout(ctx, endpointHealthEmitTimeout)
	defer cancel()

	// The "since last report" counts are kept until a report reaches the
	// managed destination, so an undelivered report's counts are not lost.
	previousCursor := r.cursor
	sources := r.sidecar.collectEndpointHealthSources(ctx, &r.cursor)
	r.sequence++
	report := buildEndpointHealthReport(sources, endpointHealthReportMeta{
		ReportID: newEndpointHealthReportID(),
		Sequence: r.sequence,
		Trigger:  trigger,
		Interval: r.sidecar.endpointHealthInterval(),
	})

	delivery := diagnostics.HealthDelivery{At: r.now().Format(time.RFC3339)}
	result, err := r.emit(ctx, report)
	switch {
	case err != nil:
		delivery.Result = "failed"
		delivery.FailureClass = endpointHealthEmitFailureClass(err)
		fmt.Fprintf(os.Stderr, "[endpoint-health] emit %s report failed: %s\n", trigger, delivery.FailureClass)
	case result.routedToManaged:
		delivery.Result = "queued"
	default:
		delivery.Result = "not_routed"
	}
	if err != nil || !result.routedToManaged {
		r.cursor = previousCursor
	}
	delivery.CloudState = report.CloudDeliveryState
	delivery.CloudLastSuccessAt = report.CloudDeliveryLastSuccessAt

	body, err := json.Marshal(report)
	if err != nil {
		return
	}
	if err := r.write(cfg.DataDir, diagnostics.HealthReportFileContent{
		SchemaVersion: diagnostics.HealthReportFileVersion,
		BuiltAt:       r.now().Format(time.RFC3339),
		Report:        body,
		Delivery:      delivery,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "[endpoint-health] write local report: %v\n", err)
	}
}

// loadSequence continues the sequence from the last local report, so a
// restart keeps it increasing. A missing or unreadable file starts at zero;
// AI Defense orders reports by observed time first, so a reset is harmless.
func (r *endpointHealthReporter) loadSequence() uint64 {
	cfg := r.sidecar.currentConfig()
	if cfg == nil || cfg.DataDir == "" {
		return 0
	}
	raw, err := safefile.ReadRegularFileBounded(
		diagnostics.Path(cfg.DataDir, diagnostics.HealthReportFile), endpointHealthMaxFileBytes,
	)
	if err != nil {
		return 0
	}
	var content diagnostics.HealthReportFileContent
	if json.Unmarshal(raw, &content) != nil || content.SchemaVersion != diagnostics.HealthReportFileVersion {
		return 0
	}
	var previous struct {
		Sequence uint64 `json:"defenseclaw.health.sequence"`
	}
	if json.Unmarshal(content.Report, &previous) != nil || previous.Sequence > math.MaxInt64/2 {
		return 0
	}
	return previous.Sequence
}

// newEndpointHealthReportID is a random (version 4) UUID in lower case.
func newEndpointHealthReportID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// endpointHealthEmitFailureClass maps an emit error to a bounded code.
func endpointHealthEmitFailureClass(err error) string {
	var sidecarErr *sidecarObservabilityError
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "TIMEOUT"
	case errors.As(err, &sidecarErr):
		return "BUILD_FAILED"
	default:
		return "EMIT_FAILED"
	}
}

// endpointHealthSeverity maps the report status to the record severity and
// log level.
func endpointHealthSeverity(status string) (observability.Severity, observability.LogLevel) {
	switch status {
	case "unhealthy":
		return observability.SeverityHigh, observability.LogLevelError
	case "degraded":
		return observability.SeverityMedium, observability.LogLevelWarn
	case "starting":
		return observability.SeverityLow, observability.LogLevelInfo
	default:
		return observability.SeverityInfo, observability.LogLevelInfo
	}
}

// emitV8 hands the report to the v8 runtime as one platform.health record
// with the release-owned endpoint_health action, which only the managed AI
// Defense destination and local storage receive.
func (r *endpointHealthReporter) emitV8(ctx context.Context, report endpointHealthReport) (endpointHealthEmitResult, error) {
	return emitEndpointHealthV8(ctx, r.sidecar.observabilityV8Emitter(), report)
}

// emitEndpointHealthV8 emits one report through emitter.
func emitEndpointHealthV8(
	ctx context.Context,
	emitter sidecarRuntimeEmitter,
	report endpointHealthReport,
) (endpointHealthEmitResult, error) {
	if emitter == nil {
		return endpointHealthEmitResult{}, &sidecarObservabilityError{code: sidecarObservabilityInvalidBinding}
	}
	severity, logLevel := endpointHealthSeverity(report.Status)
	action := config.ObservabilityV8ManagedEndpointHealthAction
	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerGatewayEvent,
		action,
		observability.ClassificationContext{
			Bucket:      observability.BucketPlatformHealth,
			EventName:   observability.EventName(observability.TelemetryEventEndpointHealthReported),
			RawSeverity: string(severity),
		},
		observability.SourceGateway,
		"",
		action,
	)
	if err != nil {
		return endpointHealthEmitResult{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
	}
	input := endpointHealthV8Input(report)
	input.Severity = observability.Present(severity)
	input.LogLevel = observability.Present(logLevel)
	outcome, err := emitter.Emit(ctx, metadata, func(
		snapshot observabilityruntime.EmitContext,
		admission router.Admission,
	) (observability.Record, error) {
		if admission != router.AdmissionOrdinary || snapshot.Generation() > math.MaxInt64 {
			return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
		}
		builder, buildErr := aiDiscoveryV8Builder()
		if buildErr != nil {
			return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
		}
		input.Envelope = gatewayGeneratedEnvelope(
			ctx, snapshot, observability.SourceGateway, "", endpointHealthV8Producer, string(action), "report",
		)
		return builder.BuildLogEndpointHealthReported(input)
	})
	if err != nil {
		return endpointHealthEmitResult{}, err
	}
	result := endpointHealthEmitResult{routedToManaged: outcome.ManagedOnly()}
	for _, work := range outcome.OptionalWork() {
		if work.Delivery().DestinationName == config.ObservabilityV8ManagedAIDDestinationName {
			result.routedToManaged = true
		}
	}
	return result, nil
}

// endpointHealthV8Input maps the report onto the generated builder input.
// Empty optional values stay absent rather than empty strings.
func endpointHealthV8Input(report endpointHealthReport) observability.LogEndpointHealthReportedInput {
	text := func(value string) observability.Optional[string] {
		if value == "" {
			return observability.Absent[string]()
		}
		return observability.Present(value)
	}
	count := func(value uint64) int64 {
		if value > math.MaxInt64 {
			return math.MaxInt64
		}
		return int64(value)
	}

	reasons := observability.TelemetryStructuredDefenseClawHealthReasons{
		Items: make([]observability.TelemetryStructuredDefenseClawHealthReason, 0, len(report.Reasons)),
	}
	for _, reason := range report.Reasons {
		reasons.Items = append(reasons.Items, observability.TelemetryStructuredDefenseClawHealthReason{
			Code: reason.Code, Component: reason.Component, Severity: reason.Severity, Connector: text(reason.Connector),
		})
	}
	subsystems := observability.TelemetryStructuredDefenseClawHealthSubsystems{
		Items: make([]observability.TelemetryStructuredDefenseClawHealthSubsystemItem, 0, len(report.Subsystems)),
	}
	for _, subsystem := range report.Subsystems {
		subsystems.Items = append(subsystems.Items, observability.TelemetryStructuredDefenseClawHealthSubsystemItem{
			Name: subsystem.Name, State: subsystem.State, Since: text(subsystem.Since), ErrorClass: text(subsystem.ErrorClass),
		})
	}
	connectors := observability.TelemetryStructuredDefenseClawHealthHookConnectors{
		Items: make([]observability.TelemetryStructuredDefenseClawHealthHookConnector, 0, len(report.HooksConnectors)),
	}
	for _, c := range report.HooksConnectors {
		connectors.Items = append(connectors.Items, observability.TelemetryStructuredDefenseClawHealthHookConnector{
			Connector: c.Connector, Targets: int64(c.Targets), Ok: int64(c.OK), Failed: int64(c.Failed),
			Pending: int64(c.Pending), LastActivityAt: text(c.LastActivityAt), ToolInspectionMode: text(c.ToolInspectionMode),
		})
	}
	failing := observability.TelemetryStructuredDefenseClawHealthFailingTargets{
		Items: make([]observability.TelemetryStructuredDefenseClawHealthFailingTarget, 0, len(report.HooksFailingTargets)),
	}
	for _, target := range report.HooksFailingTargets {
		failing.Items = append(failing.Items, observability.TelemetryStructuredDefenseClawHealthFailingTarget{
			Connector: target.Connector, UserID: text(target.UserID), UserIDKind: text(target.UserIDKind),
			ErrorClass: target.ErrorClass, Pending: target.Pending,
		})
	}

	return observability.LogEndpointHealthReportedInput{
		Outcome:                                       observability.OutcomeCompleted,
		DefenseClawHealthReportID:                     report.ReportID,
		DefenseClawHealthSequence:                     count(report.Sequence),
		DefenseClawHealthTrigger:                      report.Trigger,
		DefenseClawHealthObservedAt:                   report.ObservedAt,
		DefenseClawHealthReportIntervalS:              report.ReportIntervalS,
		DefenseClawHealthStatus:                       report.Status,
		DefenseClawHealthReasons:                      observability.Present(reasons),
		DefenseClawHealthReasonsTruncated:             observability.Present(report.ReasonsTruncated),
		DefenseClawHealthVersionProduct:               text(report.ProductVersion),
		DefenseClawHealthVersionPolicyBundle:          text(report.PolicyBundleVersion),
		DefenseClawHealthVersionAvc:                   text(report.AVCVersion),
		DefenseClawHealthOsVersion:                    text(report.OSVersion),
		DefenseClawHealthGatewayStartedAt:             text(report.GatewayStartedAt),
		DefenseClawHealthGatewayUptimeS:               observability.Present(report.GatewayUptimeS),
		DefenseClawHealthGatewayConfiguration:         text(report.GatewayConfiguration),
		DefenseClawHealthSubsystems:                   observability.Present(subsystems),
		DefenseClawHealthSubsystemsTruncated:          observability.Present(report.SubsystemsTruncated),
		DefenseClawHealthGuardianState:                text(report.GuardianState),
		DefenseClawHealthGuardianLastPassAt:           text(report.GuardianLastPassAt),
		DefenseClawHealthHooksTargets:                 observability.Present(int64(report.HooksTargets)),
		DefenseClawHealthHooksOk:                      observability.Present(int64(report.HooksOK)),
		DefenseClawHealthHooksFailed:                  observability.Present(int64(report.HooksFailed)),
		DefenseClawHealthHooksPending:                 observability.Present(int64(report.HooksPending)),
		DefenseClawHealthHooksConnectors:              observability.Present(connectors),
		DefenseClawHealthHooksConnectorsTruncated:     observability.Present(report.HooksConnectorsTruncated),
		DefenseClawHealthHooksFailingTargets:          observability.Present(failing),
		DefenseClawHealthHooksFailingTargetsTruncated: observability.Present(report.HooksFailingTargetsTruncated),
		DefenseClawHealthInspectionAIDefense:          text(report.InspectionAIDefense),
		DefenseClawHealthInspectionUnavailableCode:    text(report.InspectionUnavailableCode),
		DefenseClawHealthInspectionCmidToken:          text(report.InspectionCMIDToken),
		DefenseClawHealthInspectionCmidLastSuccessAt:  text(report.InspectionCMIDLastSuccessAt),
		DefenseClawHealthInspectionFailOpenSinceLast:  observability.Present(count(report.InspectionFailOpenSinceLast)),
		DefenseClawHealthCloudDeliveryState:           text(report.CloudDeliveryState),
		DefenseClawHealthCloudDeliveryCircuit:         text(report.CloudDeliveryCircuit),
		DefenseClawHealthCloudDeliveryConsecutiveFailures: observability.Present(
			count(report.CloudDeliveryConsecutiveFailures)),
		DefenseClawHealthCloudDeliveryLastSuccessAt:    text(report.CloudDeliveryLastSuccessAt),
		DefenseClawHealthCloudDeliveryLastFailureClass: text(report.CloudDeliveryLastFailureClass),
		DefenseClawHealthCloudDeliveryDroppedSinceLast: observability.Present(count(report.CloudDeliveryDroppedSinceLast)),
		DefenseClawHealthLocalStoreAuditStore:          text(report.LocalStoreAuditStore),
	}
}
