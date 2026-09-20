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

package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
)

// ReporterError is deliberately value-free. Runtime-graph retries and callers
// can classify a failure without retaining a database diagnostic, path, field
// value, endpoint, or projected record.
type ReporterError struct{}

func (*ReporterError) Error() string { return "observability runtime report delivery failed" }

type reportDeliveryKey struct {
	sequence uint64
	index    uint32
}

// ReloadReporter persists runtime-graph compliance and health transitions
// through the exact immutable plan named by the report's graph. It is process
// stable, while the local projection binding and writer are reconstructed from
// that graph for each first delivery.
//
// Delivery identities are manager-scoped, so processRunID is part of the
// deterministic record ID. Successful identities are retained for the process
// lifetime, making runtimegraph retries idempotent without storing raw records.
type ReloadReporter struct {
	store        *audit.Store
	engine       *redaction.Engine
	signer       audit.ProjectionIntegritySigner
	processRunID string
	binary       string

	mu        sync.Mutex
	delivered map[reportDeliveryKey]struct{}
}

func NewReloadReporter(
	store *audit.Store,
	engine *redaction.Engine,
	signer audit.ProjectionIntegritySigner,
	processRunID string,
	binaryVersion string,
) (*ReloadReporter, error) {
	if store == nil || !store.Ready() || engine == nil || processRunID == "" ||
		len(processRunID) > observability.MaxCorrelationIDBytes || binaryVersion == "" ||
		len(binaryVersion) > observability.MaxBinaryVersionBytes {
		return nil, &ReporterError{}
	}
	return &ReloadReporter{
		store: store, engine: engine, signer: signer,
		processRunID: processRunID, binary: binaryVersion,
		delivered: make(map[reportDeliveryKey]struct{}),
	}, nil
}

func (reporter *ReloadReporter) PlatformHealth(
	graph *runtimegraph.Graph,
	report runtimegraph.Report,
) error {
	return reporter.persist(graph, report, true)
}

func (reporter *ReloadReporter) ComplianceActivity(
	graph *runtimegraph.Graph,
	report runtimegraph.Report,
) error {
	return reporter.persist(graph, report, false)
}

func (reporter *ReloadReporter) persist(
	graph *runtimegraph.Graph,
	report runtimegraph.Report,
	health bool,
) error {
	if reporter == nil || reporter.store == nil || reporter.engine == nil ||
		graph == nil || graph.Plan() == nil || graph.Digest() == "" ||
		report.Generation != graph.Generation() || report.Generation == 0 ||
		report.OccurredAt.IsZero() || report.DeliverySequence == 0 ||
		!validRuntimeReportChannel(report, health) {
		return &ReporterError{}
	}

	key := reportDeliveryKey{sequence: report.DeliverySequence, index: report.DeliveryIndex}
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	if _, ok := reporter.delivered[key]; ok {
		return nil
	}

	record, err := reporter.buildRecord(graph, report, health)
	if err != nil {
		return &ReporterError{}
	}
	binding, err := pipeline.NewLocalProjectionBinding(graph.Plan(), reporter.engine)
	if err != nil {
		return &ReporterError{}
	}
	writer, err := audit.NewEventHistoryWriter(
		reporter.store,
		reporter.signer,
		nil, // Persisting writer-health through the same failing store would recurse.
		binding,
	)
	if err != nil {
		return &ReporterError{}
	}
	profileName, err := graph.Plan().ResolveLocalRedactionProfile(record.Bucket())
	if err != nil {
		return &ReporterError{}
	}
	catalog, err := graph.Plan().RedactionProfileCatalog()
	if err != nil {
		return &ReporterError{}
	}
	profile, ok := catalog.Resolve(profileName)
	if !ok {
		return &ReporterError{}
	}
	projection, _, err := reporter.engine.Project(record, profile)
	if err != nil {
		return &ReporterError{}
	}
	if err := writer.AppendContext(context.Background(), record, projection); err != nil {
		return &ReporterError{}
	}
	reporter.delivered[key] = struct{}{}
	return nil
}

func (reporter *ReloadReporter) buildRecord(
	graph *runtimegraph.Graph,
	report runtimegraph.Report,
	health bool,
) (observability.Record, error) {
	if !validRuntimeReportChannel(report, health) {
		return observability.Record{}, &ReporterError{}
	}
	recordID := reporter.recordID(report)
	builder, err := observability.NewFamilyBuilder(
		observability.ClockFunc(func() time.Time { return report.OccurredAt.UTC() }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) { return recordID, nil }),
	)
	if err != nil {
		return observability.Record{}, err
	}
	outcome, ok := runtimeReportOutcome(report.Outcome)
	if !ok {
		return observability.Record{}, &ReporterError{}
	}
	envelope := observability.FamilyEnvelopeInput{
		ObservedAt: observability.Present(report.OccurredAt),
		Source:     observability.SourceSystem,
		Phase:      runtimeReportPhase(report.Code),
		Correlation: observability.Correlation{
			RunID: reporter.processRunID,
		},
		Provenance: observability.FamilyProvenanceInput{
			Producer: "observability_runtime", BinaryVersion: reporter.binary,
			ConfigGeneration: int64(report.Generation), ConfigDigest: graph.Digest(),
		},
	}
	if health {
		envelope.Action = "subsystem.degraded"
		subsystem := report.ComponentName
		if subsystem == "" {
			subsystem = "observability_runtime"
		}
		return builder.BuildLogSubsystemDegraded(observability.LogSubsystemDegradedInput{
			Envelope: envelope, Severity: observability.Present(observability.SeverityHigh),
			Outcome: outcome, DefenseClawHealthSubsystem: subsystem,
			DefenseClawHealthState:           "failed",
			DefenseClawSchemaErrorCode:       observability.Present(string(report.Code)),
			MandatoryDurableHealthTransition: true,
		})
	}

	adminOperation := string(report.Code)
	if report.Code == runtimegraph.ReportReloadApplied {
		envelope.Action = "config.change.applied"
		return builder.BuildLogConfigChangeApplied(observability.LogConfigChangeAppliedInput{
			Envelope: envelope, Severity: observability.Present(observability.SeverityInfo),
			LogLevel: observability.Present(observability.LogLevelInfo), Outcome: outcome,
			DefenseClawAdminOperation: adminOperation, MandatoryControlPlaneMutation: true,
		})
	}
	envelope.Action = "config.reload.rejected"
	return builder.BuildLogConfigReloadRejected(observability.LogConfigReloadRejectedInput{
		Envelope: envelope, Severity: observability.Present(observability.SeverityInfo),
		LogLevel: observability.Present(observability.LogLevelInfo), Outcome: outcome,
		DefenseClawAdminOperation: adminOperation, MandatoryControlPlaneMutation: true,
	})
}

func runtimeReportPhase(code runtimegraph.ReportCode) string {
	switch code {
	case runtimegraph.ReportReloadApplied:
		return "swap"
	case runtimegraph.ReportValidationRejected, runtimegraph.ReportRestartRequired:
		return "validate"
	case runtimegraph.ReportInitializationFail:
		return "build"
	case runtimegraph.ReportCleanupFailed, runtimegraph.ReportDrainFailed:
		return "drain"
	default:
		return "validate"
	}
}

func (reporter *ReloadReporter) recordID(report runtimegraph.Report) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("defenseclaw-observability-runtime-report-v1\x00"))
	_, _ = hash.Write([]byte(reporter.processRunID))
	var identity [12]byte
	for shift := 0; shift < 8; shift++ {
		identity[shift] = byte(report.DeliverySequence >> (8 * shift))
	}
	for shift := 0; shift < 4; shift++ {
		identity[8+shift] = byte(report.DeliveryIndex >> (8 * shift))
	}
	_, _ = hash.Write(identity[:])
	return "observability-runtime-report-" + hex.EncodeToString(hash.Sum(nil))
}

func validRuntimeReport(report runtimegraph.Report) bool {
	switch report.Code {
	case runtimegraph.ReportReloadApplied,
		runtimegraph.ReportValidationRejected,
		runtimegraph.ReportRestartRequired,
		runtimegraph.ReportInitializationFail,
		runtimegraph.ReportCleanupFailed,
		runtimegraph.ReportDrainFailed:
	default:
		return false
	}
	if report.ComponentName != "" && !observability.IsStableToken(report.ComponentName) {
		return false
	}
	switch report.FieldPath {
	case "", runtimegraph.FieldLocalPath, runtimegraph.FieldJudgeBodiesPath,
		runtimegraph.FieldRetainJudgeBodies:
		return true
	default:
		return false
	}
}

// Runtime failure codes are emitted to both operator health and compliance
// activity. A successful reload is compliance activity only and must never be
// mislabeled as a degraded subsystem health transition.
func validRuntimeReportChannel(report runtimegraph.Report, health bool) bool {
	if !validRuntimeReport(report) {
		return false
	}
	switch report.Code {
	case runtimegraph.ReportReloadApplied:
		return !health
	case runtimegraph.ReportValidationRejected,
		runtimegraph.ReportRestartRequired,
		runtimegraph.ReportInitializationFail,
		runtimegraph.ReportCleanupFailed,
		runtimegraph.ReportDrainFailed:
		return true
	default:
		return false
	}
}

func runtimeReportOutcome(value string) (observability.Outcome, bool) {
	result := observability.Outcome(value)
	switch result {
	case observability.OutcomeApplied, observability.OutcomeRejected, observability.OutcomeFailed:
		return result, true
	default:
		return "", false
	}
}

var _ runtimegraph.Reporter = (*ReloadReporter)(nil)
var _ error = (*ReporterError)(nil)
