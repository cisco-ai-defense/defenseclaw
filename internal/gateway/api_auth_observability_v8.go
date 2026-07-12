// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"math"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/version"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"
)

const (
	apiAuthenticationLogV8Producer      = "gateway_api"
	apiAuthenticationMetricV8Producer   = "gateway.api.authentication"
	proxyAuthenticationLogV8Producer    = "gateway_proxy"
	proxyAuthenticationMetricV8Producer = "gateway.proxy.authentication"
)

// emitAPIAuthenticationFailureV8 returns true as soon as the canonical runtime
// owns this occurrence. Ownership is deliberately independent of the eventual
// build or persistence result: callers must never fall back to a second legacy
// event after selecting a runtime generation.
func (a *APIServer) emitAPIAuthenticationFailureV8(ctx context.Context, reason string) bool {
	if a == nil {
		return false
	}
	return emitProtectedBoundaryAuthenticationFailureV8(
		ctx,
		a.observabilityV8RuntimeEmitter(),
		observability.SourceOperatorAPI,
		apiAuthenticationLogV8Producer,
		apiAuthenticationMetricV8Producer,
		"sidecar-api",
		reason,
	)
}

func emitProtectedBoundaryAuthenticationFailureV8(
	ctx context.Context,
	emitter sidecarRuntimeEmitter,
	source observability.Source,
	logProducer string,
	metricProducer string,
	route string,
	reason string,
) bool {
	if emitter == nil {
		return false
	}
	if ctx == nil {
		ctx = context.Background()
	}

	producerKey := observability.ProducerKey(audit.ActionAPIAuthFailure)
	classification := observability.ClassificationContext{
		EventName:   observability.EventName(observability.TelemetryEventAuthenticationFailed),
		RawSeverity: "WARN",
		MandatoryFacts: observability.MandatoryFacts{
			ProtectedBoundaryAuthFailure: true,
		},
	}
	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerAuditAction,
		producerKey,
		classification,
		source,
		"",
		producerKey,
	)
	if err != nil {
		return true
	}

	// metricReason is supplied only by fixed middleware branches. Still use an
	// explicit allowlist so a future caller cannot turn this metadata field into
	// an error, path, header, token, address, or user-agent exfiltration channel.
	canonicalReason := apiAuthenticationFailureReason(reason)
	_, _ = emitter.Emit(ctx, metadata, func(
		snapshot observabilityruntime.EmitContext,
		admission router.Admission,
	) (observability.Record, error) {
		if snapshot.Generation() > math.MaxInt64 || !observability.IsStableToken(snapshot.Digest()) {
			return observability.Record{}, &apiAuthenticationV8Error{}
		}
		provenance := observability.Provenance{
			Producer:              logProducer,
			BinaryVersion:         version.Current().BinaryVersion,
			RegistrySchemaVersion: observability.CurrentRecordSchemaVersion,
			ConfigGeneration:      int64(snapshot.Generation()),
			ConfigDigest:          snapshot.Digest(),
		}
		correlation := authenticationFailureCorrelation(ctx)
		clock := observability.ClockFunc(func() time.Time { return time.Now().UTC() })
		ids := observability.OccurrenceIDGeneratorFunc(func() (string, error) {
			return uuid.NewString(), nil
		})

		if admission == router.AdmissionFloor {
			builder, buildErr := observability.NewRecordBuilder(clock, ids)
			if buildErr != nil {
				return observability.Record{}, &apiAuthenticationV8Error{}
			}
			return builder.BuildMandatoryFloorLog(observability.MandatoryFloorLogInput{
				ProducerKind:          observability.ProducerAuditAction,
				ProducerKey:           producerKey,
				ClassificationContext: classification,
				Source:                source,
				Action:                string(audit.ActionAPIAuthFailure),
				Phase:                 "authentication",
				Outcome:               observability.OutcomeRejected,
				Correlation:           correlation,
				Provenance:            provenance,
			})
		}
		if admission != router.AdmissionOrdinary {
			return observability.Record{}, &apiAuthenticationV8Error{}
		}

		builder, buildErr := observability.NewFamilyBuilder(clock, ids)
		if buildErr != nil {
			return observability.Record{}, &apiAuthenticationV8Error{}
		}
		reasonValue := observability.Absent[string]()
		if canonicalReason != "" {
			reasonValue = observability.Present(canonicalReason)
		}
		return builder.BuildLogAuthenticationFailed(observability.LogAuthenticationFailedInput{
			Envelope: observability.FamilyEnvelopeInput{
				Source:      source,
				Action:      string(audit.ActionAPIAuthFailure),
				Phase:       "authentication",
				Correlation: correlation,
				Provenance: observability.FamilyProvenanceInput{
					Producer:         provenance.Producer,
					BinaryVersion:    provenance.BinaryVersion,
					ConfigGeneration: provenance.ConfigGeneration,
					ConfigDigest:     provenance.ConfigDigest,
				},
			},
			Severity:                              observability.Present(observability.SeverityMedium),
			LogLevel:                              observability.Present(observability.LogLevelWarn),
			Outcome:                               observability.OutcomeRejected,
			DefenseClawAdminOperation:             string(audit.ActionAPIAuthFailure),
			DefenseClawAdminReason:                reasonValue,
			ConditionAdminPrincipalKnown:          false,
			MandatoryProtectedBoundaryAuthFailure: true,
		})
	})
	recordAuthenticationFailureMetricV8(
		ctx, emitter, source, metricProducer, route, canonicalReason,
	)
	return true
}

func (a *APIServer) recordAPIAuthenticationFailureMetricV8(ctx context.Context, route, reason string) {
	if a == nil || ctx == nil {
		return
	}
	recordAuthenticationFailureMetricV8(
		ctx,
		a.observabilityV8RuntimeEmitter(),
		observability.SourceOperatorAPI,
		apiAuthenticationMetricV8Producer,
		route,
		reason,
	)
}

func recordAuthenticationFailureMetricV8(
	ctx context.Context,
	emitter sidecarRuntimeEmitter,
	source observability.Source,
	producer string,
	route string,
	reason string,
) {
	if ctx == nil || emitter == nil {
		return
	}
	runtime, ok := emitter.(hookLifecycleMetricV8Runtime)
	if !ok || runtime == nil {
		return
	}
	route = strings.TrimSpace(route)
	if route == "" {
		route = "sidecar-api"
	}
	reason = httpAuthenticationMetricReason(reason)
	observedAt := time.Now().UTC()
	item := observabilityruntime.GeneratedMetricBatchItem{
		Family: observability.EventName(observability.TelemetryInstrumentDefenseClawHTTPAuthFailures),
		Builder: func(snapshot observabilityruntime.EmitContext) (observability.Record, error) {
			if snapshot.Generation() > math.MaxInt64 {
				return observability.Record{}, &apiAuthenticationV8Error{}
			}
			builder, err := observability.NewFamilyBuilder(
				observability.ClockFunc(func() time.Time { return observedAt }),
				observability.OccurrenceIDGeneratorFunc(func() (string, error) { return uuid.NewString(), nil }),
			)
			if err != nil {
				return observability.Record{}, &apiAuthenticationV8Error{}
			}
			return builder.BuildMetricDefenseClawHTTPAuthFailures(
				observability.MetricDefenseClawHTTPAuthFailuresInput{
					Envelope: observability.FamilyEnvelopeInput{
						Source: source, Action: string(audit.ActionAPIAuthFailure),
						Phase: "authentication", Correlation: authenticationFailureCorrelation(ctx),
						Provenance: observability.FamilyProvenanceInput{
							Producer:         producer,
							BinaryVersion:    version.Current().BinaryVersion,
							ConfigGeneration: int64(snapshot.Generation()), ConfigDigest: snapshot.Digest(),
						},
					},
					Value: 1, HTTPRoute: observability.Present(route),
					DefenseClawMetricReason: observability.Present(reason),
				},
			)
		},
	}
	_, _ = runtime.RecordGeneratedMetricBatch(ctx, []observabilityruntime.GeneratedMetricBatchItem{item})
}

// apiAuthenticationV8Error intentionally carries no wrapped error or request
// data. The runtime health channel reports canonical pipeline failures without
// making authentication input part of an error string.
type apiAuthenticationV8Error struct{}

func (*apiAuthenticationV8Error) Error() string {
	return "canonical API authentication failure emission failed"
}

func apiAuthenticationFailureReason(reason string) string {
	switch reason {
	case "no_token_configured",
		"missing_token",
		"invalid_token",
		"sec_fetch_site_rejected",
		"origin_blocked",
		"bad_content_type",
		"csrf_mismatch_options",
		"csrf_mismatch":
		return reason
	default:
		return ""
	}
}

func httpAuthenticationMetricReason(reason string) string {
	switch reason {
	case "scoped_otlp_rejects_header_token", "invalid_scoped_path_token":
		return reason
	default:
		if canonical := apiAuthenticationFailureReason(reason); canonical != "" {
			return canonical
		}
		return "unknown"
	}
}

func authenticationFailureCorrelation(ctx context.Context) observability.Correlation {
	// Authentication has not succeeded, so no caller-supplied agent, session,
	// connector, user, tool, or destination identity is trusted here. W3C IDs
	// remain useful transport correlation and do not grant identity authority.
	traceID := TraceIDFromContext(ctx)
	spanID := ""
	if span := trace.SpanFromContext(ctx); span != nil && span.SpanContext().IsValid() {
		if traceID == "" {
			traceID = span.SpanContext().TraceID().String()
		}
		spanID = span.SpanContext().SpanID().String()
	}
	return observability.Correlation{
		RunID:             gatewaylog.ProcessRunID(),
		RequestID:         RequestIDFromContext(ctx),
		TraceID:           traceID,
		SpanID:            spanID,
		SidecarInstanceID: gatewaylog.SidecarInstanceID(),
	}
}
