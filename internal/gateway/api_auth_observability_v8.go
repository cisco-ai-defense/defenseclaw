// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"math"
	"regexp"
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
func (a *APIServer) emitAPIAuthenticationFailureV8(ctx context.Context, reason string, facts apiAuthenticationFailureFacts) bool {
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
		facts,
	)
}

// apiAuthenticationFailureFacts are what a refusal row may name beyond the
// reason. Principal is set only for a caller the gateway has proven (the
// hook-socket peer, or the account of a per-user credential that was
// presented with another identity); nothing an unauthenticated caller sent
// is recorded as its identity.
type apiAuthenticationFailureFacts struct {
	Principal   string // "uid:1001", "sid:S-1-5-21-..."
	AuthnMethod string
	Connector   string
	Route       string
}

// apiAuthenticationFailureFactsFor collects the verified facts of a refused
// request.
func apiAuthenticationFailureFactsFor(ctx context.Context, route, connectorName string) apiAuthenticationFailureFacts {
	facts := apiAuthenticationFailureFacts{Route: route, Connector: connectorName}
	if caller, ok := verifiedAuditCaller(ctx); ok {
		facts.Principal = caller.principalRef()
		if _, peer := managedHookPeerFromContext(ctx); peer {
			facts.AuthnMethod = "hook_socket_peer"
		} else {
			facts.AuthnMethod = "user_scoped_credential"
		}
	}
	if facts.Connector == "" && ctx != nil {
		facts.Connector = authenticatedHookConnector(ctx)
		if facts.Connector == "" {
			facts.Connector = authenticatedInspectConnector(ctx)
		}
	}
	return facts
}

// authFailureRefPattern is the shape the family's *_ref fields accept.
var authFailureRefPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]*$`)

func (f apiAuthenticationFailureFacts) principalRef() observability.Optional[string] {
	if f.Principal == "" || len(f.Principal) > 256 || !authFailureRefPattern.MatchString(f.Principal) {
		return observability.Absent[string]()
	}
	return observability.Present(f.Principal)
}

// targetRef is "route:<route>", with characters the field does not accept
// (a pattern's braces or spaces) replaced.
func (f apiAuthenticationFailureFacts) targetRef() observability.Optional[string] {
	route := strings.TrimSpace(f.Route)
	if route == "" {
		return observability.Absent[string]()
	}
	cleaned := strings.Map(func(c rune) rune {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '.', c == '_', c == ':', c == '/', c == '-':
			return c
		}
		return '_'
	}, route)
	ref := "route:" + cleaned
	if len(ref) > 1024 {
		ref = ref[:1024]
	}
	return observability.Present(ref)
}

func (f apiAuthenticationFailureFacts) connector() string {
	if observability.IsStableToken(f.Connector) {
		return f.Connector
	}
	return ""
}

func emitProtectedBoundaryAuthenticationFailureV8(
	ctx context.Context,
	emitter sidecarRuntimeEmitter,
	source observability.Source,
	logProducer string,
	metricProducer string,
	route string,
	reason string,
	facts apiAuthenticationFailureFacts,
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
		facts.connector(),
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
		if logReason := apiAuthenticationFailureLogReason(reason); logReason != "" {
			reasonValue = observability.Present(logReason)
		}
		principal := facts.principalRef()
		authnMethod := observability.Absent[string]()
		if principal.IsPresent() && facts.AuthnMethod != "" {
			authnMethod = observability.Present(facts.AuthnMethod)
		}
		return builder.BuildLogAuthenticationFailed(observability.LogAuthenticationFailedInput{
			Envelope: observability.FamilyEnvelopeInput{
				Source:      source,
				Connector:   facts.connector(),
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
			DefenseClawAdminPrincipalRef:          principal,
			DefenseClawAdminAuthnMethod:           authnMethod,
			DefenseClawAdminTargetRef:             facts.targetRef(),
			ConditionAdminPrincipalKnown:          principal.IsPresent(),
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

// apiAuthenticationFailureLogReason is the reason a refusal row names: the
// canonical token reasons plus the fixed standalone refusal reasons (hook
// socket authorization, per-user credential identity and listener proof).
// Like apiAuthenticationFailureReason it is an allowlist of constants, never
// caller input.
func apiAuthenticationFailureLogReason(reason string) string {
	if canonical := apiAuthenticationFailureReason(reason); canonical != "" {
		return canonical
	}
	switch reason {
	case managedHookReasonPeerUnverified,
		managedHookReasonUIDUnregistered,
		managedHookReasonRootDenied,
		managedHookReasonLedgerUnavailable,
		managedHookReasonConnectorUnknown,
		userScopedIdentityMismatchReason,
		userScopedListenerProofRefusedReason,
		"invalid_scoped_header_token",
		"scoped_otlp_rejects_header_token",
		"invalid_scoped_path_token",
		"invalid_acp_signed_request",
		"missing_acp_authenticated_transport",
		"invalid_acp_scoped_token":
		return reason
	}
	return ""
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
