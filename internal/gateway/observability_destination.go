// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinationtest"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/version"
	"github.com/google/uuid"
)

const (
	destinationTestClient = "python-cli"
	destinationTestAction = "observability.destination.test"
)

type destinationTestActivityErrorCode string

const (
	destinationTestInvalidGraph    destinationTestActivityErrorCode = "invalid_graph"
	destinationTestInvalidMetadata destinationTestActivityErrorCode = "invalid_metadata"
	destinationTestBuildFailed     destinationTestActivityErrorCode = "record_build_failed"
	destinationTestEmitFailed      destinationTestActivityErrorCode = "emit_failed"
)

type destinationTestActivityError struct {
	code destinationTestActivityErrorCode
}

func (err *destinationTestActivityError) Error() string {
	if err == nil {
		return "destination-test activity failed"
	}
	return "destination-test activity failed: " + string(err.code)
}

func (a *APIServer) handleObservabilityDestinationTestActivity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	clients := r.Header.Values("X-DefenseClaw-Client")
	if !destinationTestRequestIsLoopback(r) || len(clients) != 1 || clients[0] != destinationTestClient {
		http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
		return
	}
	activity, status := decodeDestinationTestActivityRequest(r.Body)
	if status != 0 {
		http.Error(w, `{"error":"invalid destination-test activity"}`, status)
		return
	}
	if _, err := a.emitDestinationTestActivity(r.Context(), activity); err != nil {
		http.Error(w, `{"error":"destination-test compliance persistence unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func destinationTestRequestIsLoopback(r *http.Request) bool {
	if r == nil {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func decodeDestinationTestActivityRequest(body io.Reader) (destinationtest.Activity, int) {
	if body == nil {
		return destinationtest.Activity{}, http.StatusBadRequest
	}
	raw, err := io.ReadAll(io.LimitReader(body, destinationtest.MaxEncodedBytes+1))
	if err != nil || len(raw) == 0 {
		return destinationtest.Activity{}, http.StatusBadRequest
	}
	if len(raw) > destinationtest.MaxEncodedBytes {
		return destinationtest.Activity{}, http.StatusRequestEntityTooLarge
	}
	if !destinationTestActivityHasUniqueKeys(raw) {
		return destinationtest.Activity{}, http.StatusBadRequest
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var activity destinationtest.Activity
	if err := decoder.Decode(&activity); err != nil {
		return destinationtest.Activity{}, http.StatusBadRequest
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return destinationtest.Activity{}, http.StatusBadRequest
	}
	if err := activity.Validate(); err != nil {
		return destinationtest.Activity{}, http.StatusBadRequest
	}
	return activity, 0
}

func destinationTestActivityHasUniqueKeys(raw []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return false
	}
	seen := make(map[string]struct{}, 6)
	for decoder.More() {
		keyToken, keyErr := decoder.Token()
		key, ok := keyToken.(string)
		if keyErr != nil || !ok {
			return false
		}
		if _, duplicate := seen[key]; duplicate {
			return false
		}
		seen[key] = struct{}{}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return false
		}
	}
	closing, err := decoder.Token()
	return err == nil && closing == json.Delim('}')
}

func (a *APIServer) emitDestinationTestActivity(
	ctx context.Context,
	activity destinationtest.Activity,
) (pipeline.LocalLogOutcome, error) {
	if a == nil || ctx == nil {
		return pipeline.LocalLogOutcome{}, &destinationTestActivityError{code: destinationTestInvalidGraph}
	}
	localOnly := a.observabilityV8LocalOnlyRuntime()
	if localOnly == nil {
		return pipeline.LocalLogOutcome{}, &destinationTestActivityError{code: destinationTestInvalidGraph}
	}
	eventName, phase, outcome := destinationTestActivitySemantics(activity)
	if eventName == "" {
		return pipeline.LocalLogOutcome{}, &destinationTestActivityError{code: destinationTestInvalidMetadata}
	}
	classification := observability.ClassificationContext{
		Bucket:      observability.BucketComplianceActivity,
		EventName:   eventName,
		RawSeverity: "INFO",
		MandatoryFacts: observability.MandatoryFacts{
			DestinationTestActivity: true,
		},
	}
	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerGatewayEvent,
		observability.ProducerKey("destination_test"),
		classification,
		observability.SourceCLI,
		destinationTestClient,
		observability.ProducerKey(destinationTestAction),
	)
	if err != nil {
		return pipeline.LocalLogOutcome{}, &destinationTestActivityError{code: destinationTestInvalidMetadata}
	}

	result, emitErr := localOnly.EmitLocalOnly(ctx, metadata, func(
		snapshot observabilityruntime.EmitContext,
		admission router.Admission,
	) (observability.Record, error) {
		if snapshot.Generation() > math.MaxInt64 {
			return observability.Record{}, &destinationTestActivityError{code: destinationTestBuildFailed}
		}
		provenance := observability.FamilyProvenanceInput{
			Producer: "defenseclaw", BinaryVersion: version.Current().BinaryVersion,
			ConfigGeneration: int64(snapshot.Generation()), ConfigDigest: snapshot.Digest(),
		}
		correlation := destinationTestActivityCorrelation(ctx)
		if admission == router.AdmissionFloor {
			builder, buildErr := observability.NewRecordBuilder(
				observability.ClockFunc(func() time.Time { return time.Now().UTC() }),
				observability.OccurrenceIDGeneratorFunc(func() (string, error) { return uuid.NewString(), nil }),
			)
			if buildErr != nil {
				return observability.Record{}, &destinationTestActivityError{code: destinationTestBuildFailed}
			}
			return builder.BuildMandatoryFloorLog(observability.MandatoryFloorLogInput{
				ProducerKind:          observability.ProducerGatewayEvent,
				ProducerKey:           observability.ProducerKey("destination_test"),
				ClassificationContext: classification,
				Source:                observability.SourceCLI,
				Connector:             destinationTestClient,
				Action:                destinationTestAction,
				Phase:                 phase,
				Outcome:               outcome,
				Correlation:           correlation,
				Provenance: observability.Provenance{
					Producer: "defenseclaw", BinaryVersion: version.Current().BinaryVersion,
					RegistrySchemaVersion: observability.CurrentRecordSchemaVersion,
					ConfigGeneration:      int64(snapshot.Generation()), ConfigDigest: snapshot.Digest(),
				},
			})
		}
		if admission != router.AdmissionOrdinary {
			return observability.Record{}, &destinationTestActivityError{code: destinationTestBuildFailed}
		}
		builder, buildErr := observability.NewFamilyBuilder(
			observability.ClockFunc(func() time.Time { return time.Now().UTC() }),
			observability.OccurrenceIDGeneratorFunc(func() (string, error) { return uuid.NewString(), nil }),
		)
		if buildErr != nil {
			return observability.Record{}, &destinationTestActivityError{code: destinationTestBuildFailed}
		}
		envelope := observability.FamilyEnvelopeInput{
			Source: observability.SourceCLI, Connector: destinationTestClient,
			Action: destinationTestAction, Phase: phase, Correlation: correlation,
			Provenance: provenance,
		}
		if activity.Phase == "attempt" {
			return builder.BuildLogDestinationTestAttempted(observability.LogDestinationTestAttemptedInput{
				Envelope:                          envelope,
				Severity:                          observability.Present(observability.SeverityInfo),
				LogLevel:                          observability.Present(observability.LogLevelInfo),
				Outcome:                           observability.OutcomeAttempted,
				DefenseClawAdminOperation:         destinationTestAction,
				DefenseClawAdminOrigin:            observability.Present("cli"),
				DefenseClawDestinationID:          activity.Destination,
				DefenseClawDestinationTestProbeID: activity.ProbeID,
				DefenseClawDestinationTestMode:    activity.Mode,
				DefenseClawDestinationTestResult:  activity.Result,
				MandatoryDestinationTestActivity:  true,
			})
		}
		failureClass := observability.Absent[string]()
		failed := activity.Result == "failed"
		if failed {
			failureClass = observability.Present(activity.FailureClass)
		}
		return builder.BuildLogDestinationTestCompleted(observability.LogDestinationTestCompletedInput{
			Envelope:                               envelope,
			Severity:                               observability.Present(observability.SeverityInfo),
			LogLevel:                               observability.Present(observability.LogLevelInfo),
			Outcome:                                outcome,
			DefenseClawAdminOperation:              destinationTestAction,
			DefenseClawAdminOrigin:                 observability.Present("cli"),
			DefenseClawDestinationID:               activity.Destination,
			DefenseClawDestinationTestProbeID:      activity.ProbeID,
			DefenseClawDestinationTestMode:         activity.Mode,
			DefenseClawDestinationTestResult:       activity.Result,
			DefenseClawDestinationTestFailureClass: failureClass,
			ConditionDestinationTestFailed:         failed,
			MandatoryDestinationTestActivity:       true,
		})
	})
	if emitErr != nil || !result.LocalPersisted() {
		return result, &destinationTestActivityError{code: destinationTestEmitFailed}
	}
	return result, nil
}

func destinationTestActivitySemantics(
	activity destinationtest.Activity,
) (observability.EventName, string, observability.Outcome) {
	switch activity.Phase {
	case "attempt":
		return observability.EventName(observability.TelemetryEventDestinationTestAttempted), "attempt", observability.OutcomeAttempted
	case "outcome":
		if activity.Result == "succeeded" {
			return observability.EventName(observability.TelemetryEventDestinationTestCompleted), "outcome", observability.OutcomeCompleted
		}
		if activity.Result == "failed" {
			return observability.EventName(observability.TelemetryEventDestinationTestCompleted), "outcome", observability.OutcomeFailed
		}
	}
	return "", "", ""
}

func destinationTestActivityCorrelation(ctx context.Context) observability.Correlation {
	return observability.Correlation{
		RunID: gatewaylog.ProcessRunID(), RequestID: RequestIDFromContext(ctx),
		SidecarInstanceID: gatewaylog.SidecarInstanceID(), ConnectorID: destinationTestClient,
	}
}
