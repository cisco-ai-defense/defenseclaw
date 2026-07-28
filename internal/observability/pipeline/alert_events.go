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

package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

const alertCanonicalProducer = "observability_alert_projection"

// AlertCanonicalEventFactory is one immutable runtime graph's implementation
// of audit.AlertCanonicalEventFactory. It snapshots the complete local-profile
// binding and profile catalog so a later config-source mutation cannot change
// how an in-flight transaction is projected.
type AlertCanonicalEventFactory struct {
	builder    *observability.RecordBuilder
	projector  Projector
	catalog    redaction.ProfileCatalog
	local      map[observability.Bucket]redaction.ProfileName
	provenance observability.Provenance
	planDigest string
}

// GraphDigest identifies the immutable compiled graph captured by the factory.
func (factory *AlertCanonicalEventFactory) GraphDigest() string {
	if factory == nil {
		return ""
	}
	return factory.planDigest
}

// NewAlertCanonicalEventFactory binds alert evidence construction to one
// compiled plan, projection engine, occurrence builder, and real binary
// provenance. Binary/version/generation data is never fabricated here.
func NewAlertCanonicalEventFactory(
	plan *config.ObservabilityV8Plan,
	projector Projector,
	builder *observability.RecordBuilder,
	provenance observability.Provenance,
) (*AlertCanonicalEventFactory, error) {
	if plan == nil || builder == nil || nilAlertDependency(projector) || plan.Digest() == "" {
		return nil, fmt.Errorf("observability alert event factory dependencies are invalid")
	}
	catalog, err := plan.RedactionProfileCatalog()
	if err != nil {
		return nil, fmt.Errorf("observability alert event factory profile catalog is invalid")
	}
	local := make(map[observability.Bucket]redaction.ProfileName, len(observability.Buckets()))
	for _, bucket := range observability.Buckets() {
		profileName, resolveErr := plan.ResolveLocalRedactionProfile(bucket)
		if resolveErr != nil {
			return nil, fmt.Errorf("observability alert event factory local profile binding is invalid")
		}
		if _, found := catalog.Resolve(profileName); !found {
			return nil, fmt.Errorf("observability alert event factory local profile is absent from the catalog")
		}
		local[bucket] = profileName
	}

	planDigest := plan.Digest()
	if provenance.ConfigDigest == "" {
		provenance.ConfigDigest = planDigest
	} else if provenance.ConfigDigest != planDigest {
		return nil, fmt.Errorf("observability alert event factory provenance does not match the compiled plan")
	}
	provenance.Producer = alertCanonicalProducer
	if err := provenance.Validate(); err != nil {
		return nil, fmt.Errorf("observability alert event factory provenance is invalid")
	}

	return &AlertCanonicalEventFactory{
		builder: builder, projector: projector, catalog: catalog, local: local,
		provenance: provenance, planDigest: planDigest,
	}, nil
}

// BuildAlertCanonicalEvent builds and projects the canonical mandatory record.
// Errors deliberately contain no body values, actor data, or alert identifier.
func (factory *AlertCanonicalEventFactory) BuildAlertCanonicalEvent(
	ctx context.Context,
	input audit.AlertCanonicalEventInput,
) (observability.Record, redaction.Projection, error) {
	if factory == nil || factory.builder == nil || nilAlertDependency(factory.projector) ||
		factory.planDigest == "" || len(factory.local) != len(observability.Buckets()) {
		return observability.Record{}, redaction.Projection{}, fmt.Errorf("observability alert event factory is not initialized")
	}
	if ctx == nil {
		return observability.Record{}, redaction.Projection{}, fmt.Errorf("observability alert event context is required")
	}
	if err := ctx.Err(); err != nil {
		return observability.Record{}, redaction.Projection{}, err
	}
	if err := validateAlertIdentifier(input.AlertID); err != nil {
		return observability.Record{}, redaction.Projection{}, err
	}

	shape, body, classes, err := classifyAlertCanonicalInput(input)
	if err != nil {
		return observability.Record{}, redaction.Projection{}, err
	}
	profileName, found := factory.local[input.Bucket]
	if !found {
		return observability.Record{}, redaction.Projection{}, fmt.Errorf("observability alert event bucket is not bound to a local profile")
	}
	profile, found := factory.catalog.Resolve(profileName)
	if !found {
		return observability.Record{}, redaction.Projection{}, fmt.Errorf("observability alert event local profile is unavailable")
	}

	record, err := factory.builder.BuildClassifiedLog(observability.ClassifiedLogInput{
		ProducerKind: observability.ProducerGatewayEvent,
		ProducerKey:  shape.producerKey,
		ClassificationContext: observability.ClassificationContext{
			Bucket: input.Bucket, EventName: input.EventName, RawSeverity: "INFO",
			MandatoryFacts: shape.mandatoryFacts,
		},
		Source:       shape.source,
		Action:       string(input.EventName),
		Outcome:      input.Outcome,
		Provenance:   factory.provenance,
		Body:         body,
		FieldClasses: classes,
	})
	if err != nil {
		return observability.Record{}, redaction.Projection{}, fmt.Errorf("observability alert event record construction failed")
	}
	severity, hasSeverity := record.Severity()
	if record.Bucket() != input.Bucket || record.EventName() != input.EventName ||
		record.Signal() != observability.SignalLogs || record.Outcome() != input.Outcome ||
		!record.Mandatory() || !hasSeverity || severity != observability.SeverityInfo {
		return observability.Record{}, redaction.Projection{}, fmt.Errorf("observability alert event record construction mismatch")
	}

	projection, _, err := factory.projector.Project(record, profile)
	if err != nil {
		return observability.Record{}, redaction.Projection{}, fmt.Errorf("observability alert event projection failed")
	}
	if projection.Metadata().RedactionProfile != string(profileName) {
		return observability.Record{}, redaction.Projection{}, fmt.Errorf("observability alert event projection profile mismatch")
	}
	projectedBody, err := projection.Payload().Object()
	if err != nil || validateAlertProjectedControls(shape, body, projectedBody) != nil {
		return observability.Record{}, redaction.Projection{}, fmt.Errorf("observability alert event projection changed control fields")
	}
	if _, err := projection.Bytes(); err != nil {
		return observability.Record{}, redaction.Projection{}, fmt.Errorf("observability alert event projection is invalid")
	}
	return record, projection, nil
}

type alertCanonicalShape struct {
	producerKey    observability.ProducerKey
	source         observability.Source
	mandatoryFacts observability.MandatoryFacts
	keys           map[string]bool
	actor          bool
}

func classifyAlertCanonicalInput(
	input audit.AlertCanonicalEventInput,
) (alertCanonicalShape, map[string]any, map[string]observability.FieldClass, error) {
	var shape alertCanonicalShape
	switch {
	case input.Bucket == observability.BucketComplianceActivity &&
		(input.EventName == "alert.acknowledgement.requested" || input.EventName == "alert.dismissal.requested") &&
		(input.Outcome == observability.OutcomeApplied || input.Outcome == observability.OutcomeNoChange ||
			input.Outcome == observability.OutcomeRejected):
		shape = alertCanonicalShape{
			producerKey: "activity", source: observability.SourceOperatorAPI,
			mandatoryFacts: observability.MandatoryFacts{AlertMutation: true}, actor: true,
			keys: map[string]bool{
				"target": true, "operation_id": true, "target_event_id": true,
				"requested_disposition": true, "actor": true, "outcome": true,
				"rejection_reason": false, "expected_projection_version": true,
				"observed_projection_version": true, "projection_version_before": true,
				"projection_version_after": true,
			},
		}
	case input.Bucket == observability.BucketPlatformHealth &&
		input.EventName == "subsystem.degraded" && input.Outcome == observability.OutcomeFailed:
		shape = alertCanonicalShape{
			producerKey: "lifecycle", source: observability.SourceSystem,
			mandatoryFacts: observability.MandatoryFacts{DurableHealthTransition: true},
			keys:           map[string]bool{"target": true, "alert_id": true, "code": true},
		}
	default:
		return alertCanonicalShape{}, nil, nil, fmt.Errorf("observability alert event semantic identity is invalid")
	}

	encoded, err := json.Marshal(input.Body)
	if err != nil {
		return alertCanonicalShape{}, nil, nil, fmt.Errorf("observability alert event body is invalid")
	}
	value, err := observability.ParseValue(encoded)
	if err != nil {
		return alertCanonicalShape{}, nil, nil, fmt.Errorf("observability alert event body is invalid")
	}
	body, err := value.Object()
	if err != nil || !exactAlertSchema(body, shape.keys) {
		return alertCanonicalShape{}, nil, nil, fmt.Errorf("observability alert event body schema is invalid")
	}
	if err := validateAlertBodyValues(input, shape, body); err != nil {
		return alertCanonicalShape{}, nil, nil, err
	}
	classes := make(map[string]observability.FieldClass, len(body))
	for key := range body {
		classes["/"+key] = observability.FieldClassMetadata
	}
	if shape.actor {
		classes["/actor"] = observability.FieldClassContent
	}
	return shape, body, classes, nil
}

func exactAlertSchema(body map[string]any, schema map[string]bool) bool {
	for key := range body {
		if _, known := schema[key]; !known {
			return false
		}
	}
	for key, required := range schema {
		if _, present := body[key]; required && !present {
			return false
		}
	}
	return true
}

func validateAlertBodyValues(
	input audit.AlertCanonicalEventInput,
	shape alertCanonicalShape,
	body map[string]any,
) error {
	stringValue := func(key string) (string, bool) {
		value, ok := body[key].(string)
		return value, ok && value != "" && utf8.ValidString(value)
	}
	target, targetOK := stringValue("target")
	if !targetOK || target != input.AlertID {
		return fmt.Errorf("observability alert event body target is invalid")
	}
	if shape.actor {
		targetEventID, targetEventOK := stringValue("target_event_id")
		operationID, operationOK := stringValue("operation_id")
		actor, actorOK := stringValue("actor")
		disposition, dispositionOK := stringValue("requested_disposition")
		outcome, outcomeOK := stringValue("outcome")
		if !targetEventOK || targetEventID != input.AlertID || !operationOK || !actorOK ||
			!dispositionOK || !outcomeOK || outcome != string(input.Outcome) ||
			len(operationID) > observability.MaxCorrelationIDBytes ||
			len(actor) > observability.MaxCorrelationIDBytes {
			return fmt.Errorf("observability alert event compliance body is invalid")
		}
		wantDisposition := "acknowledged"
		if input.EventName == "alert.dismissal.requested" {
			wantDisposition = "dismissed"
		}
		if disposition != wantDisposition {
			return fmt.Errorf("observability alert event disposition does not match its event")
		}
		versions := make(map[string]int64, 4)
		for _, key := range []string{
			"expected_projection_version", "observed_projection_version",
			"projection_version_before", "projection_version_after",
		} {
			version, ok := nonNegativeAlertInteger(body[key])
			if !ok {
				return fmt.Errorf("observability alert event projection version is invalid")
			}
			versions[key] = version
		}
		reason, reasonPresent := body["rejection_reason"]
		if reasonPresent {
			reasonString, ok := reason.(string)
			if !ok || (reasonString != "stale_projection_version" && reasonString != "idempotency_conflict") {
				return fmt.Errorf("observability alert event rejection reason is invalid")
			}
		}
		if reasonPresent != (input.Outcome == observability.OutcomeRejected) ||
			versions["observed_projection_version"] != versions["projection_version_before"] {
			return fmt.Errorf("observability alert event outcome controls are inconsistent")
		}
		wantAfter := versions["projection_version_before"]
		if input.Outcome == observability.OutcomeApplied {
			wantAfter++
		}
		if versions["projection_version_after"] != wantAfter {
			return fmt.Errorf("observability alert event projection transition is invalid")
		}
		return nil
	}
	alertID, alertOK := stringValue("alert_id")
	code, codeOK := stringValue("code")
	if !alertOK || alertID != input.AlertID || !codeOK ||
		(code != "version_gap" && code != "version_conflict" && code != "projection_ahead") {
		return fmt.Errorf("observability alert health event body is invalid")
	}
	return nil
}

func validateAlertProjectedControls(
	shape alertCanonicalShape,
	original map[string]any,
	projected map[string]any,
) error {
	for key := range shape.keys {
		if shape.actor && key == "actor" {
			continue
		}
		originalValue, originallyPresent := original[key]
		projectedValue, projectedPresent := projected[key]
		if originallyPresent != projectedPresent || !reflect.DeepEqual(originalValue, projectedValue) {
			return fmt.Errorf("control field changed")
		}
	}
	if actor, present := projected["actor"]; present {
		if value, ok := actor.(string); !ok || value == "" {
			return fmt.Errorf("governed actor is malformed")
		}
	}
	return nil
}

func validateAlertIdentifier(value string) error {
	if value == "" || !utf8.ValidString(value) || len(value) > observability.MaxCorrelationIDBytes {
		return fmt.Errorf("observability alert event alert identifier is invalid")
	}
	return nil
}

func nonNegativeAlertInteger(value any) (int64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	parsed, err := number.Int64()
	return parsed, err == nil && parsed >= 0
}

func nilAlertDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

var _ audit.AlertCanonicalEventFactory = (*AlertCanonicalEventFactory)(nil)
