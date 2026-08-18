// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package openinference projects generated canonical trace attributes into the
// pinned OpenInference compatibility vocabulary. Inputs are already routed and
// redacted for one destination; the projector never receives producer objects.
package openinference

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/compatibility/profilemanifest"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
)

const ProfileID = observability.RuntimeOpenInferenceCompatibilityProfile

type Reason string

const (
	ReasonEligible       Reason = "eligible"
	ReasonUnsupported    Reason = "unsupported_family"
	ReasonInvalidInput   Reason = "invalid_projection"
	ReasonAliasConflict  Reason = "alias_conflict"
	ReasonOutputTooLarge Reason = "output_too_large"
)

const (
	SpanKindAttribute    = "openinference.span.kind"
	InputValueAttribute  = "input.value"
	InputMIMEAttribute   = "input.mime_type"
	OutputValueAttribute = "output.value"
	OutputMIMEAttribute  = "output.mime_type"
)

var projectionAttributes = map[string]struct{}{
	SpanKindAttribute: {}, InputValueAttribute: {}, InputMIMEAttribute: {},
	OutputValueAttribute: {}, OutputMIMEAttribute: {},
}

// Result contains only compatibility aliases, never canonical source values by
// reference. Attributes returns a detached copy.
type Result struct {
	reason     Reason
	attributes map[string]string
}

func (result Result) Eligible() bool { return result.reason == ReasonEligible }

func (result Result) Reason() Reason {
	if result.reason == "" {
		return ReasonInvalidInput
	}
	return result.reason
}

func (result Result) Attributes() (map[string]string, bool) {
	if !result.Eligible() {
		return nil, false
	}
	copy := make(map[string]string, len(result.attributes))
	for key, value := range result.attributes {
		copy[key] = strings.Clone(value)
	}
	return copy, true
}

// IsProjectionAttribute reports the exact OpenInference aliases this package
// can add to the OTLP wire. It is a vocabulary check, not family eligibility.
func IsProjectionAttribute(key string) bool {
	_, ok := projectionAttributes[key]
	return ok
}

// Project derives aliases only from the generated profile contract and the
// already-redacted canonical attributes for one registered span family.
func Project(
	bucket observability.Bucket,
	family observability.EventName,
	spanKind string,
	attributes map[string]any,
) Result {
	identity := observability.EventIdentity{Bucket: bucket, Signal: observability.SignalTraces, Name: family}
	if !observability.IsRegisteredEventIdentity(identity) || attributes == nil {
		return rejected(ReasonInvalidInput)
	}
	if !profilemanifest.Eligible(ProfileID, observability.SignalTraces, family) {
		return rejected(ReasonUnsupported)
	}
	runtime, ok := profilemanifest.Runtime(ProfileID)
	if !ok || runtime.Status != "available" ||
		runtime.Mode != "destination_owned_openinference_alias_projection" ||
		runtime.AliasConflictBehavior != "reject" {
		return rejected(ReasonInvalidInput)
	}
	projection, ok := profilemanifest.FamilyProjection(ProfileID, observability.SignalTraces, family)
	if !ok || projection.Mode != "openinference_trace_aliases_v1" ||
		projection.OpenInferenceSpanKind == "" ||
		projection.InputAttribute == "" || projection.OutputAttribute == "" ||
		projection.InputMIMEType == "" || projection.OutputMIMEType == "" ||
		!contains(projection.AllowedSpanKinds, spanKind) {
		return rejected(ReasonInvalidInput)
	}
	traceContract, ok := profilemanifest.FamilyTraceContract(ProfileID, observability.SignalTraces, family)
	registered, registeredOK := observability.RegisteredTraceProjectionContract(identity)
	if !ok || !registeredOK || !sameStrings(traceContract.AttributeKeys, registered.AttributeKeys) ||
		!contains(traceContract.AttributeKeys, projection.InputAttribute) ||
		!contains(traceContract.AttributeKeys, projection.OutputAttribute) ||
		!sameStrings(traceContract.EventNames, sortedKeys(registered.EventAttributeKeys)) ||
		!sameStrings(traceContract.LinkRelations, registered.LinkRelations) {
		return rejected(ReasonInvalidInput)
	}
	for key := range projectionAttributes {
		if _, exists := attributes[key]; exists {
			return rejected(ReasonAliasConflict)
		}
	}

	aliases := map[string]string{SpanKindAttribute: projection.OpenInferenceSpanKind}
	if value, present := attributes[projection.InputAttribute]; present {
		encoded, valid := encodeValue(value)
		if !valid {
			return rejected(ReasonInvalidInput)
		}
		aliases[InputValueAttribute] = encoded
		aliases[InputMIMEAttribute] = projection.InputMIMEType
	}
	if value, present := attributes[projection.OutputAttribute]; present {
		encoded, valid := encodeValue(value)
		if !valid {
			return rejected(ReasonInvalidInput)
		}
		aliases[OutputValueAttribute] = encoded
		aliases[OutputMIMEAttribute] = projection.OutputMIMEType
	}
	total := 0
	for key, value := range aliases {
		total += len(key) + len(value)
		if total > delivery.MaxPayloadBytes {
			return rejected(ReasonOutputTooLarge)
		}
	}
	return Result{reason: ReasonEligible, attributes: aliases}
}

func encodeValue(value any) (string, bool) {
	if text, ok := value.(string); ok && json.Valid([]byte(text)) {
		var compact bytes.Buffer
		if json.Compact(&compact, []byte(text)) == nil && compact.Len() <= delivery.MaxPayloadBytes {
			return compact.String(), true
		}
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) == 0 || len(encoded) > delivery.MaxPayloadBytes || !utf8.Valid(encoded) {
		return "", false
	}
	return string(encoded), true
}

func rejected(reason Reason) Result { return Result{reason: reason} }

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func sortedKeys(values map[string][]string) []string {
	result := make([]string, 0, len(values))
	for key := range values {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}
