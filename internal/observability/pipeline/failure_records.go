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
	"fmt"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

// CanonicalProjectionFailureFactory owns the injected clock/occurrence-ID
// builder used for recursion-safe local projection failure records.
type CanonicalProjectionFailureFactory struct {
	builder *observability.RecordBuilder
}

func NewCanonicalProjectionFailureFactory(
	builder *observability.RecordBuilder,
) (*CanonicalProjectionFailureFactory, error) {
	if builder == nil {
		return nil, fmt.Errorf("observability projection failure record builder is required")
	}
	return &CanonicalProjectionFailureFactory{builder: builder}, nil
}

func (factory *CanonicalProjectionFailureFactory) BuildProjectionFailure(
	ctx context.Context,
	failure ProjectionFailureRecord,
) (observability.Record, error) {
	if factory == nil || factory.builder == nil {
		return observability.Record{}, fmt.Errorf("observability projection failure factory is not initialized")
	}
	if ctx == nil {
		return observability.Record{}, fmt.Errorf("observability projection failure context is required")
	}
	if err := ctx.Err(); err != nil {
		return observability.Record{}, err
	}
	if !observability.IsBucket(failure.FailedBucket) ||
		!observability.IsStableToken(string(failure.RedactionProfile)) ||
		!validOptionalFailureCode(failure.FailureCode) {
		return observability.Record{}, fmt.Errorf("observability projection failure identity is invalid")
	}
	provenance := failure.Provenance
	provenance.Producer = "observability_pipeline"
	body := map[string]any{
		"component":         "redaction",
		"destination_name":  config.ObservabilityV8LocalDestinationName,
		"failed_bucket":     string(failure.FailedBucket),
		"failure_code":      string(failure.FailureCode),
		"redaction_profile": string(failure.RedactionProfile),
	}
	classes := map[string]observability.FieldClass{
		"/component":         observability.FieldClassMetadata,
		"/destination_name":  observability.FieldClassMetadata,
		"/failed_bucket":     observability.FieldClassMetadata,
		"/failure_code":      observability.FieldClassMetadata,
		"/redaction_profile": observability.FieldClassMetadata,
	}
	return factory.builder.BuildClassifiedLog(observability.ClassifiedLogInput{
		ProducerKind: observability.ProducerGatewayEvent,
		ProducerKey:  "lifecycle",
		ClassificationContext: observability.ClassificationContext{
			Bucket:      observability.BucketPlatformHealth,
			EventName:   "redaction.failed_closed",
			RawSeverity: "INFO",
			MandatoryFacts: observability.MandatoryFacts{
				DurableHealthTransition: true,
			},
		},
		Source:       observability.SourceSystem,
		Action:       "redaction.failed_closed",
		Outcome:      observability.OutcomeFailed,
		Correlation:  failure.Correlation,
		Provenance:   provenance,
		Body:         body,
		FieldClasses: classes,
	})
}

func validOptionalFailureCode(code OptionalFailureCode) bool {
	switch code {
	case OptionalFailureProfile,
		OptionalFailureClassification,
		OptionalFailureMetricClass,
		OptionalFailureContext,
		OptionalFailureOutputLimit,
		OptionalFailureSerialization,
		OptionalFailureProjection:
		return true
	default:
		return false
	}
}
