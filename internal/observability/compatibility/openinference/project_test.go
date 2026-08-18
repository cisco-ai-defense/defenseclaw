// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package openinference

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/compatibility/profilemanifest"
)

func TestProjectCoversEveryGeneratedEligibleFamily(t *testing.T) {
	t.Parallel()
	manifest, err := profilemanifest.Get(ProfileID)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Availability != "available" || len(manifest.Families) == 0 {
		t.Fatalf("manifest unavailable: %+v", manifest)
	}
	for _, family := range manifest.Families {
		family := family
		t.Run(family.FamilyID, func(t *testing.T) {
			t.Parallel()
			projection, ok := profilemanifest.FamilyProjection(ProfileID, family.Signal, family.EventName)
			if !ok || len(projection.AllowedSpanKinds) == 0 {
				t.Fatalf("projection unavailable: %+v", projection)
			}
			attributes := map[string]any{
				projection.InputAttribute:  []any{map[string]any{"role": "user", "content": "redacted-input"}},
				projection.OutputAttribute: []any{map[string]any{"role": "assistant", "content": "redacted-output"}},
			}
			result := Project(family.Bucket, family.EventName, projection.AllowedSpanKinds[0], attributes)
			aliases, eligible := result.Attributes()
			if !eligible || result.Reason() != ReasonEligible {
				t.Fatalf("projection rejected: %s", result.Reason())
			}
			if aliases[SpanKindAttribute] != projection.OpenInferenceSpanKind ||
				aliases[InputMIMEAttribute] != "application/json" ||
				aliases[OutputMIMEAttribute] != "application/json" ||
				!strings.Contains(aliases[InputValueAttribute], "redacted-input") ||
				!strings.Contains(aliases[OutputValueAttribute], "redacted-output") {
				t.Fatalf("aliases = %#v", aliases)
			}
			aliases[SpanKindAttribute] = "MUTATED"
			fresh, _ := result.Attributes()
			if fresh[SpanKindAttribute] != projection.OpenInferenceSpanKind {
				t.Fatal("result exposed mutable projection state")
			}
		})
	}
}

func TestProjectFailsClosedForUnsupportedMalformedAndConflictingInputs(t *testing.T) {
	t.Parallel()
	if result := Project(
		observability.BucketGuardrailEvaluation,
		"span.guardrail.apply",
		"INTERNAL",
		map[string]any{},
	); result.Reason() != ReasonUnsupported {
		t.Fatalf("unsupported family reason = %s", result.Reason())
	}
	valid := map[string]any{
		"gen_ai.input.messages":  []any{map[string]any{"role": "user"}},
		"gen_ai.output.messages": []any{map[string]any{"role": "assistant"}},
	}
	if result := Project(observability.BucketModelIO, "span.model.chat", "INTERNAL", valid); result.Reason() != ReasonInvalidInput {
		t.Fatalf("invalid span kind reason = %s", result.Reason())
	}
	conflicting := map[string]any{
		"gen_ai.input.messages": []any{}, SpanKindAttribute: "LLM",
	}
	if result := Project(observability.BucketModelIO, "span.model.chat", "CLIENT", conflicting); result.Reason() != ReasonAliasConflict {
		t.Fatalf("alias conflict reason = %s", result.Reason())
	}
	if result := Project(observability.BucketToolActivity, "span.model.chat", "CLIENT", valid); result.Reason() != ReasonInvalidInput {
		t.Fatalf("bucket mismatch reason = %s", result.Reason())
	}
}

func TestProjectUsesOnlyAlreadyRedactedValues(t *testing.T) {
	t.Parallel()
	attributes := map[string]any{
		"gen_ai.input.messages": []any{
			map[string]any{"role": "user", "parts": []any{nil, "[REDACTED]"}},
		},
	}
	result := Project(observability.BucketModelIO, "span.model.chat", "CLIENT", attributes)
	aliases, ok := result.Attributes()
	if !ok || !strings.Contains(aliases[InputValueAttribute], "[REDACTED]") ||
		!strings.Contains(aliases[InputValueAttribute], "null") {
		t.Fatalf("redacted alias = %#v reason=%s", aliases, result.Reason())
	}
	if _, present := aliases[OutputValueAttribute]; present {
		t.Fatal("projector invented missing output content")
	}
}
