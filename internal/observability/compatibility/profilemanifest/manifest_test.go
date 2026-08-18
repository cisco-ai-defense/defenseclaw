// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package profilemanifest

import (
	"reflect"
	"sort"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

func TestGeneratedCompatibilityProfileAuthorityIsExactAndDetached(t *testing.T) {
	t.Parallel()
	tests := []struct {
		id            string
		availability  string
		status        string
		familyCount   int
		traceCount    int
		knownFamily   observability.EventName
		unknownFamily observability.EventName
	}{
		{"galileo-rich-v2", "available", "available", 6, 6, "span.agent.invoke", "span.agent.transition"},
		// Local observability intentionally follows the complete generated
		// family catalog. Its additive inventory is checked structurally below,
		// not frozen into a second handwritten global total here.
		{"local-observability-v1", "available", "available", 0, 0, "span.diagnostic.canary", "span.unknown"},
		{"openinference-v1", "available", "available", 7, 7, "span.retrieval.search", "span.guardrail.apply"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.id, func(t *testing.T) {
			t.Parallel()
			manifest, err := Get(test.id)
			if err != nil {
				t.Fatal(err)
			}
			if manifest.ProfileID != test.id || manifest.Availability != test.availability ||
				manifest.RuntimeProjection.Status != test.status ||
				(test.familyCount > 0 && len(manifest.Families) != test.familyCount) {
				t.Fatalf("manifest = %+v", manifest)
			}
			if got := len(SortedFamilyIDs(manifest, observability.SignalTraces)); test.traceCount > 0 && got != test.traceCount {
				t.Fatalf("trace family count = %d, want %d", got, test.traceCount)
			}
			if test.status == "available" && !Eligible(test.id, observability.SignalTraces, test.knownFamily) {
				t.Fatalf("known family %q was not eligible", test.knownFamily)
			}
			if test.status != "available" && Eligible(test.id, observability.SignalTraces, test.knownFamily) {
				t.Fatalf("runtime-unsupported family %q became eligible", test.knownFamily)
			}
			if Eligible(test.id, observability.SignalTraces, test.unknownFamily) {
				t.Fatalf("unknown family %q became eligible", test.unknownFamily)
			}

			manifest.Families[0].FamilyID = "mutated"
			fresh, err := Get(test.id)
			if err != nil {
				t.Fatal(err)
			}
			if fresh.Families[0].FamilyID == "mutated" {
				t.Fatal("caller mutated cached generated authority")
			}
		})
	}
}

func TestLocalRuntimeProjectionCarriesExactAliasContract(t *testing.T) {
	t.Parallel()
	projection, ok := Runtime("local-observability-v1")
	if !ok {
		t.Fatal("local runtime projection unavailable")
	}
	want := []AttributeAlias{
		{Source: "defenseclaw.connector.source", Target: "connector"},
		{Source: "defenseclaw.agent.type", Target: "gen_ai.agent.type"},
		{Source: "defenseclaw.guardrail.raw_action", Target: "defenseclaw.raw_action", EventDerived: true},
		{Source: "defenseclaw.guardrail.effective_action", Target: "defenseclaw.decision", EventDerived: true},
		{Source: "defenseclaw.guardrail.would_block", Target: "defenseclaw.would_block", EventDerived: true},
	}
	if !reflect.DeepEqual(projection.AttributeAliases, want) ||
		!reflect.DeepEqual(projection.EventAliasSources, []string{"guardrail.decision", "hook.decision"}) ||
		projection.AliasConflictBehavior != "reject" {
		t.Fatalf("local runtime projection = %+v", projection)
	}
}

func TestFamilyProjectionIsDetached(t *testing.T) {
	t.Parallel()
	first, ok := FamilyProjection("galileo-rich-v2", observability.SignalTraces, "span.agent.invoke")
	if !ok || first.OperationAttribute == nil || len(first.AllowedOperations) == 0 {
		t.Fatalf("generated agent projection unavailable: %+v", first)
	}
	*first.OperationAttribute = "mutated"
	first.AllowedOperations[0] = "mutated"
	first.AllowedSpanKinds[0] = "mutated"
	first.RequiredAttributes[0] = "mutated"

	fresh, ok := FamilyProjection("galileo-rich-v2", observability.SignalTraces, "span.agent.invoke")
	if !ok || fresh.OperationAttribute == nil || *fresh.OperationAttribute != "gen_ai.operation.name" ||
		fresh.AllowedOperations[0] != "invoke_agent" || fresh.AllowedSpanKinds[0] != "CLIENT" ||
		fresh.RequiredAttributes[0] != "gen_ai.agent.name" {
		t.Fatalf("caller mutated cached family projection: %+v", fresh)
	}
}

func TestFamilyTraceContractIsGeneratedAndDetached(t *testing.T) {
	t.Parallel()
	first, ok := FamilyTraceContract(
		"galileo-rich-v2", observability.SignalTraces, "span.agent.invoke",
	)
	if !ok || len(first.AttributeKeys) == 0 || len(first.EventNames) == 0 ||
		len(first.LinkRelations) == 0 || first.StatusRule == "" {
		t.Fatalf("generated trace contract unavailable: %+v", first)
	}
	first.AttributeKeys[0] = "mutated"
	first.EventNames[0] = "mutated"
	first.LinkRelations[0] = "mutated"
	fresh, ok := FamilyTraceContract(
		"galileo-rich-v2", observability.SignalTraces, "span.agent.invoke",
	)
	if !ok || fresh.AttributeKeys[0] == "mutated" || fresh.EventNames[0] == "mutated" ||
		fresh.LinkRelations[0] == "mutated" || !sort.StringsAreSorted(fresh.AttributeKeys) ||
		!sort.StringsAreSorted(fresh.EventNames) || !sort.StringsAreSorted(fresh.LinkRelations) {
		t.Fatalf("caller mutated cached trace contract: %+v", fresh)
	}
}

func TestMetricProjectionPreservesBoundaryNullAndCanonicalFieldsAreDetached(t *testing.T) {
	counter, ok := FamilyProjection(
		"local-observability-v1", observability.SignalMetrics, "defenseclaw.activity.total",
	)
	if !ok || counter.Boundaries != nil {
		t.Fatalf("counter boundaries=%v ok=%v", counter.Boundaries, ok)
	}
	histogram, ok := FamilyProjection(
		"local-observability-v1", observability.SignalMetrics, "defenseclaw.activity.diff_entries",
	)
	if !ok || histogram.Boundaries == nil || len(histogram.Boundaries) != 0 {
		t.Fatalf("histogram authored empty boundaries=%v ok=%v", histogram.Boundaries, ok)
	}
	fields, ok := FamilyAttributeKeys(
		"local-observability-v1", observability.SignalMetrics, "defenseclaw.agent.lifecycle.transitions",
	)
	if !ok || len(fields) == 0 || !sort.StringsAreSorted(fields) {
		t.Fatalf("canonical fields=%v ok=%v", fields, ok)
	}
	fields[0] = "mutated"
	fresh, ok := FamilyAttributeKeys(
		"local-observability-v1", observability.SignalMetrics, "defenseclaw.agent.lifecycle.transitions",
	)
	if !ok || len(fresh) == 0 || fresh[0] == "mutated" {
		t.Fatal("canonical field snapshot aliases cached authority")
	}
}

func TestLocalMetricProjectionCarriesGeneratedCardinalityAndInstrumentFacts(t *testing.T) {
	t.Parallel()
	manifest, err := Get("local-observability-v1")
	if err != nil {
		t.Fatal(err)
	}
	metrics := 0
	for _, family := range manifest.Families {
		if family.Signal != observability.SignalMetrics {
			continue
		}
		metrics++
		projection := family.Projection
		if projection.Mode != "otel_sdk_metric_v1" || projection.CardinalityLimit != 2048 ||
			projection.InstrumentType == "" || projection.ValueType == "" || projection.Unit == "" ||
			projection.Temporality == "" || projection.LabelProjection.Profile != "local-observability-v1" {
			t.Fatalf("metric %q projection = %+v", family.FamilyID, projection)
		}
	}
	// loadProfiles already proves exact manifest membership against the
	// generated catalog. This assertion protects the metric arm without
	// freezing the additive global inventory into a second number.
	if metrics == 0 {
		t.Fatal("local metric projection is empty")
	}
}

func TestOpenInferenceProjectionIsExplicitForEveryGeneratedFamily(t *testing.T) {
	t.Parallel()
	manifest, err := Get("openinference-v1")
	if err != nil {
		t.Fatal(err)
	}
	if manifest.RuntimeProjection.Status != "available" ||
		manifest.RuntimeProjection.Mode != "destination_owned_openinference_alias_projection" ||
		manifest.RuntimeProjection.UnsupportedBehavior != "reject" ||
		manifest.RuntimeProjection.AliasConflictBehavior != "reject" || manifest.RuntimeProjection.Reason != "" {
		t.Fatalf("runtime projection = %+v", manifest.RuntimeProjection)
	}
	for _, family := range manifest.Families {
		if family.Projection.Mode != "openinference_trace_aliases_v1" ||
			family.Projection.OpenInferenceSpanKind == "" ||
			family.Projection.InputAttribute == "" || family.Projection.OutputAttribute == "" ||
			len(family.Projection.AllowedSpanKinds) == 0 {
			t.Fatalf("family %q has incomplete projection: %+v", family.FamilyID, family.Projection)
		}
		if _, ok := FamilyProjection(manifest.ProfileID, family.Signal, family.EventName); !ok {
			t.Fatalf("runtime family %q has no executable projection", family.FamilyID)
		}
	}
}

func TestUnknownProfileFailsClosed(t *testing.T) {
	t.Parallel()
	if _, err := Get("unknown-v1"); err == nil {
		t.Fatal("unknown profile was accepted")
	}
	if Eligible("unknown-v1", observability.SignalTraces, "span.agent.invoke") {
		t.Fatal("unknown profile gained eligibility")
	}
	if _, ok := Runtime("unknown-v1"); ok {
		t.Fatal("unknown profile gained runtime projection")
	}
	if _, ok := FamilyProjection("unknown-v1", observability.SignalTraces, "span.agent.invoke"); ok {
		t.Fatal("unknown profile gained family projection")
	}
}
