// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"reflect"
	"slices"
	"sort"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	publicschemas "github.com/defenseclaw/defenseclaw/schemas"
)

func TestObservabilityV8CompatibilityProfilesComeFromGeneratedCatalog(t *testing.T) {
	profiles, err := observabilityV8CatalogCompatibilityProfiles()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		profile      string
		family       observability.EventName
		availability string
	}{
		{"galileo-rich-v2", observability.EventName("span.model.chat"), "available"},
		{"galileo-rich-v2", observability.EventName("span.agent.invoke"), "available"},
		{"local-observability-v1", observability.EventName("span.tool.execute"), "available"},
		{"openinference-v1", observability.EventName("span.retrieval.search"), "available"},
	} {
		profile, ok := profiles[test.profile]
		if !ok || profile.Availability != test.availability || !slices.ContainsFunc(profile.TraceFamilies, func(family observabilityV8CatalogTraceFamily) bool {
			return family.EventName == test.family && family.Availability == test.availability
		}) {
			t.Fatalf("generated profile %q does not contain %q: %+v", test.profile, test.family, profile)
		}
	}
	first := profiles["galileo-rich-v2"]
	first.TraceFamilies[0].EventName = "span.mutated"
	second, err := observabilityV8CatalogCompatibilityProfiles()
	if err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(
		second["galileo-rich-v2"].TraceFamilies,
		func(family observabilityV8CatalogTraceFamily) bool { return family.EventName == "span.mutated" },
	) {
		t.Fatal("generated compatibility accessor returned mutable shared state")
	}
}

func TestObservabilityV8CompatibilityAccessorExactlyMatchesGeneratedTraceMembership(t *testing.T) {
	var catalog struct {
		CompatibilityManifests []struct {
			ID           string `json:"id"`
			Availability string `json:"availability"`
		} `json:"compatibility_manifests"`
		Families []struct {
			EventName             string               `json:"event_name"`
			Bucket                observability.Bucket `json:"bucket"`
			Signal                observability.Signal `json:"signal"`
			CompatibilityProfiles []struct {
				ID           string `json:"id"`
				Availability string `json:"availability"`
			} `json:"compatibility_profiles"`
		} `json:"families"`
	}
	if err := json.Unmarshal(publicschemas.TelemetryV8Catalog(), &catalog); err != nil {
		t.Fatal(err)
	}
	expectedAvailability := make(map[string]string)
	for _, profile := range catalog.CompatibilityManifests {
		expectedAvailability[profile.ID] = profile.Availability
	}
	expected := make(map[string][]string)
	for _, family := range catalog.Families {
		if family.Signal != observability.SignalTraces {
			continue
		}
		for _, profile := range family.CompatibilityProfiles {
			expected[profile.ID] = append(expected[profile.ID], family.EventName+"|"+string(family.Bucket)+"|"+profile.Availability)
		}
	}
	for profile := range expected {
		sort.Strings(expected[profile])
	}
	actualProfiles, err := observabilityV8CatalogCompatibilityProfiles()
	if err != nil {
		t.Fatal(err)
	}
	actual := make(map[string][]string)
	for id, profile := range actualProfiles {
		if profile.Availability != expectedAvailability[id] {
			t.Fatalf("profile %q availability=%q, want %q", id, profile.Availability, expectedAvailability[id])
		}
		for _, family := range profile.TraceFamilies {
			actual[id] = append(actual[id], string(family.EventName)+"|"+string(family.Bucket)+"|"+family.Availability)
		}
		sort.Strings(actual[id])
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("generated trace compatibility membership drifted\nactual: %#v\nexpected: %#v", actual, expected)
	}
}

func TestObservabilityV8GalileoCapabilityDefaultRouteMatchesGeneratedCompatibility(t *testing.T) {
	disabled := false
	defaultDestination := validObservabilityV8Destination("galileo-default", ObservabilityV8DestinationOTLP)
	defaultDestination.Preset = "galileo"
	defaultDestination.Enabled = &disabled
	explicitDestination := validObservabilityV8Destination("galileo-explicit", ObservabilityV8DestinationOTLP)
	explicitDestination.Preset = "galileo"
	explicitDestination.Send = &ObservabilityV8SendSource{
		Signals: []observability.Signal{observability.SignalTraces},
		Buckets: []observability.Bucket{"*"}, RedactionProfile: "none",
	}
	advancedSelector := ObservabilityV8SelectorSource{Buckets: []observability.Bucket{"*"}}
	advancedDestination := validObservabilityV8Destination("galileo-advanced", ObservabilityV8DestinationOTLP)
	advancedDestination.Preset = "galileo"
	advancedDestination.Routes = []ObservabilityV8RouteSource{{
		Name: "operator-route", Signals: []observability.Signal{observability.SignalTraces},
		Selector: &advancedSelector, Action: ObservabilityV8RouteSend, RedactionProfile: "none",
	}}
	plan := mustCompileObservabilityV8(t, &ObservabilityV8Source{
		Destinations: []ObservabilityV8DestinationSource{
			defaultDestination, explicitDestination, advancedDestination,
		},
	})

	compiledDefault, ok := plan.Destination(defaultDestination.Name)
	if !ok || compiledDefault.PolicyForm != ObservabilityV8PolicyCapabilityDefault ||
		compiledDefault.Enabled || len(compiledDefault.CompatibilityProfiles) != 1 ||
		len(compiledDefault.Routes) != 1 {
		t.Fatalf("default Galileo destination = %+v", compiledDefault)
	}
	eligible := compiledDefault.CompatibilityProfiles[0].EligibleSpanFamilies
	wantEventNames := make([]observability.EventName, len(eligible))
	for index, family := range eligible {
		wantEventNames[index] = family.EventName
	}
	if got := compiledDefault.Routes[0].Selector.EventNames; !reflect.DeepEqual(got, wantEventNames) {
		t.Fatalf("default Galileo route event names = %v, want generated eligibility %v", got, wantEventNames)
	}
	if slices.Contains(wantEventNames, observability.EventName(observability.TelemetryFamilyAgentTransition)) {
		t.Fatal("generated Galileo default route admitted span.agent.transition")
	}

	compiledExplicit, ok := plan.Destination(explicitDestination.Name)
	if !ok || compiledExplicit.PolicyForm != ObservabilityV8PolicyConciseSend ||
		len(compiledExplicit.Routes) != 1 || len(compiledExplicit.Routes[0].Selector.EventNames) != 0 {
		t.Fatalf("explicit Galileo route was compatibility-narrowed = %+v", compiledExplicit)
	}
	compiledAdvanced, ok := plan.Destination(advancedDestination.Name)
	if !ok || compiledAdvanced.PolicyForm != ObservabilityV8PolicyAdvancedRoutes ||
		len(compiledAdvanced.Routes) != 1 || len(compiledAdvanced.Routes[0].Selector.EventNames) != 0 {
		t.Fatalf("advanced Galileo route was compatibility-narrowed = %+v", compiledAdvanced)
	}
}

func TestConstrainObservabilityV8CapabilityRouteUsesAvailableUniqueSortedFamilies(t *testing.T) {
	destinationWithFamilies := func(families []ObservabilityV8EffectiveSpanFamily) ObservabilityV8EffectiveDestination {
		return ObservabilityV8EffectiveDestination{
			PolicyForm: ObservabilityV8PolicyCapabilityDefault,
			Routes: []ObservabilityV8EffectiveRoute{{
				Generated: true, Action: ObservabilityV8RouteSend,
			}},
			CompatibilityProfiles: []ObservabilityV8EffectiveCompatibilityProfile{{
				ID: "test-profile", Availability: "available", EligibleSpanFamilies: families,
			}},
		}
	}
	destination := destinationWithFamilies([]ObservabilityV8EffectiveSpanFamily{
		{EventName: "span.model.chat", Availability: "available"},
		{EventName: "span.agent.transition", Availability: "pending"},
		{EventName: "span.agent.invoke", Availability: "available"},
		{EventName: "span.model.chat", Availability: "available"},
	})
	if err := constrainObservabilityV8CapabilityRouteToCompatibility(&destination); err != nil {
		t.Fatal(err)
	}
	want := []observability.EventName{"span.agent.invoke", "span.model.chat"}
	if got := destination.Routes[0].Selector.EventNames; !reflect.DeepEqual(got, want) {
		t.Fatalf("available compatibility event names = %v, want %v", got, want)
	}

	noAvailable := destinationWithFamilies([]ObservabilityV8EffectiveSpanFamily{{
		EventName: "span.agent.transition", Availability: "pending",
	}})
	if err := constrainObservabilityV8CapabilityRouteToCompatibility(&noAvailable); err == nil ||
		len(noAvailable.Routes[0].Selector.EventNames) != 0 {
		t.Fatalf("no-available compatibility route error=%v route=%+v", err, noAvailable.Routes[0])
	}
}

func TestObservabilityV8EffectivePlanPublishesCompatibilityAndReloadApplicability(t *testing.T) {
	local := validObservabilityV8Destination(observability.RuntimeLocalObservabilityDestination, ObservabilityV8DestinationOTLP)
	galileo := validObservabilityV8Destination("galileo", ObservabilityV8DestinationOTLP)
	galileo.Preset = "galileo"
	generic := validObservabilityV8Destination("generic", ObservabilityV8DestinationOTLP)
	prometheus := validObservabilityV8Destination("prometheus", ObservabilityV8DestinationPrometheus)
	plan := mustCompileObservabilityV8(t, &ObservabilityV8Source{
		Destinations: []ObservabilityV8DestinationSource{local, galileo, generic, prometheus},
	})

	snapshot := plan.Snapshot()
	for _, bucket := range snapshot.Buckets {
		if bucket.ReloadApplicability != ObservabilityV8LiveReloadable {
			t.Fatalf("bucket %q reload applicability = %q", bucket.Bucket, bucket.ReloadApplicability)
		}
	}
	assertDestination := func(name string) ObservabilityV8EffectiveDestination {
		t.Helper()
		destination, ok := plan.Destination(name)
		if !ok {
			t.Fatalf("destination %q missing", name)
		}
		return destination
	}
	localSQLite := assertDestination(ObservabilityV8LocalDestinationName)
	if localSQLite.ReloadApplicability.Policy != ObservabilityV8LiveReloadable ||
		localSQLite.ReloadApplicability.Transport != ObservabilityV8RestartRequired {
		t.Fatalf("local SQLite reload applicability = %+v", localSQLite.ReloadApplicability)
	}
	for _, name := range []string{observability.RuntimeLocalObservabilityDestination, "galileo", "generic"} {
		destination := assertDestination(name)
		if destination.ReloadApplicability.Policy != ObservabilityV8LiveReloadable ||
			destination.ReloadApplicability.Transport != ObservabilityV8LiveReloadable {
			t.Fatalf("destination %q reload applicability = %+v", name, destination.ReloadApplicability)
		}
	}
	prometheusReload := assertDestination("prometheus").ReloadApplicability
	if prometheusReload.Policy != ObservabilityV8RestartRequired ||
		prometheusReload.Transport != ObservabilityV8RestartRequired {
		t.Fatalf("Prometheus reload applicability = %+v", prometheusReload)
	}
	localProfile := assertDestination(observability.RuntimeLocalObservabilityDestination).CompatibilityProfiles
	if len(localProfile) != 1 || localProfile[0].ID != observability.RuntimeLocalObservabilityProfile ||
		localProfile[0].Availability != "available" ||
		!slices.ContainsFunc(localProfile[0].EligibleSpanFamilies, func(family ObservabilityV8EffectiveSpanFamily) bool {
			return family.EventName == "span.tool.execute" && family.Bucket == observability.BucketToolActivity &&
				family.Availability == "available"
		}) {
		t.Fatalf("local compatibility = %+v", localProfile)
	}
	galileoProfile := assertDestination("galileo").CompatibilityProfiles
	if len(galileoProfile) != 1 || galileoProfile[0].ID != "galileo-rich-v2" ||
		galileoProfile[0].Availability != "available" ||
		!slices.ContainsFunc(galileoProfile[0].EligibleSpanFamilies, func(family ObservabilityV8EffectiveSpanFamily) bool {
			return family.EventName == "span.model.chat" && family.Bucket == observability.BucketModelIO &&
				family.Availability == "available"
		}) {
		t.Fatalf("Galileo compatibility = %+v", galileoProfile)
	}
	openInference := assertDestination("generic").CompatibilityProfiles
	if len(openInference) != 1 || openInference[0].ID != observability.RuntimeOpenInferenceCompatibilityProfile ||
		openInference[0].Availability != "available" ||
		!slices.ContainsFunc(openInference[0].EligibleSpanFamilies, func(family ObservabilityV8EffectiveSpanFamily) bool {
			return family.EventName == "span.model.embeddings" && family.Bucket == observability.BucketModelIO &&
				family.Availability == "available"
		}) {
		t.Fatalf("OpenInference compatibility = %+v", openInference)
	}
}
