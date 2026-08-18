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
	"fmt"
	"sort"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	publicschemas "github.com/defenseclaw/defenseclaw/schemas"
)

type observabilityV8CatalogCompatibilityProfile struct {
	ID            string
	Availability  string
	TraceFamilies []observabilityV8CatalogTraceFamily
}

type observabilityV8CatalogTraceFamily struct {
	EventName    observability.EventName
	Bucket       observability.Bucket
	Availability string
}

var observabilityV8CatalogCompatibilityCache struct {
	once     sync.Once
	profiles map[string]observabilityV8CatalogCompatibilityProfile
	err      error
}

// observabilityV8CatalogCompatibilityProfiles reads compatibility membership
// from the embedded generated telemetry catalog. It deliberately does not keep
// a second family list in configuration code: registry generation remains the
// only authority for whether a span family belongs to a destination profile.
func observabilityV8CatalogCompatibilityProfiles() (map[string]observabilityV8CatalogCompatibilityProfile, error) {
	observabilityV8CatalogCompatibilityCache.once.Do(func() {
		var catalog struct {
			CompatibilityManifests []struct {
				ID           string `json:"id"`
				Availability string `json:"availability"`
			} `json:"compatibility_manifests"`
			Families []struct {
				EventName             string               `json:"event_name"`
				Signal                observability.Signal `json:"signal"`
				Bucket                observability.Bucket `json:"bucket"`
				CompatibilityProfiles []struct {
					ID           string `json:"id"`
					Availability string `json:"availability"`
				} `json:"compatibility_profiles"`
			} `json:"families"`
		}
		if err := json.Unmarshal(publicschemas.TelemetryV8Catalog(), &catalog); err != nil {
			observabilityV8CatalogCompatibilityCache.err = fmt.Errorf("decode generated telemetry compatibility catalog: %w", err)
			return
		}
		profiles := make(map[string]observabilityV8CatalogCompatibilityProfile)
		for _, manifest := range catalog.CompatibilityManifests {
			if manifest.ID == "" || (manifest.Availability != "available" && manifest.Availability != "pending") {
				observabilityV8CatalogCompatibilityCache.err = fmt.Errorf(
					"generated telemetry compatibility catalog contains invalid manifest availability",
				)
				return
			}
			if _, duplicate := profiles[manifest.ID]; duplicate {
				observabilityV8CatalogCompatibilityCache.err = fmt.Errorf(
					"generated telemetry compatibility catalog repeats manifest %q",
					manifest.ID,
				)
				return
			}
			profiles[manifest.ID] = observabilityV8CatalogCompatibilityProfile{
				ID: manifest.ID, Availability: manifest.Availability,
			}
		}
		seen := make(map[string]map[observability.EventName]struct{})
		for _, family := range catalog.Families {
			if family.Signal != observability.SignalTraces {
				continue
			}
			eventName := observability.EventName(family.EventName)
			if !observability.IsRegisteredEventNameForSignal(observability.SignalTraces, eventName) {
				observabilityV8CatalogCompatibilityCache.err = fmt.Errorf(
					"generated telemetry compatibility catalog contains unknown trace family %q",
					family.EventName,
				)
				return
			}
			if !observability.IsBucket(family.Bucket) {
				observabilityV8CatalogCompatibilityCache.err = fmt.Errorf(
					"generated telemetry compatibility catalog contains unknown bucket %q for trace family %q",
					family.Bucket,
					family.EventName,
				)
				return
			}
			for _, profile := range family.CompatibilityProfiles {
				if profile.ID == "" || (profile.Availability != "available" && profile.Availability != "pending") {
					observabilityV8CatalogCompatibilityCache.err = fmt.Errorf(
						"generated telemetry compatibility catalog contains an empty profile for %q",
						family.EventName,
					)
					return
				}
				if seen[profile.ID] == nil {
					seen[profile.ID] = make(map[observability.EventName]struct{})
				}
				if _, duplicate := seen[profile.ID][eventName]; duplicate {
					observabilityV8CatalogCompatibilityCache.err = fmt.Errorf(
						"generated telemetry compatibility catalog repeats trace family %q in profile %q",
						family.EventName,
						profile.ID,
					)
					return
				}
				seen[profile.ID][eventName] = struct{}{}
				entry, declared := profiles[profile.ID]
				if !declared {
					observabilityV8CatalogCompatibilityCache.err = fmt.Errorf(
						"generated telemetry compatibility catalog references undeclared profile %q",
						profile.ID,
					)
					return
				}
				entry.TraceFamilies = append(entry.TraceFamilies, observabilityV8CatalogTraceFamily{
					EventName: eventName, Bucket: family.Bucket, Availability: profile.Availability,
				})
				profiles[profile.ID] = entry
			}
		}
		for id, profile := range profiles {
			sort.Slice(profile.TraceFamilies, func(left, right int) bool {
				return profile.TraceFamilies[left].EventName < profile.TraceFamilies[right].EventName
			})
			profiles[id] = profile
		}
		observabilityV8CatalogCompatibilityCache.profiles = profiles
	})
	if observabilityV8CatalogCompatibilityCache.err != nil {
		return nil, observabilityV8CatalogCompatibilityCache.err
	}
	result := make(map[string]observabilityV8CatalogCompatibilityProfile, len(observabilityV8CatalogCompatibilityCache.profiles))
	for id, profile := range observabilityV8CatalogCompatibilityCache.profiles {
		profile.TraceFamilies = append([]observabilityV8CatalogTraceFamily(nil), profile.TraceFamilies...)
		result[id] = profile
	}
	return result, nil
}

func compileObservabilityV8DestinationCompatibility(
	destination ObservabilityV8EffectiveDestination,
) ([]ObservabilityV8EffectiveCompatibilityProfile, error) {
	if !destination.Capabilities.Supports(observability.SignalTraces) ||
		!effectiveObservabilityV8DestinationSelectsSignal(destination, observability.SignalTraces) {
		return nil, nil
	}
	profileID := ""
	switch {
	case destination.Preset == "galileo":
		profileID = destination.PresetProfile
	case destination.Name == observability.RuntimeLocalObservabilityDestination && destination.Kind == ObservabilityV8DestinationOTLP:
		profileID = observability.RuntimeLocalObservabilityProfile
	case destination.Kind == ObservabilityV8DestinationOTLP && destination.Preset == "":
		profileID = observability.RuntimeOpenInferenceCompatibilityProfile
	default:
		return nil, nil
	}
	profiles, err := observabilityV8CatalogCompatibilityProfiles()
	if err != nil {
		return nil, err
	}
	profile, ok := profiles[profileID]
	if !ok || len(profile.TraceFamilies) == 0 {
		return nil, fmt.Errorf("generated telemetry catalog does not define trace compatibility profile %q", profileID)
	}
	result := ObservabilityV8EffectiveCompatibilityProfile{
		ID:                   profile.ID,
		Availability:         profile.Availability,
		EligibleSpanFamilies: make([]ObservabilityV8EffectiveSpanFamily, len(profile.TraceFamilies)),
	}
	for index, family := range profile.TraceFamilies {
		result.EligibleSpanFamilies[index] = ObservabilityV8EffectiveSpanFamily{
			EventName: family.EventName, Bucket: family.Bucket, Availability: family.Availability,
		}
	}
	return []ObservabilityV8EffectiveCompatibilityProfile{result}, nil
}

func constrainObservabilityV8CapabilityRouteToCompatibility(
	destination *ObservabilityV8EffectiveDestination,
) error {
	if destination == nil || destination.PolicyForm != ObservabilityV8PolicyCapabilityDefault ||
		len(destination.Routes) != 1 || !destination.Routes[0].Generated ||
		destination.Routes[0].Action != ObservabilityV8RouteSend ||
		len(destination.CompatibilityProfiles) != 1 {
		return fmt.Errorf("capability-default compatibility route is incomplete")
	}
	families := destination.CompatibilityProfiles[0].EligibleSpanFamilies
	eventNames := make([]observability.EventName, 0, len(families))
	seen := make(map[observability.EventName]struct{}, len(families))
	for _, family := range families {
		if family.Availability != "available" {
			continue
		}
		if _, duplicate := seen[family.EventName]; duplicate {
			continue
		}
		seen[family.EventName] = struct{}{}
		eventNames = append(eventNames, family.EventName)
	}
	if len(eventNames) == 0 {
		return fmt.Errorf("capability-default compatibility route has no available span families")
	}
	sort.Slice(eventNames, func(left, right int) bool { return eventNames[left] < eventNames[right] })
	destination.Routes[0].Selector.EventNames = eventNames
	return nil
}

func effectiveObservabilityV8DestinationSelectsSignal(
	destination ObservabilityV8EffectiveDestination,
	signal observability.Signal,
) bool {
	for _, selected := range destination.SelectedSignals {
		if selected == signal {
			return true
		}
	}
	return false
}
