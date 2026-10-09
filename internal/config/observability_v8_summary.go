// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"sort"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

// ObservabilityV8DestinationSummary is one compiled destination as the
// managed status commands show it: identity, signal set and the distinct
// effective redaction profiles of its send routes (GAP-1105).
type ObservabilityV8DestinationSummary struct {
	Name              string
	Kind              ObservabilityV8DestinationKind
	Enabled           bool
	Preset            string
	Signals           []observability.Signal
	RedactionProfiles []string
}

// SummarizeObservabilityV8Destinations compiles a config.yaml with the
// compiler `defenseclaw observability plan` uses and summarizes each
// destination. Secret references only need to be present: it never reads a
// secret value.
func SummarizeObservabilityV8Destinations(
	path string,
	data []byte,
	defaultDataDir string,
) ([]ObservabilityV8DestinationSummary, error) {
	compiled, err := ParseCompileObservabilityV8(path, data, ObservabilityV8CompileOptions{
		DefaultDataDir: defaultDataDir, Secrets: observabilityV8PresentSecrets{},
	})
	if err != nil {
		return nil, err
	}
	return compiled.Plan.DestinationSummaries(), nil
}

// DestinationSummaries lists every effective destination, the generated
// local-sqlite one included, in plan order.
func (plan *ObservabilityV8Plan) DestinationSummaries() []ObservabilityV8DestinationSummary {
	if plan == nil {
		return nil
	}
	destinations := plan.Destinations()
	summaries := make([]ObservabilityV8DestinationSummary, 0, len(destinations))
	for _, destination := range destinations {
		seen := map[string]bool{}
		profiles := []string{}
		for _, route := range destination.Routes {
			if route.Action != ObservabilityV8RouteSend {
				continue
			}
			for _, profile := range route.RedactionProfileByBucket {
				if profile != "" && !seen[profile] {
					seen[profile] = true
					profiles = append(profiles, profile)
				}
			}
		}
		sort.Strings(profiles)
		summaries = append(summaries, ObservabilityV8DestinationSummary{
			Name: destination.Name, Kind: destination.Kind, Enabled: destination.Enabled,
			Preset:            destination.Preset,
			Signals:           append([]observability.Signal{}, destination.SelectedSignals...),
			RedactionProfiles: profiles,
		})
	}
	return summaries
}

// observabilityV8PresentSecrets answers every reference with a placeholder:
// a summary needs the plan's shape, never a secret.
type observabilityV8PresentSecrets struct{}

func (observabilityV8PresentSecrets) ResolveObservabilitySecret(string) (string, bool) {
	return "present", true
}

func (observabilityV8PresentSecrets) ResolveObservabilityCredential(string) (string, bool) {
	return "present", true
}
