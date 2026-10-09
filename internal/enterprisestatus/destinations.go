// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import (
	"fmt"
	"io"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// DestinationsFromSummaries converts compiled destination summaries to the
// status document's destinations list.
func DestinationsFromSummaries(summaries []config.ObservabilityV8DestinationSummary) []Destination {
	destinations := make([]Destination, 0, len(summaries))
	for _, summary := range summaries {
		signals := make([]string, 0, len(summary.Signals))
		for _, signal := range summary.Signals {
			signals = append(signals, string(signal))
		}
		destinations = append(destinations, Destination{
			Name: summary.Name, Kind: string(summary.Kind), Enabled: summary.Enabled, Preset: summary.Preset,
			Signals: signals, RedactionProfiles: append([]string{}, summary.RedactionProfiles...),
		})
	}
	return destinations
}

// WriteDestinations prints the human status lines for destinations, one per
// destination: name, kind, preset, signals and redaction profiles.
func WriteDestinations(w io.Writer, destinations []Destination) {
	if len(destinations) == 0 {
		return
	}
	fmt.Fprintln(w, "  observability destinations:")
	for _, destination := range destinations {
		kind := destination.Kind
		if destination.Preset != "" {
			kind += " (" + destination.Preset + ")"
		}
		state := ""
		if !destination.Enabled {
			state = " disabled"
		}
		profiles := strings.Join(destination.RedactionProfiles, ", ")
		if profiles == "" {
			profiles = "-"
		}
		signals := strings.Join(destination.Signals, ",")
		if signals == "" {
			signals = "-"
		}
		fmt.Fprintf(w, "    %s: %s%s signals=%s redaction=%s\n", destination.Name, kind, state, signals, profiles)
	}
}
