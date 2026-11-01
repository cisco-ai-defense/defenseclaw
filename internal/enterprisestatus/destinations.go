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

// AuditStore is the local audit store (audit.db) of the installed config:
// observability.local.retention_days (0: kept until the size cap or forever),
// observability.local.max_store_mb (0: no size cap) and the bytes of the store
// files on disk (omitted when they cannot be read). The per-user status that
// shows the retention and the cap is refused on a managed computer, so
// enterprise status shows them (GAP-0141).
type AuditStore struct {
	RetentionDays int    `json:"retention_days"`
	MaxStoreMB    int    `json:"max_store_mb"`
	SizeBytes     *int64 `json:"size_bytes,omitempty"`
}

// RetentionLabel is the retention as the per-user status says it: "7 days",
// "unbounded", "7 days, size cap 64 MiB" or "size cap 64 MiB".
func RetentionLabel(days, maxStoreMB int64) string {
	if maxStoreMB > 0 {
		capText := fmt.Sprintf("size cap %d MiB", maxStoreMB)
		if days == 0 {
			return capText
		}
		return fmt.Sprintf("%d days, %s", days, capText)
	}
	if days == 0 {
		return "unbounded"
	}
	return fmt.Sprintf("%d days", days)
}

// WriteAuditStore prints the human status line of the audit store.
func WriteAuditStore(w io.Writer, store *AuditStore) {
	if store == nil {
		return
	}
	line := "  audit store retention: " + RetentionLabel(int64(store.RetentionDays), int64(store.MaxStoreMB))
	if store.SizeBytes != nil {
		line += fmt.Sprintf(" (%.1f MiB on disk)", float64(*store.SizeBytes)/(1<<20))
	}
	fmt.Fprintln(w, line)
}
