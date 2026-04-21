// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"context"

	tea "charm.land/bubbletea/v2"

	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

// FilterChangeMsg is emitted when a logs/verdicts filter chip advances.
type FilterChangeMsg struct {
	Panel      string
	FilterType string
	Old        string
	New        string
}

// Panel names for OTel (stable, lower_snake).
const (
	PanelNameAlerts = "alerts"
	PanelNameLogs   = "logs"
	PanelNameSkills = "skills"
	PanelNameMCPs   = "mcps"
)

func (m Model) noteTUIFilterChange(panel, filterType, oldVal, newVal string) {
	emitTUIFilter(m.otelProv, panel, filterType, oldVal, newVal)
}

func emitTUIFilter(otel *telemetry.Provider, panel, filterType, oldVal, newVal string) {
	if otel == nil || !otel.Enabled() {
		return
	}
	ctx := context.Background()
	otel.EmitTUIFilterTrace(ctx, panel, filterType, oldVal, newVal)
	otel.RecordTUIFilterApplied(ctx, panel, filterType)
}

func filterChangeCmd(panel, ft, oldVal, newVal string) tea.Cmd {
	return func() tea.Msg {
		return FilterChangeMsg{Panel: panel, FilterType: ft, Old: oldVal, New: newVal}
	}
}
