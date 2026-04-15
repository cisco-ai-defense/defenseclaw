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

package tui

import "charm.land/lipgloss/v2"

// Theme centralizes all visual styles for the unified TUI.
type Theme struct {
	// Severity / state
	Critical    lipgloss.Style
	High        lipgloss.Style
	Medium      lipgloss.Style
	Low         lipgloss.Style
	Info        lipgloss.Style
	Clean       lipgloss.Style
	Blocked     lipgloss.Style
	Allowed     lipgloss.Style
	Quarantined lipgloss.Style
	Disabled    lipgloss.Style

	// Status dots
	DotRunning  string
	DotDegraded string
	DotError    string
	DotOff      string

	// UI chrome
	Title         lipgloss.Style
	ActiveTab     lipgloss.Style
	InactiveTab   lipgloss.Style
	SectionHeader lipgloss.Style
	KeyHint       lipgloss.Style
	HintText      lipgloss.Style
	Timestamp     lipgloss.Style
	Dimmed        lipgloss.Style
	Bold          lipgloss.Style

	// Panels
	PanelBorder lipgloss.Style

	// Status strip
	StatusBar   lipgloss.Style
	StatusLabel lipgloss.Style

	// Command palette
	PaletteInput lipgloss.Style
	PaletteItem  lipgloss.Style

	// Detail modal
	Modal      lipgloss.Style
	ModalTitle lipgloss.Style
	ModalLabel lipgloss.Style

	// Help
	Help lipgloss.Style

	// Activity
	CmdName    lipgloss.Style
	ExitOK     lipgloss.Style
	ExitFail   lipgloss.Style
	Spinner    lipgloss.Style
	LogError   lipgloss.Style
	LogWarn    lipgloss.Style
	LogKeyword lipgloss.Style
}

// DefaultTheme returns the standard DefenseClaw color theme.
func DefaultTheme() *Theme {
	return &Theme{
		Critical:    lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true),
		High:        lipgloss.NewStyle().Foreground(lipgloss.Color("208")).Bold(true),
		Medium:      lipgloss.NewStyle().Foreground(lipgloss.Color("220")),
		Low:         lipgloss.NewStyle().Foreground(lipgloss.Color("39")),
		Info:        lipgloss.NewStyle().Foreground(lipgloss.Color("245")),
		Clean:       lipgloss.NewStyle().Foreground(lipgloss.Color("46")),
		Blocked:     lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true),
		Allowed:     lipgloss.NewStyle().Foreground(lipgloss.Color("46")),
		Quarantined: lipgloss.NewStyle().Foreground(lipgloss.Color("133")),
		Disabled:    lipgloss.NewStyle().Foreground(lipgloss.Color("245")),

		DotRunning:  lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Render("●"),
		DotDegraded: lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render("●"),
		DotError:    lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render("●"),
		DotOff:      lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("○"),

		Title:         lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("62")),
		ActiveTab:     lipgloss.NewStyle().Padding(0, 2).Bold(true).Foreground(lipgloss.Color("230")).Background(lipgloss.Color("62")),
		InactiveTab:   lipgloss.NewStyle().Padding(0, 2).Foreground(lipgloss.Color("245")),
		SectionHeader: lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39")).BorderBottom(true).BorderStyle(lipgloss.NormalBorder()).BorderForeground(lipgloss.Color("238")),
		KeyHint:       lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("220")),
		HintText:      lipgloss.NewStyle().Italic(true).Foreground(lipgloss.Color("80")),
		Timestamp:     lipgloss.NewStyle().Foreground(lipgloss.Color("241")),
		Dimmed:        lipgloss.NewStyle().Foreground(lipgloss.Color("245")),
		Bold:          lipgloss.NewStyle().Bold(true),

		PanelBorder: lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("238")),

		StatusBar:   lipgloss.NewStyle().Background(lipgloss.Color("236")).Foreground(lipgloss.Color("252")).Padding(0, 1),
		StatusLabel: lipgloss.NewStyle().Background(lipgloss.Color("62")).Foreground(lipgloss.Color("230")).Padding(0, 1).Bold(true),

		PaletteInput: lipgloss.NewStyle().Foreground(lipgloss.Color("252")).Background(lipgloss.Color("236")).Padding(0, 1),
		PaletteItem:  lipgloss.NewStyle().Foreground(lipgloss.Color("252")),

		Modal:      lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("62")).Padding(1, 2),
		ModalTitle: lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39")),
		ModalLabel: lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("245")),

		Help: lipgloss.NewStyle().Foreground(lipgloss.Color("241")),

		CmdName:    lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39")),
		ExitOK:     lipgloss.NewStyle().Foreground(lipgloss.Color("46")),
		ExitFail:   lipgloss.NewStyle().Foreground(lipgloss.Color("196")),
		Spinner:    lipgloss.NewStyle().Foreground(lipgloss.Color("220")),
		LogError:   lipgloss.NewStyle().Foreground(lipgloss.Color("196")),
		LogWarn:    lipgloss.NewStyle().Foreground(lipgloss.Color("220")),
		LogKeyword: lipgloss.NewStyle().Foreground(lipgloss.Color("39")),
	}
}

// SeverityColor returns the appropriate style for a severity string.
func (t *Theme) SeverityColor(sev string) lipgloss.Style {
	switch sev {
	case "CRITICAL":
		return t.Critical
	case "HIGH":
		return t.High
	case "MEDIUM":
		return t.Medium
	case "LOW":
		return t.Low
	default:
		return t.Info
	}
}

// StateColor returns the appropriate style for a service state.
func (t *Theme) StateColor(state string) lipgloss.Style {
	switch state {
	case "running", "active", "allowed", "clean", "enabled":
		return t.Clean
	case "blocked", "rejected":
		return t.Blocked
	case "warning":
		return t.Medium
	case "reconnecting", "starting":
		return t.Medium
	case "error", "stopped":
		return t.Critical
	case "disabled":
		return t.Disabled
	default:
		return t.Disabled
	}
}

// StateDot returns a colored dot for a service state.
func (t *Theme) StateDot(state string) string {
	switch state {
	case "running", "active":
		return t.DotRunning
	case "reconnecting", "starting":
		return t.DotDegraded
	case "error", "stopped":
		return t.DotError
	default:
		return t.DotOff
	}
}
