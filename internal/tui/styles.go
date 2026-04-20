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

var (
	// Tab bar
	TabStyle       = lipgloss.NewStyle().Padding(0, 2).Foreground(lipgloss.Color("245"))
	ActiveTabStyle = lipgloss.NewStyle().Padding(0, 2).Bold(true).Foreground(lipgloss.Color("39")).Underline(true)
	TabBarStyle    = lipgloss.NewStyle().BorderBottom(true).BorderStyle(lipgloss.NormalBorder()).BorderForeground(lipgloss.Color("238"))

	// Severity colors
	StyleCritical = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	StyleHigh     = lipgloss.NewStyle().Foreground(lipgloss.Color("208")).Bold(true)
	StyleMedium   = lipgloss.NewStyle().Foreground(lipgloss.Color("220"))
	StyleLow      = lipgloss.NewStyle().Foreground(lipgloss.Color("39"))
	StyleInfo     = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))

	// Status indicators
	StyleBlocked = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	StyleAllowed = lipgloss.NewStyle().Foreground(lipgloss.Color("46"))
	StyleUnknown = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))

	// List
	SelectedStyle = lipgloss.NewStyle().Background(lipgloss.Color("237")).Bold(true)
	NormalStyle   = lipgloss.NewStyle()
	HeaderStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39")).BorderBottom(true).BorderStyle(lipgloss.NormalBorder()).BorderForeground(lipgloss.Color("238"))

	// Detail modal
	ModalStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("62")).
			Padding(1, 2)
	ModalTitleStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	ModalLabelStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("245"))

	// Help
	HelpStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))

	// Title
	TitleStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("62"))
)

func SeverityStyle(sev string) lipgloss.Style {
	switch sev {
	case "CRITICAL":
		return StyleCritical
	case "HIGH":
		return StyleHigh
	case "MEDIUM":
		return StyleMedium
	case "LOW":
		return StyleLow
	default:
		return StyleInfo
	}
}

func StatusStyle(status string) lipgloss.Style {
	switch status {
	case "blocked":
		return StyleBlocked
	case "allowed":
		return StyleAllowed
	default:
		return StyleUnknown
	}
}
