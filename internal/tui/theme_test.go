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

import "testing"

func TestDefaultThemeNotNil(t *testing.T) {
	theme := DefaultTheme()
	if theme == nil {
		t.Fatal("DefaultTheme returned nil")
		return
	}

	if theme.DotRunning == "" {
		t.Error("DotRunning should not be empty")
	}
	if theme.DotDegraded == "" {
		t.Error("DotDegraded should not be empty")
	}
	if theme.DotError == "" {
		t.Error("DotError should not be empty")
	}
	if theme.DotOff == "" {
		t.Error("DotOff should not be empty")
	}
}

func TestSeverityColor(t *testing.T) {
	theme := DefaultTheme()

	tests := []struct {
		severity string
	}{
		{"CRITICAL"},
		{"HIGH"},
		{"MEDIUM"},
		{"LOW"},
		{"UNKNOWN"},
		{""},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			style := theme.SeverityColor(tt.severity)
			rendered := style.Render("test")
			if rendered == "" {
				t.Errorf("SeverityColor(%q).Render returned empty string", tt.severity)
			}
		})
	}
}

func TestStateColor(t *testing.T) {
	theme := DefaultTheme()

	tests := []struct {
		state string
	}{
		{"running"},
		{"active"},
		{"allowed"},
		{"blocked"},
		{"clean"},
		{"enabled"},
		{"warning"},
		{"rejected"},
		{"reconnecting"},
		{"starting"},
		{"error"},
		{"stopped"},
		{"disabled"},
		{"unknown"},
		{""},
	}

	for _, tt := range tests {
		t.Run(tt.state, func(t *testing.T) {
			style := theme.StateColor(tt.state)
			rendered := style.Render("test")
			if rendered == "" {
				t.Errorf("StateColor(%q).Render returned empty string", tt.state)
			}
		})
	}
}

func TestStateDot(t *testing.T) {
	theme := DefaultTheme()

	tests := []struct {
		state   string
		wantDot string
	}{
		{"running", theme.DotRunning},
		{"active", theme.DotRunning},
		{"reconnecting", theme.DotDegraded},
		{"starting", theme.DotDegraded},
		{"error", theme.DotError},
		{"stopped", theme.DotError},
		{"disabled", theme.DotOff},
		{"unknown", theme.DotOff},
		{"", theme.DotOff},
	}

	for _, tt := range tests {
		t.Run(tt.state, func(t *testing.T) {
			got := theme.StateDot(tt.state)
			if got != tt.wantDot {
				t.Errorf("StateDot(%q) = %q, want %q", tt.state, got, tt.wantDot)
			}
		})
	}
}
