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

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestConnectorSetupWizardArgsCoverEveryConnector(t *testing.T) {
	t.Parallel()
	cases := []struct {
		connector string
		want      []string
	}{
		{"openclaw", []string{"setup", "openclaw", "--yes", "--mode", "observe", "--scanner-mode", "local"}},
		{"zeptoclaw", []string{"setup", "zeptoclaw", "--yes", "--mode", "observe", "--scanner-mode", "local"}},
		{"codex", []string{"setup", "codex", "--yes"}},
		{"claudecode", []string{"setup", "claude-code", "--yes"}},
		{"hermes", []string{"setup", "hermes", "--yes"}},
		{"cursor", []string{"setup", "cursor", "--yes"}},
		{"windsurf", []string{"setup", "windsurf", "--yes"}},
		{"geminicli", []string{"setup", "geminicli", "--yes"}},
		{"copilot", []string{"setup", "copilot", "--yes"}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.connector, func(t *testing.T) {
			t.Parallel()
			p := NewSetupPanel(nil, &config.Config{}, nil)
			p.wizFormFields = p.connectorSetupWizardFields()
			for i := range p.wizFormFields {
				if p.wizFormFields[i].Label == "Connector" {
					p.wizFormFields[i].Value = tc.connector
				}
			}
			got := p.buildWizardArgs(wizardConnectorSetup)
			if strings.Join(got, " ") != strings.Join(tc.want, " ") {
				t.Fatalf("connector %s args=%v want=%v", tc.connector, got, tc.want)
			}
			if strings.Contains(strings.Join(got, " "), "setup mode") {
				t.Fatalf("connector wizard must run full setup, not setup mode: %v", got)
			}
		})
	}
}

func TestConnectorSetupWizardArgsObservabilityOptions(t *testing.T) {
	t.Parallel()
	p := NewSetupPanel(nil, &config.Config{}, nil)
	p.wizFormFields = p.connectorSetupWizardFields()
	for i := range p.wizFormFields {
		switch p.wizFormFields[i].Label {
		case "Connector":
			p.wizFormFields[i].Value = "codex"
		case "Restart Gateway":
			p.wizFormFields[i].Value = "no"
		case "Local Stack":
			p.wizFormFields[i].Value = "yes"
		}
	}
	got := p.buildWizardArgs(wizardConnectorSetup)
	want := []string{"setup", "codex", "--yes", "--no-restart", "--with-local-stack"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("observability args=%v want=%v", got, want)
	}
}

func TestCredentialsWizardSetRequiresEnvAndSecret(t *testing.T) {
	t.Parallel()
	p := NewSetupPanel(nil, &config.Config{}, nil)
	p.activeWizard = wizardCredentials
	p.wizFormFields = p.wizardFormDefs(wizardCredentials)
	p.wizFormFields[0].Value = "set"
	missing := p.missingRequiredFields()
	if strings.Join(missing, ",") != "Env Name,Secret Value" {
		t.Fatalf("missing=%v", missing)
	}
}
