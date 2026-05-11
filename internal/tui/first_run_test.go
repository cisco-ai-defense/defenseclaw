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
	"reflect"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
)

func TestFirstRunPanelArgsUseCanonicalInitBackend(t *testing.T) {
	p := NewFirstRunPanel(DefaultTheme(), true)

	got := p.Args()
	want := []string{
		"init", "--non-interactive", "--yes", "--json-summary",
		"--connector", "codex",
		"--profile", "observe",
		"--scanner-mode", "local",
		"--no-judge",
		"--no-start-gateway",
		"--verify",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Args() = %#v, want %#v", got, want)
	}
}

func TestFirstRunPanelConnectorChoicesCoverBuiltinConnectors(t *testing.T) {
	p := NewFirstRunPanel(DefaultTheme(), true)
	var connectors []string
	for _, field := range p.fields {
		if field.Label == "Connector" {
			connectors = field.Options
			break
		}
	}
	want := []string{
		"codex",
		"claudecode",
		"zeptoclaw",
		"openclaw",
		"hermes",
		"cursor",
		"windsurf",
		"geminicli",
		"copilot",
	}
	for _, name := range want {
		if !containsArg(connectors, name) {
			t.Fatalf("first-run connector choices missing %q: %v", name, connectors)
		}
	}
}

func TestFirstRunPanelCtrlRAppliesInit(t *testing.T) {
	p := NewFirstRunPanel(DefaultTheme(), true)
	run, binary, args, display := p.HandleKey(tea.KeyPressMsg(tea.Key{Code: 'r', Mod: tea.ModCtrl}))

	if !run {
		t.Fatal("Ctrl+R should request command execution")
	}
	if binary != "defenseclaw" {
		t.Fatalf("binary=%q, want defenseclaw", binary)
	}
	if display != "init first-run" {
		t.Fatalf("display=%q, want init first-run", display)
	}
	if len(args) < 4 || args[0] != "init" || !containsArg(args, "--json-summary") {
		t.Fatalf("unexpected init args: %v", args)
	}
}

func TestNewWithoutConfigStartsFirstRunPanel(t *testing.T) {
	m := New(Deps{Version: "test", FirstRun: true})
	m.width = 120
	m.height = 40

	if !m.firstRun.Active() {
		t.Fatal("missing config should activate first-run panel")
	}
	if m.activePanel != PanelSetup {
		t.Fatalf("activePanel=%d, want PanelSetup", m.activePanel)
	}
	out := m.View().Content
	if !strings.Contains(out, "DefenseClaw first-run setup") {
		t.Fatalf("first-run view missing setup title:\n%s", out)
	}
}
