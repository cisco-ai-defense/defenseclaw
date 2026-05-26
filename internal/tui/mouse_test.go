// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func leftClick(x, y int) tea.Mouse {
	return tea.Mouse{X: x, Y: y, Button: tea.MouseLeft}
}

func TestMouseCommandPreviewButtons(t *testing.T) {
	m := New(Deps{Config: config.DefaultConfig(), Version: "test"})
	m.width = 100
	m.height = 30
	m.commandPreview = CommandPreviewModal{
		Active: true,
		Intent: NewCommandIntent("defenseclaw", []string{"setup", "guardrail"}, "setup guardrail", "setup", "test"),
	}
	box, hintY := m.commandPreview.renderBox(m.width, m.height, m.theme)
	rect := centeredRenderedBox(box, m.width, m.height)
	row := rect.y + 2 + hintY

	next, _ := m.handleMouseClick(leftClick(rect.x+18, row))
	got := next.(Model)
	if got.commandPreview.Active {
		t.Fatal("clicking cancel should close the command preview")
	}

	m.commandPreview.Active = true
	next, cmd := m.handleMouseClick(leftClick(rect.x+4, row))
	got = next.(Model)
	if got.commandPreview.Active {
		t.Fatal("clicking run should close the command preview")
	}
	if got.activePanel != PanelActivity || cmd == nil {
		t.Fatalf("clicking run should dispatch to Activity with a command, panel=%s cmd=%v", panelNames[got.activePanel], cmd)
	}
}

func TestMouseActionMenuRunsClickedRow(t *testing.T) {
	m := newTestModelWithPlugin(pluginItem{
		Name:    "tutor",
		ID:      "plug_tutor",
		Status:  "installed",
		Verdict: "clean",
		Enabled: true,
	})
	next, _ := m.handlePluginsKey(pressKey("o"))
	m = next.(Model)
	if !m.actionMenu.IsVisible() {
		t.Fatal("action menu did not open")
	}

	next, cmd := m.handleMouseClick(leftClick(4, 4))
	got := next.(Model)
	if got.actionMenu.IsVisible() {
		t.Fatal("clicking an action row should close the action menu")
	}
	if cmd == nil && !got.commandPreview.Active {
		t.Fatal("clicking an action row should run or preview the selected action")
	}
}

func TestMousePaletteRowExecutesSelectedCommand(t *testing.T) {
	m := New(Deps{Config: config.DefaultConfig(), Version: "test"})
	m.width = 120
	m.height = 40
	m.cmdInputFocus = true
	m.cmdInput.Focus()
	m.palette.Open()
	m.palette.SetInput("doctor")

	next, cmd := m.handleMouseClick(leftClick(4, m.paletteStartY()))
	got := next.(Model)
	if got.cmdInputFocus || got.palette.Active {
		t.Fatal("clicking a palette row should close the command input and palette")
	}
	if got.activePanel != PanelActivity || cmd == nil {
		t.Fatalf("palette click should dispatch selected command, panel=%s cmd=%v", panelNames[got.activePanel], cmd)
	}
}

func TestCommandInputCtrlCQuits(t *testing.T) {
	m := New(Deps{Config: config.DefaultConfig(), Version: "test"})
	m.cmdInputFocus = true
	m.cmdInput.Focus()
	_, cmd := m.handleKey(pressKey("ctrl+c"))
	if cmd == nil {
		t.Fatal("ctrl+c should quit even while command input is focused")
	}
}

func TestSetupMouseCredentialMatrixActions(t *testing.T) {
	p := NewSetupPanel(DefaultTheme(), config.DefaultConfig(), NewCommandExecutor())
	p.SetSize(140, 40)
	p.mode = setupModeWizards
	p.activeWizard = wizardCredentials
	p.SetCredentialSnapshot([]CredentialRow{
		{EnvName: "DEFENSECLAW_LLM_KEY", Feature: "llm", Requirement: "required", Source: "env", Set: false},
	}, time.Now(), nil)

	rowY := p.credentialMatrixStartY() + 2
	p.HandleMouseClick(4, rowY)
	if p.credentialCursor != 0 {
		t.Fatalf("credential row click should select row 0, got %d", p.credentialCursor)
	}

	actionY := p.credentialMatrixStartY() + p.credentialMatrixLineCount() - 1
	p.HandleMouseClick(51, actionY)
	if got := p.TakeMouseAction(); got != "refresh-credentials" {
		t.Fatalf("credential refresh click action=%q", got)
	}

	p.HandleMouseClick(3, actionY)
	if !p.wizFormActive {
		t.Fatal("credential set click should open the masked set form")
	}
}

func TestSetupMouseWizardFormFieldClick(t *testing.T) {
	p := NewSetupPanel(DefaultTheme(), config.DefaultConfig(), NewCommandExecutor())
	p.SetSize(120, 40)
	p.showWizardForm(wizardConnectorSetup)
	before := p.wizFormFields[0].Value

	p.HandleMouseClick(4, 3)
	if p.wizFormFields[0].Value == before {
		t.Fatalf("clicking choice field should cycle value, still %q", before)
	}

	p.HandleMouseClick(4, 7)
	if p.wizFormFields[4].Value != "no" {
		t.Fatalf("clicking bool field should toggle to no, got %q", p.wizFormFields[4].Value)
	}
}
