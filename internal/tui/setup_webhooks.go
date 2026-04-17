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
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"charm.land/lipgloss/v2"
)

// webhookRow mirrors the JSON schema emitted by
// `defenseclaw setup webhook list --json` (see
// cli/defenseclaw/commands/cmd_setup_webhook.py::_view_to_dict).
// Extra fields the TUI does not currently render are still declared
// so unmarshal stays lenient if the CLI surface grows new keys.
type webhookRow struct {
	Name            string   `json:"name"`
	Type            string   `json:"type"`
	URL             string   `json:"url"`
	SecretEnv       string   `json:"secret_env"`
	RoomID          string   `json:"room_id"`
	MinSeverity     string   `json:"min_severity"`
	Events          []string `json:"events"`
	TimeoutSeconds  int      `json:"timeout_seconds"`
	CooldownSeconds *int     `json:"cooldown_seconds"`
	Enabled         bool     `json:"enabled"`
}

type webhookLister func() ([]webhookRow, error)

// WebhookEditorModel is the Webhooks interactive sub-mode for the
// Setup panel. It mirrors SinkEditorModel: every mutation shells out
// to `defenseclaw setup webhook` with --non-interactive semantics so
// the CLI is the single source of truth and audit events are emitted
// by the Python command group, not duplicated in Go. The list is
// fetched synchronously via `list --json` because the editor must
// render rows on the first frame.
type WebhookEditorModel struct {
	active      bool
	webhooks    []webhookRow
	cursor      int
	loadErr     string
	status      string
	confirmRm   bool
	wantsWizard bool
	resumePend  bool
	width       int
	height      int
	lister      webhookLister
}

func NewWebhookEditorModel() WebhookEditorModel {
	return WebhookEditorModel{lister: defaultWebhookLister}
}

// SetLister swaps the list-fetching hook. Used by tests to inject a
// deterministic stub so we never exec the real binary in CI.
func (m *WebhookEditorModel) SetLister(l webhookLister) {
	if l != nil {
		m.lister = l
	}
}

func (m *WebhookEditorModel) IsActive() bool { return m.active }

func (m *WebhookEditorModel) Open() {
	m.active = true
	m.confirmRm = false
	m.status = ""
	m.wantsWizard = false
	if m.cursor < 0 {
		m.cursor = 0
	}
	m.Refresh()
}

func (m *WebhookEditorModel) Close() {
	m.active = false
	m.confirmRm = false
	m.resumePend = false
	m.wantsWizard = false
}

// ResumeAfterCommand is called by SetupPanel after a mutation the
// editor kicked off finishes. We defer the list refresh to the next
// key dispatch (via DrainResume) to keep the CommandDoneMsg path
// cheap and avoid re-entering exec under lock.
func (m *WebhookEditorModel) ResumeAfterCommand() {
	m.resumePend = true
}

func (m *WebhookEditorModel) DrainResume() bool {
	if !m.resumePend {
		return false
	}
	m.resumePend = false
	m.Refresh()
	return true
}

// WantsWebhookWizard is the editor's signal to SetupPanel that the
// user pressed 'a' and wants the webhook add-wizard. The flag is
// cleared after the caller reads it so repeated Opens don't loop
// back into the wizard.
func (m *WebhookEditorModel) WantsWebhookWizard() bool {
	v := m.wantsWizard
	m.wantsWizard = false
	return v
}

func (m *WebhookEditorModel) Refresh() {
	if m.lister == nil {
		m.lister = defaultWebhookLister
	}
	rows, err := m.lister()
	if err != nil {
		m.loadErr = err.Error()
		m.webhooks = nil
		m.cursor = 0
		return
	}
	m.loadErr = ""
	m.webhooks = rows
	if m.cursor >= len(rows) {
		m.cursor = len(rows) - 1
	}
	if m.cursor < 0 {
		m.cursor = 0
	}
}

func (m *WebhookEditorModel) Selected() *webhookRow {
	if m.cursor < 0 || m.cursor >= len(m.webhooks) {
		return nil
	}
	return &m.webhooks[m.cursor]
}

func (m *WebhookEditorModel) SetSize(w, h int) {
	m.width = w
	m.height = h
}

// HandleKey dispatches a key event and returns the optional CLI
// command to run. Returning (binary, args) lets SetupPanel's executor
// re-use the same command pipeline as the rest of the wizard without
// us needing a second parallel plumbing.
func (m *WebhookEditorModel) HandleKey(key string) (runCmd bool, binary string, args []string, displayName string) {
	if !m.active {
		return false, "", nil, ""
	}

	if m.confirmRm {
		switch key {
		case "y", "Y":
			sel := m.Selected()
			m.confirmRm = false
			if sel == nil {
				return false, "", nil, ""
			}
			m.resumePend = true
			m.status = fmt.Sprintf("removing %s…", sel.Name)
			return true, "defenseclaw",
				[]string{"setup", "webhook", "remove", sel.Name, "--yes"},
				"webhook remove " + sel.Name
		case "n", "N", "esc":
			m.confirmRm = false
			m.status = ""
			return false, "", nil, ""
		}
		return false, "", nil, ""
	}

	switch key {
	case "esc", "q":
		m.Close()

	case "j", "down":
		if m.cursor < len(m.webhooks)-1 {
			m.cursor++
		}

	case "k", "up":
		if m.cursor > 0 {
			m.cursor--
		}

	case "g", "home":
		m.cursor = 0

	case "G", "end":
		if len(m.webhooks) > 0 {
			m.cursor = len(m.webhooks) - 1
		}

	case "f5", "ctrl+r":
		m.Refresh()
		m.status = "refreshed"

	case "e":
		sel := m.Selected()
		if sel == nil {
			m.status = "no webhook selected"
			return false, "", nil, ""
		}
		if sel.Enabled {
			m.status = fmt.Sprintf("%s already enabled", sel.Name)
			return false, "", nil, ""
		}
		m.resumePend = true
		m.status = fmt.Sprintf("enabling %s…", sel.Name)
		return true, "defenseclaw",
			[]string{"setup", "webhook", "enable", sel.Name},
			"webhook enable " + sel.Name

	case "d":
		sel := m.Selected()
		if sel == nil {
			m.status = "no webhook selected"
			return false, "", nil, ""
		}
		if !sel.Enabled {
			m.status = fmt.Sprintf("%s already disabled", sel.Name)
			return false, "", nil, ""
		}
		m.resumePend = true
		m.status = fmt.Sprintf("disabling %s…", sel.Name)
		return true, "defenseclaw",
			[]string{"setup", "webhook", "disable", sel.Name},
			"webhook disable " + sel.Name

	case "r":
		if m.Selected() != nil {
			m.confirmRm = true
		} else {
			m.status = "no webhook selected"
		}

	case "t":
		sel := m.Selected()
		if sel == nil {
			m.status = "no webhook selected"
			return false, "", nil, ""
		}
		m.resumePend = true
		m.status = fmt.Sprintf("testing %s…", sel.Name)
		return true, "defenseclaw",
			[]string{"setup", "webhook", "test", sel.Name},
			"webhook test " + sel.Name

	case "s":
		sel := m.Selected()
		if sel == nil {
			m.status = "no webhook selected"
			return false, "", nil, ""
		}
		m.resumePend = true
		m.status = fmt.Sprintf("showing %s…", sel.Name)
		return true, "defenseclaw",
			[]string{"setup", "webhook", "show", sel.Name},
			"webhook show " + sel.Name

	case "a":
		// The add-webhook surface has per-type prompts (slack
		// room_id, generic HMAC secret, etc.) that a flat list-view
		// can't represent. Hand off to the Setup wizard form, which
		// already knows how to collect them (see webhookWizardFields).
		m.active = false
		m.confirmRm = false
		m.resumePend = false
		m.wantsWizard = true
	}

	return false, "", nil, ""
}

func (m *WebhookEditorModel) View() string {
	var b strings.Builder

	bold := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("252"))
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	high := lipgloss.NewStyle().Bold(true).
		Foreground(lipgloss.Color("230")).
		Background(lipgloss.Color("62"))
	errStyle := lipgloss.NewStyle().Bold(true).
		Foreground(lipgloss.Color("230")).
		Background(lipgloss.Color("196")).
		Padding(0, 1)
	warn := lipgloss.NewStyle().Bold(true).
		Foreground(lipgloss.Color("230")).
		Background(lipgloss.Color("160")).
		Padding(0, 1)
	ok := lipgloss.NewStyle().Foreground(lipgloss.Color("34"))
	off := lipgloss.NewStyle().Foreground(lipgloss.Color("243"))

	b.WriteString(bold.Render("  ── Webhooks (notifiers) ──"))
	b.WriteString("\n")
	b.WriteString(dim.Render(
		"  j/k nav · e enable · d disable · r remove · t test · s show · a add · Ctrl+R refresh · Esc close",
	))
	b.WriteString("\n\n")

	if m.loadErr != "" {
		b.WriteString("  " + errStyle.Render("Error loading webhooks: "+m.loadErr))
		b.WriteString("\n\n")
	}

	if len(m.webhooks) == 0 && m.loadErr == "" {
		b.WriteString("  " + dim.Render(
			"(no webhooks configured — press 'a' to open the Webhooks wizard)"))
		b.WriteString("\n")
	} else if len(m.webhooks) > 0 {
		header := fmt.Sprintf(
			"  %-28s %-12s %-8s %-10s %s",
			"NAME", "TYPE", "ENABLED", "MIN-SEV", "URL",
		)
		b.WriteString(dim.Render(header))
		b.WriteString("\n")

		urlMax := 60
		if m.width > 0 {
			// 28 + 12 + 8 + 10 + 4 spaces + 2 leading = 64
			urlMax = m.width - 64
			if urlMax < 20 {
				urlMax = 20
			}
		}

		for i, w := range m.webhooks {
			name := truncMid(w.Name, 28)
			kind := truncMid(w.Type, 12)
			sev := w.MinSeverity
			if sev == "" {
				sev = "-"
			}
			url := truncMid(w.URL, urlMax)
			enabledText := "no"
			if w.Enabled {
				enabledText = "yes"
			}
			line := fmt.Sprintf(
				"  %-28s %-12s %-8s %-10s %s",
				name, kind, enabledText, sev, url,
			)
			if i == m.cursor {
				b.WriteString(high.Render(line))
			} else {
				if w.Enabled {
					line = strings.Replace(line, " yes      ", " "+ok.Render("yes")+"      ", 1)
				} else {
					line = strings.Replace(line, " no       ", " "+off.Render("no")+"       ", 1)
				}
				b.WriteString(line)
			}
			b.WriteString("\n")
		}
	}

	b.WriteString("\n")

	if m.confirmRm {
		if sel := m.Selected(); sel != nil {
			b.WriteString("  " + warn.Render(
				fmt.Sprintf("Remove %q? [y/N]", sel.Name)))
			b.WriteString("\n")
		}
	} else if m.status != "" {
		b.WriteString("  " + dim.Render(m.status))
		b.WriteString("\n")
	}

	return b.String()
}

func defaultWebhookLister() ([]webhookRow, error) {
	cmd := exec.Command("defenseclaw", "setup", "webhook", "list", "--json")
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok && len(ee.Stderr) > 0 {
			return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, err
	}
	return parseWebhookListJSON(out)
}

// parseWebhookListJSON is factored out so tests can exercise the
// unmarshal path directly without exec'ing the binary.
func parseWebhookListJSON(raw []byte) ([]webhookRow, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, nil
	}
	var rows []webhookRow
	if err := json.Unmarshal([]byte(trimmed), &rows); err != nil {
		return nil, fmt.Errorf("parse webhook list: %w", err)
	}
	return rows, nil
}
