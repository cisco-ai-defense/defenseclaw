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

// sinkRow mirrors the JSON schema emitted by
// `defenseclaw setup observability list --json`
// (see cli/defenseclaw/commands/cmd_setup_observability.py `_dest_to_dict`).
// Fields the TUI does not display are still parsed so unmarshal stays
// lenient if the CLI surface grows new keys.
type sinkRow struct {
	Name     string   `json:"name"`
	Target   string   `json:"target"`
	Kind     string   `json:"kind"`
	Enabled  bool     `json:"enabled"`
	PresetID string   `json:"preset_id"`
	Endpoint string   `json:"endpoint"`
	Signals  []string `json:"signals"`
}

// sinkLister runs the CLI list command and returns the parsed rows.
// Stored as a field on SinkEditorModel so tests can inject a deterministic
// stub without shelling out to the real binary.
type sinkLister func() ([]sinkRow, error)

// SinkEditorModel is the Audit Sinks interactive sub-mode for the Setup
// panel. It shells out to `defenseclaw setup observability` for every
// mutation (enable / disable / remove / test / migrate-splunk) so the
// CLI stays the single source of truth and audit events are logged by
// the Python command group, not forked in the TUI. `list --json` is the
// only call issued in-process (synchronously) since the CLI is fast and
// the editor must render immediately on open.
type SinkEditorModel struct {
	active      bool
	sinks       []sinkRow
	cursor      int
	loadErr     string
	status      string
	confirmRm   bool
	wantsWizard bool // 'a' pressed — SetupPanel should open the Observability wizard
	resumePend  bool // set when a mutation is kicked off, cleared by DrainResume on return
	width       int
	height      int
	lister      sinkLister
}

// NewSinkEditorModel constructs the editor with the default live lister
// (real `defenseclaw` binary). Tests should call `SetLister` with a stub.
func NewSinkEditorModel() SinkEditorModel {
	return SinkEditorModel{lister: defaultSinkLister}
}

// SetLister swaps the list-fetching hook. Used by tests to avoid
// exec'ing the real CLI (which would require an installed binary + a
// configured `~/.defenseclaw/config.yaml`).
func (m *SinkEditorModel) SetLister(l sinkLister) {
	if l != nil {
		m.lister = l
	}
}

// IsActive reports whether the editor is currently visible. Used by
// SetupPanel.HandleKey / View to route events to the editor instead of
// the config form.
func (m *SinkEditorModel) IsActive() bool { return m.active }

// Open turns the editor on and fetches the current sink list. Safe to
// call repeatedly — this is what `E` on the Audit Sinks row triggers.
func (m *SinkEditorModel) Open() {
	m.active = true
	m.confirmRm = false
	m.status = ""
	m.wantsWizard = false
	if m.cursor < 0 {
		m.cursor = 0
	}
	m.Refresh()
}

// Close hides the editor and drops transient state (confirmation gate,
// resume flag). The list of sinks is kept so the next Open starts from
// the previous cursor position — rapid e/d cycles feel stable.
func (m *SinkEditorModel) Close() {
	m.active = false
	m.confirmRm = false
	m.resumePend = false
	m.wantsWizard = false
}

// ResumeAfterCommand is called by SetupPanel when a mutation that the
// editor kicked off has finished running. It flags the editor for a
// list refresh — we don't refresh synchronously here because the caller
// may still be inside the CommandDoneMsg dispatch and we want to keep
// that path cheap. DrainResume() does the actual refresh on next key
// handling.
func (m *SinkEditorModel) ResumeAfterCommand() {
	m.resumePend = true
}

// DrainResume consumes the pending refresh flag. Returns true iff a
// refresh was performed so the caller can log / toast accordingly.
func (m *SinkEditorModel) DrainResume() bool {
	if !m.resumePend {
		return false
	}
	m.resumePend = false
	m.Refresh()
	return true
}

// WantsObservabilityWizard reports (and clears) a pending request to
// open the Observability setup wizard — set when the user presses 'a'.
// SetupPanel checks this after each editor HandleKey and, if true,
// transitions to the wizard form.
func (m *SinkEditorModel) WantsObservabilityWizard() bool {
	v := m.wantsWizard
	m.wantsWizard = false
	return v
}

// Refresh re-fetches the sink list via the CLI. Any failure is stored
// in `loadErr` and rendered in the view — we never silently fall back
// to stale data because stale rows would mislead destructive actions
// (e.g. enabling a sink that has just been removed from disk).
func (m *SinkEditorModel) Refresh() {
	if m.lister == nil {
		m.lister = defaultSinkLister
	}
	rows, err := m.lister()
	if err != nil {
		m.loadErr = err.Error()
		m.sinks = nil
		m.cursor = 0
		return
	}
	m.loadErr = ""
	m.sinks = rows
	if m.cursor >= len(rows) {
		m.cursor = len(rows) - 1
	}
	if m.cursor < 0 {
		m.cursor = 0
	}
}

// Selected returns the currently highlighted sink, or nil if the list
// is empty. Callers must not retain the pointer across Refresh() — the
// underlying slice may be reallocated.
func (m *SinkEditorModel) Selected() *sinkRow {
	if m.cursor < 0 || m.cursor >= len(m.sinks) {
		return nil
	}
	return &m.sinks[m.cursor]
}

// SetSize lets SetupPanel flow its dimensions into the editor so long
// endpoint strings truncate to visible width instead of wrapping.
func (m *SinkEditorModel) SetSize(w, h int) {
	m.width = w
	m.height = h
}

// HandleKey processes an editor key event. Returns (runCmd, binary,
// args, displayName) so the enclosing SetupPanel can route the command
// through its existing executor + wizard-output plumbing.
func (m *SinkEditorModel) HandleKey(key string) (runCmd bool, binary string, args []string, displayName string) {
	if !m.active {
		return false, "", nil, ""
	}

	// Remove-confirmation gate — intercepts everything so the user
	// can't accidentally mutate via a stray 'e' while the [y/N] prompt
	// is up.
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
				[]string{"setup", "observability", "remove", sel.Name, "--yes"},
				"observability remove " + sel.Name
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
		if m.cursor < len(m.sinks)-1 {
			m.cursor++
		}

	case "k", "up":
		if m.cursor > 0 {
			m.cursor--
		}

	case "g", "home":
		m.cursor = 0

	case "G", "end":
		if len(m.sinks) > 0 {
			m.cursor = len(m.sinks) - 1
		}

	case "f5", "ctrl+r":
		m.Refresh()
		m.status = "refreshed"

	case "e":
		sel := m.Selected()
		if sel == nil {
			m.status = "no sink selected"
			return false, "", nil, ""
		}
		if sel.Enabled {
			m.status = fmt.Sprintf("%s already enabled", sel.Name)
			return false, "", nil, ""
		}
		m.resumePend = true
		m.status = fmt.Sprintf("enabling %s…", sel.Name)
		return true, "defenseclaw",
			[]string{"setup", "observability", "enable", sel.Name},
			"observability enable " + sel.Name

	case "d":
		sel := m.Selected()
		if sel == nil {
			m.status = "no sink selected"
			return false, "", nil, ""
		}
		if !sel.Enabled {
			m.status = fmt.Sprintf("%s already disabled", sel.Name)
			return false, "", nil, ""
		}
		m.resumePend = true
		m.status = fmt.Sprintf("disabling %s…", sel.Name)
		return true, "defenseclaw",
			[]string{"setup", "observability", "disable", sel.Name},
			"observability disable " + sel.Name

	case "r":
		if m.Selected() != nil {
			m.confirmRm = true
		} else {
			m.status = "no sink selected"
		}

	case "t":
		sel := m.Selected()
		if sel == nil {
			m.status = "no sink selected"
			return false, "", nil, ""
		}
		m.resumePend = true
		m.status = fmt.Sprintf("testing %s…", sel.Name)
		return true, "defenseclaw",
			[]string{"setup", "observability", "test", sel.Name},
			"observability test " + sel.Name

	case "a":
		// Hand off to the Observability wizard. The wizard form has
		// preset + prompt fields that the editor's flat list-view
		// cannot represent, and re-implementing preset prompts here
		// would fork the CLI surface — not an option.
		// NB: we deactivate directly instead of calling Close() so the
		// `wantsWizard` signal survives for SetupPanel.HandleKey to
		// drain one frame later.
		m.active = false
		m.confirmRm = false
		m.resumePend = false
		m.wantsWizard = true

	case "m":
		// `migrate-splunk --apply` is idempotent: running it against a
		// config without a legacy `splunk:` block is a no-op, so we
		// don't bother gating it on detection.
		m.resumePend = true
		m.status = "migrating legacy splunk: block…"
		return true, "defenseclaw",
			[]string{"setup", "observability", "migrate-splunk", "--apply"},
			"observability migrate-splunk --apply"
	}

	return false, "", nil, ""
}

// View renders the editor list + hotkey bar. Always keep the instruction
// row visible — operators coming from the config form have no way to
// discover editor-specific bindings otherwise.
func (m *SinkEditorModel) View() string {
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

	b.WriteString(bold.Render("  ── Audit Sinks (observability) ──"))
	b.WriteString("\n")
	b.WriteString(dim.Render(
		"  j/k nav · e enable · d disable · r remove · t test · a add · m migrate-splunk · Ctrl+R refresh · Esc close",
	))
	b.WriteString("\n\n")

	if m.loadErr != "" {
		b.WriteString("  " + errStyle.Render("Error loading sinks: "+m.loadErr))
		b.WriteString("\n\n")
	}

	if len(m.sinks) == 0 && m.loadErr == "" {
		b.WriteString("  " + dim.Render(
			"(no sinks configured — press 'a' to open the Observability wizard, "+
				"'m' to migrate a legacy splunk: block)"))
		b.WriteString("\n")
	} else if len(m.sinks) > 0 {
		header := fmt.Sprintf(
			"  %-30s %-12s %-8s %-14s %s",
			"NAME", "KIND", "ENABLED", "PRESET", "ENDPOINT",
		)
		b.WriteString(dim.Render(header))
		b.WriteString("\n")

		// Compute endpoint width budget based on panel width.
		endpointMax := 60
		if m.width > 0 {
			// 30+12+8+14 + 5 spaces + 2 leading = 71
			endpointMax = m.width - 71
			if endpointMax < 20 {
				endpointMax = 20
			}
		}

		for i, s := range m.sinks {
			name := truncMid(s.Name, 30)
			preset := s.PresetID
			if preset == "" {
				preset = "-"
			}
			preset = truncMid(preset, 14)
			endpoint := truncMid(s.Endpoint, endpointMax)
			kind := truncMid(s.Kind, 12)

			enabledText := "no"
			if s.Enabled {
				enabledText = "yes"
			}

			line := fmt.Sprintf(
				"  %-30s %-12s %-8s %-14s %s",
				name, kind, enabledText, preset, endpoint,
			)
			if i == m.cursor {
				b.WriteString(high.Render(line))
			} else {
				// Dim the enabled column when disabled, bold green
				// when enabled — operators need to see state at a glance.
				if s.Enabled {
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

// truncMid shortens s to fit within width, inserting an ellipsis in the
// middle rather than the tail so both sink name prefix (e.g. provider)
// and suffix (e.g. host) remain visible. Width <= 3 degrades to leading
// characters — the column is too narrow for ellipsis to be useful.
func truncMid(s string, width int) string {
	if width <= 0 {
		return ""
	}
	if len(s) <= width {
		return s
	}
	if width <= 3 {
		return s[:width]
	}
	half := (width - 1) / 2
	return s[:half] + "…" + s[len(s)-(width-half-1):]
}

// defaultSinkLister runs `defenseclaw setup observability list --json`
// and parses the result. Any non-zero exit / unparseable JSON is returned
// as an error and surfaced in the editor's loadErr row.
//
// We deliberately use `exec.Command` here (not the TUI's CommandExecutor)
// because:
//   - list is read-only, fast (<200ms) and non-interactive
//   - the executor streams output line-by-line which would force us to
//     reassemble the JSON payload from a scanner and re-parse
//   - the editor needs rows synchronously on Open/Refresh so the View
//     has data to render on the first frame
func defaultSinkLister() ([]sinkRow, error) {
	cmd := exec.Command("defenseclaw", "setup", "observability", "list", "--json")
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok && len(ee.Stderr) > 0 {
			return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, err
	}
	return parseSinkListJSON(out)
}

// parseSinkListJSON is separated for testability — the JSON shape is
// authored by cmd_setup_observability.py `_dest_to_dict` and any
// incompatible change should fail fast, not silently paper over.
func parseSinkListJSON(raw []byte) ([]sinkRow, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, nil
	}
	var rows []sinkRow
	if err := json.Unmarshal([]byte(trimmed), &rows); err != nil {
		return nil, fmt.Errorf("parse sink list: %w", err)
	}
	return rows, nil
}
