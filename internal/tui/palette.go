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
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/sahilm/fuzzy"
)

// PaletteModel implements the command palette overlay.
type PaletteModel struct {
	Active   bool
	input    string
	cursor   int
	matches  []fuzzy.Match
	theme    *Theme
	registry []CmdEntry
	executor *CommandExecutor

	cmdNames []string // pre-built for fuzzy matching
}

// NewPaletteModel creates a new command palette.
func NewPaletteModel(theme *Theme, registry []CmdEntry, executor *CommandExecutor) PaletteModel {
	names := make([]string, len(registry))
	for i, e := range registry {
		names[i] = e.TUIName
	}
	return PaletteModel{
		theme:    theme,
		registry: registry,
		executor: executor,
		cmdNames: names,
	}
}

// Open activates the palette.
func (p *PaletteModel) Open() {
	p.Active = true
	p.input = ""
	p.cursor = 0
	p.updateMatches()
}

// Close deactivates the palette.
func (p *PaletteModel) Close() {
	p.Active = false
	p.input = ""
	p.cursor = 0
	p.matches = nil
}

// HandleKey processes key input while the palette is active.
func (p *PaletteModel) HandleKey(msg tea.KeyPressMsg) {
	switch msg.String() {
	case "backspace":
		if len(p.input) > 0 {
			p.input = p.input[:len(p.input)-1]
			p.cursor = 0
			p.updateMatches()
		}
	case "up":
		if p.cursor > 0 {
			p.cursor--
		}
	case "down":
		if p.cursor < len(p.matches)-1 {
			p.cursor++
		}
	case "tab":
		if p.cursor >= 0 && p.cursor < len(p.matches) {
			p.input = p.registry[p.matches[p.cursor].Index].TUIName + " "
			p.cursor = 0
			p.updateMatches()
		}
	default:
		if len(msg.String()) == 1 {
			p.input += msg.String()
			p.cursor = 0
			p.updateMatches()
		}
	}
}

// SetInput updates the palette's search text and re-runs fuzzy matching.
func (p *PaletteModel) SetInput(s string) {
	p.input = s
	p.cursor = 0
	p.updateMatches()
}

// SelectedName returns the TUIName of the currently highlighted match, or "".
func (p *PaletteModel) SelectedName() string {
	if p.cursor >= 0 && p.cursor < len(p.matches) {
		return p.registry[p.matches[p.cursor].Index].TUIName
	}
	return ""
}

// MoveUp moves the cursor up in the match list.
func (p *PaletteModel) MoveUp() {
	if p.cursor > 0 {
		p.cursor--
	}
}

// MoveDown moves the cursor down in the match list.
func (p *PaletteModel) MoveDown() {
	if p.cursor < len(p.matches)-1 {
		p.cursor++
	}
}

// MatchCount returns the number of current fuzzy matches.
func (p *PaletteModel) MatchCount() int {
	return len(p.matches)
}

// Execute runs the matched command and returns a tea.Cmd.
func (p *PaletteModel) Execute() (tea.Cmd, error) {
	entry, extra := MatchCommand(p.input, p.registry)
	if entry == nil {
		return nil, nil
	}

	args, err := buildCLIArgs(entry, extra)
	if err != nil {
		return nil, err
	}

	displayName := entry.TUIName
	if extra != "" {
		displayName += " " + extra
	}

	return p.executor.Execute(entry.CLIBinary, args, displayName), nil
}

func (p *PaletteModel) updateMatches() {
	if p.input == "" {
		p.matches = nil
		for i := range p.registry {
			p.matches = append(p.matches, fuzzy.Match{Index: i, Str: p.cmdNames[i]})
		}
		return
	}
	p.matches = fuzzy.Find(p.input, p.cmdNames)
}

// View renders the palette as a full overlay (with its own prompt).
func (p *PaletteModel) View(width int) string {
	var b strings.Builder

	prompt := p.theme.PaletteInput.Render(fmt.Sprintf(" > %s", p.input))
	b.WriteString(prompt)
	b.WriteString("\n")

	b.WriteString(p.renderMatches(width))

	if p.input == "" {
		b.WriteString(p.theme.HintText.Render("   Type a command (no \"defenseclaw\" prefix needed). Try: scan, block, status, doctor"))
	}

	return b.String()
}

// InlineView renders only the match dropdown (no prompt), for use under the textinput bar.
func (p *PaletteModel) InlineView(width int) string {
	if len(p.matches) == 0 {
		return ""
	}
	return p.renderMatches(width)
}

func (p *PaletteModel) renderMatches(width int) string {
	var b strings.Builder

	maxItems := 8
	if len(p.matches) < maxItems {
		maxItems = len(p.matches)
	}

	for i := 0; i < maxItems; i++ {
		match := p.matches[i]
		entry := p.registry[match.Index]
		name := entry.TUIName
		desc := entry.Description
		if entry.NeedsArg {
			name += " " + entry.ArgHint
		}

		line := fmt.Sprintf("   %-30s %s", name, p.theme.Dimmed.Render(desc))
		if i == p.cursor {
			line = SelectedStyle.Width(width).Render(line)
		}
		b.WriteString(line + "\n")
	}

	return b.String()
}
