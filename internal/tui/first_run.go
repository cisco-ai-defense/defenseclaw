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
	"charm.land/lipgloss/v2"
)

type firstRunField struct {
	Label   string
	Kind    string
	Value   string
	Options []string
	Hint    string
}

// FirstRunPanel is the missing-config bootstrap surface. It collects the
// same high-level choices as `defenseclaw init`, then shells out to the
// canonical Python backend with --json-summary so all setup logic stays in
// one place.
type FirstRunPanel struct {
	theme  *Theme
	active bool
	fields []firstRunField
	cursor int
	width  int
	height int
}

func NewFirstRunPanel(theme *Theme, active bool) FirstRunPanel {
	fields := []firstRunField{
		{Label: "Connector", Kind: "choice", Value: "codex", Options: []string{"codex", "claudecode", "zeptoclaw", "openclaw", "hermes", "cursor", "windsurf", "geminicli", "copilot"},
			Hint: "Agent framework to protect. OpenClaw is optional, not assumed."},
		{Label: "Profile", Kind: "choice", Value: "observe", Options: []string{"observe", "action"},
			Hint: "observe=detect/log; action=block."},
		{Label: "Scanner Mode", Kind: "choice", Value: "local", Options: []string{"local", "remote", "both"},
			Hint: "local needs no Cisco key; remote/both probe Cisco AI Defense."},
		{Label: "LLM Judge", Kind: "bool", Value: "false",
			Hint: "Enable LLM adjudication now. Requires a configured LLM key/model."},
		{Label: "Start Gateway", Kind: "bool", Value: "false",
			Hint: "Start the sidecar after writing config."},
		{Label: "Verify", Kind: "bool", Value: "true",
			Hint: "Run targeted readiness checks before landing on Overview."},
	}
	return FirstRunPanel{theme: theme, active: active, fields: fields}
}

func (p *FirstRunPanel) Active() bool { return p.active }

func (p *FirstRunPanel) SetSize(w, h int) {
	p.width = w
	p.height = h
}

func (p *FirstRunPanel) HandleKey(msg tea.KeyPressMsg) (bool, string, []string, string) {
	switch msg.String() {
	case "up", "k":
		if p.cursor > 0 {
			p.cursor--
		}
	case "down", "j":
		if p.cursor < len(p.fields)-1 {
			p.cursor++
		}
	case "left", "h":
		p.cycle(-1)
	case "right", "l", "enter", " ":
		p.cycle(1)
	case "ctrl+r":
		return true, "defenseclaw", p.Args(), "init first-run"
	}
	return false, "", nil, ""
}

func (p *FirstRunPanel) Args() []string {
	args := []string{"init", "--non-interactive", "--yes", "--json-summary"}
	connector := p.value("Connector")
	profile := p.value("Profile")
	scanner := p.value("Scanner Mode")
	args = append(args, "--connector", connector, "--profile", profile, "--scanner-mode", scanner)
	if p.value("LLM Judge") == "true" {
		args = append(args, "--with-judge")
	} else {
		args = append(args, "--no-judge")
	}
	if p.value("Start Gateway") == "true" {
		args = append(args, "--start-gateway")
	} else {
		args = append(args, "--no-start-gateway")
	}
	if p.value("Verify") == "true" {
		args = append(args, "--verify")
	} else {
		args = append(args, "--no-verify")
	}
	return args
}

func (p *FirstRunPanel) value(label string) string {
	for _, f := range p.fields {
		if f.Label == label {
			return f.Value
		}
	}
	return ""
}

func (p *FirstRunPanel) cycle(delta int) {
	if p.cursor < 0 || p.cursor >= len(p.fields) {
		return
	}
	f := &p.fields[p.cursor]
	switch f.Kind {
	case "bool":
		if f.Value == "true" {
			f.Value = "false"
		} else {
			f.Value = "true"
		}
	case "choice":
		if len(f.Options) == 0 {
			return
		}
		cur := 0
		for i, opt := range f.Options {
			if opt == f.Value {
				cur = i
				break
			}
		}
		next := (cur + delta + len(f.Options)) % len(f.Options)
		f.Value = f.Options[next]
	}
}

func (p *FirstRunPanel) setValue(label, value string) {
	for i := range p.fields {
		if p.fields[i].Label == label {
			p.fields[i].Value = value
			return
		}
	}
}

func (p FirstRunPanel) View() string {
	var b strings.Builder
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("230")).Render("DefenseClaw first-run setup")
	sub := lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("No config.yaml was found. Pick the basics, then press Ctrl+R to apply.")
	b.WriteString("\n  " + title + "\n")
	b.WriteString("  " + sub + "\n\n")
	for i, f := range p.fields {
		prefix := "  "
		style := lipgloss.NewStyle().Foreground(lipgloss.Color("252"))
		if i == p.cursor {
			prefix = "▸ "
			style = style.Bold(true).Foreground(lipgloss.Color("230")).Background(lipgloss.Color("62"))
		}
		value := f.Value
		if f.Kind == "bool" {
			if value == "true" {
				value = "on"
			} else {
				value = "off"
			}
		}
		row := fmt.Sprintf("%-16s %s", f.Label, value)
		b.WriteString(prefix + style.Render(row) + "\n")
		if i == p.cursor && f.Hint != "" {
			b.WriteString("    " + lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render(f.Hint) + "\n")
		}
	}
	b.WriteString("\n  " + lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("↑/↓ move  ←/→ change  Ctrl+R apply  Ctrl+C quit") + "\n")
	return b.String()
}
