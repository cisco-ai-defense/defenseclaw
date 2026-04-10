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

	"github.com/charmbracelet/lipgloss"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

type skillItem struct {
	Name      string
	Status    string
	Verified  bool
	Publisher string
	Actions   string
	Reason    string
	Time      string
}

type SkillsPanel struct {
	items   []skillItem
	cursor  int
	width   int
	height  int
	store   *audit.Store
	message string
}

func NewSkillsPanel(store *audit.Store) SkillsPanel {
	return SkillsPanel{store: store}
}

func (p *SkillsPanel) Refresh() {
	if p.store == nil {
		return
	}

	p.items = nil

	entries, err := p.store.ListActionsByType("skill")
	if err != nil {
		p.message = fmt.Sprintf("Error: %v", err)
		return
	}
	for _, e := range entries {
		var status string
		switch e.Actions.Install {
		case "block":
			status = "blocked"
		case "allow":
			status = "allowed"
		default:
			status = "active"
		}
		item := skillItem{
			Name:    e.TargetName,
			Status:  status,
			Actions: e.Actions.Summary(),
			Reason:  e.Reason,
			Time:    e.UpdatedAt.Format("2006-01-02 15:04"),
		}
		if sig, err := p.store.GetSignatureStatus("skill", e.TargetName); err == nil && sig != nil {
			item.Verified = sig.Verified
			item.Publisher = sig.Publisher
		}
		p.items = append(p.items, item)
	}

	if p.cursor >= len(p.items) && len(p.items) > 0 {
		p.cursor = len(p.items) - 1
	}
	p.message = ""
}

func (p *SkillsPanel) SetSize(w, h int) {
	p.width = w
	p.height = h
}

func (p *SkillsPanel) CursorUp()   { if p.cursor > 0 { p.cursor-- } }
func (p *SkillsPanel) CursorDown() { if p.cursor < len(p.items)-1 { p.cursor++ } }

func (p *SkillsPanel) Selected() *skillItem {
	if p.cursor >= 0 && p.cursor < len(p.items) {
		return &p.items[p.cursor]
	}
	return nil
}

func (p *SkillsPanel) ToggleBlock() string {
	sel := p.Selected()
	if sel == nil {
		return ""
	}
	if sel.Status == "blocked" {
		_ = p.store.SetActionField("skill", sel.Name, "install", "allow", "unblocked from TUI")
		p.Refresh()
		return fmt.Sprintf("Allowed skill: %s", sel.Name)
	}
	_ = p.store.SetActionField("skill", sel.Name, "install", "block", "blocked from TUI")
	p.Refresh()
	return fmt.Sprintf("Blocked skill: %s", sel.Name)
}

func (p *SkillsPanel) Count() int { return len(p.items) }
func (p *SkillsPanel) BlockedCount() int {
	n := 0
	for _, i := range p.items {
		if i.Status == "blocked" {
			n++
		}
	}
	return n
}

func (p *SkillsPanel) View() string {
	if p.message != "" {
		return p.message
	}
	if len(p.items) == 0 {
		return StyleInfo.Render("  No skills with enforcement actions. Use 'defenseclaw block skill' or 'defenseclaw allow skill' to add.")
	}

	var b strings.Builder
	header := fmt.Sprintf("  %-10s %-8s %-28s %-18s %-18s %-16s", "STATUS", "SIGNED", "NAME", "ACTIONS", "REASON", "SINCE")
	b.WriteString(HeaderStyle.Render(header))
	b.WriteString("\n")

	maxVisible := p.height - 4
	if maxVisible < 1 {
		maxVisible = 10
	}

	start := 0
	if p.cursor >= maxVisible {
		start = p.cursor - maxVisible + 1
	}
	end := start + maxVisible
	if end > len(p.items) {
		end = len(p.items)
	}

	for i := start; i < end; i++ {
		item := p.items[i]
		status := StatusStyle(item.Status).Render(fmt.Sprintf("%-10s", strings.ToUpper(item.Status)))
		var badge string
		if item.Verified {
			badge = StyleVerified.Render("YES")
			badge = fmt.Sprintf("%-8s", badge)
		} else {
			badge = StyleUnverified.Render("-")
			badge = fmt.Sprintf("  %-6s", badge)
		}
		name := item.Name
		if len(name) > 28 {
			name = name[:25] + "..."
		}
		actions := item.Actions
		if len(actions) > 18 {
			actions = actions[:15] + "..."
		}
		reason := item.Reason
		if len(reason) > 18 {
			reason = reason[:15] + "..."
		}

		line := fmt.Sprintf("  %s %s %-28s %-18s %-18s %-16s", status, badge, name, actions, reason, item.Time)

		if i == p.cursor {
			line = SelectedStyle.Width(p.width).Render(line)
		}
		b.WriteString(line)
		if i < end-1 {
			b.WriteString("\n")
		}
	}

	if len(p.items) > maxVisible {
		b.WriteString("\n")
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render(
			fmt.Sprintf("  showing %d-%d of %d", start+1, end, len(p.items)),
		))
	}

	return b.String()
}
