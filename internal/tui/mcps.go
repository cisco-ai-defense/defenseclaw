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

type mcpItem struct {
	URL       string
	Status    string
	Verified  bool
	Publisher string
	Actions   string
	Reason    string
	Time      string
}

type MCPsPanel struct {
	items   []mcpItem
	cursor  int
	width   int
	height  int
	store   *audit.Store
	message string
}

func NewMCPsPanel(store *audit.Store) MCPsPanel {
	return MCPsPanel{store: store}
}

func (p *MCPsPanel) Refresh() {
	if p.store == nil {
		return
	}

	p.items = nil

	entries, err := p.store.ListActionsByType("mcp")
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
		item := mcpItem{
			URL:     e.TargetName,
			Status:  status,
			Actions: e.Actions.Summary(),
			Reason:  e.Reason,
			Time:    e.UpdatedAt.Format("2006-01-02 15:04"),
		}
		if sig, err := p.store.GetSignatureStatus("mcp", e.TargetName); err == nil && sig != nil {
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

func (p *MCPsPanel) SetSize(w, h int) {
	p.width = w
	p.height = h
}

func (p *MCPsPanel) CursorUp()   { if p.cursor > 0 { p.cursor-- } }
func (p *MCPsPanel) CursorDown() { if p.cursor < len(p.items)-1 { p.cursor++ } }

func (p *MCPsPanel) Selected() *mcpItem {
	if p.cursor >= 0 && p.cursor < len(p.items) {
		return &p.items[p.cursor]
	}
	return nil
}

func (p *MCPsPanel) ToggleBlock() string {
	sel := p.Selected()
	if sel == nil {
		return ""
	}
	if sel.Status == "blocked" {
		_ = p.store.SetActionField("mcp", sel.URL, "install", "allow", "unblocked from TUI")
		p.Refresh()
		return fmt.Sprintf("Allowed MCP: %s", sel.URL)
	}
	_ = p.store.SetActionField("mcp", sel.URL, "install", "block", "blocked from TUI")
	p.Refresh()
	return fmt.Sprintf("Blocked MCP: %s", sel.URL)
}

func (p *MCPsPanel) Count() int { return len(p.items) }
func (p *MCPsPanel) BlockedCount() int {
	n := 0
	for _, i := range p.items {
		if i.Status == "blocked" {
			n++
		}
	}
	return n
}

func (p *MCPsPanel) View() string {
	if p.message != "" {
		return p.message
	}
	if len(p.items) == 0 {
		return StyleInfo.Render("  No MCP servers with enforcement actions. Use 'defenseclaw block mcp' or 'defenseclaw allow mcp' to add.")
	}

	var b strings.Builder
	header := fmt.Sprintf("  %-10s %-8s %-36s %-18s %-18s %-16s", "STATUS", "SIGNED", "URL", "ACTIONS", "REASON", "SINCE")
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
		url := item.URL
		if len(url) > 36 {
			url = url[:33] + "..."
		}
		actions := item.Actions
		if len(actions) > 18 {
			actions = actions[:15] + "..."
		}
		reason := item.Reason
		if len(reason) > 18 {
			reason = reason[:15] + "..."
		}

		line := fmt.Sprintf("  %s %s %-36s %-18s %-18s %-16s", status, badge, url, actions, reason, item.Time)

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
