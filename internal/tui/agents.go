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
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/capability"
)

type AgentItem struct {
	Agent        string
	Capabilities int
	Restrictions int
	Decisions    int
	LastDecision string
	Status       string // "approved", "pending review", or "manual"
}

type AgentsPanel struct {
	items    []AgentItem
	cursor   int
	width    int
	height   int
	store    *audit.Store
	policies map[string]*capability.AgentPolicy
}

func NewAgentsPanel(store *audit.Store) AgentsPanel {
	return AgentsPanel{store: store}
}

func (p *AgentsPanel) SetPolicies(policies map[string]*capability.AgentPolicy) {
	p.policies = policies
}

func (p *AgentsPanel) SetSize(w, h int) {
	p.width = w
	p.height = h
}

func (p *AgentsPanel) Refresh() {
	if p.store == nil {
		return
	}

	decisions, err := p.store.ListCapabilityDecisions(100)
	if err != nil {
		return
	}

	agentMap := make(map[string]*AgentItem)
	for _, d := range decisions {
		item, ok := agentMap[d.Agent]
		if !ok {
			item = &AgentItem{Agent: d.Agent}
			agentMap[d.Agent] = item
		}
		item.Decisions++
		if item.LastDecision == "" {
			if d.Allowed {
				item.LastDecision = "allowed"
			} else {
				item.LastDecision = "denied: " + d.Reason
			}
		}
	}

	// Merge agents from policies that have no decisions yet
	for name := range p.policies {
		if _, ok := agentMap[name]; !ok {
			agentMap[name] = &AgentItem{Agent: name, LastDecision: "-"}
		}
	}

	// Resolve status from policies
	for name, item := range agentMap {
		pol, hasPol := p.policies[name]
		if !hasPol {
			item.Status = "manual"
			continue
		}
		item.Capabilities = len(pol.Capabilities)
		item.Restrictions = len(pol.Restrictions)
		switch {
		case pol.Generated && !pol.Approved:
			item.Status = "pending review"
		case pol.Generated && pol.Approved:
			item.Status = "approved"
		default:
			item.Status = "manual"
		}
	}

	p.items = make([]AgentItem, 0, len(agentMap))
	for _, item := range agentMap {
		p.items = append(p.items, *item)
	}
	sort.Slice(p.items, func(i, j int) bool {
		return p.items[i].Agent < p.items[j].Agent
	})
}

func (p *AgentsPanel) Count() int {
	return len(p.items)
}

func (p *AgentsPanel) CursorUp() {
	if p.cursor > 0 {
		p.cursor--
	}
}

func (p *AgentsPanel) CursorDown() {
	if p.cursor < len(p.items)-1 {
		p.cursor++
	}
}

func (p *AgentsPanel) Selected() *AgentItem {
	if p.cursor >= 0 && p.cursor < len(p.items) {
		return &p.items[p.cursor]
	}
	return nil
}

func (p AgentsPanel) View() string {
	if len(p.items) == 0 {
		return lipgloss.NewStyle().
			Foreground(lipgloss.Color("241")).
			Render("  No capability decisions recorded yet.\n  Add .capability.yaml files to ~/.defenseclaw/capabilities/")
	}

	var b strings.Builder
	header := fmt.Sprintf("  %-20s %-16s %-12s %s", "AGENT", "STATUS", "DECISIONS", "LAST DECISION")
	b.WriteString(HeaderStyle.Render(header))
	b.WriteString("\n")

	for i, item := range p.items {
		statusStr := renderStatus(item.Status)
		line := fmt.Sprintf("  %-20s %-16s %-12d %s",
			item.Agent, statusStr, item.Decisions, item.LastDecision)

		if i == p.cursor {
			b.WriteString(SelectedStyle.Render(line))
		} else {
			b.WriteString(line)
		}
		b.WriteString("\n")
	}

	return b.String()
}

func renderStatus(status string) string {
	switch status {
	case "pending review":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(status)
	default:
		return status
	}
}
