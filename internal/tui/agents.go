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
)

type AgentItem struct {
	Agent        string
	Capabilities int
	Restrictions int
	Decisions    int
	LastDecision string
}

type AgentsPanel struct {
	items  []AgentItem
	cursor int
	width  int
	height int
	store  *audit.Store
}

func NewAgentsPanel(store *audit.Store) AgentsPanel {
	return AgentsPanel{store: store}
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

	// Aggregate by agent
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
	header := fmt.Sprintf("  %-20s %-12s %s", "AGENT", "DECISIONS", "LAST DECISION")
	b.WriteString(HeaderStyle.Render(header))
	b.WriteString("\n")

	for i, item := range p.items {
		line := fmt.Sprintf("  %-20s %-12d %s",
			item.Agent, item.Decisions, item.LastDecision)

		if i == p.cursor {
			b.WriteString(SelectedStyle.Render(line))
		} else {
			b.WriteString(line)
		}
		b.WriteString("\n")
	}

	return b.String()
}
