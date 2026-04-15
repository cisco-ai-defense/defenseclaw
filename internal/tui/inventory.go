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

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// InventoryLoadedMsg is sent when the AIBOM scan completes.
type InventoryLoadedMsg struct {
	Inv *aibomInventory
	Err error
}

const (
	invSubSummary = iota
	invSubSkills
	invSubPlugins
	invSubMCPs
	invSubAgents
	invSubModels
	invSubMemory
	invSubCount
)

var invSubNames = [invSubCount]string{
	"Summary", "Skills", "Plugins", "MCPs", "Agents", "Models", "Memory",
}

// ---------- AIBOM JSON structures (matching actual output) ----------

type aibomInventory struct {
	Version     json.Number       `json:"version"`
	GeneratedAt string            `json:"generated_at"`
	OpenclawCfg string            `json:"openclaw_config"`
	ClawHome    string            `json:"claw_home"`
	ClawMode    string            `json:"claw_mode"`
	Live        bool              `json:"live"`
	Skills      []aibomSkill      `json:"skills"`
	Plugins     []aibomPlugin     `json:"plugins"`
	MCPs        []aibomMCP        `json:"mcp"`
	Agents      []aibomAgent      `json:"agents"`
	Tools       []aibomTool       `json:"tools"`
	Models      []aibomModel      `json:"model_providers"`
	Memory      []aibomMemory     `json:"memory"`
	Errors      []json.RawMessage `json:"errors"`
	Summary     aibomSummary      `json:"summary"`
}

type aibomSkill struct {
	ID            string `json:"id"`
	Source        string `json:"source"`
	Eligible      bool   `json:"eligible"`
	Enabled       bool   `json:"enabled"`
	Bundled       bool   `json:"bundled"`
	Description   string `json:"description"`
	Emoji         string `json:"emoji"`
	Verdict       string `json:"policy_verdict"`
	VerdictDetail string `json:"policy_detail"`
	ScanFindings  int    `json:"scan_findings"`
	ScanSeverity  string `json:"scan_severity"`
	ScanTarget    string `json:"scan_target"`
}

type aibomPlugin struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Version       string `json:"version"`
	Origin        string `json:"origin"`
	Enabled       bool   `json:"enabled"`
	Status        string `json:"status"`
	Verdict       string `json:"policy_verdict"`
	VerdictDetail string `json:"policy_detail"`
	ScanFindings  int    `json:"scan_findings"`
	ScanSeverity  string `json:"scan_severity"`
	ScanTarget    string `json:"scan_target"`
}

type aibomMCP struct {
	ID        string `json:"id"`
	Source    string `json:"source"`
	Transport string `json:"transport"`
	Command   string `json:"command"`
	URL       string `json:"url"`
}

type aibomAgent struct {
	ID        string          `json:"id"`
	Model     string          `json:"model"`
	Workspace string          `json:"workspace"`
	Default   bool            `json:"is_default"`
	Source    string          `json:"source"`
	Bindings  json.RawMessage `json:"bindings"`
	MaxConc   int             `json:"subagents_max_concurrent"`
}

type aibomTool struct {
	Name   string `json:"name"`
	Source string `json:"source_plugin"`
	Block  string `json:"block_status"`
}

type aibomModel struct {
	ID           string   `json:"id"`
	Source       string   `json:"source"`
	DefaultModel string   `json:"default_model"`
	Fallbacks    []string `json:"fallbacks"`
	Allowed      []string `json:"allowed"`
	ConfigPath   string   `json:"config_path"`
	Status       string   `json:"status"`
}

type aibomMemory struct {
	ID            string   `json:"id"`
	Backend       string   `json:"backend"`
	Files         int      `json:"files"`
	Chunks        int      `json:"chunks"`
	DBPath        string   `json:"db_path"`
	Provider      string   `json:"provider"`
	Sources       []string `json:"sources"`
	Workspace     string   `json:"workspace"`
	FTSAvail      bool     `json:"fts_available"`
	VectorEnabled bool     `json:"vector_enabled"`
}

type aibomSummary struct {
	TotalItems    int                    `json:"total_items"`
	Skills        map[string]interface{} `json:"skills"`
	Plugins       map[string]interface{} `json:"plugins"`
	MCP           map[string]interface{} `json:"mcp"`
	Agents        map[string]interface{} `json:"agents"`
	Tools         map[string]interface{} `json:"tools"`
	Models        map[string]interface{} `json:"model_providers"`
	Memory        map[string]interface{} `json:"memory"`
	Errors        interface{}            `json:"errors"`
	PolicySkills  map[string]interface{} `json:"policy_skills"`
	ScanSkills    map[string]interface{} `json:"scan_skills"`
	PolicyPlugins map[string]interface{} `json:"policy_plugins"`
	ScanPlugins   map[string]interface{} `json:"scan_plugins"`
}

// ---------- Panel ----------

type InventoryPanel struct {
	theme          *Theme
	store          *audit.Store
	executor       *CommandExecutor
	activeSub      int
	loading        bool
	loaded         bool
	inv            *aibomInventory
	cursor         int
	errMsg         string
	detailOpen     bool
	width          int
	height         int
	detailCache    *InventoryDetailInfo
	detailCacheIdx int
	detailCacheSub int
}

func NewInventoryPanel(theme *Theme, exec *CommandExecutor, store *audit.Store) InventoryPanel {
	return InventoryPanel{theme: theme, executor: exec, store: store}
}

func (p *InventoryPanel) LoadCmd() tea.Cmd {
	p.loading = true
	return func() tea.Msg {
		cmd := exec.Command("defenseclaw", "aibom", "scan", "--json")
		out, err := cmd.Output()
		if err != nil {
			return InventoryLoadedMsg{Err: err}
		}
		var inv aibomInventory
		if err := json.Unmarshal(out, &inv); err != nil {
			return InventoryLoadedMsg{Err: err}
		}
		return InventoryLoadedMsg{Inv: &inv}
	}
}

func (p *InventoryPanel) ApplyLoaded(msg InventoryLoadedMsg) {
	p.loading = false
	if msg.Err != nil {
		p.errMsg = fmt.Sprintf("Error loading inventory: %v", msg.Err)
		return
	}
	p.inv = msg.Inv
	p.loaded = true
	p.errMsg = ""
}

func (p *InventoryPanel) ScrollBy(delta int) {
	p.cursor += delta
	if p.cursor < 0 {
		p.cursor = 0
	}
	max := p.currentListLen() - 1
	if max >= 0 && p.cursor > max {
		p.cursor = max
	}
}

func (p *InventoryPanel) SetCursor(i int) {
	if i < 0 {
		i = 0
	}
	max := p.currentListLen() - 1
	if max >= 0 && i > max {
		i = max
	}
	p.cursor = i
}

func (p *InventoryPanel) CursorAt() int      { return p.cursor }
func (p *InventoryPanel) IsDetailOpen() bool { return p.detailOpen }
func (p *InventoryPanel) ToggleDetail() {
	p.detailOpen = !p.detailOpen
	p.detailCache = nil
}

func (p *InventoryPanel) detailHeight() int {
	if !p.detailOpen {
		return 0
	}
	h := p.height / 3
	if h < 6 {
		h = 6
	}
	if h > 14 {
		h = 14
	}
	return h
}

type InventoryDetailInfo struct {
	Title   string
	Fields  [][2]string // label, value pairs
	Action  *audit.ActionEntry
	History []audit.Event
}

func (p *InventoryPanel) GetDetailInfo() *InventoryDetailInfo {
	if p.inv == nil {
		return nil
	}
	switch p.activeSub {
	case invSubSkills:
		if p.cursor < 0 || p.cursor >= len(p.inv.Skills) {
			return nil
		}
		sk := p.inv.Skills[p.cursor]
		info := &InventoryDetailInfo{
			Title: "SKILL: " + sk.ID,
			Fields: [][2]string{
				{"Source", sk.Source},
				{"Eligible", fmt.Sprintf("%v", sk.Eligible)},
				{"Enabled", fmt.Sprintf("%v", sk.Enabled)},
				{"Bundled", fmt.Sprintf("%v", sk.Bundled)},
				{"Verdict", sk.Verdict},
				{"Detail", sk.VerdictDetail},
				{"Scan Findings", fmt.Sprintf("%d", sk.ScanFindings)},
				{"Scan Severity", sk.ScanSeverity},
			},
		}
		if sk.Description != "" {
			info.Fields = append([][2]string{{"Description", sk.Description}}, info.Fields...)
		}
		p.enrichInventoryDetail(info, "skill", sk.ID)
		return info

	case invSubPlugins:
		if p.cursor < 0 || p.cursor >= len(p.inv.Plugins) {
			return nil
		}
		pl := p.inv.Plugins[p.cursor]
		info := &InventoryDetailInfo{
			Title: "PLUGIN: " + pl.Name,
			Fields: [][2]string{
				{"ID", pl.ID},
				{"Version", pl.Version},
				{"Origin", pl.Origin},
				{"Status", pl.Status},
				{"Enabled", fmt.Sprintf("%v", pl.Enabled)},
				{"Verdict", pl.Verdict},
				{"Detail", pl.VerdictDetail},
				{"Scan Findings", fmt.Sprintf("%d", pl.ScanFindings)},
				{"Scan Severity", pl.ScanSeverity},
			},
		}
		p.enrichInventoryDetail(info, "plugin", pl.ID)
		return info

	case invSubMCPs:
		if p.cursor < 0 || p.cursor >= len(p.inv.MCPs) {
			return nil
		}
		m := p.inv.MCPs[p.cursor]
		info := &InventoryDetailInfo{
			Title: "MCP: " + m.ID,
			Fields: [][2]string{
				{"Source", m.Source},
				{"Transport", m.Transport},
				{"Command", m.Command},
				{"URL", m.URL},
			},
		}
		target := m.URL
		if target == "" {
			target = m.ID
		}
		p.enrichInventoryDetail(info, "mcp", target)
		return info

	case invSubAgents:
		if p.cursor < 0 || p.cursor >= len(p.inv.Agents) {
			return nil
		}
		a := p.inv.Agents[p.cursor]
		info := &InventoryDetailInfo{
			Title: "AGENT: " + a.ID,
			Fields: [][2]string{
				{"Model", a.Model},
				{"Workspace", a.Workspace},
				{"Default", fmt.Sprintf("%v", a.Default)},
				{"Source", a.Source},
				{"Max Concurrent", fmt.Sprintf("%d", a.MaxConc)},
			},
		}
		return info

	case invSubModels:
		if p.cursor < 0 || p.cursor >= len(p.inv.Models) {
			return nil
		}
		mo := p.inv.Models[p.cursor]
		info := &InventoryDetailInfo{
			Title: "MODEL: " + mo.ID,
			Fields: [][2]string{
				{"Source", mo.Source},
				{"Default Model", mo.DefaultModel},
				{"Status", mo.Status},
				{"Config", mo.ConfigPath},
			},
		}
		if len(mo.Fallbacks) > 0 {
			info.Fields = append(info.Fields, [2]string{"Fallbacks", strings.Join(mo.Fallbacks, ", ")})
		}
		if len(mo.Allowed) > 0 {
			info.Fields = append(info.Fields, [2]string{"Allowed", strings.Join(mo.Allowed, ", ")})
		}
		return info

	case invSubMemory:
		if p.cursor < 0 || p.cursor >= len(p.inv.Memory) {
			return nil
		}
		mem := p.inv.Memory[p.cursor]
		info := &InventoryDetailInfo{
			Title: "MEMORY: " + mem.ID,
			Fields: [][2]string{
				{"Backend", mem.Backend},
				{"Provider", mem.Provider},
				{"Workspace", mem.Workspace},
				{"DB Path", mem.DBPath},
				{"Files", fmt.Sprintf("%d", mem.Files)},
				{"Chunks", fmt.Sprintf("%d", mem.Chunks)},
				{"FTS Available", fmt.Sprintf("%v", mem.FTSAvail)},
				{"Vector Enabled", fmt.Sprintf("%v", mem.VectorEnabled)},
			},
		}
		if len(mem.Sources) > 0 {
			info.Fields = append(info.Fields, [2]string{"Sources", strings.Join(mem.Sources, ", ")})
		}
		return info
	}
	return nil
}

func (p *InventoryPanel) enrichInventoryDetail(info *InventoryDetailInfo, targetType, targetName string) {
	if p.store == nil {
		return
	}
	action, err := p.store.GetAction(targetType, targetName)
	if err == nil && action != nil {
		info.Action = action
	}
	history, _ := p.store.ListEventsByTarget(targetName, 5)
	info.History = history
}

func (p *InventoryPanel) currentListLen() int {
	if p.inv == nil {
		return 0
	}
	switch p.activeSub {
	case invSubSkills:
		return len(p.inv.Skills)
	case invSubPlugins:
		return len(p.inv.Plugins)
	case invSubMCPs:
		return len(p.inv.MCPs)
	case invSubAgents:
		return len(p.inv.Agents)
	case invSubModels:
		return len(p.inv.Models)
	case invSubMemory:
		return len(p.inv.Memory)
	default:
		return 0
	}
}

// ---------- View ----------

func (p *InventoryPanel) View(width, height int) string {
	p.width = width
	p.height = height
	var b strings.Builder

	b.WriteString("  ")
	for i, name := range invSubNames {
		count := ""
		if p.loaded && p.inv != nil {
			switch i {
			case invSubSkills:
				count = fmt.Sprintf("(%d)", len(p.inv.Skills))
			case invSubPlugins:
				count = fmt.Sprintf("(%d)", len(p.inv.Plugins))
			case invSubMCPs:
				count = fmt.Sprintf("(%d)", len(p.inv.MCPs))
			case invSubAgents:
				count = fmt.Sprintf("(%d)", len(p.inv.Agents))
			case invSubModels:
				count = fmt.Sprintf("(%d)", len(p.inv.Models))
			case invSubMemory:
				count = fmt.Sprintf("(%d)", len(p.inv.Memory))
			}
		}
		label := fmt.Sprintf(" %s %s ", name, count)
		if i == p.activeSub {
			b.WriteString(p.theme.ActiveTab.Render(label))
		} else {
			b.WriteString(p.theme.InactiveTab.Render(label))
		}
		if i < invSubCount-1 {
			b.WriteString(" ")
		}
	}
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("238")).Render(strings.Repeat("─", width)))
	b.WriteString("\n")

	if p.loading {
		b.WriteString(p.theme.Spinner.Render("  Scanning inventory from OpenClaw... (this may take 15-30s)"))
		return b.String()
	}

	if p.errMsg != "" {
		b.WriteString(p.theme.Critical.Render("  [error] " + p.errMsg))
		b.WriteString("\n\n")
		b.WriteString(p.theme.Dimmed.Render("  Press \"r\" to retry."))
		return b.String()
	}

	if !p.loaded || p.inv == nil {
		b.WriteString("\n")
		b.WriteString(p.theme.Dimmed.Render("  Press \"r\" to load inventory."))
		b.WriteString("\n")
		b.WriteString(p.theme.Dimmed.Render("  This runs \"defenseclaw aibom scan\" to enumerate all components."))
		return b.String()
	}

	maxLines := height - 6 - p.detailHeight()
	if maxLines < 5 {
		maxLines = 5
	}

	switch p.activeSub {
	case invSubSummary:
		b.WriteString(p.renderSummary(width))
	case invSubSkills:
		b.WriteString(p.renderSkills(width, maxLines))
	case invSubPlugins:
		b.WriteString(p.renderPlugins(width, maxLines))
	case invSubMCPs:
		b.WriteString(p.renderMCPs(width, maxLines))
	case invSubAgents:
		b.WriteString(p.renderAgents(width))
	case invSubModels:
		b.WriteString(p.renderModels(width))
	case invSubMemory:
		b.WriteString(p.renderMemory(width))
	}

	if p.detailOpen && p.activeSub != invSubSummary {
		b.WriteString("\n")
		b.WriteString(p.renderDetail())
	}

	return b.String()
}

func (p *InventoryPanel) renderDetail() string {
	if p.detailCache == nil || p.detailCacheIdx != p.cursor || p.detailCacheSub != p.activeSub {
		p.detailCache = p.GetDetailInfo()
		p.detailCacheIdx = p.cursor
		p.detailCacheSub = p.activeSub
	}
	info := p.detailCache
	if info == nil {
		return ""
	}

	dh := p.detailHeight()
	boxStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("62")).
		Width(p.width - 4).
		MaxHeight(dh)
	titleStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("62")).Bold(true)
	labelStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	valStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("252"))

	var d strings.Builder
	d.WriteString(titleStyle.Render("  "+info.Title) + "\n")

	for _, f := range info.Fields {
		if f[1] == "" || f[1] == "0" || f[1] == "false" {
			continue
		}
		val := f[1]
		if len(val) > 70 {
			val = val[:67] + "..."
		}
		if f[0] == "Verdict" {
			d.WriteString(labelStyle.Render(fmt.Sprintf("  %-16s", f[0]+":")) + p.verdictBadge(val) + "\n")
		} else if f[0] == "Scan Severity" && val != "" {
			d.WriteString(labelStyle.Render(fmt.Sprintf("  %-16s", f[0]+":")) + SeverityStyle(val).Render(val) + "\n")
		} else {
			d.WriteString(labelStyle.Render(fmt.Sprintf("  %-16s", f[0]+":")) + valStyle.Render(val) + "\n")
		}
	}

	if info.Action != nil {
		d.WriteString("\n" + labelStyle.Render("  Enforcement: ") + valStyle.Render(info.Action.Actions.Summary()))
		if info.Action.Reason != "" {
			d.WriteString(labelStyle.Render("  (" + info.Action.Reason + ")"))
		}
		d.WriteString("\n")
	}

	if len(info.History) > 0 {
		d.WriteString("\n" + titleStyle.Render("  Recent Activity:") + "\n")
		shown := 0
		for _, h := range info.History {
			if shown >= 3 {
				break
			}
			ts := h.Timestamp.Format("Jan 02 15:04")
			action := h.Action
			if len(action) > 18 {
				action = action[:15] + "..."
			}
			fmt.Fprintf(&d, "    %s  %-18s  %s\n",
				labelStyle.Render(ts),
				action,
				SeverityStyle(h.Severity).Render(h.Severity))
			shown++
		}
	}

	d.WriteString(labelStyle.Render("  [Enter] close  [Esc] close"))

	return boxStyle.Render(d.String())
}

// ---------- Summary tab ----------

func (p *InventoryPanel) renderSummary(width int) string {
	var b strings.Builder
	s := p.inv.Summary
	inv := p.inv

	// Header
	fmt.Fprintf(&b, "\n  AIBOM v%s  generated %s\n", inv.Version.String(), inv.GeneratedAt)
	fmt.Fprintf(&b, "  %s  %s\n",
		lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render("Mode:"),
		inv.ClawMode)
	fmt.Fprintf(&b, "  %s  %s\n\n",
		lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render("Home:"),
		inv.ClawHome)

	halfW := width/2 - 2
	if halfW < 35 {
		halfW = 35
	}

	// Left: Component counts
	var left strings.Builder
	box := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("62")).Padding(0, 1).Width(halfW)
	left.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("62")).Render("COMPONENTS") + "\n")
	fmt.Fprintf(&left, "  Total items   %s\n", lipgloss.NewStyle().Bold(true).Render(fmt.Sprintf("%d", s.TotalItems)))
	fmt.Fprintf(&left, "  Skills        %s", p.fmtCount(s.Skills, "count"))
	if v := p.mapVal(s.Skills, "eligible"); v != "" && v != "0" {
		fmt.Fprintf(&left, "  (%s eligible)", v)
	}
	left.WriteString("\n")
	fmt.Fprintf(&left, "  Plugins       %s", p.fmtCount(s.Plugins, "count"))
	if loaded := p.mapVal(s.Plugins, "loaded"); loaded != "" {
		fmt.Fprintf(&left, "  (%s loaded, %s disabled)", loaded, p.mapVal(s.Plugins, "disabled"))
	}
	left.WriteString("\n")
	fmt.Fprintf(&left, "  MCPs          %s\n", p.fmtCount(s.MCP, "count"))
	fmt.Fprintf(&left, "  Agents        %s\n", p.fmtCount(s.Agents, "count"))
	fmt.Fprintf(&left, "  Models        %s\n", p.fmtCount(s.Models, "count"))
	fmt.Fprintf(&left, "  Memory        %s\n", p.fmtCount(s.Memory, "count"))
	if errCount := fmt.Sprintf("%v", s.Errors); errCount != "0" && errCount != "<nil>" {
		fmt.Fprintf(&left, "  Errors        %s\n", p.theme.Critical.Render(errCount))
	}

	// Right: Policy verdicts
	var right strings.Builder
	right.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("62")).Render("POLICY VERDICTS") + "\n")
	if s.PolicySkills != nil {
		right.WriteString("  Skills:\n")
		right.WriteString(p.renderVerdictRow(s.PolicySkills))
	}
	if s.PolicyPlugins != nil {
		right.WriteString("  Plugins:\n")
		right.WriteString(p.renderVerdictRow(s.PolicyPlugins))
	}

	right.WriteString("\n")
	right.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("62")).Render("SCAN COVERAGE") + "\n")
	if s.ScanSkills != nil {
		scanned := p.mapVal(s.ScanSkills, "scanned")
		unscanned := p.mapVal(s.ScanSkills, "unscanned")
		findings := p.mapVal(s.ScanSkills, "total_findings")
		fmt.Fprintf(&right, "  Skills   %s scanned  %s unscanned  %s findings\n",
			p.theme.Clean.Render(scanned), p.theme.Dimmed.Render(unscanned), p.colorFindings(findings))
	}
	if s.ScanPlugins != nil {
		scanned := p.mapVal(s.ScanPlugins, "scanned")
		unscanned := p.mapVal(s.ScanPlugins, "unscanned")
		findings := p.mapVal(s.ScanPlugins, "total_findings")
		fmt.Fprintf(&right, "  Plugins  %s scanned  %s unscanned  %s findings\n",
			p.theme.Clean.Render(scanned), p.theme.Dimmed.Render(unscanned), p.colorFindings(findings))
	}

	leftBox := box.Render(left.String())
	rightBox := box.Width(halfW).Render(right.String())
	b.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, leftBox, "  ", rightBox))

	b.WriteString("\n\n")
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render(
		fmt.Sprintf("  Config: %s  │  Use Tab/← → to switch sub-tabs  │  Press \"r\" to reload", inv.OpenclawCfg)))

	return b.String()
}

func (p *InventoryPanel) renderVerdictRow(m map[string]interface{}) string {
	blocked := p.mapVal(m, "blocked")
	allowed := p.mapVal(m, "allowed")
	warning := p.mapVal(m, "warning")
	clean := p.mapVal(m, "clean")
	rejected := p.mapVal(m, "rejected")
	unscanned := p.mapVal(m, "unscanned")

	var parts []string
	if blocked != "0" && blocked != "" {
		parts = append(parts, p.theme.Critical.Render(blocked+" blocked"))
	}
	if rejected != "0" && rejected != "" {
		parts = append(parts, p.theme.Critical.Render(rejected+" rejected"))
	}
	if allowed != "0" && allowed != "" {
		parts = append(parts, p.theme.Clean.Render(allowed+" allowed"))
	}
	if warning != "0" && warning != "" {
		parts = append(parts, p.theme.Medium.Render(warning+" warning"))
	}
	if clean != "0" && clean != "" {
		parts = append(parts, p.theme.Clean.Render(clean+" clean"))
	}
	if unscanned != "0" && unscanned != "" {
		parts = append(parts, p.theme.Dimmed.Render(unscanned+" unscanned"))
	}

	return "    " + strings.Join(parts, "  ") + "\n"
}

func (p *InventoryPanel) colorFindings(s string) string {
	if s == "0" || s == "" {
		return p.theme.Clean.Render(s)
	}
	return p.theme.High.Render(s)
}

func (p *InventoryPanel) fmtCount(m map[string]interface{}, key string) string {
	return lipgloss.NewStyle().Bold(true).Render(p.mapVal(m, key))
}

func (p *InventoryPanel) mapVal(m map[string]interface{}, key string) string {
	if m == nil {
		return "0"
	}
	v, ok := m[key]
	if !ok {
		return "0"
	}
	return fmt.Sprintf("%v", v)
}

// ---------- Skills tab ----------

func (p *InventoryPanel) renderSkills(width, maxLines int) string {
	var b strings.Builder
	items := p.inv.Skills

	if len(items) == 0 {
		return p.theme.Dimmed.Render("  No skills found.")
	}

	// Count summaries
	var eligible, warned, blocked int
	for _, s := range items {
		if s.Eligible {
			eligible++
		}
		if s.Verdict == "warning" {
			warned++
		}
		if s.Verdict == "blocked" {
			blocked++
		}
	}
	fmt.Fprintf(&b, "  %d skills  ·  %s eligible  ·  %s warnings  ·  %s blocked\n\n",
		len(items),
		p.theme.Clean.Render(fmt.Sprintf("%d", eligible)),
		p.warnCount(warned),
		p.blockCount(blocked))

	header := fmt.Sprintf("  %-3s %-26s %-12s %-8s %-12s %-6s %-10s",
		"", "ID", "VERDICT", "ENABLED", "SEVERITY", "FINDS", "SOURCE")
	b.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("243")).Render(header))
	b.WriteString("\n")

	start := 0
	if p.cursor >= maxLines {
		start = p.cursor - maxLines + 1
	}
	end := start + maxLines
	if end > len(items) {
		end = len(items)
	}

	for i := start; i < end; i++ {
		s := items[i]
		pointer := "  "
		if i == p.cursor {
			pointer = lipgloss.NewStyle().Foreground(lipgloss.Color("62")).Bold(true).Render("▸ ")
		}

		emoji := s.Emoji
		if emoji == "" {
			emoji = " "
		}

		id := s.ID
		if len(id) > 24 {
			id = id[:21] + "…"
		}

		verdict := p.verdictBadge(s.Verdict)
		enabled := p.theme.Dimmed.Render("no")
		if s.Enabled {
			enabled = p.theme.Clean.Render("yes")
		}

		severity := p.theme.Dimmed.Render("—")
		if s.ScanSeverity != "" {
			severity = p.theme.SeverityColor(s.ScanSeverity).Render(s.ScanSeverity)
		}
		findings := p.theme.Dimmed.Render("—")
		if s.ScanFindings > 0 {
			findings = p.theme.High.Render(fmt.Sprintf("%d", s.ScanFindings))
		}

		line := fmt.Sprintf("%s%s %-24s %s %-8s %-12s %-6s %-10s",
			pointer, emoji, id, verdict, enabled, severity, findings, truncate(s.Source, 10))

		if i == p.cursor {
			line = lipgloss.NewStyle().Background(lipgloss.Color("236")).Width(width).Render(line)
		}
		b.WriteString(line + "\n")
	}

	if len(items) > maxLines {
		pct := 0
		if len(items) > 0 {
			pct = (end * 100) / len(items)
		}
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render(
			fmt.Sprintf("  ↕ %d–%d of %d (%d%%)", start+1, end, len(items), pct)))
	}

	// Show detail of selected skill
	if p.cursor >= 0 && p.cursor < len(items) {
		sel := items[p.cursor]
		b.WriteString("\n\n")
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("238")).Render(strings.Repeat("─", width)))
		b.WriteString("\n")
		fmt.Fprintf(&b, "  %s %s", sel.Emoji, lipgloss.NewStyle().Bold(true).Render(sel.ID))
		if sel.Description != "" {
			fmt.Fprintf(&b, " — %s", lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render(sel.Description))
		}
		b.WriteString("\n")
		fmt.Fprintf(&b, "  Policy: %s  %s",
			p.verdictBadge(sel.Verdict),
			lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render(sel.VerdictDetail))
		if sel.ScanTarget != "" {
			fmt.Fprintf(&b, "\n  Scan target: %s", lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render(sel.ScanTarget))
		}
	}

	return b.String()
}

// ---------- Plugins tab ----------

func (p *InventoryPanel) renderPlugins(width, maxLines int) string {
	var b strings.Builder
	items := p.inv.Plugins

	if len(items) == 0 {
		return p.theme.Dimmed.Render("  No plugins found.")
	}

	var loaded, disabled, blocked int
	for _, pl := range items {
		if pl.Status == "loaded" {
			loaded++
		}
		if pl.Status == "disabled" {
			disabled++
		}
		if pl.Verdict == "blocked" {
			blocked++
		}
	}
	fmt.Fprintf(&b, "  %d plugins  ·  %s loaded  ·  %s disabled  ·  %s blocked\n\n",
		len(items),
		p.theme.Clean.Render(fmt.Sprintf("%d", loaded)),
		p.theme.Dimmed.Render(fmt.Sprintf("%d", disabled)),
		p.blockCount(blocked))

	header := fmt.Sprintf("  %-3s %-22s %-10s %-10s %-8s %-12s %-6s %-10s",
		"", "NAME", "VERSION", "ORIGIN", "STATUS", "VERDICT", "FINDS", "SEVERITY")
	b.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("243")).Render(header))
	b.WriteString("\n")

	start := 0
	if p.cursor >= maxLines {
		start = p.cursor - maxLines + 1
	}
	end := start + maxLines
	if end > len(items) {
		end = len(items)
	}

	for i := start; i < end; i++ {
		pl := items[i]
		pointer := "  "
		if i == p.cursor {
			pointer = lipgloss.NewStyle().Foreground(lipgloss.Color("62")).Bold(true).Render("▸ ")
		}

		name := pl.Name
		if name == "" {
			name = pl.ID
		}
		if len(name) > 20 {
			name = name[:17] + "…"
		}

		statusStyle := p.theme.Dimmed
		if pl.Status == "loaded" {
			statusStyle = p.theme.Clean
		}

		verdict := p.verdictBadge(pl.Verdict)
		findings := p.theme.Dimmed.Render("—")
		if pl.ScanFindings > 0 {
			findings = p.theme.High.Render(fmt.Sprintf("%d", pl.ScanFindings))
		}
		severity := p.theme.Dimmed.Render("—")
		if pl.ScanSeverity != "" {
			severity = p.theme.SeverityColor(pl.ScanSeverity).Render(pl.ScanSeverity)
		}

		line := fmt.Sprintf("%s %-20s %-10s %-10s %s %s %-6s %-10s",
			pointer, name, truncate(pl.Version, 10), truncate(pl.Origin, 10),
			statusStyle.Render(fmt.Sprintf("%-8s", pl.Status)), verdict, findings, severity)

		if i == p.cursor {
			line = lipgloss.NewStyle().Background(lipgloss.Color("236")).Width(width).Render(line)
		}
		b.WriteString(line + "\n")
	}

	if len(items) > maxLines {
		pct := 0
		if len(items) > 0 {
			pct = (end * 100) / len(items)
		}
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render(
			fmt.Sprintf("  ↕ %d–%d of %d (%d%%)", start+1, end, len(items), pct)))
	}

	// Detail of selected plugin
	if p.cursor >= 0 && p.cursor < len(items) {
		sel := items[p.cursor]
		b.WriteString("\n\n")
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("238")).Render(strings.Repeat("─", width)))
		b.WriteString("\n")
		displayName := sel.Name
		if displayName == "" {
			displayName = sel.ID
		}
		fmt.Fprintf(&b, "  %s", lipgloss.NewStyle().Bold(true).Render(displayName))
		if sel.Version != "" {
			fmt.Fprintf(&b, " v%s", sel.Version)
		}
		fmt.Fprintf(&b, "  [%s]", sel.Origin)
		fmt.Fprintf(&b, "\n  Policy: %s  %s",
			p.verdictBadge(sel.Verdict),
			lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render(sel.VerdictDetail))
		if sel.ScanTarget != "" {
			fmt.Fprintf(&b, "\n  Scan target: %s", lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render(sel.ScanTarget))
		}
	}

	return b.String()
}

// ---------- MCPs tab ----------

func (p *InventoryPanel) renderMCPs(width, maxLines int) string {
	var b strings.Builder
	items := p.inv.MCPs

	if len(items) == 0 {
		return p.theme.Dimmed.Render("  No MCP servers found in this environment.\n  Use : then \"set mcp <url>\" to add one.")
	}

	header := fmt.Sprintf("  %-3s %-22s %-14s %-14s %-30s", "", "ID", "SOURCE", "TRANSPORT", "COMMAND/URL")
	b.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("243")).Render(header))
	b.WriteString("\n")

	for i, m := range items {
		if i >= maxLines {
			break
		}
		pointer := "  "
		if i == p.cursor {
			pointer = lipgloss.NewStyle().Foreground(lipgloss.Color("62")).Bold(true).Render("▸ ")
		}
		cmdUrl := m.Command
		if cmdUrl == "" {
			cmdUrl = m.URL
		}
		line := fmt.Sprintf("%s %-20s %-14s %-14s %-30s",
			pointer, truncate(m.ID, 20), truncate(m.Source, 14), m.Transport, truncate(cmdUrl, 30))
		if i == p.cursor {
			line = lipgloss.NewStyle().Background(lipgloss.Color("236")).Width(width).Render(line)
		}
		b.WriteString(line + "\n")
	}

	return b.String()
}

// ---------- Agents tab ----------

func (p *InventoryPanel) renderAgents(width int) string {
	var b strings.Builder
	items := p.inv.Agents

	if len(items) == 0 {
		return p.theme.Dimmed.Render("  No agents configured.")
	}

	for i, a := range items {
		isDefault := ""
		if a.Default {
			isDefault = p.theme.Clean.Render(" (default)")
		}

		idStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("62"))
		fmt.Fprintf(&b, "  %s %s%s\n", idStyle.Render(a.ID), a.Source, isDefault)

		dim := lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
		if a.Model != "" {
			fmt.Fprintf(&b, "    %s  %s\n", dim.Render("Model:"), a.Model)
		}
		if a.MaxConc > 0 {
			fmt.Fprintf(&b, "    %s  %d\n", dim.Render("Max concurrent subagents:"), a.MaxConc)
		}
		if a.Workspace != "" {
			fmt.Fprintf(&b, "    %s  %s\n", dim.Render("Workspace:"), a.Workspace)
		}
		if len(a.Bindings) > 0 && string(a.Bindings) != "null" && string(a.Bindings) != "0" {
			var bindMap map[string]interface{}
			if json.Unmarshal(a.Bindings, &bindMap) == nil && len(bindMap) > 0 {
				fmt.Fprintf(&b, "    %s  %v\n", dim.Render("Bindings:"), bindMap)
			}
		}

		if i < len(items)-1 {
			b.WriteString("\n")
		}
	}

	return b.String()
}

// ---------- Models tab ----------

func (p *InventoryPanel) renderModels(width int) string {
	var b strings.Builder
	items := p.inv.Models

	if len(items) == 0 {
		return p.theme.Dimmed.Render("  No model providers configured.")
	}

	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("243"))

	for i, m := range items {
		idStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("62"))
		fmt.Fprintf(&b, "  %s  %s\n", idStyle.Render(m.ID), dim.Render(m.Source))

		if m.DefaultModel != "" {
			fmt.Fprintf(&b, "    %s  %s\n", dim.Render("Default model:"), m.DefaultModel)
		}
		if m.Status != "" {
			fmt.Fprintf(&b, "    %s  %s\n", dim.Render("Status:"), m.Status)
		}
		if m.ConfigPath != "" {
			fmt.Fprintf(&b, "    %s  %s\n", dim.Render("Config:"), m.ConfigPath)
		}
		if len(m.Allowed) > 0 {
			fmt.Fprintf(&b, "    %s\n", dim.Render("Allowed models:"))
			for _, model := range m.Allowed {
				fmt.Fprintf(&b, "      • %s\n", model)
			}
		}
		if len(m.Fallbacks) > 0 {
			fmt.Fprintf(&b, "    %s  %s\n", dim.Render("Fallbacks:"), strings.Join(m.Fallbacks, ", "))
		}

		if i < len(items)-1 {
			b.WriteString("\n")
		}
	}

	return b.String()
}

// ---------- Memory tab ----------

func (p *InventoryPanel) renderMemory(width int) string {
	var b strings.Builder
	items := p.inv.Memory

	if len(items) == 0 {
		return p.theme.Dimmed.Render("  No memory stores found.")
	}

	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("243"))

	for _, m := range items {
		idStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("62"))
		fmt.Fprintf(&b, "  %s  %s\n", idStyle.Render(m.ID), dim.Render(m.Backend))

		fmt.Fprintf(&b, "    %s  %d files, %d chunks\n", dim.Render("Data:"), m.Files, m.Chunks)
		if m.DBPath != "" {
			fmt.Fprintf(&b, "    %s  %s\n", dim.Render("DB:"), m.DBPath)
		}
		if m.Provider != "" {
			fmt.Fprintf(&b, "    %s  %s\n", dim.Render("Provider:"), m.Provider)
		}
		if m.Workspace != "" {
			fmt.Fprintf(&b, "    %s  %s\n", dim.Render("Workspace:"), m.Workspace)
		}
		if len(m.Sources) > 0 {
			fmt.Fprintf(&b, "    %s  %s\n", dim.Render("Sources:"), strings.Join(m.Sources, ", "))
		}

		features := []string{}
		if m.FTSAvail {
			features = append(features, p.theme.Clean.Render("FTS ✓"))
		} else {
			features = append(features, p.theme.Dimmed.Render("FTS ✗"))
		}
		if m.VectorEnabled {
			features = append(features, p.theme.Clean.Render("Vector ✓"))
		} else {
			features = append(features, p.theme.Dimmed.Render("Vector ✗"))
		}
		fmt.Fprintf(&b, "    %s  %s\n", dim.Render("Features:"), strings.Join(features, "  "))
	}

	return b.String()
}

// ---------- Helpers ----------

func (p *InventoryPanel) verdictBadge(verdict string) string {
	label := fmt.Sprintf(" %-10s ", verdict)
	switch verdict {
	case "blocked":
		return lipgloss.NewStyle().Background(lipgloss.Color("196")).Foreground(lipgloss.Color("16")).Bold(true).Render(label)
	case "rejected":
		return lipgloss.NewStyle().Background(lipgloss.Color("196")).Foreground(lipgloss.Color("16")).Bold(true).Render(label)
	case "allowed":
		return lipgloss.NewStyle().Background(lipgloss.Color("46")).Foreground(lipgloss.Color("16")).Bold(true).Render(label)
	case "clean":
		return lipgloss.NewStyle().Background(lipgloss.Color("46")).Foreground(lipgloss.Color("16")).Render(label)
	case "warning":
		return lipgloss.NewStyle().Background(lipgloss.Color("220")).Foreground(lipgloss.Color("16")).Bold(true).Render(label)
	case "unscanned":
		return lipgloss.NewStyle().Background(lipgloss.Color("238")).Foreground(lipgloss.Color("252")).Render(label)
	default:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render(label)
	}
}

func (p *InventoryPanel) warnCount(n int) string {
	s := fmt.Sprintf("%d", n)
	if n > 0 {
		return p.theme.Medium.Render(s)
	}
	return p.theme.Clean.Render(s)
}

func (p *InventoryPanel) blockCount(n int) string {
	s := fmt.Sprintf("%d", n)
	if n > 0 {
		return p.theme.Critical.Render(s)
	}
	return p.theme.Clean.Render(s)
}

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max-3] + "…"
	}
	return s
}

// Style alias for lipgloss.Style.
type Style = lipgloss.Style
