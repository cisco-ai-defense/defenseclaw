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
	filter         string // "eligible", "warning", "blocked", "loaded", "disabled", "" = all

	// P3-#19: category scope mirrors the CLI --only flag. nil means
	// "scan everything" (the CLI default); a non-nil slice narrows
	// the scan to the listed categories and is forwarded to
	// `defenseclaw aibom scan --only <csv>`. Keeping a slice rather
	// than a bool preset lets future toggles grow cleanly; today the
	// UI only exposes a fast-mode preset via the 'o' key but the
	// internals already round-trip arbitrary subsets so tests can
	// exercise them.
	categoryScope []string
}

// InventoryCategories lists the seven categories the Python AIBOM
// scanner knows about (cli/defenseclaw/commands/cmd_aibom.py). Kept
// ordered so chip rendering stays deterministic — the UI sorts by
// this slice, not by map iteration.
var InventoryCategories = []string{
	"skills", "plugins", "mcp", "agents", "tools", "models", "memory",
}

// fastScanCategories is the "just the security surface" preset —
// skills/plugins/mcp are the scanned-and-enforced items, so this
// skips the slow discovery calls for agents/tools/models/memory
// that AIBOM otherwise makes. Matches the UX hint text.
var fastScanCategories = []string{"skills", "plugins", "mcp"}

func NewInventoryPanel(theme *Theme, exec *CommandExecutor, store *audit.Store) InventoryPanel {
	return InventoryPanel{theme: theme, executor: exec, store: store}
}

func (p *InventoryPanel) LoadCmd() tea.Cmd {
	p.loading = true
	args := p.loadCmdArgs()
	return func() tea.Msg {
		cmd := exec.Command("defenseclaw", args...)
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

// loadCmdArgs builds the argv for the aibom scan, adding `--only`
// only when the operator has narrowed the scope. This is extracted
// so tests can assert the exact flag surface without needing to
// exec the binary (which would require an installed defenseclaw
// CLI in CI).
func (p *InventoryPanel) loadCmdArgs() []string {
	args := []string{"aibom", "scan", "--json"}
	if len(p.categoryScope) > 0 {
		args = append(args, "--only", strings.Join(p.categoryScope, ","))
	}
	return args
}

// CategoryScope returns the active category filter (nil = scan all).
// Exported for tests and for the renderer.
func (p *InventoryPanel) CategoryScope() []string { return p.categoryScope }

// SetCategoryScope replaces the scope. nil / empty clears back to
// "scan all". Values not in InventoryCategories are dropped so a
// malformed persisted value can't land a bogus --only on the next
// reload.
func (p *InventoryPanel) SetCategoryScope(cats []string) {
	if len(cats) == 0 {
		p.categoryScope = nil
		return
	}
	allowed := make(map[string]bool, len(InventoryCategories))
	for _, c := range InventoryCategories {
		allowed[c] = true
	}
	out := cats[:0:0]
	for _, c := range cats {
		if allowed[c] {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		p.categoryScope = nil
		return
	}
	p.categoryScope = out
}

// ToggleCategory flips membership for a single chip. Unknown
// categories are ignored so a stray keystroke doesn't corrupt
// scope. Empty scope after a toggle falls back to nil, which is
// semantically "scan all" and is what LoadCmd emits when no
// --only is needed.
func (p *InventoryPanel) ToggleCategory(cat string) {
	found := false
	for _, c := range InventoryCategories {
		if c == cat {
			found = true
			break
		}
	}
	if !found {
		return
	}
	for i, existing := range p.categoryScope {
		if existing == cat {
			p.categoryScope = append(p.categoryScope[:i], p.categoryScope[i+1:]...)
			if len(p.categoryScope) == 0 {
				p.categoryScope = nil
			}
			return
		}
	}
	p.categoryScope = append(p.categoryScope, cat)
}

// ToggleFastScan flips between "all" and the fast-scan preset
// (skills+plugins+mcp). Used by the 'o' hotkey to give operators a
// one-press way to skip the slow discovery tails (agents/tools/
// models/memory) when they're iterating on security work.
func (p *InventoryPanel) ToggleFastScan() {
	if p.isFastScan() {
		p.categoryScope = nil
		return
	}
	scope := make([]string, len(fastScanCategories))
	copy(scope, fastScanCategories)
	p.categoryScope = scope
}

// isFastScan reports whether the current scope matches the fast
// preset exactly (regardless of order). Used by View to render the
// chip row and by tests.
func (p *InventoryPanel) isFastScan() bool {
	if len(p.categoryScope) != len(fastScanCategories) {
		return false
	}
	want := map[string]bool{}
	for _, c := range fastScanCategories {
		want[c] = true
	}
	for _, c := range p.categoryScope {
		if !want[c] {
			return false
		}
	}
	return true
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
func (p *InventoryPanel) Filter() string     { return p.filter }
func (p *InventoryPanel) IsDetailOpen() bool { return p.detailOpen }
func (p *InventoryPanel) ToggleDetail() {
	p.detailOpen = !p.detailOpen
	p.detailCache = nil
}

// renderCategoryChips draws the "Load scope" chip row showing which
// AIBOM categories will be requested on the next scan. Active chips
// are highlighted; when the scope is nil (scan-all) every chip is
// dimmed-but-on so the visual matches the "no --only flag"
// semantics. The row is prefixed with "Scope:" so operators can
// tell at a glance whether they're looking at a fast scan vs the
// default full scan — which matters because counts in the sub-tab
// bar only cover what was actually scanned.
func (p *InventoryPanel) renderCategoryChips(width int) string {
	var b strings.Builder
	b.WriteString("  ")
	active := map[string]bool{}
	if len(p.categoryScope) == 0 {
		// nil scope = "all on" for display purposes.
		for _, c := range InventoryCategories {
			active[c] = true
		}
	} else {
		for _, c := range p.categoryScope {
			active[c] = true
		}
	}
	label := "Scope"
	if len(p.categoryScope) == 0 {
		label = "Scope (all)"
	} else if p.isFastScan() {
		label = "Scope (fast)"
	}
	b.WriteString(p.theme.Dimmed.Render(label + ": "))
	for i, cat := range InventoryCategories {
		chip := " " + cat + " "
		if active[cat] {
			b.WriteString(p.theme.ActiveTab.Render(chip))
		} else {
			b.WriteString(p.theme.InactiveTab.Render(chip))
		}
		if i < len(InventoryCategories)-1 {
			b.WriteString(" ")
		}
	}
	b.WriteString(p.theme.Dimmed.Render("  (o toggles fast, r reloads)"))
	b.WriteString("\n")
	return b.String()
}

func (p *InventoryPanel) SetFilter(f string) {
	if p.filter == f {
		p.filter = ""
	} else {
		p.filter = f
	}
	p.cursor = 0
	p.detailOpen = false
	p.detailCache = nil
}

func (p *InventoryPanel) ClearFilter() {
	p.filter = ""
	p.cursor = 0
}

// SubTabHitTest returns the sub-tab index at the given x position, or -1.
func (p *InventoryPanel) SubTabHitTest(x int) int {
	pos := 2 // leading "  " indent
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
		w := lipgloss.Width(label)
		if x >= pos && x < pos+w {
			return i
		}
		pos += w + 1 // +1 for space separator
	}
	return -1
}

func (p *InventoryPanel) filteredSkills() []aibomSkill {
	if p.inv == nil {
		return nil
	}
	if p.filter == "" {
		return p.inv.Skills
	}
	var out []aibomSkill
	for _, s := range p.inv.Skills {
		switch p.filter {
		case "eligible":
			if s.Eligible {
				out = append(out, s)
			}
		case "warning":
			if s.Verdict == "warning" {
				out = append(out, s)
			}
		case "blocked":
			if s.Verdict == "blocked" {
				out = append(out, s)
			}
		}
	}
	return out
}

func (p *InventoryPanel) filteredPlugins() []aibomPlugin {
	if p.inv == nil {
		return nil
	}
	if p.filter == "" {
		return p.inv.Plugins
	}
	var out []aibomPlugin
	for _, pl := range p.inv.Plugins {
		switch p.filter {
		case "loaded":
			if pl.Status == "loaded" {
				out = append(out, pl)
			}
		case "disabled":
			if pl.Status == "disabled" {
				out = append(out, pl)
			}
		case "blocked":
			if pl.Verdict == "blocked" {
				out = append(out, pl)
			}
		}
	}
	return out
}

func (p *InventoryPanel) detailHeight() int {
	if !p.detailOpen {
		return 0
	}
	h := p.height / 2
	if h < 8 {
		h = 8
	}
	if h > 26 {
		h = 26
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
		skills := p.filteredSkills()
		if p.cursor < 0 || p.cursor >= len(skills) {
			return nil
		}
		sk := skills[p.cursor]
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
		plugins := p.filteredPlugins()
		if p.cursor < 0 || p.cursor >= len(plugins) {
			return nil
		}
		pl := plugins[p.cursor]
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
	history, _ := p.store.ListEventsByTarget(targetName, 10)
	info.History = history
}

func (p *InventoryPanel) currentListLen() int {
	if p.inv == nil {
		return 0
	}
	switch p.activeSub {
	case invSubSkills:
		return len(p.filteredSkills())
	case invSubPlugins:
		return len(p.filteredPlugins())
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
	b.WriteString(p.renderCategoryChips(width))
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
		if f[0] == "Verdict" {
			d.WriteString(labelStyle.Render(fmt.Sprintf("  %-16s", f[0]+":")) + p.verdictBadge(f[1]) + "\n")
		} else if f[0] == "Scan Severity" && f[1] != "" {
			d.WriteString(labelStyle.Render(fmt.Sprintf("  %-16s", f[0]+":")) + SeverityStyle(f[1]).Render(f[1]) + "\n")
		} else {
			d.WriteString(labelStyle.Render(fmt.Sprintf("  %-16s", f[0]+":")) + valStyle.Render(f[1]) + "\n")
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
			if shown >= 5 {
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

// SkillFilterPositions returns [start,end] x-positions for each clickable filter label.
// Order: all, eligible, warnings, blocked
func (p *InventoryPanel) SkillFilterPositions() [][2]int {
	if p.inv == nil {
		return nil
	}
	var eligible, warned, blocked int
	for _, s := range p.inv.Skills {
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
	labels := []string{
		fmt.Sprintf("%d skills", len(p.inv.Skills)),
		fmt.Sprintf("%d eligible", eligible),
		fmt.Sprintf("%d warnings", warned),
		fmt.Sprintf("%d blocked", blocked),
	}
	pos := 2 // leading indent
	var positions [][2]int
	for i, l := range labels {
		w := len(l)
		positions = append(positions, [2]int{pos, pos + w})
		pos += w
		if i < len(labels)-1 {
			pos += 5 // "  ·  " separator
		}
	}
	return positions
}

func (p *InventoryPanel) renderSkills(width, maxLines int) string {
	var b strings.Builder
	allItems := p.inv.Skills

	if len(allItems) == 0 {
		return p.theme.Dimmed.Render("  No skills found.")
	}

	var eligible, warned, blocked int
	for _, s := range allItems {
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

	allLabel := fmt.Sprintf("%d skills", len(allItems))
	eligLabel := fmt.Sprintf("%d eligible", eligible)
	warnLabel := fmt.Sprintf("%d warnings", warned)
	blockLabel := fmt.Sprintf("%d blocked", blocked)

	renderLabel := func(label, filterKey string, style lipgloss.Style) string {
		if p.filter == filterKey {
			return lipgloss.NewStyle().Bold(true).Underline(true).Inherit(style).Render(label)
		}
		return style.Render(label)
	}

	fmt.Fprintf(&b, "  %s  ·  %s  ·  %s  ·  %s\n",
		renderLabel(allLabel, "", lipgloss.NewStyle()),
		renderLabel(eligLabel, "eligible", p.theme.Clean),
		renderLabel(warnLabel, "warning", lipgloss.NewStyle().Foreground(lipgloss.Color("214"))),
		renderLabel(blockLabel, "blocked", p.theme.Critical))
	if p.filter != "" {
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render(
			fmt.Sprintf("  Filtered: %s  (click again or press Esc to clear)", p.filter)))
		b.WriteString("\n")
	}
	b.WriteString("\n")

	items := p.filteredSkills()

	dimHeader := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("243"))
	header := fmt.Sprintf("  %-4s%-24s %-12s %-8s %-10s %-6s %s",
		"", "ID", "VERDICT", "ON", "SEVERITY", "FINDS", "SOURCE")
	b.WriteString(dimHeader.Render(header))
	b.WriteString("\n")

	if len(items) == 0 {
		b.WriteString(p.theme.Dimmed.Render("  No items match the current filter."))
		return b.String()
	}

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
		if len(id) > 22 {
			id = id[:19] + "..."
		}

		verdict := p.verdictBadge(s.Verdict)
		enabled := p.theme.Dimmed.Render("no")
		if s.Enabled {
			enabled = p.theme.Clean.Render("yes")
		}

		severity := p.theme.Dimmed.Render("--")
		if s.ScanSeverity != "" {
			severity = p.theme.SeverityColor(s.ScanSeverity).Render(s.ScanSeverity)
		}
		findings := p.theme.Dimmed.Render("--")
		if s.ScanFindings > 0 {
			findings = p.theme.High.Render(fmt.Sprintf("%d", s.ScanFindings))
		}

		src := truncate(s.Source, 18)

		var line strings.Builder
		line.WriteString(pointer)
		line.WriteString(padRight(emoji, 2))
		line.WriteString(padRight(id, 23))
		line.WriteString(padRight(verdict, 13))
		line.WriteString(padRight(enabled, 8))
		line.WriteString(padRight(severity, 11))
		line.WriteString(padRight(findings, 7))
		line.WriteString(src)

		row := line.String()
		if i == p.cursor {
			row = lipgloss.NewStyle().Background(lipgloss.Color("236")).Width(width).Render(row)
		}
		b.WriteString(row + "\n")
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

	b.WriteString("\n\n")
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Italic(true).Render(
		"  Note: Inventory lists all skills found by AIBOM on disk. The Skills tab only shows skills with scan/enforcement records."))

	return b.String()
}

// ---------- Plugins tab ----------

// PluginFilterPositions returns [start,end] x-positions for each clickable filter label.
// Order: all, loaded, disabled, blocked
func (p *InventoryPanel) PluginFilterPositions() [][2]int {
	if p.inv == nil {
		return nil
	}
	var loaded, disabled, blocked int
	for _, pl := range p.inv.Plugins {
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
	labels := []string{
		fmt.Sprintf("%d plugins", len(p.inv.Plugins)),
		fmt.Sprintf("%d loaded", loaded),
		fmt.Sprintf("%d disabled", disabled),
		fmt.Sprintf("%d blocked", blocked),
	}
	pos := 2
	var positions [][2]int
	for i, l := range labels {
		w := len(l)
		positions = append(positions, [2]int{pos, pos + w})
		pos += w
		if i < len(labels)-1 {
			pos += 5
		}
	}
	return positions
}

func (p *InventoryPanel) renderPlugins(width, maxLines int) string {
	var b strings.Builder
	allItems := p.inv.Plugins

	if len(allItems) == 0 {
		return p.theme.Dimmed.Render("  No plugins found.")
	}

	var loaded, disabled, blocked int
	for _, pl := range allItems {
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

	allLabel := fmt.Sprintf("%d plugins", len(allItems))
	loadLabel := fmt.Sprintf("%d loaded", loaded)
	disLabel := fmt.Sprintf("%d disabled", disabled)
	blockLabel := fmt.Sprintf("%d blocked", blocked)

	renderLabel := func(label, filterKey string, style lipgloss.Style) string {
		if p.filter == filterKey {
			return lipgloss.NewStyle().Bold(true).Underline(true).Inherit(style).Render(label)
		}
		return style.Render(label)
	}

	fmt.Fprintf(&b, "  %s  ·  %s  ·  %s  ·  %s\n",
		renderLabel(allLabel, "", lipgloss.NewStyle()),
		renderLabel(loadLabel, "loaded", p.theme.Clean),
		renderLabel(disLabel, "disabled", p.theme.Dimmed),
		renderLabel(blockLabel, "blocked", p.theme.Critical))
	if p.filter != "" {
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render(
			fmt.Sprintf("  Filtered: %s  (click again or press Esc to clear)", p.filter)))
		b.WriteString("\n")
	}
	b.WriteString("\n")

	items := p.filteredPlugins()

	dimHeader := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("243"))
	header := fmt.Sprintf("  %-3s%-20s %-10s %-10s %-8s %-12s %-6s %s",
		"", "NAME", "VERSION", "ORIGIN", "STATUS", "VERDICT", "FINDS", "SEVERITY")
	b.WriteString(dimHeader.Render(header))
	b.WriteString("\n")

	if len(items) == 0 {
		b.WriteString(p.theme.Dimmed.Render("  No items match the current filter."))
		return b.String()
	}

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
		if len(name) > 18 {
			name = name[:15] + "..."
		}

		statusStyle := p.theme.Dimmed
		if pl.Status == "loaded" {
			statusStyle = p.theme.Clean
		}

		verdict := p.verdictBadge(pl.Verdict)
		findings := p.theme.Dimmed.Render("--")
		if pl.ScanFindings > 0 {
			findings = p.theme.High.Render(fmt.Sprintf("%d", pl.ScanFindings))
		}
		severity := p.theme.Dimmed.Render("--")
		if pl.ScanSeverity != "" {
			severity = p.theme.SeverityColor(pl.ScanSeverity).Render(pl.ScanSeverity)
		}

		var line strings.Builder
		line.WriteString(pointer)
		line.WriteString(padRight(name, 20))
		line.WriteString(" ")
		line.WriteString(padRight(truncate(pl.Version, 10), 10))
		line.WriteString(" ")
		line.WriteString(padRight(truncate(pl.Origin, 10), 10))
		line.WriteString(" ")
		line.WriteString(padRight(statusStyle.Render(pl.Status), 8))
		line.WriteString(" ")
		line.WriteString(padRight(verdict, 13))
		line.WriteString(padRight(findings, 7))
		line.WriteString(severity)

		row := line.String()
		if i == p.cursor {
			row = lipgloss.NewStyle().Background(lipgloss.Color("236")).Width(width).Render(row)
		}
		b.WriteString(row + "\n")
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

	b.WriteString("\n\n")
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Italic(true).Render(
		"  Note: Inventory lists all plugins found by AIBOM. The Plugins tab only shows plugins with scan/enforcement records."))

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

	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Italic(true).Render(
		"  Note: Inventory lists all MCP servers found by AIBOM. The MCPs tab only shows servers with scan/enforcement records."))

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

// padRight pads a styled string to a visual width using spaces.
func padRight(s string, width int) string {
	vw := lipgloss.Width(s)
	if vw >= width {
		return s
	}
	return s + strings.Repeat(" ", width-vw)
}

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max-3] + "…"
	}
	return s
}

// Style alias for lipgloss.Style.
type Style = lipgloss.Style
