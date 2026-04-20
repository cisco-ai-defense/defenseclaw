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
	"os"
	"path/filepath"
	"sort"
	"strings"

	"charm.land/lipgloss/v2"
	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// Sub-tab indices for the Policy panel.
const (
	policyTabRulePacks = iota
	policyTabJudge
	policyTabSuppressions
	policyTabOPA
	policyTabCount
)

var policyTabNames = [policyTabCount]string{
	"Rule Packs", "Judge Prompts", "Suppressions", "OPA / Rego",
}

// PolicyPanel provides full browsing, editing, and testing of guardrail
// rule packs, judge prompts, suppressions, and OPA/Rego policies.
type PolicyPanel struct {
	theme *Theme
	cfg   *config.Config

	activeTab int
	loaded    bool

	// Rule Packs sub-tab
	packs       []string
	activePack  string
	packCursor  int
	packRules   []*guardrail.RulesFileYAML
	packDetail  bool
	ruleCursor  int
	ruleScroll  int

	// Judge Prompts sub-tab
	judgeNames  []string
	judgeCursor int
	judgeYAMLs  map[string]*guardrail.JudgeYAML
	judgeScroll int

	// Suppressions sub-tab
	suppressions *guardrail.SuppressionsConfig
	suppSection  int
	suppCursor   int
	suppScroll   int

	// OPA sub-tab
	regoFiles   []string
	regoCursor  int
	regoSource  string
	regoScroll  int
	showTests   bool
	regoOutput  string
}

// NewPolicyPanel creates a PolicyPanel.
func NewPolicyPanel(theme *Theme, cfg *config.Config) PolicyPanel {
	return PolicyPanel{
		theme:      theme,
		cfg:        cfg,
		judgeYAMLs: make(map[string]*guardrail.JudgeYAML),
	}
}

// load reads all policy data from disk based on the current config.
func (p *PolicyPanel) load() {
	p.loaded = true
	if p.cfg == nil {
		return
	}

	// Discover rule packs
	packBase := filepath.Dir(p.cfg.Guardrail.RulePackDir)
	p.packs = discoverPacks(packBase)
	p.activePack = filepath.Base(p.cfg.Guardrail.RulePackDir)

	// Load active pack details
	rp := guardrail.LoadRulePack(p.cfg.Guardrail.RulePackDir)
	if rp != nil {
		p.packRules = rp.RuleFiles
		p.judgeYAMLs = rp.JudgeConfigs
		p.suppressions = rp.Suppressions
	}

	p.judgeNames = []string{"injection", "pii", "tool-injection"}

	// Load OPA Rego files
	p.loadRegoFiles()
}

func discoverPacks(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var packs []string
	for _, e := range entries {
		if e.IsDir() {
			packs = append(packs, e.Name())
		}
	}
	sort.Strings(packs)
	return packs
}

func (p *PolicyPanel) loadRegoFiles() {
	if p.cfg == nil {
		return
	}
	regoDir := p.cfg.PolicyDir
	if regoDir == "" {
		return
	}
	sub := filepath.Join(regoDir, "rego")
	if info, err := os.Stat(sub); err == nil && info.IsDir() {
		regoDir = sub
	}

	entries, err := os.ReadDir(regoDir)
	if err != nil {
		return
	}
	p.regoFiles = nil
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".rego") {
			continue
		}
		if strings.HasSuffix(name, "_test.rego") && !p.showTests {
			continue
		}
		p.regoFiles = append(p.regoFiles, filepath.Join(regoDir, name))
	}
	sort.Strings(p.regoFiles)
	if p.regoCursor >= len(p.regoFiles) {
		p.regoCursor = 0
	}
	if len(p.regoFiles) > 0 {
		p.loadRegoSource()
	}
}

func (p *PolicyPanel) loadRegoSource() {
	if p.regoCursor < 0 || p.regoCursor >= len(p.regoFiles) {
		p.regoSource = ""
		return
	}
	data, err := os.ReadFile(p.regoFiles[p.regoCursor])
	if err != nil {
		p.regoSource = fmt.Sprintf("Error reading file: %v", err)
		return
	}
	p.regoSource = string(data)
}

// HandleKey processes keyboard input for the policy panel.
func (p *PolicyPanel) HandleKey(key string) (runBin string, runArgs []string, runName string) {
	if !p.loaded {
		p.load()
	}

	switch key {
	case "tab", "right":
		p.activeTab = (p.activeTab + 1) % policyTabCount
		p.resetCursors()
		return
	case "shift+tab", "left":
		p.activeTab = (p.activeTab + policyTabCount - 1) % policyTabCount
		p.resetCursors()
		return
	}

	switch p.activeTab {
	case policyTabRulePacks:
		return p.handleRulePackKey(key)
	case policyTabJudge:
		p.handleJudgeKey(key)
	case policyTabSuppressions:
		p.handleSuppressionsKey(key)
	case policyTabOPA:
		return p.handleOPAKey(key)
	}
	return
}

func (p *PolicyPanel) resetCursors() {
	// Keep existing cursors; just reset scroll
	p.ruleScroll = 0
	p.judgeScroll = 0
	p.suppScroll = 0
	p.regoScroll = 0
}

// ScrollBy scrolls the active sub-tab.
func (p *PolicyPanel) ScrollBy(delta int) {
	switch p.activeTab {
	case policyTabRulePacks:
		p.ruleScroll += delta
		if p.ruleScroll < 0 {
			p.ruleScroll = 0
		}
	case policyTabJudge:
		p.judgeScroll += delta
		if p.judgeScroll < 0 {
			p.judgeScroll = 0
		}
	case policyTabSuppressions:
		p.suppScroll += delta
		if p.suppScroll < 0 {
			p.suppScroll = 0
		}
	case policyTabOPA:
		p.regoScroll += delta
		if p.regoScroll < 0 {
			p.regoScroll = 0
		}
	}
}

// ----------------------------------------------------------------
// Rule Packs sub-tab
// ----------------------------------------------------------------

func (p *PolicyPanel) handleRulePackKey(key string) (string, []string, string) {
	if p.packDetail {
		switch key {
		case "esc":
			p.packDetail = false
			p.ruleCursor = 0
			p.ruleScroll = 0
		case "up", "k":
			if p.ruleCursor > 0 {
				p.ruleCursor--
			}
		case "down", "j":
			p.ruleCursor++
		}
		return "", nil, ""
	}

	switch key {
	case "up", "k":
		if p.packCursor > 0 {
			p.packCursor--
		}
	case "down", "j":
		if p.packCursor < len(p.packs)-1 {
			p.packCursor++
		}
	case "enter":
		if p.packCursor < len(p.packs) {
			selected := p.packs[p.packCursor]
			if selected != p.activePack {
				p.switchPack(selected)
				return "defenseclaw", []string{"policy", "reload"}, "policy reload"
			}
			p.packDetail = true
			p.ruleCursor = 0
		}
	}
	return "", nil, ""
}

func (p *PolicyPanel) switchPack(name string) {
	if p.cfg == nil {
		return
	}
	packBase := filepath.Dir(p.cfg.Guardrail.RulePackDir)
	newDir := filepath.Join(packBase, name)
	p.cfg.Guardrail.RulePackDir = newDir
	_ = p.cfg.Save()
	p.activePack = name

	rp := guardrail.LoadRulePack(newDir)
	if rp != nil {
		p.packRules = rp.RuleFiles
		p.judgeYAMLs = rp.JudgeConfigs
		p.suppressions = rp.Suppressions
	}
}

// ----------------------------------------------------------------
// Judge Prompts sub-tab
// ----------------------------------------------------------------

func (p *PolicyPanel) handleJudgeKey(key string) {
	switch key {
	case "up", "k":
		if p.judgeCursor > 0 {
			p.judgeCursor--
			p.judgeScroll = 0
		}
	case "down", "j":
		if p.judgeCursor < len(p.judgeNames)-1 {
			p.judgeCursor++
			p.judgeScroll = 0
		}
	}
}

// ----------------------------------------------------------------
// Suppressions sub-tab
// ----------------------------------------------------------------

func (p *PolicyPanel) handleSuppressionsKey(key string) {
	if p.suppressions == nil {
		return
	}

	maxSection := 2
	switch key {
	case "tab":
		p.suppSection = (p.suppSection + 1) % (maxSection + 1)
		p.suppCursor = 0
		p.suppScroll = 0
	case "up", "k":
		if p.suppCursor > 0 {
			p.suppCursor--
		}
	case "down", "j":
		p.suppCursor++
	case "d":
		p.deleteSuppression()
	}
}

func (p *PolicyPanel) deleteSuppression() {
	if p.suppressions == nil {
		return
	}
	changed := false
	switch p.suppSection {
	case 0:
		if p.suppCursor < len(p.suppressions.PreJudgeStrips) {
			p.suppressions.PreJudgeStrips = append(
				p.suppressions.PreJudgeStrips[:p.suppCursor],
				p.suppressions.PreJudgeStrips[p.suppCursor+1:]...,
			)
			changed = true
		}
	case 1:
		if p.suppCursor < len(p.suppressions.FindingSupps) {
			p.suppressions.FindingSupps = append(
				p.suppressions.FindingSupps[:p.suppCursor],
				p.suppressions.FindingSupps[p.suppCursor+1:]...,
			)
			changed = true
		}
	case 2:
		if p.suppCursor < len(p.suppressions.ToolSuppressions) {
			p.suppressions.ToolSuppressions = append(
				p.suppressions.ToolSuppressions[:p.suppCursor],
				p.suppressions.ToolSuppressions[p.suppCursor+1:]...,
			)
			changed = true
		}
	}
	if changed {
		p.saveSuppressionsYAML()
	}
}

func (p *PolicyPanel) saveSuppressionsYAML() {
	if p.cfg == nil || p.suppressions == nil {
		return
	}
	path := filepath.Join(p.cfg.Guardrail.RulePackDir, "suppressions.yaml")
	data, err := yaml.Marshal(p.suppressions)
	if err != nil {
		return
	}
	_ = os.WriteFile(path, data, 0o600)
}

// ----------------------------------------------------------------
// OPA / Rego sub-tab
// ----------------------------------------------------------------

func (p *PolicyPanel) handleOPAKey(key string) (string, []string, string) {
	switch key {
	case "up", "k":
		if p.regoCursor > 0 {
			p.regoCursor--
			p.loadRegoSource()
			p.regoScroll = 0
		}
	case "down", "j":
		if p.regoCursor < len(p.regoFiles)-1 {
			p.regoCursor++
			p.loadRegoSource()
			p.regoScroll = 0
		}
	case "t":
		p.showTests = !p.showTests
		p.loadRegoFiles()
	case "v":
		return "defenseclaw", []string{"policy", "validate"}, "policy validate"
	case "r":
		return "defenseclaw", []string{"policy", "reload"}, "policy reload"
	}
	return "", nil, ""
}

// ----------------------------------------------------------------
// View
// ----------------------------------------------------------------

// View renders the policy panel.
func (p *PolicyPanel) View(w, h int) string {
	if !p.loaded {
		p.load()
	}

	var b strings.Builder

	// Sub-tab bar
	for i := 0; i < policyTabCount; i++ {
		name := policyTabNames[i]
		if i == p.activeTab {
			b.WriteString(ActiveTabStyle.Render(name))
		} else {
			b.WriteString(TabStyle.Render(name))
		}
	}
	b.WriteString("\n")

	contentH := h - 3

	switch p.activeTab {
	case policyTabRulePacks:
		b.WriteString(p.viewRulePacks(w, contentH))
	case policyTabJudge:
		b.WriteString(p.viewJudge(w, contentH))
	case policyTabSuppressions:
		b.WriteString(p.viewSuppressions(w, contentH))
	case policyTabOPA:
		b.WriteString(p.viewOPA(w, contentH))
	}

	// Help bar
	b.WriteString("\n")
	help := p.helpText()
	b.WriteString(HelpStyle.Render(help))

	return b.String()
}

func (p *PolicyPanel) helpText() string {
	switch p.activeTab {
	case policyTabRulePacks:
		if p.packDetail {
			return "↑/↓ browse rules  esc back"
		}
		return "↑/↓ select pack  enter activate/browse  tab next section"
	case policyTabJudge:
		return "↑/↓ select judge  tab next section"
	case policyTabSuppressions:
		return "↑/↓ select  tab section  d delete  tab next section"
	case policyTabOPA:
		return "↑/↓ select module  v validate  r reload  t toggle tests"
	}
	return ""
}

// ----------------------------------------------------------------
// Rule Packs view
// ----------------------------------------------------------------

func (p *PolicyPanel) viewRulePacks(w, h int) string {
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	bold := lipgloss.NewStyle().Bold(true)
	active := lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Bold(true)

	if p.packDetail {
		return p.viewRuleDetail(w, h)
	}

	listW := 24
	var left strings.Builder
	left.WriteString(bold.Render("PACKS") + "\n\n")
	for i, name := range p.packs {
		prefix := "  "
		if i == p.packCursor {
			prefix = "▸ "
		}
		label := name
		if name == p.activePack {
			label = active.Render(name + " ●")
		}
		left.WriteString(prefix + label + "\n")
	}

	var right strings.Builder
	right.WriteString(bold.Render("PACK CONTENTS") + "\n\n")
	if p.packCursor < len(p.packs) {
		selected := p.packs[p.packCursor]
		packDir := filepath.Join(filepath.Dir(p.cfg.Guardrail.RulePackDir), selected)
		right.WriteString(dim.Render("Path: "+packDir) + "\n\n")

		rp := guardrail.LoadRulePack(packDir)
		if rp != nil {
			nRules := 0
			for _, rf := range rp.RuleFiles {
				nRules += len(rf.Rules)
			}
			fmt.Fprintf(&right, "  Rule files:       %d (%d rules)\n", len(rp.RuleFiles), nRules)
			fmt.Fprintf(&right, "  Judge configs:    %d\n", len(rp.JudgeConfigs))
			nSupp := 0
			if rp.Suppressions != nil {
				nSupp = len(rp.Suppressions.PreJudgeStrips) + len(rp.Suppressions.FindingSupps) + len(rp.Suppressions.ToolSuppressions)
			}
			fmt.Fprintf(&right, "  Suppressions:     %d\n", nSupp)
			nTools := 0
			if rp.SensitiveTools != nil {
				nTools = len(rp.SensitiveTools.Tools)
			}
			fmt.Fprintf(&right, "  Sensitive tools:  %d\n", nTools)
		}
	}

	leftBox := lipgloss.NewStyle().Width(listW).Height(h).Render(left.String())
	rightBox := lipgloss.NewStyle().Width(w - listW - 2).Height(h).Render(right.String())
	return lipgloss.JoinHorizontal(lipgloss.Top, leftBox, " ", rightBox)
}

func (p *PolicyPanel) viewRuleDetail(w, h int) string {
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	bold := lipgloss.NewStyle().Bold(true)

	var b strings.Builder
	b.WriteString(bold.Render("RULES — "+p.activePack) + "  " + dim.Render("(esc to go back)") + "\n\n")

	type flatRule struct {
		Category string
		Rule     guardrail.RuleDefYAML
	}
	var rules []flatRule
	for _, rf := range p.packRules {
		for _, r := range rf.Rules {
			rules = append(rules, flatRule{Category: rf.Category, Rule: r})
		}
	}

	if p.ruleCursor >= len(rules) {
		p.ruleCursor = len(rules) - 1
	}
	if p.ruleCursor < 0 {
		p.ruleCursor = 0
	}

	visible := h - 3
	start := p.ruleScroll
	if p.ruleCursor < start {
		start = p.ruleCursor
	}
	if p.ruleCursor >= start+visible {
		start = p.ruleCursor - visible + 1
	}
	p.ruleScroll = start

	end := start + visible
	if end > len(rules) {
		end = len(rules)
	}

	for i := start; i < end; i++ {
		r := rules[i]
		prefix := "  "
		if i == p.ruleCursor {
			prefix = "▸ "
		}
		sev := SeverityStyle(strings.ToUpper(r.Rule.Severity)).Render(r.Rule.Severity)
		line := fmt.Sprintf("%s%-12s %-8s %s", prefix, r.Rule.ID, sev, r.Rule.Title)
		if len(line) > w {
			line = line[:w]
		}
		b.WriteString(line + "\n")
	}

	fmt.Fprintf(&b, "\n%s", dim.Render(fmt.Sprintf("  %d rules total", len(rules))))
	return b.String()
}

// ----------------------------------------------------------------
// Judge Prompts view
// ----------------------------------------------------------------

func (p *PolicyPanel) viewJudge(w, h int) string {
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	bold := lipgloss.NewStyle().Bold(true)

	listW := 22
	var left strings.Builder
	left.WriteString(bold.Render("JUDGE") + "\n\n")
	for i, name := range p.judgeNames {
		prefix := "  "
		if i == p.judgeCursor {
			prefix = "▸ "
		}
		left.WriteString(prefix + name + "\n")
	}

	var right strings.Builder
	if p.judgeCursor < len(p.judgeNames) {
		name := p.judgeNames[p.judgeCursor]
		jy := p.judgeYAMLs[name]
		if jy == nil {
			right.WriteString(dim.Render("No judge config loaded for " + name))
		} else {
			right.WriteString(bold.Render(jy.Name) + "\n")
			enabledStr := "disabled"
			if jy.Enabled {
				enabledStr = "enabled"
			}
			right.WriteString(dim.Render("Status: "+enabledStr) + "\n\n")

			right.WriteString(bold.Render("System Prompt:") + "\n")
			prompt := jy.SystemPrompt
			lines := strings.Split(prompt, "\n")
			maxLines := h - 12
			scroll := p.judgeScroll
			if scroll > len(lines)-maxLines {
				scroll = len(lines) - maxLines
			}
			if scroll < 0 {
				scroll = 0
			}
			p.judgeScroll = scroll
			end := scroll + maxLines
			if end > len(lines) {
				end = len(lines)
			}
			for _, l := range lines[scroll:end] {
				if len(l) > w-listW-4 {
					l = l[:w-listW-4]
				}
				right.WriteString("  " + l + "\n")
			}

			if jy.AdjudicationPrompt != "" {
				right.WriteString("\n" + bold.Render("Adjudication Prompt:") + "\n")
				adjLines := strings.Split(jy.AdjudicationPrompt, "\n")
				for _, l := range adjLines {
					if len(l) > w-listW-4 {
						l = l[:w-listW-4]
					}
					right.WriteString("  " + l + "\n")
				}
			}

			right.WriteString("\n" + bold.Render("Categories:") + "\n")
			for catName, cat := range jy.Categories {
				sev := cat.Severity
				if sev == "" {
					sev = cat.SeverityDefault
				}
				enabledTag := "on"
				if !cat.Enabled {
					enabledTag = "off"
				}
				fmt.Fprintf(&right, "  %-20s %s  %s  %s\n",
					catName,
					SeverityStyle(strings.ToUpper(sev)).Render(sev),
					dim.Render(cat.FindingID),
					dim.Render("["+enabledTag+"]"),
				)
			}
		}
	}

	leftBox := lipgloss.NewStyle().Width(listW).Height(h).Render(left.String())
	rightBox := lipgloss.NewStyle().Width(w - listW - 2).Height(h).Render(right.String())
	return lipgloss.JoinHorizontal(lipgloss.Top, leftBox, " ", rightBox)
}

// ----------------------------------------------------------------
// Suppressions view
// ----------------------------------------------------------------

func (p *PolicyPanel) viewSuppressions(w, h int) string {
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	bold := lipgloss.NewStyle().Bold(true)

	var b strings.Builder

	sectionNames := []string{"Pre-Judge Strips", "Finding Suppressions", "Tool Suppressions"}
	for i, name := range sectionNames {
		if i == p.suppSection {
			b.WriteString(ActiveTabStyle.Render(name))
		} else {
			b.WriteString(TabStyle.Render(name))
		}
	}
	b.WriteString("\n\n")

	if p.suppressions == nil {
		b.WriteString(dim.Render("No suppressions loaded"))
		return b.String()
	}

	switch p.suppSection {
	case 0:
		b.WriteString(bold.Render("PRE-JUDGE STRIPS") + "\n\n")
		if len(p.suppressions.PreJudgeStrips) == 0 {
			b.WriteString(dim.Render("  (none)") + "\n")
		}
		for i, s := range p.suppressions.PreJudgeStrips {
			prefix := "  "
			if i == p.suppCursor {
				prefix = "▸ "
			}
			line := fmt.Sprintf("%s%-16s pattern=%q  context=%s  applies_to=%v",
				prefix, s.ID, s.Pattern, s.Context, s.AppliesTo)
			if len(line) > w {
				line = line[:w]
			}
			b.WriteString(line + "\n")
		}
	case 1:
		b.WriteString(bold.Render("FINDING SUPPRESSIONS") + "\n\n")
		if len(p.suppressions.FindingSupps) == 0 {
			b.WriteString(dim.Render("  (none)") + "\n")
		}
		for i, s := range p.suppressions.FindingSupps {
			prefix := "  "
			if i == p.suppCursor {
				prefix = "▸ "
			}
			line := fmt.Sprintf("%s%-16s finding=%q  entity=%q  reason=%s",
				prefix, s.ID, s.FindingPattern, s.EntityPattern, s.Reason)
			if len(line) > w {
				line = line[:w]
			}
			b.WriteString(line + "\n")
		}
	case 2:
		b.WriteString(bold.Render("TOOL SUPPRESSIONS") + "\n\n")
		if len(p.suppressions.ToolSuppressions) == 0 {
			b.WriteString(dim.Render("  (none)") + "\n")
		}
		for i, s := range p.suppressions.ToolSuppressions {
			prefix := "  "
			if i == p.suppCursor {
				prefix = "▸ "
			}
			line := fmt.Sprintf("%stool=%q  suppress=%v  reason=%s",
				prefix, s.ToolPattern, s.SuppressFindings, s.Reason)
			if len(line) > w {
				line = line[:w]
			}
			b.WriteString(line + "\n")
		}
	}

	return b.String()
}

// ----------------------------------------------------------------
// OPA / Rego view
// ----------------------------------------------------------------

func (p *PolicyPanel) viewOPA(w, h int) string {
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	bold := lipgloss.NewStyle().Bold(true)

	listW := 28
	var left strings.Builder
	left.WriteString(bold.Render("REGO MODULES") + "\n")
	testLabel := "show tests"
	if p.showTests {
		testLabel = "hide tests"
	}
	left.WriteString(dim.Render("[t] "+testLabel) + "\n\n")

	for i, path := range p.regoFiles {
		name := filepath.Base(path)
		prefix := "  "
		if i == p.regoCursor {
			prefix = "▸ "
		}
		left.WriteString(prefix + name + "\n")
	}

	var right strings.Builder
	if p.regoCursor < len(p.regoFiles) {
		right.WriteString(bold.Render(filepath.Base(p.regoFiles[p.regoCursor])) + "\n\n")
		lines := strings.Split(p.regoSource, "\n")
		maxLines := h - 4
		scroll := p.regoScroll
		if scroll > len(lines)-maxLines {
			scroll = len(lines) - maxLines
		}
		if scroll < 0 {
			scroll = 0
		}
		p.regoScroll = scroll
		end := scroll + maxLines
		if end > len(lines) {
			end = len(lines)
		}
		for _, l := range lines[scroll:end] {
			highlighted := highlightRego(l)
			if len(l) > w-listW-4 {
				l = l[:w-listW-4]
				highlighted = highlightRego(l)
			}
			right.WriteString("  " + highlighted + "\n")
		}
	}

	if p.regoOutput != "" {
		right.WriteString("\n" + bold.Render("OUTPUT:") + "\n")
		right.WriteString(dim.Render(p.regoOutput) + "\n")
	}

	leftBox := lipgloss.NewStyle().Width(listW).Height(h).Render(left.String())
	rightBox := lipgloss.NewStyle().Width(w - listW - 2).Height(h).Render(right.String())
	return lipgloss.JoinHorizontal(lipgloss.Top, leftBox, " ", rightBox)
}

var regoKeywords = []string{"package", "import", "default", "allow", "deny", "not", "with", "as", "else"}

func highlightRego(line string) string {
	kw := lipgloss.NewStyle().Foreground(lipgloss.Color("135")).Bold(true)
	comment := lipgloss.NewStyle().Foreground(lipgloss.Color("243"))

	trimmed := strings.TrimSpace(line)
	if strings.HasPrefix(trimmed, "#") {
		return comment.Render(line)
	}

	for _, word := range regoKeywords {
		if strings.HasPrefix(trimmed, word+" ") || strings.HasPrefix(trimmed, word+"\t") || trimmed == word {
			idx := strings.Index(line, word)
			if idx < 0 {
				continue
			}
			return line[:idx] + kw.Render(word) + line[idx+len(word):]
		}
	}
	return line
}

// HandleMouseClick processes a mouse click at (x, relY) where relY is relative
// to the panel top. Returns a command to execute, if any.
func (p *PolicyPanel) HandleMouseClick(x, relY int) (runBin string, runArgs []string, runName string) {
	if !p.loaded {
		p.load()
	}

	// Row 0 is the sub-tab bar — handled separately via SubTabHitTest in app.go
	if relY <= 1 {
		return
	}

	contentY := relY - 2 // account for sub-tab bar + blank line

	switch p.activeTab {
	case policyTabRulePacks:
		if p.packDetail {
			if contentY >= 2 { // header lines
				p.ruleCursor = contentY - 2 + p.ruleScroll
			}
		} else {
			// Left pane: pack list (starts at line 2 after "PACKS" + blank)
			if x < 24 && contentY >= 2 {
				idx := contentY - 2
				if idx >= 0 && idx < len(p.packs) {
					if p.packCursor == idx {
						// Double-click: activate or drill in
						selected := p.packs[idx]
						if selected != p.activePack {
							p.switchPack(selected)
							return "defenseclaw", []string{"policy", "reload"}, "policy reload"
						}
						p.packDetail = true
						p.ruleCursor = 0
					} else {
						p.packCursor = idx
					}
				}
			}
		}

	case policyTabJudge:
		// Left pane: judge list (starts at line 2 after "JUDGE" + blank)
		if x < 22 && contentY >= 2 {
			idx := contentY - 2
			if idx >= 0 && idx < len(p.judgeNames) {
				p.judgeCursor = idx
				p.judgeScroll = 0
			}
		}

	case policyTabSuppressions:
		// Section tabs on first line, items start at line 3
		if contentY == 0 {
			// Click on section tabs
			pos := 0
			sectionNames := []string{"Pre-Judge Strips", "Finding Suppressions", "Tool Suppressions"}
			for i, name := range sectionNames {
				nameLen := len(name) + 4
				if x >= pos && x < pos+nameLen {
					p.suppSection = i
					p.suppCursor = 0
					p.suppScroll = 0
					return
				}
				pos += nameLen
			}
		}
		if contentY >= 3 {
			p.suppCursor = contentY - 3 + p.suppScroll
		}

	case policyTabOPA:
		// Left pane: rego file list (starts at line 3 after header + toggle + blank)
		if x < 28 && contentY >= 3 {
			idx := contentY - 3
			if idx >= 0 && idx < len(p.regoFiles) {
				p.regoCursor = idx
				p.loadRegoSource()
				p.regoScroll = 0
			}
		}
	}
	return
}

// SubTabHitTest returns the sub-tab index at horizontal position x, or -1.
func (p *PolicyPanel) SubTabHitTest(x int) int {
	pos := 0
	for i := 0; i < policyTabCount; i++ {
		nameLen := len(policyTabNames[i]) + 4
		if x >= pos && x < pos+nameLen {
			return i
		}
		pos += nameLen
	}
	return -1
}

// SetSubTab switches to the given sub-tab.
func (p *PolicyPanel) SetSubTab(idx int) {
	if idx >= 0 && idx < policyTabCount {
		p.activeTab = idx
	}
}
