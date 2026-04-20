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
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// Sub-tab indices for the Policy panel.
const (
	policyTabPolicies = iota
	policyTabRulePacks
	policyTabJudge
	policyTabSuppressions
	policyTabOPA
	policyTabCount
)

var policyTabNames = [policyTabCount]string{
	"Policies", "Rule Packs", "Judge Prompts", "Suppressions", "OPA / Rego",
}

// PolicyPanel provides full browsing, editing, and testing of guardrail
// rule packs, judge prompts, suppressions, and OPA/Rego policies.
type PolicyPanel struct {
	theme *Theme
	cfg   *config.Config

	activeTab int
	loaded    bool

	// Rule Packs sub-tab
	packs      []string
	activePack string
	packCursor int
	packRules  []*guardrail.RulesFileYAML
	packDetail bool
	ruleCursor int
	ruleScroll int

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
	regoFiles  []string
	regoCursor int
	regoSource string
	regoScroll int
	showTests  bool
	regoOutput string

	// Policies sub-tab — admission-gate YAML policies managed via
	// `defenseclaw policy <verb>`. We intentionally keep this
	// distinct from rule packs (which are a guardrail concept) so
	// the help text and verbs don't collide.
	policies       []string // policy names (basename w/o .yaml)
	activePolicy   string   // name of the currently-activated policy
	policyCursor   int
	policyScroll   int
	policiesLoaded bool // lazy-loaded so tests don't need a real ~/.defenseclaw
	policyForm     PolicyCreateForm

	// B3a: Policies tab viewer overlay. When open, the panel renders
	// the YAML of the highlighted admission policy in a bordered
	// overlay so operators never have to leave the Policies tab.
	// policyDetailScroll is the index of the first body line to
	// render; clamped in renderPolicyDetailOverlay so a window
	// resize never strands the view past EOF.
	policyDetailOpen   bool
	policyDetailYAML   string
	policyDetailName   string
	policyDetailScroll int

	// B3b: Rule-pack rule detail overlay. Same idea as the policy
	// overlay but scoped to a single rule inside the active pack.
	// ruleDetailPath is the backing file for the highlighted rule,
	// populated at openRuleDetail() time so the 'e' edit keybind
	// can launch ``$EDITOR`` on the exact file (rules are grouped
	// per-file by category, so editing the file is the right unit
	// of editing — tweaking one rule in isolation would require
	// a structured patch the guardrail loader doesn't offer yet).
	ruleDetailOpen   bool
	ruleDetailYAML   string
	ruleDetailPath   string
	ruleDetailScroll int

	// B3d: pendingCmd is a tea.Cmd queued by HandleKey that should
	// run in the TUI (not via the CommandExecutor / Activity panel).
	// We use this for `defenseclaw policy test` so the output lands
	// in the OPA side panel instead of flipping the active tab.
	pendingCmd tea.Cmd
}

// RegoTestResultMsg carries the raw stdout+stderr of `defenseclaw
// policy test`. Kept as a single blob because operators want to
// eyeball the whole report (pass/fail counts + individual failures)
// rather than paginate it.
type RegoTestResultMsg struct {
	Output string
	Err    error
}

// NewPolicyPanel creates a PolicyPanel.
func NewPolicyPanel(theme *Theme, cfg *config.Config) PolicyPanel {
	return PolicyPanel{
		theme:      theme,
		cfg:        cfg,
		judgeYAMLs: make(map[string]*guardrail.JudgeYAML),
		policyForm: NewPolicyCreateForm(),
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

// TakeCmd drains a pending tea.Cmd queued by HandleKey. Returns nil
// when no async command was requested. Callers should invoke this
// after HandleKey to pick up jobs that run inside the TUI (vs. via
// the CommandExecutor / Activity panel).
func (p *PolicyPanel) TakeCmd() tea.Cmd {
	cmd := p.pendingCmd
	p.pendingCmd = nil
	return cmd
}

// IsOverlayActive reports whether the panel is in a state where it
// must exclusively own keyboard/mouse input. The outer key router in
// app.go consults this so shortcuts like digit-panel-switch or the
// global palette binding can't fire out from under a read-only YAML
// viewer or an in-panel form. Keeping this one predicate avoids the
// per-overlay check lists we had before (and the associated "oh we
// forgot to guard the new one" bugs).
func (p *PolicyPanel) IsOverlayActive() bool {
	return p.policyDetailOpen || p.ruleDetailOpen || p.policyForm.IsActive()
}

// HandleKey processes keyboard input for the policy panel.
func (p *PolicyPanel) HandleKey(key string) (runBin string, runArgs []string, runName string) {
	if !p.loaded {
		p.load()
	}

	// The create-form overlay owns the keyboard while open. If we
	// routed tab/right through here we'd lose field navigation
	// inside the form — check before the tab/right fallthrough.
	if p.policyForm.IsActive() {
		submit, bin, args, name := p.policyForm.HandleKey(key)
		if submit {
			p.policyForm.Close()
			return bin, args, name
		}
		return
	}

	// B3a / B3b: if a read-only YAML overlay is open, let it absorb
	// esc / enter / q to close. Anything else on an overlay is a
	// no-op so typing 'tab' while reading a policy doesn't silently
	// flip tabs underneath it.
	if p.policyDetailOpen {
		switch key {
		case "esc", "enter", "q":
			p.policyDetailOpen = false
			p.policyDetailYAML = ""
			p.policyDetailName = ""
			p.policyDetailScroll = 0
		case "up", "k":
			if p.policyDetailScroll > 0 {
				p.policyDetailScroll--
			}
		case "down", "j":
			p.policyDetailScroll++
		case "pgup":
			p.policyDetailScroll -= 10
			if p.policyDetailScroll < 0 {
				p.policyDetailScroll = 0
			}
		case "pgdown":
			p.policyDetailScroll += 10
		case "home", "g":
			p.policyDetailScroll = 0
		case "end", "G":
			// Render clamps on draw; use a large sentinel and rely
			// on renderPolicyDetailOverlay to pin to EOF.
			p.policyDetailScroll = 1 << 30
		}
		return
	}
	if p.ruleDetailOpen {
		switch key {
		case "esc", "enter", "q":
			p.ruleDetailOpen = false
			p.ruleDetailYAML = ""
			p.ruleDetailPath = ""
			p.ruleDetailScroll = 0
		case "up", "k":
			if p.ruleDetailScroll > 0 {
				p.ruleDetailScroll--
			}
		case "down", "j":
			p.ruleDetailScroll++
		case "pgup":
			p.ruleDetailScroll -= 10
			if p.ruleDetailScroll < 0 {
				p.ruleDetailScroll = 0
			}
		case "pgdown":
			p.ruleDetailScroll += 10
		case "home", "g":
			p.ruleDetailScroll = 0
		case "end", "G":
			p.ruleDetailScroll = 1 << 30
		case "e":
			// Launch $EDITOR on the file that backs this rule.
			// We edit the whole file (not just the single rule)
			// because rules are grouped per-category in one YAML
			// and the guardrail loader re-reads the file wholesale.
			// Trying to splice a single rule back in would need a
			// structured patcher we don't have yet; opening the
			// file directly is honest about what's being edited.
			if p.ruleDetailPath != "" {
				p.pendingCmd = launchEditorCmd(p.ruleDetailPath)
			}
		}
		return
	}

	// B3c: on the Suppressions tab we want `tab` to cycle the inner
	// sections (pre-judge → finding → tool), not the outer
	// sub-tabs. Gate the outer tab handler so
	// handleSuppressionsKey's `tab` branch is reachable. Outer
	// navigation is still accessible via ]/[ (bracket keys), which
	// we add below for every sub-tab as an alias so the habit is
	// consistent.
	switch key {
	case "]":
		p.activeTab = (p.activeTab + 1) % policyTabCount
		p.resetCursors()
		return
	case "[":
		p.activeTab = (p.activeTab + policyTabCount - 1) % policyTabCount
		p.resetCursors()
		return
	case "tab", "right":
		if p.activeTab != policyTabSuppressions {
			p.activeTab = (p.activeTab + 1) % policyTabCount
			p.resetCursors()
			return
		}
	case "shift+tab", "left":
		if p.activeTab != policyTabSuppressions {
			p.activeTab = (p.activeTab + policyTabCount - 1) % policyTabCount
			p.resetCursors()
			return
		}
	}

	switch p.activeTab {
	case policyTabPolicies:
		return p.handlePoliciesKey(key)
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
	case policyTabPolicies:
		p.policyScroll += delta
		if p.policyScroll < 0 {
			p.policyScroll = 0
		}
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
// Policies sub-tab — admission-gate YAML policies
// ----------------------------------------------------------------

// loadPolicies populates p.policies / p.activePolicy by reading the
// on-disk policies directory. Kept cheap (filesystem-only, no YAML
// parse) so we can call it on every tab activation without a
// noticeable delay — the admission policy list is typically <10
// entries.
func (p *PolicyPanel) loadPolicies() {
	p.policiesLoaded = true
	p.policies = nil
	p.activePolicy = ""
	if p.cfg == nil || p.cfg.PolicyDir == "" {
		return
	}

	entries, err := os.ReadDir(p.cfg.PolicyDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		base := strings.TrimSuffix(strings.TrimSuffix(name, ".yaml"), ".yml")
		if base == "active" {
			// `active.yaml` is a symlink / copy marker written by
			// `policy activate`, not a selectable policy. Skip it
			// from the list but keep a record so we can highlight
			// the active entry.
			if target, err := os.Readlink(filepath.Join(p.cfg.PolicyDir, name)); err == nil {
				p.activePolicy = strings.TrimSuffix(strings.TrimSuffix(filepath.Base(target), ".yaml"), ".yml")
			}
			continue
		}
		p.policies = append(p.policies, base)
	}
	sort.Strings(p.policies)

	// Clamp cursor — lists can shrink if a policy was just deleted
	// from the CLI while the TUI was open.
	if p.policyCursor >= len(p.policies) {
		if len(p.policies) == 0 {
			p.policyCursor = 0
		} else {
			p.policyCursor = len(p.policies) - 1
		}
	}
}

// selectedPolicyName returns the policy name under the cursor, or
// "" if the list is empty.
func (p *PolicyPanel) selectedPolicyName() string {
	if p.policyCursor < 0 || p.policyCursor >= len(p.policies) {
		return ""
	}
	return p.policies[p.policyCursor]
}

// openPolicyDetail loads a policy's YAML directly from disk and
// prepares the read-only overlay. Intentionally bypasses the CLI
// because `policy show` is just a pretty-printer over the same file
// — staying local removes a subprocess per click and lets the
// operator keep filter/cursor state on the tab.
func (p *PolicyPanel) openPolicyDetail(name string) {
	if p.cfg == nil || p.cfg.PolicyDir == "" {
		return
	}
	candidates := []string{
		filepath.Join(p.cfg.PolicyDir, name+".yaml"),
		filepath.Join(p.cfg.PolicyDir, name+".yml"),
	}
	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		p.policyDetailOpen = true
		p.policyDetailYAML = string(data)
		p.policyDetailName = name
		p.policyDetailScroll = 0
		return
	}
	// Couldn't find a readable YAML — surface the miss in the
	// overlay itself so the operator isn't left staring at an
	// unresponsive key press.
	p.policyDetailOpen = true
	p.policyDetailName = name
	p.policyDetailYAML = fmt.Sprintf("(policy %q not found in %s)", name, p.cfg.PolicyDir)
	p.policyDetailScroll = 0
}

// handlePoliciesKey dispatches admission-policy verbs. Everything
// that mutates state routes through the CLI for audit-event parity
// (same rationale as skills/mcps). Only list navigation and the
// create-form overlay are handled locally.
func (p *PolicyPanel) handlePoliciesKey(key string) (string, []string, string) {
	if !p.policiesLoaded {
		p.loadPolicies()
	}

	switch key {
	case "up", "k":
		if p.policyCursor > 0 {
			p.policyCursor--
		}
	case "down", "j":
		if p.policyCursor < len(p.policies)-1 {
			p.policyCursor++
		}
	case "r":
		// Refresh the list from disk. Intentionally a local action
		// rather than a CLI dispatch — `policy list` is a
		// read-only verb and would just print to the activity
		// panel while we'd still need to re-scan locally anyway.
		p.loadPolicies()
	case "l":
		// `policy list` in the activity panel is useful for the
		// operator who wants the nicely-formatted table + active
		// marker. Separate from 'r' (which refreshes our view).
		return "defenseclaw", []string{"policy", "list"}, "policy list"
	case "s", "enter":
		// B3a: open the policy YAML in an in-panel overlay. Reading
		// the file locally keeps the operator on the Policies tab
		// instead of bouncing to Activity — the CLI `policy show`
		// just pretty-prints the same YAML we can read directly.
		// Enter triggers the overlay as well; activation now
		// happens via 'a' (see below) to remove the ambiguity of
		// "enter sometimes opens, sometimes activates".
		if name := p.selectedPolicyName(); name != "" {
			p.openPolicyDetail(name)
		}
	case "a":
		if name := p.selectedPolicyName(); name != "" {
			return "defenseclaw", []string{"policy", "activate", name}, "policy activate " + name
		}
	case "d":
		if name := p.selectedPolicyName(); name != "" {
			return "defenseclaw", []string{"policy", "delete", name}, "policy delete " + name
		}
	case "v":
		return "defenseclaw", []string{"policy", "validate"}, "policy validate"
	case "n", "+":
		p.policyForm.Open()
	}
	return "", nil, ""
}

// viewPolicies renders the admission-policy list. The create-form
// overlay, when active, replaces the list entirely so it gets the
// full available height for its 7 rows + status line.
func (p *PolicyPanel) viewPolicies(w, h int) string {
	if p.policyForm.IsActive() {
		p.policyForm.SetSize(w, h)
		return p.policyForm.View()
	}
	if p.policyDetailOpen {
		return p.renderPolicyDetailOverlay(w, h)
	}
	if !p.policiesLoaded {
		p.loadPolicies()
	}

	var b strings.Builder
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	bold := lipgloss.NewStyle().Bold(true)
	active := lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Bold(true)
	cursor := lipgloss.NewStyle().Background(lipgloss.Color("237"))

	b.WriteString(bold.Render("Admission Policies"))
	b.WriteString("\n")
	b.WriteString(dim.Render(fmt.Sprintf("  %d polic", len(p.policies))))
	if len(p.policies) == 1 {
		b.WriteString(dim.Render("y"))
	} else {
		b.WriteString(dim.Render("ies"))
	}
	if p.activePolicy != "" {
		b.WriteString(dim.Render("  ·  active: "))
		b.WriteString(active.Render(p.activePolicy))
	}
	b.WriteString("\n\n")

	if len(p.policies) == 0 {
		b.WriteString(dim.Render("  (no policies yet — press 'n' to create one)"))
		return b.String()
	}

	// We render a simple "name  [ACTIVE]" list. The scroll window is
	// sized to the content region; we don't page because 10 policies
	// almost never won't fit.
	start := p.policyScroll
	if start < 0 {
		start = 0
	}
	maxRows := h - 5
	if maxRows < 3 {
		maxRows = 3
	}
	end := start + maxRows
	if end > len(p.policies) {
		end = len(p.policies)
	}

	for i := start; i < end; i++ {
		name := p.policies[i]
		line := "  " + name
		if name == p.activePolicy {
			line += "  " + active.Render("[active]")
		}
		if i == p.policyCursor {
			line = cursor.Render(line)
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
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
		case "enter":
			// B3b: drill into the highlighted rule. The overlay
			// itself offers an 'e' key that delegates to the
			// editor path below, so users can preview first or
			// skip straight to editing.
			p.openRuleDetail()
		case "e":
			// Shortcut: edit the highlighted rule's file without
			// first opening the viewer overlay. Uses the same
			// flat-index logic as openRuleDetail so ruleCursor
			// maps consistently whether the user drills in or not.
			if path := p.ruleFilePathAtCursor(); path != "" {
				p.pendingCmd = launchEditorCmd(path)
			}
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
		// B3c: cycle *within* the suppressions tab so
		// pre-judge → finding → tool → pre-judge feels like a
		// toggle. The outer panel gates the global tab handler
		// exactly so this branch is reachable.
		p.suppSection = (p.suppSection + 1) % (maxSection + 1)
		p.suppCursor = 0
		p.suppScroll = 0
	case "shift+tab":
		p.suppSection = (p.suppSection + maxSection) % (maxSection + 1)
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
	case "enter", "e":
		// B3c: editing individual suppression rows inline would
		// require a multi-field form for each section (pre-judge
		// has strips; finding has id+reason; tool has pattern+
		// reason+severity). Until that lands, launch $EDITOR on
		// suppressions.yaml so operators aren't blocked on
		// changing anything at all. loadSuppressions() re-reads
		// the file when the tab is revisited.
		if p.cfg != nil && p.cfg.Guardrail.RulePackDir != "" {
			path := filepath.Join(p.cfg.Guardrail.RulePackDir, "suppressions.yaml")
			p.pendingCmd = launchEditorCmd(path)
		}
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
	case "T":
		// Capital-T runs the rego test suite (`policy test`). We
		// capture stdout+stderr into regoOutput via a pendingCmd
		// instead of dispatching through the Activity panel — the
		// operator is already reading a policy on this tab, so
		// flipping the active view would be jarring. Matching
		// casing here because lowercase t already toggles
		// show-tests and we don't want to reshuffle muscle memory.
		p.regoOutput = "running `defenseclaw policy test` …"
		p.pendingCmd = runPolicyTestCmd()
	case "E":
		// B3d: launch $EDITOR on the highlighted rego file. We do
		// this via a pending tea.ExecProcess so bubbletea can
		// release the terminal cleanly; saving and quitting the
		// editor returns control to the TUI. No-op when there's
		// no selected file so we don't spawn an editor on an
		// empty buffer.
		if p.regoCursor >= 0 && p.regoCursor < len(p.regoFiles) {
			path := p.regoFiles[p.regoCursor]
			p.pendingCmd = launchEditorCmd(path)
		}
	}
	return "", nil, ""
}

// runPolicyTestCmd returns a tea.Cmd that shells out to
// `defenseclaw policy test` and wraps the combined output in a
// RegoTestResultMsg. Runs with a bounded context so a hung test
// binary can't freeze the UI.
func runPolicyTestCmd() tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, resolveDefenseclawBin(), "policy", "test")
		out, err := cmd.CombinedOutput()
		return RegoTestResultMsg{Output: string(out), Err: err}
	}
}

// launchEditorCmd returns a tea.Cmd that pauses bubbletea, opens
// $EDITOR on path, and resumes. Falls back to `vi` so we always
// have something to launch.
func launchEditorCmd(path string) tea.Cmd {
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vi"
	}
	c := exec.Command(editor, path)
	return tea.ExecProcess(c, func(err error) tea.Msg {
		return EditorClosedMsg{Path: path, Err: err}
	})
}

// EditorClosedMsg is dispatched after the external editor exits so
// the OPA tab can reload the rego source from disk.
type EditorClosedMsg struct {
	Path string
	Err  error
}

// ApplyRegoTestResult stores the output of `defenseclaw policy test`
// in the side panel. Exposed as a method so app.go can wire the
// RegoTestResultMsg without touching unexported fields.
func (p *PolicyPanel) ApplyRegoTestResult(out string, err error) {
	if err != nil && out == "" {
		p.regoOutput = "policy test failed: " + err.Error()
		return
	}
	p.regoOutput = strings.TrimRight(out, "\n")
}

// ReloadRegoSource re-reads the highlighted file from disk after an
// external editor session so edits are visible immediately.
func (p *PolicyPanel) ReloadRegoSource() {
	p.loadRegoSource()
}

// ReloadFromDisk re-runs the full policy-panel load sequence. Used
// after an external editor session on a non-rego file (e.g.,
// suppressions.yaml) where we don't know which caches need
// invalidating, so just reload everything. The cost is cheap —
// guardrail.LoadRulePack is a handful of YAML unmarshals.
func (p *PolicyPanel) ReloadFromDisk() {
	p.load()
	// If an overlay is open it's showing stale YAML now; re-render
	// against the freshly-loaded rule files so the operator sees
	// their edits. If the edited file removed the rule under the
	// cursor we clamp and skip, rather than error-out mid-view.
	if p.ruleDetailOpen {
		if p.ruleFilePathAtCursor() == "" {
			p.ruleDetailOpen = false
			p.ruleDetailYAML = ""
			p.ruleDetailPath = ""
			return
		}
		p.openRuleDetail()
	}
}

// openRuleDetail serializes the highlighted rule back to YAML for
// the detail overlay. We marshal a single-rule RulesFileYAML so the
// output is self-describing (category + version header) and
// copy-pasteable into a real rule file.
// ruleFilePathAtCursor returns the backing file of the rule under
// ruleCursor, flattening the (file → rules) layout the same way
// openRuleDetail does so the two paths always agree on which rule
// the cursor is "on".
func (p *PolicyPanel) ruleFilePathAtCursor() string {
	idx := 0
	for _, rf := range p.packRules {
		for range rf.Rules {
			if idx == p.ruleCursor {
				return rf.SourcePath
			}
			idx++
		}
	}
	return ""
}

func (p *PolicyPanel) openRuleDetail() {
	type flatRule struct {
		Category   string
		SourcePath string
		Rule       guardrail.RuleDefYAML
	}
	var rules []flatRule
	for _, rf := range p.packRules {
		for _, r := range rf.Rules {
			rules = append(rules, flatRule{
				Category:   rf.Category,
				SourcePath: rf.SourcePath,
				Rule:       r,
			})
		}
	}
	if p.ruleCursor < 0 || p.ruleCursor >= len(rules) {
		return
	}
	selected := rules[p.ruleCursor]
	p.ruleDetailPath = selected.SourcePath
	wrapper := guardrail.RulesFileYAML{
		Version:  1,
		Category: selected.Category,
		Rules:    []guardrail.RuleDefYAML{selected.Rule},
	}
	out, err := yaml.Marshal(&wrapper)
	if err != nil {
		p.ruleDetailOpen = true
		p.ruleDetailYAML = "(failed to marshal rule: " + err.Error() + ")"
		p.ruleDetailScroll = 0
		return
	}
	p.ruleDetailOpen = true
	p.ruleDetailYAML = string(out)
	p.ruleDetailScroll = 0
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
	case policyTabPolicies:
		b.WriteString(p.viewPolicies(w, contentH))
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
	case policyTabPolicies:
		if p.policyForm.IsActive() {
			return "tab/↓ next  shift+tab/↑ prev  enter submit  esc cancel"
		}
		if p.policyDetailOpen {
			return "↑/↓ scroll · pgup/pgdn page · g/G jump · esc/enter/q close"
		}
		return "↑/↓ nav · s/enter show · a activate · n create · d delete · l list · v validate · r refresh · ]/[ tab"
	case policyTabRulePacks:
		if p.ruleDetailOpen {
			if p.ruleDetailPath != "" {
				return "↑/↓ scroll · pgup/pgdn · g/G · e edit file · esc/enter/q close"
			}
			return "↑/↓ scroll · pgup/pgdn · g/G · esc/enter/q close (embedded default)"
		}
		if p.packDetail {
			return "↑/↓ browse rules · enter view · e edit file · esc back"
		}
		return "↑/↓ select pack  enter activate/browse  ]/[ next section"
	case policyTabJudge:
		return "↑/↓ select judge  ]/[ next section"
	case policyTabSuppressions:
		return "↑/↓ select · tab/shift+tab section · enter/e edit · d delete · ]/[ outer tab"
	case policyTabOPA:
		return "↑/↓ select · v validate · r reload · t toggle tests · T run tests · E edit"
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
	if p.ruleDetailOpen {
		return p.renderRuleDetailOverlay(w, h)
	}
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	bold := lipgloss.NewStyle().Bold(true)

	var b strings.Builder
	b.WriteString(bold.Render("RULES — "+p.activePack) + "  " + dim.Render("(enter: view · esc: back)") + "\n\n")

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

// clampYAMLBody prepares a read-only YAML body for rendering inside
// a fixed viewport: splits into lines, clamps *scroll to stay within
// the document, truncates each visible line to the column budget,
// and returns both the joined text and the scroll window so the
// caller can render an "N/M" footer. Extracted so the policy and
// rule overlays agree on behavior — the review caught them both
// overflowing on long sensitive-paths files.
func clampYAMLBody(yaml string, w, bodyRows int, scroll *int) (rendered string, first, last, total int) {
	lines := strings.Split(yaml, "\n")
	total = len(lines)
	if bodyRows < 1 {
		bodyRows = 1
	}
	if w < 8 {
		w = 8
	}

	// Clamp scroll: allow leaving the last page visible, never past EOF.
	maxScroll := total - bodyRows
	if maxScroll < 0 {
		maxScroll = 0
	}
	if scroll != nil {
		if *scroll > maxScroll {
			*scroll = maxScroll
		}
		if *scroll < 0 {
			*scroll = 0
		}
	}
	start := 0
	if scroll != nil {
		start = *scroll
	}
	end := start + bodyRows
	if end > total {
		end = total
	}

	var b strings.Builder
	for i := start; i < end; i++ {
		line := lines[i]
		// Plain byte truncation — YAML bodies are ASCII-dominant
		// and the terminals we target render the occasional
		// multibyte code point wider than its rune count anyway.
		// Matches viewRuleDetail's existing truncation approach.
		if len(line) > w {
			line = line[:w]
		}
		b.WriteString(line)
		if i < end-1 {
			b.WriteString("\n")
		}
	}
	first = start + 1
	last = end
	if total == 0 {
		first = 0
	}
	return b.String(), first, last, total
}

// renderPolicyDetailOverlay draws the read-only YAML viewer for the
// Policies tab. The header tells the operator this is a modal-like
// overlay (hence the esc/enter hint). The body is hard-clamped to
// the available (w, h): long sensitive-paths files used to overflow
// the panel and spill into neighbouring chrome; we now paginate in
// place with j/k/pgup/pgdown/home/end and show an N/M footer so the
// operator knows when there's more to scroll. We intentionally
// don't colorize the YAML body because the bundled terminals vary
// wildly on 256-color support and mis-rendered YAML is worse than
// plain text.
func (p *PolicyPanel) renderPolicyDetailOverlay(w, h int) string {
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	bold := lipgloss.NewStyle().Bold(true)

	header := bold.Render("POLICY — "+p.policyDetailName) +
		"  " + dim.Render("(↑/↓ scroll · esc/enter/q: close)")

	// Reserve two rows: one blank separator after the header and
	// one footer line. The rest is body.
	bodyRows := h - 3
	if bodyRows < 1 {
		bodyRows = 1
	}
	body, first, last, total := clampYAMLBody(p.policyDetailYAML, w, bodyRows, &p.policyDetailScroll)

	footer := dim.Render(fmt.Sprintf("lines %d-%d / %d", first, last, total))
	return header + "\n\n" + body + "\n" + footer
}

// renderRuleDetailOverlay draws the read-only YAML for a single rule
// inside the active pack. Mirrors renderPolicyDetailOverlay so the
// two feel like the same control — muscle memory matters here.
func (p *PolicyPanel) renderRuleDetailOverlay(w, h int) string {
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	bold := lipgloss.NewStyle().Bold(true)

	hint := "(↑/↓ scroll · e: edit file · esc/enter/q: close)"
	if p.ruleDetailPath == "" {
		// No source path means the rule was synthesised (embedded
		// default) and can't be edited in place — don't advertise
		// an edit key that will silently do nothing.
		hint = "(↑/↓ scroll · esc/enter/q: close · embedded default, not editable)"
	}
	header := bold.Render("RULE") + "  " + dim.Render(hint)

	// Reserve rows for header (2), optional file line (1-2), and footer (1-2).
	reserved := 4
	if p.ruleDetailPath != "" {
		reserved += 2
	}
	bodyRows := h - reserved
	if bodyRows < 1 {
		bodyRows = 1
	}
	body, first, last, total := clampYAMLBody(p.ruleDetailYAML, w, bodyRows, &p.ruleDetailScroll)

	footer := dim.Render(fmt.Sprintf("lines %d-%d / %d", first, last, total))
	fileLine := ""
	if p.ruleDetailPath != "" {
		fileLine = "\n\n" + dim.Render("file: "+p.ruleDetailPath)
	}
	return header + "\n\n" + body + "\n" + footer + fileLine
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
	case policyTabPolicies:
		// The create form swallows mouse interactions — text entry
		// panes don't expose hit-testable regions and clicking
		// elsewhere would feel like a dead click.
		if p.policyForm.IsActive() {
			return
		}
		// List rows start at line 4 after header + count + blank.
		if contentY >= 4 {
			idx := contentY - 4 + p.policyScroll
			if idx >= 0 && idx < len(p.policies) {
				p.policyCursor = idx
			}
		}

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
