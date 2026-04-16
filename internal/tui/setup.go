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
	"time"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

const (
	setupModeWizards = iota
	setupModeConfig
)

const (
	wizardSkillScanner = iota
	wizardMCPScanner
	wizardGateway
	wizardGuardrail
	wizardSplunk
	wizardSandbox
	wizardCount
)

var wizardNames = [wizardCount]string{
	"Skill Scanner", "MCP Scanner", "Gateway",
	"Guardrail", "Splunk", "Sandbox",
}

var wizardCommands = [wizardCount][]string{
	{"setup", "skill-scanner"},
	{"setup", "mcp-scanner"},
	{"setup", "gateway"},
	{"setup", "guardrail"},
	{"setup", "splunk"},
	{"sandbox", "setup"},
}

var wizardDescriptions = [wizardCount]string{
	"Configure skill scanner analyzers (manifest, permissions, LLM, AI Defense, behavioral, trigger, VirusTotal).",
	"Configure MCP scanner analyzers and which components to scan (prompts, resources, instructions).",
	"Configure gateway connection settings (host, port, TLS, auto-approve, reconnect parameters).",
	"Configure LLM guardrail proxy (mode, model, scanner mode, judge settings).",
	"Configure Splunk HEC integration for SIEM (endpoint, token, index, source).",
	"Initialize and configure sandbox environment (OpenShell policy, networking).",
}

type configSection struct {
	Name   string
	Fields []configField
}

type configField struct {
	Label    string
	Key      string
	Kind     string // "string", "int", "bool", "password", "choice", "header"
	Value    string
	Original string
	Options  []string // valid choices for "choice" kind
}

// wizardFormField defines a single field in a wizard setup form.
type wizardFormField struct {
	Label   string
	Flag    string   // CLI flag (e.g., "--use-llm")
	NoFlag  string   // negation flag for bool toggles (e.g., "--no-verify")
	Kind    string   // "bool", "string", "choice", "int", "section" (divider)
	Value   string   // current value set by user
	Default string   // pre-filled default
	Options []string // valid choices for "choice" kind
	Hint    string   // help text shown when selected
}

// SetupPanel provides the Setup Wizards + Config Editor panel.
type SetupPanel struct {
	theme    *Theme
	cfg      *config.Config
	executor *CommandExecutor

	mode         int // setupModeWizards or setupModeConfig
	activeWizard int
	wizardStatus [wizardCount]string
	wizardHover  int // -1 = none hovered

	// Wizard form (collects input before running --non-interactive)
	wizFormActive  bool
	wizFormFields  []wizardFormField
	wizFormCursor  int
	wizFormEditing bool
	wizFormScroll  int

	// Wizard output terminal (shows command output after form submission)
	wizRunning bool
	wizRunIdx  int // which wizard is running
	wizOutput  []string
	wizScroll  int // lines from bottom (0 = pinned)

	// Config editor
	sections      []configSection
	activeSection int
	activeLine    int
	editing       bool
	editInput     textinput.Model
	scroll        int
	lastSaved     time.Time
	configHover   int // hovered field index, -1 = none

	pendingFocusCmd tea.Cmd

	width  int
	height int
}

// NewSetupPanel creates the setup and config panel.
func NewSetupPanel(theme *Theme, cfg *config.Config, executor *CommandExecutor) SetupPanel {
	ei := textinput.New()
	ei.Placeholder = ""
	ei.Prompt = ""
	ei.CharLimit = 512
	ei.SetWidth(40)

	p := SetupPanel{
		theme:       theme,
		cfg:         cfg,
		executor:    executor,
		editInput:   ei,
		wizardHover: -1,
		configHover: -1,
		wizRunIdx:   -1,
	}
	p.loadSections()
	return p
}

// SetSize updates the panel dimensions.
func (p *SetupPanel) SetSize(w, h int) {
	p.width = w
	p.height = h
	p.editInput.SetWidth(w/2 - 4)
}

func (p *SetupPanel) loadSections() {
	if p.cfg == nil {
		return
	}
	c := p.cfg
	p.sections = []configSection{
		{Name: "General", Fields: []configField{
			{Label: "Data Dir", Key: "data_dir", Kind: "string", Value: c.DataDir},
			{Label: "Audit DB", Key: "audit_db", Kind: "string", Value: c.AuditDB},
			{Label: "Quarantine Dir", Key: "quarantine_dir", Kind: "string", Value: c.QuarantineDir},
			{Label: "Plugin Dir", Key: "plugin_dir", Kind: "string", Value: c.PluginDir},
			{Label: "Policy Dir", Key: "policy_dir", Kind: "string", Value: c.PolicyDir},
			{Label: "Environment", Key: "environment", Kind: "string", Value: c.Environment},
			{Label: "── Shared LLM ──", Kind: "header"},
			{Label: "Default LLM API Key Env", Key: "default_llm_api_key_env", Kind: "password", Value: c.DefaultLLMAPIKeyEnv},
			{Label: "Default LLM Model", Key: "default_llm_model", Kind: "string", Value: c.DefaultLLMModel},
		}},
		{Name: "Claw", Fields: []configField{
			{Label: "Mode", Key: "claw.mode", Kind: "string", Value: string(c.Claw.Mode)},
			{Label: "Home Dir", Key: "claw.home_dir", Kind: "string", Value: c.Claw.HomeDir},
			{Label: "Config File", Key: "claw.config_file", Kind: "string", Value: c.Claw.ConfigFile},
		}},
		{Name: "Gateway", Fields: []configField{
			{Label: "Host", Key: "gateway.host", Kind: "string", Value: c.Gateway.Host},
			{Label: "Port", Key: "gateway.port", Kind: "int", Value: fmt.Sprintf("%d", c.Gateway.Port)},
			{Label: "API Port", Key: "gateway.api_port", Kind: "int", Value: fmt.Sprintf("%d", c.Gateway.APIPort)},
			{Label: "API Bind", Key: "gateway.api_bind", Kind: "string", Value: c.Gateway.APIBind},
			{Label: "Auto Approve Safe", Key: "gateway.auto_approve_safe", Kind: "bool", Value: fmt.Sprintf("%v", c.Gateway.AutoApprove)},
			{Label: "TLS", Key: "gateway.tls", Kind: "bool", Value: fmt.Sprintf("%v", c.Gateway.TLS)},
			{Label: "Reconnect MS", Key: "gateway.reconnect_ms", Kind: "int", Value: fmt.Sprintf("%d", c.Gateway.ReconnectMs)},
			{Label: "Max Reconnect MS", Key: "gateway.max_reconnect_ms", Kind: "int", Value: fmt.Sprintf("%d", c.Gateway.MaxReconnectMs)},
			{Label: "Token Env", Key: "gateway.token_env", Kind: "password", Value: c.Gateway.TokenEnv},
		}},
		{Name: "Guardrail", Fields: []configField{
			// Core
			{Label: "── Core ──", Kind: "header"},
			{Label: "Enabled", Key: "guardrail.enabled", Kind: "bool", Value: fmt.Sprintf("%v", c.Guardrail.Enabled)},
			{Label: "Mode", Key: "guardrail.mode", Kind: "choice", Value: c.Guardrail.Mode, Options: []string{"observe", "action"}},
			{Label: "Scanner Mode", Key: "guardrail.scanner_mode", Kind: "choice", Value: c.Guardrail.ScannerMode, Options: []string{"local", "remote", "both"}},
			{Label: "Port", Key: "guardrail.port", Kind: "int", Value: fmt.Sprintf("%d", c.Guardrail.Port)},
			{Label: "Model", Key: "guardrail.model", Kind: "string", Value: c.Guardrail.Model},
			{Label: "API Key Env", Key: "guardrail.api_key_env", Kind: "password", Value: c.Guardrail.APIKeyEnv},
			{Label: "Block Message", Key: "guardrail.block_message", Kind: "string", Value: c.Guardrail.BlockMessage},
			{Label: "Stream Buffer", Key: "guardrail.stream_buffer_bytes", Kind: "int", Value: fmt.Sprintf("%d", c.Guardrail.StreamBufferBytes)},
			// Detection
			{Label: "── Detection ──", Kind: "header"},
			{Label: "Strategy", Key: "guardrail.detection_strategy", Kind: "choice", Value: c.Guardrail.DetectionStrategy, Options: []string{"regex_only", "regex_judge", "judge_first"}},
			{Label: "Strategy (Prompt)", Key: "guardrail.detection_strategy_prompt", Kind: "choice", Value: c.Guardrail.DetectionStrategyPrompt, Options: []string{"", "regex_only", "regex_judge", "judge_first"}},
			{Label: "Strategy (Completion)", Key: "guardrail.detection_strategy_completion", Kind: "choice", Value: c.Guardrail.DetectionStrategyCompletion, Options: []string{"", "regex_only", "regex_judge", "judge_first"}},
			{Label: "Strategy (Tool Call)", Key: "guardrail.detection_strategy_tool_call", Kind: "choice", Value: c.Guardrail.DetectionStrategyToolCall, Options: []string{"", "regex_only", "regex_judge", "judge_first"}},
			{Label: "Rule Pack Dir", Key: "guardrail.rule_pack_dir", Kind: "string", Value: c.Guardrail.RulePackDir},
			{Label: "Judge Sweep", Key: "guardrail.judge_sweep", Kind: "bool", Value: fmt.Sprintf("%v", c.Guardrail.JudgeSweep)},
			// LLM Judge
			{Label: "── LLM Judge ──", Kind: "header"},
			{Label: "Judge Enabled", Key: "guardrail.judge.enabled", Kind: "bool", Value: fmt.Sprintf("%v", c.Guardrail.Judge.Enabled)},
			{Label: "Judge Model", Key: "guardrail.judge.model", Kind: "string", Value: c.Guardrail.Judge.Model},
			{Label: "Judge API Key Env", Key: "guardrail.judge.api_key_env", Kind: "password", Value: c.Guardrail.Judge.APIKeyEnv},
			{Label: "Judge API Base", Key: "guardrail.judge.api_base", Kind: "string", Value: c.Guardrail.Judge.APIBase},
			{Label: "Judge Timeout", Key: "guardrail.judge.timeout", Kind: "string", Value: fmt.Sprintf("%.1f", c.Guardrail.Judge.Timeout)},
			{Label: "Adjudication Timeout", Key: "guardrail.judge.adjudication_timeout", Kind: "string", Value: fmt.Sprintf("%.1f", c.Guardrail.Judge.AdjudicationTimeout)},
			{Label: "Fallbacks", Key: "guardrail.judge.fallbacks", Kind: "string", Value: strings.Join(c.Guardrail.Judge.Fallbacks, ",")},
			// Judge Categories
			{Label: "── Judge Categories ──", Kind: "header"},
			{Label: "Injection", Key: "guardrail.judge.injection", Kind: "bool", Value: fmt.Sprintf("%v", c.Guardrail.Judge.Injection)},
			{Label: "PII", Key: "guardrail.judge.pii", Kind: "bool", Value: fmt.Sprintf("%v", c.Guardrail.Judge.PII)},
			{Label: "PII (Prompt)", Key: "guardrail.judge.pii_prompt", Kind: "bool", Value: fmt.Sprintf("%v", c.Guardrail.Judge.PIIPrompt)},
			{Label: "PII (Completion)", Key: "guardrail.judge.pii_completion", Kind: "bool", Value: fmt.Sprintf("%v", c.Guardrail.Judge.PIICompletion)},
			{Label: "Tool Injection", Key: "guardrail.judge.tool_injection", Kind: "bool", Value: fmt.Sprintf("%v", c.Guardrail.Judge.ToolInjection)},
		}},
		{Name: "Scanners", Fields: []configField{
			{Label: "Skill Binary", Key: "scanners.skill_scanner.binary", Kind: "string", Value: c.Scanners.SkillScanner.Binary},
			{Label: "Use LLM", Key: "scanners.skill_scanner.use_llm", Kind: "bool", Value: fmt.Sprintf("%v", c.Scanners.SkillScanner.UseLLM)},
			{Label: "Use Behavioral", Key: "scanners.skill_scanner.use_behavioral", Kind: "bool", Value: fmt.Sprintf("%v", c.Scanners.SkillScanner.UseBehavioral)},
			{Label: "MCP Binary", Key: "scanners.mcp_scanner.binary", Kind: "string", Value: c.Scanners.MCPScanner.Binary},
			{Label: "MCP Analyzers", Key: "scanners.mcp_scanner.analyzers", Kind: "string", Value: c.Scanners.MCPScanner.Analyzers},
			{Label: "CodeGuard", Key: "scanners.codeguard", Kind: "string", Value: c.Scanners.CodeGuard},
		}},
		// Audit sinks live in their own list-based section editor (Phase
		// 3.3). The single-key-per-row form below cannot represent the
		// audit_sinks[] schema without losing per-sink kind/filter
		// metadata, so we surface a read-only summary here and direct
		// the operator to the dedicated editor.
		{Name: "Audit Sinks", Fields: auditSinkSummaryFields(c)},
		{Name: "OTel", Fields: []configField{
			{Label: "Enabled", Key: "otel.enabled", Kind: "bool", Value: fmt.Sprintf("%v", c.OTel.Enabled)},
			{Label: "Protocol", Key: "otel.protocol", Kind: "string", Value: c.OTel.Protocol},
			{Label: "Endpoint", Key: "otel.endpoint", Kind: "string", Value: c.OTel.Endpoint},
			{Label: "Traces Enabled", Key: "otel.traces.enabled", Kind: "bool", Value: fmt.Sprintf("%v", c.OTel.Traces.Enabled)},
			{Label: "Logs Enabled", Key: "otel.logs.enabled", Kind: "bool", Value: fmt.Sprintf("%v", c.OTel.Logs.Enabled)},
			{Label: "Metrics Enabled", Key: "otel.metrics.enabled", Kind: "bool", Value: fmt.Sprintf("%v", c.OTel.Metrics.Enabled)},
		}},
		{Name: "Watch", Fields: []configField{
			{Label: "Debounce MS", Key: "watch.debounce_ms", Kind: "int", Value: fmt.Sprintf("%d", c.Watch.DebounceMs)},
			{Label: "Auto Block", Key: "watch.auto_block", Kind: "bool", Value: fmt.Sprintf("%v", c.Watch.AutoBlock)},
			{Label: "Allow List Bypass", Key: "watch.allow_list_bypass_scan", Kind: "bool", Value: fmt.Sprintf("%v", c.Watch.AllowListBypassScan)},
			{Label: "Rescan Enabled", Key: "watch.rescan_enabled", Kind: "bool", Value: fmt.Sprintf("%v", c.Watch.RescanEnabled)},
			{Label: "Rescan Interval Min", Key: "watch.rescan_interval_min", Kind: "int", Value: fmt.Sprintf("%d", c.Watch.RescanIntervalMin)},
		}},
		{Name: "OpenShell", Fields: []configField{
			{Label: "Binary", Key: "openshell.binary", Kind: "string", Value: c.OpenShell.Binary},
			{Label: "Policy Dir", Key: "openshell.policy_dir", Kind: "string", Value: c.OpenShell.PolicyDir},
			{Label: "Mode", Key: "openshell.mode", Kind: "string", Value: c.OpenShell.Mode},
			{Label: "Version", Key: "openshell.version", Kind: "string", Value: c.OpenShell.Version},
		}},
	}
	for si := range p.sections {
		for fi := range p.sections[si].Fields {
			p.sections[si].Fields[fi].Original = p.sections[si].Fields[fi].Value
		}
	}
}

// IsWizardRunning returns true when a wizard command is executing.
func (p *SetupPanel) IsWizardRunning() bool {
	return p.wizRunning
}

// IsFormActive returns true when the wizard form is visible.
func (p *SetupPanel) IsFormActive() bool {
	return p.wizFormActive
}

// DrainFocusCmd returns and clears any pending focus command from textinput.Focus().
func (p *SetupPanel) DrainFocusCmd() tea.Cmd {
	cmd := p.pendingFocusCmd
	p.pendingFocusCmd = nil
	return cmd
}

// WizardAppendOutput adds a line from the running wizard process.
func (p *SetupPanel) WizardAppendOutput(line string) {
	p.wizOutput = append(p.wizOutput, line)
}

// WizardFinished marks the wizard as complete.
func (p *SetupPanel) WizardFinished(exitCode int) {
	p.wizRunning = false
	if p.wizRunIdx >= 0 && p.wizRunIdx < wizardCount {
		if exitCode == 0 {
			p.wizardStatus[p.wizRunIdx] = "Configured"
		} else {
			p.wizardStatus[p.wizRunIdx] = fmt.Sprintf("Failed (exit %d)", exitCode)
		}
	}
	p.wizOutput = append(p.wizOutput, "", fmt.Sprintf("-- Setup finished (exit %d). Press Esc to return. --", exitCode))
}

// HandleKey processes key events. Returns (runCmd, binary, args, displayName).
func (p *SetupPanel) HandleKey(msg tea.KeyPressMsg) (runCmd bool, binary string, args []string, displayName string) {
	key := msg.String()

	// Wizard form takes priority
	if p.wizFormActive {
		return p.handleFormKey(msg)
	}

	// Wizard output terminal (running or finished)
	if p.wizRunning {
		return p.handleWizardOutputKey(key)
	}

	// Wizard finished but still viewing output
	if len(p.wizOutput) > 0 {
		if key == "esc" || key == "q" {
			p.wizOutput = nil
			p.wizScroll = 0
			p.wizRunIdx = -1
			return false, "", nil, ""
		}
		if key == "up" || key == "k" {
			p.wizScroll++
		}
		if key == "down" || key == "j" {
			if p.wizScroll > 0 {
				p.wizScroll--
			}
		}
		return false, "", nil, ""
	}

	if p.mode == setupModeWizards {
		return p.handleWizardKey(key)
	}
	return p.handleConfigKey(msg)
}

func (p *SetupPanel) handleWizardOutputKey(key string) (bool, string, []string, string) {
	switch key {
	case "ctrl+c":
		p.executor.Cancel()
	case "up", "k":
		p.wizScroll++
	case "down", "j":
		if p.wizScroll > 0 {
			p.wizScroll--
		}
	}
	return false, "", nil, ""
}

func (p *SetupPanel) handleWizardKey(key string) (bool, string, []string, string) {
	switch key {
	case "`":
		p.mode = setupModeConfig
	case "up", "k":
		if p.activeWizard > 0 {
			p.activeWizard--
		}
	case "down", "j":
		if p.activeWizard < wizardCount-1 {
			p.activeWizard++
		}
	case "left", "h":
		if p.activeWizard > 0 {
			p.activeWizard--
		}
	case "right", "l":
		if p.activeWizard < wizardCount-1 {
			p.activeWizard++
		}
	case "enter":
		p.showWizardForm(p.activeWizard)
	}
	return false, "", nil, ""
}

func (p *SetupPanel) showWizardForm(idx int) {
	if idx < 0 || idx >= wizardCount {
		return
	}
	p.wizFormActive = true
	p.wizFormFields = p.wizardFormDefs(idx)
	p.wizFormCursor = 0
	// Skip initial section divider so cursor starts on first real field
	for p.wizFormCursor < len(p.wizFormFields) && p.wizFormFields[p.wizFormCursor].Kind == "section" {
		p.wizFormCursor++
	}
	p.wizFormEditing = false
	p.wizFormScroll = 0
	p.wizRunIdx = idx
}

func (p *SetupPanel) handleFormKey(msg tea.KeyPressMsg) (bool, string, []string, string) {
	key := msg.String()

	if len(p.wizFormFields) == 0 || p.wizFormCursor < 0 || p.wizFormCursor >= len(p.wizFormFields) {
		return false, "", nil, ""
	}

	if p.wizFormEditing {
		switch key {
		case "enter":
			f := &p.wizFormFields[p.wizFormCursor]
			f.Value = p.editInput.Value()
			p.wizFormEditing = false
			p.editInput.Blur()
		case "esc":
			p.wizFormEditing = false
			p.editInput.Blur()
		default:
			p.editInput, _ = p.editInput.Update(msg)
		}
		return false, "", nil, ""
	}

	switch key {
	case "esc":
		p.wizFormActive = false
		p.wizFormFields = nil
		p.wizRunIdx = -1
	case "up", "k":
		if p.wizFormCursor > 0 {
			p.wizFormCursor--
			for p.wizFormCursor > 0 && p.wizFormFields[p.wizFormCursor].Kind == "section" {
				p.wizFormCursor--
			}
			if p.wizFormCursor < p.wizFormScroll {
				p.wizFormScroll = p.wizFormCursor
			}
		}
	case "down", "j":
		if p.wizFormCursor < len(p.wizFormFields)-1 {
			p.wizFormCursor++
			for p.wizFormCursor < len(p.wizFormFields)-1 && p.wizFormFields[p.wizFormCursor].Kind == "section" {
				p.wizFormCursor++
			}
			visibleLines := p.height - 8
			if visibleLines < 5 {
				visibleLines = 5
			}
			if p.wizFormCursor >= p.wizFormScroll+visibleLines {
				p.wizFormScroll = p.wizFormCursor - visibleLines + 1
			}
		}
	case "enter", " ":
		f := &p.wizFormFields[p.wizFormCursor]
		switch f.Kind {
		case "section":
			// no-op: section dividers are non-interactive
		case "bool":
			if f.Value == "yes" {
				f.Value = "no"
			} else {
				f.Value = "yes"
			}
		case "choice":
			if len(f.Options) > 0 {
				cur := 0
				for i, o := range f.Options {
					if o == f.Value {
						cur = i
						break
					}
				}
				f.Value = f.Options[(cur+1)%len(f.Options)]
			}
		default:
			p.wizFormEditing = true
			p.editInput.SetValue(f.Value)
			p.pendingFocusCmd = p.editInput.Focus()
			p.editInput.CursorEnd()
		}
	case "ctrl+r":
		return p.submitWizardForm()
	}
	return false, "", nil, ""
}

func (p *SetupPanel) submitWizardForm() (bool, string, []string, string) {
	idx := p.wizRunIdx
	if idx < 0 || idx >= wizardCount {
		return false, "", nil, ""
	}
	args := p.buildWizardArgs(idx)
	name := wizardNames[idx]

	p.wizFormActive = false
	p.wizFormFields = nil
	p.wizardStatus[idx] = "running..."
	p.wizRunning = true
	p.wizOutput = []string{fmt.Sprintf("-- Running %s Setup (non-interactive) --", name), ""}
	p.wizScroll = 0
	return true, "defenseclaw", args, "setup " + name
}

func (p *SetupPanel) buildWizardArgs(idx int) []string {
	base := make([]string, len(wizardCommands[idx]))
	copy(base, wizardCommands[idx])
	base = append(base, "--non-interactive")

	// For guardrail wizard, combine Provider + Model into --judge-model provider/model
	var judgeProvider, judgeModel string

	for _, f := range p.wizFormFields {
		if f.Kind == "section" {
			continue
		}
		// The Judge section uses "Provider" and "Model" labels (under "LLM Judge" section)
		if f.Label == "Provider" && f.Flag == "" {
			judgeProvider = f.Value
			continue
		}
		if f.Label == "Model" && f.Flag == "--judge-model" {
			judgeModel = f.Value
			continue
		}
		if f.Value == "" || f.Value == f.Default {
			continue
		}
		switch f.Kind {
		case "bool":
			if f.Value == "yes" && f.Flag != "" {
				base = append(base, f.Flag)
			} else if f.Value == "no" && f.NoFlag != "" {
				base = append(base, f.NoFlag)
			}
		case "string", "int", "choice":
			if f.Value != "" && f.Flag != "" {
				base = append(base, f.Flag, f.Value)
			}
		}
	}

	if judgeModel != "" {
		combined := judgeModel
		if judgeProvider != "" {
			combined = judgeProvider + "/" + judgeModel
		}
		base = append(base, "--judge-model", combined)
	}

	return base
}

func (p *SetupPanel) handleConfigKey(msg tea.KeyPressMsg) (bool, string, []string, string) {
	key := msg.String()

	if p.editing {
		switch key {
		case "enter":
			f := p.currentField()
			if f != nil {
				f.Value = p.editInput.Value()
			}
			p.editing = false
			p.editInput.Blur()
		case "esc":
			p.editing = false
			p.editInput.Blur()
		default:
			p.editInput, _ = p.editInput.Update(msg)
		}
		return false, "", nil, ""
	}

	switch key {
	case "`":
		p.mode = setupModeWizards
	case "left", "h":
		if p.activeSection > 0 {
			p.activeSection--
			p.activeLine = p.firstEditableLine()
			p.scroll = 0
		}
	case "right", "l":
		if p.activeSection < len(p.sections)-1 {
			p.activeSection++
			p.activeLine = p.firstEditableLine()
			p.scroll = 0
		}
	case "up", "k":
		if p.activeLine > 0 {
			p.activeLine--
			if sec := p.currentSection(); sec != nil {
				for p.activeLine > 0 && sec.Fields[p.activeLine].Kind == "header" {
					p.activeLine--
				}
			}
			if p.activeLine < p.scroll {
				p.scroll = p.activeLine
			}
		}
	case "down", "j":
		if p.activeSection < len(p.sections) {
			sec := p.sections[p.activeSection]
			if p.activeLine < len(sec.Fields)-1 {
				p.activeLine++
				for p.activeLine < len(sec.Fields)-1 && sec.Fields[p.activeLine].Kind == "header" {
					p.activeLine++
				}
				visibleLines := p.height - 8
				if visibleLines < 5 {
					visibleLines = 5
				}
				if p.activeLine >= p.scroll+visibleLines {
					p.scroll = p.activeLine - visibleLines + 1
				}
			}
		}
	case "enter":
		f := p.currentField()
		if f != nil {
			switch f.Kind {
			case "header":
				// non-interactive
			case "bool":
				if f.Value == "true" {
					f.Value = "false"
				} else {
					f.Value = "true"
				}
			case "choice":
				// Cycle through options
				if len(f.Options) > 0 {
					cur := 0
					for i, o := range f.Options {
						if o == f.Value {
							cur = i
							break
						}
					}
					f.Value = f.Options[(cur+1)%len(f.Options)]
				}
			default:
				p.editing = true
				p.editInput.SetValue(f.Value)
				p.pendingFocusCmd = p.editInput.Focus()
				p.editInput.CursorEnd()
			}
		}
	}
	return false, "", nil, ""
}

// firstEditableLine returns the index of the first non-header field in the
// currently active config section, or 0 if none found.
func (p *SetupPanel) firstEditableLine() int {
	if p.activeSection >= len(p.sections) {
		return 0
	}
	for i, f := range p.sections[p.activeSection].Fields {
		if f.Kind != "header" {
			return i
		}
	}
	return 0
}

func (p *SetupPanel) currentSection() *configSection {
	if p.activeSection >= len(p.sections) {
		return nil
	}
	return &p.sections[p.activeSection]
}

func (p *SetupPanel) currentField() *configField {
	if p.activeSection >= len(p.sections) {
		return nil
	}
	sec := &p.sections[p.activeSection]
	if p.activeLine >= len(sec.Fields) {
		return nil
	}
	return &sec.Fields[p.activeLine]
}

// bifrostProviders returns the list of LLM providers supported by the Bifrost SDK.
// guardrailWizardFields builds the guardrail wizard form with section dividers
// and pre-fills values from the current config.
func (p *SetupPanel) guardrailWizardFields() []wizardFormField {
	// Resolve current config values for pre-fill
	mode := "observe"
	scannerMode := "local"
	strategy := "regex_only"
	rulePack := "default"
	judgeProvider := "bedrock"
	judgeModel := ""
	judgeKeyEnv := ""
	judgeBase := ""
	port := ""
	blockMsg := ""
	ciscoEndpoint := ""
	ciscoKeyEnv := ""
	ciscoTimeout := ""

	if p.cfg != nil {
		g := &p.cfg.Guardrail
		if g.Mode != "" {
			mode = g.Mode
		}
		if g.ScannerMode != "" {
			scannerMode = g.ScannerMode
		}
		if g.DetectionStrategy != "" {
			strategy = g.DetectionStrategy
		}
		if g.Port > 0 {
			port = fmt.Sprintf("%d", g.Port)
		}
		blockMsg = g.BlockMessage

		// Resolve rule pack from dir path
		if g.RulePackDir != "" {
			parts := strings.Split(g.RulePackDir, "/")
			if len(parts) > 0 {
				last := parts[len(parts)-1]
				if last == "default" || last == "strict" || last == "permissive" {
					rulePack = last
				}
			}
		}

		// Judge pre-fill: extract provider from "provider/model"
		if g.Judge.Model != "" {
			if idx := strings.Index(g.Judge.Model, "/"); idx > 0 {
				judgeProvider = g.Judge.Model[:idx]
				judgeModel = g.Judge.Model[idx+1:]
			} else {
				judgeModel = g.Judge.Model
			}
		}
		judgeKeyEnv = g.Judge.APIKeyEnv
		judgeBase = g.Judge.APIBase

		cisco := &p.cfg.CiscoAIDefense
		ciscoEndpoint = cisco.Endpoint
		ciscoKeyEnv = cisco.APIKeyEnv
		if cisco.TimeoutMs > 0 {
			ciscoTimeout = fmt.Sprintf("%d", cisco.TimeoutMs)
		}
	}

	return []wizardFormField{
		// ─── Core ───
		{Label: "Core", Kind: "section"},
		{Label: "Mode", Flag: "--mode", Kind: "choice", Options: []string{"observe", "action"}, Value: mode, Default: "observe", Hint: "observe=log only, action=block threats"},
		{Label: "Scanner Mode", Flag: "--scanner-mode", Kind: "choice", Options: []string{"local", "remote", "both"}, Value: scannerMode, Default: "local", Hint: "local=regex+judge, remote=Cisco AI Defense, both=all"},
		{Label: "Proxy Port", Flag: "--port", Kind: "int", Value: port, Hint: "Guardrail proxy listen port"},
		{Label: "Block Message", Flag: "--block-message", Kind: "string", Value: blockMsg, Hint: "Custom block response (action mode)"},

		// ─── Detection ───
		{Label: "Detection", Kind: "section"},
		{Label: "Strategy", Flag: "--detection-strategy", Kind: "choice", Options: []string{"regex_only", "regex_judge", "judge_first"}, Value: strategy, Default: "regex_only", Hint: "regex_only=fast, regex_judge=recommended, judge_first=most accurate"},
		{Label: "Rule Pack", Flag: "--rule-pack", Kind: "choice", Options: []string{"default", "strict", "permissive"}, Value: rulePack, Default: "default", Hint: "Detection rules profile (manage in Policy tab)"},

		// ─── LLM Judge ───
		{Label: "LLM Judge", Kind: "section"},
		{Label: "Provider", Flag: "", Kind: "choice", Options: bifrostProviders(), Value: judgeProvider, Default: "bedrock", Hint: "LLM provider via Bifrost SDK (Tab to cycle, type to search)"},
		{Label: "Model", Flag: "--judge-model", Kind: "string", Value: judgeModel, Hint: "e.g. us.anthropic.claude-3-5-haiku-20241022-v1:0"},
		{Label: "API Key Env", Flag: "--judge-api-key-env", Kind: "string", Value: judgeKeyEnv, Hint: "Env var holding API key (e.g. BIFROST_API_KEY)"},
		{Label: "API Base URL", Flag: "--judge-api-base", Kind: "string", Value: judgeBase, Hint: "Leave blank for direct provider access"},

		// ─── Cisco AI Defense (Remote) ───
		{Label: "Cisco AI Defense", Kind: "section"},
		{Label: "Endpoint", Flag: "--cisco-endpoint", Kind: "string", Value: ciscoEndpoint, Hint: "Cisco AI Defense API URL (remote/both mode)"},
		{Label: "API Key Env", Flag: "--cisco-api-key-env", Kind: "string", Value: ciscoKeyEnv, Hint: "Env var holding Cisco API key"},
		{Label: "Timeout (ms)", Flag: "--cisco-timeout-ms", Kind: "int", Value: ciscoTimeout, Hint: "Cisco AI Defense timeout"},

		// ─── Post-Setup ───
		{Label: "Post-Setup", Kind: "section"},
		{Label: "Restart After", Flag: "--restart", NoFlag: "--no-restart", Kind: "bool", Default: "yes", Value: "yes"},
		{Label: "Verify After Setup", Flag: "--verify", NoFlag: "--no-verify", Kind: "bool", Default: "yes", Value: "yes"},
		{Label: "Disable", Flag: "--disable", Kind: "bool", Default: "no", Value: "no", Hint: "Disable guardrail and revert config"},
	}
}

func bifrostProviders() []string {
	return []string{
		"openai", "azure", "anthropic", "bedrock", "cohere", "vertex",
		"mistral", "ollama", "groq", "sgl", "parasail", "perplexity",
		"cerebras", "gemini", "openrouter", "elevenlabs", "huggingface",
		"nebius", "xai", "replicate", "vllm", "runway", "fireworks",
	}
}

// wizardFormDefs returns the form fields for a given wizard index.
func (p *SetupPanel) wizardFormDefs(idx int) []wizardFormField {
	switch idx {
	case wizardSkillScanner:
		return []wizardFormField{
			{Label: "Behavioral Analyzer", Flag: "--use-behavioral", Kind: "bool", Default: "no", Value: "no"},
			{Label: "LLM Analyzer", Flag: "--use-llm", Kind: "bool", Default: "no", Value: "no"},
			{Label: "LLM Provider", Flag: "--llm-provider", Kind: "choice", Options: []string{"anthropic", "openai"}, Value: "anthropic", Default: "anthropic"},
			{Label: "LLM Model", Flag: "--llm-model", Kind: "string", Hint: "e.g. gpt-4o, claude-sonnet-4-20250514"},
			{Label: "LLM Consensus Runs", Flag: "--llm-consensus-runs", Kind: "int", Default: "0", Value: "0", Hint: "0 = disabled"},
			{Label: "Meta Analyzer", Flag: "--enable-meta", Kind: "bool", Default: "no", Value: "no"},
			{Label: "Trigger Analyzer", Flag: "--use-trigger", Kind: "bool", Default: "no", Value: "no"},
			{Label: "VirusTotal Scanner", Flag: "--use-virustotal", Kind: "bool", Default: "no", Value: "no"},
			{Label: "AI Defense Analyzer", Flag: "--use-aidefense", Kind: "bool", Default: "no", Value: "no"},
			{Label: "Scan Policy", Flag: "--policy", Kind: "choice", Options: []string{"strict", "balanced", "permissive"}, Value: "balanced", Default: "balanced"},
			{Label: "Lenient Mode", Flag: "--lenient", Kind: "bool", Default: "no", Value: "no", Hint: "Tolerate malformed skills"},
			{Label: "Verify After Setup", Flag: "--verify", NoFlag: "--no-verify", Kind: "bool", Default: "yes", Value: "yes"},
		}
	case wizardMCPScanner:
		return []wizardFormField{
			{Label: "Analyzers", Flag: "--analyzers", Kind: "string", Default: "yara,api,llm,behavioral,readiness", Value: "yara,api,llm,behavioral,readiness", Hint: "CSV: yara,api,llm,behavioral,readiness"},
			{Label: "LLM Provider", Flag: "--llm-provider", Kind: "choice", Options: []string{"anthropic", "openai"}, Value: "anthropic", Default: "anthropic"},
			{Label: "LLM Model", Flag: "--llm-model", Kind: "string", Hint: "Model for semantic analysis"},
			{Label: "Scan Prompts", Flag: "--scan-prompts", Kind: "bool", Default: "no", Value: "no"},
			{Label: "Scan Resources", Flag: "--scan-resources", Kind: "bool", Default: "no", Value: "no"},
			{Label: "Scan Instructions", Flag: "--scan-instructions", Kind: "bool", Default: "no", Value: "no"},
			{Label: "Verify After Setup", Flag: "--verify", NoFlag: "--no-verify", Kind: "bool", Default: "yes", Value: "yes"},
		}
	case wizardGateway:
		return []wizardFormField{
			{Label: "Remote Mode", Flag: "--remote", Kind: "bool", Default: "no", Value: "no", Hint: "Remote gateway requires auth token"},
			{Label: "Host", Flag: "--host", Kind: "string", Default: "localhost", Value: "localhost"},
			{Label: "Port", Flag: "--port", Kind: "int", Default: "9090", Value: "9090", Hint: "WebSocket port"},
			{Label: "API Port", Flag: "--api-port", Kind: "int", Default: "9099", Value: "9099", Hint: "Sidecar REST API port"},
			{Label: "Auth Token", Flag: "--token", Kind: "string", Hint: "Gateway auth token (remote only)"},
			{Label: "SSM Param", Flag: "--ssm-param", Kind: "string", Hint: "AWS SSM parameter for token"},
			{Label: "SSM Region", Flag: "--ssm-region", Kind: "string", Hint: "AWS region for SSM"},
			{Label: "SSM Profile", Flag: "--ssm-profile", Kind: "string", Hint: "AWS CLI profile"},
			{Label: "Verify After Setup", Flag: "--verify", NoFlag: "--no-verify", Kind: "bool", Default: "yes", Value: "yes"},
		}
	case wizardGuardrail:
		return p.guardrailWizardFields()
	case wizardSplunk:
		return []wizardFormField{
			{Label: "Enable O11y", Flag: "--o11y", Kind: "bool", Default: "no", Value: "no", Hint: "Splunk Observability Cloud (OTLP)"},
			{Label: "Enable Local Logs", Flag: "--logs", Kind: "bool", Default: "no", Value: "no", Hint: "Local Splunk via Docker (HEC)"},
			{Label: "Realm", Flag: "--realm", Kind: "string", Hint: "O11y realm (e.g. us1, us0, eu0)"},
			{Label: "Access Token", Flag: "--access-token", Kind: "string", Hint: "Splunk O11y access token"},
			{Label: "App Name", Flag: "--app-name", Kind: "string", Default: "defenseclaw", Value: "defenseclaw"},
			{Label: "Traces", Flag: "--traces", NoFlag: "--no-traces", Kind: "bool", Default: "yes", Value: "yes"},
			{Label: "Metrics", Flag: "--metrics", NoFlag: "--no-metrics", Kind: "bool", Default: "yes", Value: "yes"},
			{Label: "Logs Export", Flag: "--logs-export", NoFlag: "--no-logs-export", Kind: "bool", Default: "no", Value: "no"},
			{Label: "HEC Index", Flag: "--index", Kind: "string", Default: "defenseclaw_local", Value: "defenseclaw_local"},
			{Label: "HEC Source", Flag: "--source", Kind: "string", Default: "defenseclaw", Value: "defenseclaw"},
			{Label: "HEC Sourcetype", Flag: "--sourcetype", Kind: "string", Default: "defenseclaw:json", Value: "defenseclaw:json"},
			{Label: "Accept Splunk License", Flag: "--accept-splunk-license", Kind: "bool", Default: "no", Value: "no"},
			{Label: "Show Credentials", Flag: "--show-credentials", Kind: "bool", Default: "no", Value: "no"},
			{Label: "Disable", Flag: "--disable", Kind: "bool", Default: "no", Value: "no"},
		}
	case wizardSandbox:
		return []wizardFormField{
			{Label: "Sandbox IP", Flag: "--sandbox-ip", Kind: "string", Default: "10.200.0.2", Value: "10.200.0.2"},
			{Label: "Host IP", Flag: "--host-ip", Kind: "string", Default: "10.200.0.1", Value: "10.200.0.1"},
			{Label: "Sandbox Home", Flag: "--sandbox-home", Kind: "string", Default: "/home/sandbox", Value: "/home/sandbox"},
			{Label: "OpenClaw Port", Flag: "--openclaw-port", Kind: "int", Default: "18789", Value: "18789"},
			{Label: "Policy", Flag: "--policy", Kind: "choice", Options: []string{"default", "strict", "permissive"}, Value: "permissive", Default: "permissive"},
			{Label: "DNS", Flag: "--dns", Kind: "string", Default: "8.8.8.8,1.1.1.1", Value: "8.8.8.8,1.1.1.1"},
			{Label: "No Auto Pair", Flag: "--no-auto-pair", Kind: "bool", Default: "no", Value: "no"},
			{Label: "No Host Networking", Flag: "--no-host-networking", Kind: "bool", Default: "no", Value: "no"},
			{Label: "No Guardrail", Flag: "--no-guardrail", Kind: "bool", Default: "no", Value: "no"},
			{Label: "Disable", Flag: "--disable", Kind: "bool", Default: "no", Value: "no", Hint: "Revert to host mode"},
		}
	default:
		return nil
	}
}

// HandleMouseClick processes mouse clicks relative to the panel. Returns same tuple as HandleKey.
func (p *SetupPanel) HandleMouseClick(x, y int) (runCmd bool, binary string, args []string, displayName string) {
	if p.wizFormActive || p.wizRunning || len(p.wizOutput) > 0 {
		return false, "", nil, ""
	}

	if p.mode == setupModeWizards {
		return p.handleWizardClick(x, y)
	}
	return p.handleConfigClick(x, y)
}

func (p *SetupPanel) handleWizardClick(x, y int) (bool, string, []string, string) {
	if y == 0 {
		if x > 18 {
			p.mode = setupModeConfig
		}
		return false, "", nil, ""
	}

	if y == 2 {
		cursor := 0
		for i, name := range wizardNames {
			w := lipgloss.Width(name) + 2
			if x >= cursor && x < cursor+w+1 {
				p.activeWizard = i
				return false, "", nil, ""
			}
			cursor += w + 1
		}
		return false, "", nil, ""
	}

	if y >= 4 && y <= 10 {
		p.showWizardForm(p.activeWizard)
	}

	return false, "", nil, ""
}

func (p *SetupPanel) handleConfigClick(x, y int) (bool, string, []string, string) {
	// Row 0: mode tabs
	if y == 0 {
		if x < 18 {
			p.mode = setupModeWizards
		}
		return false, "", nil, ""
	}

	// Row 2: section tabs
	if y == 2 {
		cursor := 0
		for i, sec := range p.sections {
			w := lipgloss.Width(sec.Name) + 2
			if x >= cursor && x < cursor+w+1 {
				p.activeSection = i
				p.activeLine = p.firstEditableLine()
				p.scroll = 0
				return false, "", nil, ""
			}
			cursor += w + 1
		}
		return false, "", nil, ""
	}

	// Row 4+: config fields
	fieldY := y - 4
	if fieldY >= 0 && p.activeSection < len(p.sections) {
		idx := p.scroll + fieldY
		sec := &p.sections[p.activeSection]
		if idx >= 0 && idx < len(sec.Fields) {
			f := &sec.Fields[idx]
			if f.Kind == "header" {
				return false, "", nil, ""
			}
			if p.activeLine == idx && !p.editing {
				switch f.Kind {
				case "bool":
					if f.Value == "true" {
						f.Value = "false"
					} else {
						f.Value = "true"
					}
				case "choice":
					if len(f.Options) > 0 {
						cur := 0
						for i, o := range f.Options {
							if o == f.Value {
								cur = i
								break
							}
						}
						f.Value = f.Options[(cur+1)%len(f.Options)]
					}
				default:
					p.editing = true
					p.editInput.SetValue(f.Value)
					p.pendingFocusCmd = p.editInput.Focus()
					p.editInput.CursorEnd()
				}
			} else {
				p.activeLine = idx
			}
		}
	}
	return false, "", nil, ""
}

// HandleMouseMotion updates hover state.
func (p *SetupPanel) HandleMouseMotion(x, y int) {
	p.wizardHover = -1
	p.configHover = -1

	if p.wizFormActive || p.wizRunning || len(p.wizOutput) > 0 {
		return
	}

	if p.mode == setupModeWizards && y == 2 {
		cursor := 0
		for i, name := range wizardNames {
			w := lipgloss.Width(name) + 2
			if x >= cursor && x < cursor+w+1 {
				p.wizardHover = i
				return
			}
			cursor += w + 1
		}
	}

	if p.mode == setupModeConfig {
		fieldY := y - 4
		if fieldY >= 0 && p.activeSection < len(p.sections) {
			idx := p.scroll + fieldY
			sec := p.sections[p.activeSection]
			if idx >= 0 && idx < len(sec.Fields) {
				p.configHover = idx
			}
		}
	}
}

// SaveConfig writes modified fields back to the config object and saves to disk.
func (p *SetupPanel) SaveConfig() error {
	if p.cfg == nil {
		return fmt.Errorf("setup: no config loaded")
	}
	for _, sec := range p.sections {
		for _, f := range sec.Fields {
			if f.Value != f.Original {
				applyConfigField(p.cfg, f.Key, f.Value)
			}
		}
	}
	if err := p.cfg.Save(); err != nil {
		return err
	}
	p.lastSaved = time.Now()
	for si := range p.sections {
		for fi := range p.sections[si].Fields {
			p.sections[si].Fields[fi].Original = p.sections[si].Fields[fi].Value
		}
	}
	return nil
}

// RevertConfig reloads config from disk.
func (p *SetupPanel) RevertConfig() error {
	newCfg, err := config.Load()
	if err != nil {
		return err
	}
	p.cfg = newCfg
	p.loadSections()
	return nil
}

// GetConfig returns the current config pointer held by the setup panel.
func (p *SetupPanel) GetConfig() *config.Config {
	return p.cfg
}

// HasChanges returns true if any config field has been modified.
func (p *SetupPanel) HasChanges() bool {
	for _, sec := range p.sections {
		for _, f := range sec.Fields {
			if f.Value != f.Original {
				return true
			}
		}
	}
	return false
}

// ScrollBy scrolls the config editor, wizard form, or wizard terminal.
func (p *SetupPanel) ScrollBy(delta int) {
	if p.wizFormActive {
		p.wizFormScroll += delta
		if p.wizFormScroll < 0 {
			p.wizFormScroll = 0
		}
		maxScroll := len(p.wizFormFields) - (p.height - 8)
		if maxScroll < 0 {
			maxScroll = 0
		}
		if p.wizFormScroll > maxScroll {
			p.wizFormScroll = maxScroll
		}
		return
	}
	if p.wizRunning || len(p.wizOutput) > 0 {
		p.wizScroll -= delta
		if p.wizScroll < 0 {
			p.wizScroll = 0
		}
		maxS := len(p.wizOutput)
		if p.wizScroll > maxS {
			p.wizScroll = maxS
		}
		return
	}
	p.scroll += delta
	if p.scroll < 0 {
		p.scroll = 0
	}
	if p.activeSection < len(p.sections) {
		totalFields := len(p.sections[p.activeSection].Fields)
		visibleLines := p.height - 8
		if visibleLines < 5 {
			visibleLines = 5
		}
		maxScroll := totalFields - visibleLines
		if maxScroll < 0 {
			maxScroll = 0
		}
		if p.scroll > maxScroll {
			p.scroll = maxScroll
		}
	}
}

// View renders the setup panel.
func (p *SetupPanel) View(width, height int) string {
	p.width = width
	p.height = height

	if p.wizFormActive {
		return p.renderWizardForm()
	}

	if p.wizRunning || len(p.wizOutput) > 0 {
		return p.renderWizardTerminal()
	}

	var b strings.Builder

	inactiveTab := lipgloss.NewStyle().Foreground(lipgloss.Color("250")).Padding(0, 1)
	activeTab := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("230")).Background(lipgloss.Color("62")).Padding(0, 1)

	if p.mode == setupModeWizards {
		b.WriteString(activeTab.Render("Setup Wizards") + " " + inactiveTab.Render("Config Editor"))
	} else {
		b.WriteString(inactiveTab.Render("Setup Wizards") + " " + activeTab.Render("Config Editor"))
	}
	b.WriteString("\n\n")

	if p.mode == setupModeWizards {
		b.WriteString(p.renderWizards())
	} else {
		b.WriteString(p.renderConfigEditor())
	}

	return b.String()
}

func (p *SetupPanel) renderWizardForm() string {
	var b strings.Builder
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	bold := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("252"))
	highlight := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("230")).Background(lipgloss.Color("240"))
	changed := lipgloss.NewStyle().Foreground(lipgloss.Color("208"))
	hintStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Italic(true)

	wizName := "Wizard"
	if p.wizRunIdx >= 0 && p.wizRunIdx < wizardCount {
		wizName = wizardNames[p.wizRunIdx]
	}
	b.WriteString(bold.Render("  -- "+wizName+" Setup --"))
	b.WriteString("\n")
	b.WriteString(dim.Render("  Fill in the fields below, then press Ctrl+R to run."))
	b.WriteString("\n\n")

	visibleLines := p.height - 8
	if visibleLines < 5 {
		visibleLines = 5
	}
	endIdx := p.wizFormScroll + visibleLines
	if endIdx > len(p.wizFormFields) {
		endIdx = len(p.wizFormFields)
	}

	sectionStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("62"))

	for i := p.wizFormScroll; i < endIdx; i++ {
		f := p.wizFormFields[i]

		// Section dividers are non-interactive visual headers
		if f.Kind == "section" {
			if i > 0 {
				b.WriteString("\n")
			}
			b.WriteString("  " + sectionStyle.Render("─── "+f.Label+" ───"))
			b.WriteString("\n")
			continue
		}

		label := fmt.Sprintf("  %-24s", f.Label)

		mod := " "
		if f.Value != f.Default && f.Default != "" {
			mod = changed.Render("*")
		}

		var val string
		if i == p.wizFormCursor && p.wizFormEditing {
			b.WriteString(highlight.Render(label) + mod + " " + p.editInput.View())
		} else {
			switch f.Kind {
			case "bool":
				if f.Value == "yes" {
					val = lipgloss.NewStyle().Foreground(lipgloss.Color("34")).Render("yes")
				} else {
					val = dim.Render("no")
				}
			case "choice":
				val = lipgloss.NewStyle().Foreground(lipgloss.Color("81")).Render(f.Value)
			default:
				if f.Value == "" {
					val = dim.Render("(empty)")
				} else {
					val = f.Value
				}
			}

			if i == p.wizFormCursor {
				b.WriteString(highlight.Render(label) + mod + " [" + val + "]")
			} else {
				b.WriteString(dim.Render(label) + mod + " " + val)
			}
		}
		b.WriteString("\n")
	}

	// Hint for selected field
	if p.wizFormCursor >= 0 && p.wizFormCursor < len(p.wizFormFields) {
		f := p.wizFormFields[p.wizFormCursor]
		if f.Hint != "" {
			b.WriteString("  " + hintStyle.Render("  "+f.Hint))
			b.WriteString("\n")
		}
	}

	b.WriteString("\n")

	runBtn := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("230")).Background(lipgloss.Color("34")).Padding(0, 2)
	b.WriteString("  " + runBtn.Render("Ctrl+R  Run Setup"))
	b.WriteString("\n\n")
	b.WriteString("  " + dim.Render("[Enter/Space] Toggle/Edit  [Up/Down] Navigate  [Ctrl+R] Run  [Esc] Cancel"))
	b.WriteString("\n")

	return b.String()
}

func (p *SetupPanel) renderWizardTerminal() string {
	var b strings.Builder
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	cmdStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("81"))

	wizName := "Wizard"
	if p.wizRunIdx >= 0 && p.wizRunIdx < wizardCount {
		wizName = wizardNames[p.wizRunIdx]
	}
	if p.wizRunning {
		b.WriteString(cmdStyle.Render("$ defenseclaw setup " + strings.ToLower(wizName)))
		b.WriteString("  " + lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Render("running..."))
	} else {
		b.WriteString(cmdStyle.Render("$ defenseclaw setup "+strings.ToLower(wizName)) + "  " +
			lipgloss.NewStyle().Foreground(lipgloss.Color("34")).Render("done"))
	}
	b.WriteString("\n")
	b.WriteString(strings.Repeat("─", p.width))
	b.WriteString("\n")

	maxVisible := p.height - 4
	if maxVisible < 5 {
		maxVisible = 5
	}

	output := p.wizOutput
	totalLines := len(output)
	endIdx := totalLines - p.wizScroll
	if endIdx < 0 {
		endIdx = 0
	}
	if endIdx > totalLines {
		endIdx = totalLines
	}
	startIdx := endIdx - maxVisible
	if startIdx < 0 {
		startIdx = 0
	}

	for i := startIdx; i < endIdx; i++ {
		b.WriteString("  " + output[i])
		b.WriteString("\n")
	}
	rendered := endIdx - startIdx
	for rendered < maxVisible {
		b.WriteString("\n")
		rendered++
	}

	if p.wizRunning {
		b.WriteString(dim.Render("  [Ctrl+C] Cancel  [Up/Down] Scroll"))
	} else {
		if p.wizScroll > 0 {
			b.WriteString(dim.Render(fmt.Sprintf("  (scrolled up %d lines)  ", p.wizScroll)))
		}
		b.WriteString(dim.Render("  [Esc] Return to wizards  [Up/Down] Scroll"))
	}

	return b.String()
}

func (p *SetupPanel) renderWizards() string {
	var b strings.Builder
	activeStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("230")).Background(lipgloss.Color("62")).Padding(0, 1)
	inactiveStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("250")).Padding(0, 1)
	hoverStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("230")).Background(lipgloss.Color("97")).Padding(0, 1)

	var tabs []string
	for i, name := range wizardNames {
		style := inactiveStyle
		switch i {
		case p.activeWizard:
			style = activeStyle
		case p.wizardHover:
			style = hoverStyle
		}
		tabs = append(tabs, style.Render(name))
	}
	b.WriteString(strings.Join(tabs, " "))
	b.WriteString("\n\n")

	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	bold := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("252"))

	name := wizardNames[p.activeWizard]
	b.WriteString(bold.Render("  -- " + name + " Setup --"))
	b.WriteString("\n\n")

	b.WriteString("  " + dim.Render(wizardDescriptions[p.activeWizard]))
	b.WriteString("\n\n")

	status := p.wizardStatus[p.activeWizard]
	if status == "" {
		status = "Not run"
	}
	statusStyle := dim
	switch {
	case strings.HasPrefix(status, "Configured"):
		statusStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("34"))
	case strings.HasPrefix(status, "Failed"):
		statusStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	case strings.HasPrefix(status, "running"):
		statusStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	}
	fmt.Fprintf(&b, "  Status: %s\n\n", statusStyle.Render(status))

	cfgBtn := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("230")).
		Background(lipgloss.Color("34")).
		Padding(0, 2).
		Render("Configure " + name)
	b.WriteString("  " + cfgBtn)
	b.WriteString("\n\n")

	b.WriteString("  " + dim.Render("[Enter/Click] Configure  [Up/Down/Arrows] Switch  [`] Config Editor"))
	b.WriteString("\n")

	return b.String()
}

func (p *SetupPanel) renderConfigEditor() string {
	var b strings.Builder
	if len(p.sections) == 0 {
		b.WriteString("  No configuration loaded.\n")
		return b.String()
	}

	activeTabStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("230")).Background(lipgloss.Color("62")).Padding(0, 1)
	inactiveTabStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("250")).Padding(0, 1)

	var tabs []string
	for i, sec := range p.sections {
		if i == p.activeSection {
			tabs = append(tabs, activeTabStyle.Render(sec.Name))
		} else {
			tabs = append(tabs, inactiveTabStyle.Render(sec.Name))
		}
	}
	b.WriteString(strings.Join(tabs, " "))
	b.WriteString("\n\n")

	if p.activeSection < 0 || p.activeSection >= len(p.sections) {
		return b.String()
	}
	sec := p.sections[p.activeSection]
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	highlight := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("230")).Background(lipgloss.Color("240"))
	hoverFg := lipgloss.NewStyle().Foreground(lipgloss.Color("252"))
	changed := lipgloss.NewStyle().Foreground(lipgloss.Color("208"))

	visibleLines := p.height - 8
	if visibleLines < 5 {
		visibleLines = 5
	}
	endIdx := p.scroll + visibleLines
	if endIdx > len(sec.Fields) {
		endIdx = len(sec.Fields)
	}

	headerStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("62"))
	choiceStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("81"))
	boolTrue := lipgloss.NewStyle().Foreground(lipgloss.Color("34"))
	boolFalse := lipgloss.NewStyle().Foreground(lipgloss.Color("196"))

	for i := p.scroll; i < endIdx; i++ {
		f := sec.Fields[i]

		// Sub-section headers are non-interactive visual dividers
		if f.Kind == "header" {
			b.WriteString("\n  " + headerStyle.Render(f.Label) + "\n")
			continue
		}

		label := fmt.Sprintf("  %-24s", f.Label)
		val := f.Value

		mod := " "
		if f.Value != f.Original {
			mod = changed.Render("*")
		}

		// Apply type-specific styling to values
		var styledVal string
		switch f.Kind {
		case "bool":
			if val == "true" {
				styledVal = boolTrue.Render(val)
			} else {
				styledVal = boolFalse.Render(val)
			}
		case "choice":
			if val == "" {
				styledVal = dim.Render("(inherit)")
			} else {
				styledVal = choiceStyle.Render(val)
			}
		case "password":
			if val != "" {
				styledVal = val
			} else {
				styledVal = dim.Render("(empty)")
			}
		default:
			if val == "" {
				styledVal = dim.Render("(empty)")
			} else {
				styledVal = val
			}
		}

		if i == p.activeLine && p.editing {
			b.WriteString(highlight.Render(label) + mod + " " + p.editInput.View() + "\n")
		} else if i == p.activeLine {
			b.WriteString(highlight.Render(label) + mod + " [" + styledVal + "]\n")
		} else if i == p.configHover {
			b.WriteString(hoverFg.Render(label) + mod + " " + styledVal + "\n")
		} else {
			b.WriteString(dim.Render(label) + mod + " " + styledVal + "\n")
		}
	}

	b.WriteString("\n")

	// Action bar
	actions := []string{"[`] Wizards", "[Arrows] Navigate", "[Enter/Click] Edit/Toggle"}
	if p.HasChanges() {
		actions = append(actions, changed.Render("[S] Save")+" [R] Revert")
	}
	if !p.lastSaved.IsZero() {
		ago := time.Since(p.lastSaved).Truncate(time.Second)
		actions = append(actions, dim.Render(fmt.Sprintf("Saved %s ago", ago)))
	}
	b.WriteString("  " + dim.Render(strings.Join(actions, "  ")))
	b.WriteString("\n")

	return b.String()
}

// auditSinkSummaryFields renders one read-only row per declared audit
// sink. The single-key configField form cannot represent the
// audit_sinks[] schema (per-sink kind, filter, kind-specific block),
// so this view shows a summary and "no sinks configured" when empty.
func auditSinkSummaryFields(c *config.Config) []configField {
	if len(c.AuditSinks) == 0 {
		return []configField{{
			Label: "Status",
			Key:   "audit_sinks.summary",
			Kind:  "header",
			Value: "no sinks configured",
		}}
	}
	out := make([]configField, 0, len(c.AuditSinks))
	for _, s := range c.AuditSinks {
		state := "enabled"
		if !s.Enabled {
			state = "disabled"
		}
		summary := fmt.Sprintf("%s [%s] %s", s.Name, s.Kind, state)
		switch s.Kind {
		case config.SinkKindSplunkHEC:
			if s.SplunkHEC != nil {
				summary += " → " + s.SplunkHEC.Endpoint
			}
		case config.SinkKindOTLPLogs:
			if s.OTLPLogs != nil {
				summary += " → " + s.OTLPLogs.Endpoint
			}
		case config.SinkKindHTTPJSONL:
			if s.HTTPJSONL != nil {
				summary += " → " + s.HTTPJSONL.URL
			}
		}
		out = append(out, configField{
			Label: s.Name,
			Key:   "audit_sinks." + s.Name,
			Kind:  "header",
			Value: summary,
		})
	}
	return out
}
