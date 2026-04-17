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
	wizardObservability
	wizardWebhook
	wizardSandbox
	wizardCount
)

var wizardNames = [wizardCount]string{
	"Skill Scanner", "MCP Scanner", "Gateway",
	"Guardrail", "Splunk", "Observability", "Webhooks", "Sandbox",
}

var wizardCommands = [wizardCount][]string{
	{"setup", "skill-scanner"},
	{"setup", "mcp-scanner"},
	{"setup", "gateway"},
	{"setup", "guardrail"},
	{"setup", "splunk"},
	// Observability: preset id is injected positionally by
	// buildWizardArgs from the form's "preset" field.
	{"setup", "observability", "add"},
	// Webhook: channel type is injected positionally from the form's
	// "type" field. See buildWizardArgs + webhookWizardFields.
	{"setup", "webhook", "add"},
	{"sandbox", "setup"},
}

var wizardDescriptions = [wizardCount]string{
	"Configure skill scanner analyzers (manifest, permissions, LLM, AI Defense, behavioral, trigger, VirusTotal).",
	"Configure MCP scanner analyzers and which components to scan (prompts, resources, instructions).",
	"Configure gateway connection settings (host, port, TLS, auto-approve, reconnect parameters).",
	"Configure LLM guardrail proxy (mode, model, scanner mode, judge settings).",
	"Configure Splunk HEC integration for SIEM (endpoint, token, index, source).",
	"Unified OTel + audit sink setup. Pick a preset (Splunk O11y, Splunk HEC, Datadog, Honeycomb, New Relic, Grafana Cloud, generic OTLP, Generic HTTP JSONL) and fill the prompts. Shells out to `setup observability add`.",
	"Configure chat/incident notifier webhooks (Slack, PagerDuty, Webex, generic HMAC). Distinct from the observability HTTP JSONL audit-log forwarder. Shells out to `setup webhook add`.",
	"Initialize and configure sandbox environment (OpenShell policy, networking).",
}

// observabilityPresets mirrors cli/defenseclaw/observability/presets.py::preset_choices().
// The preset id is passed positionally to `setup observability add`; the
// display label is shown in the TUI picker.
//
// Keep this in sync with presets.py — ordering drives the default cursor
// position and matches the CLI `--help` output so users see one menu
// across both front-ends.
var observabilityPresets = [][2]string{
	{"splunk-o11y", "Splunk Observability Cloud"},
	{"splunk-hec", "Splunk HEC"},
	{"datadog", "Datadog"},
	{"honeycomb", "Honeycomb"},
	{"newrelic", "New Relic"},
	{"grafana-cloud", "Grafana Cloud"},
	{"otlp", "Generic OTLP"},
	{"webhook", "Generic HTTP JSONL"},
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
	Label    string
	Flag     string   // CLI flag (e.g., "--use-llm")
	NoFlag   string   // negation flag for bool toggles (e.g., "--no-verify")
	Kind     string   // "bool", "string", "choice", "int", "section" (divider)
	Value    string   // current value set by user
	Default  string   // pre-filled default
	Options  []string // valid choices for "choice" kind
	Hint     string   // help text shown when selected
	Required bool     // submit blocked + visual marker if empty (string/int/choice/password)
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
	// wizFormError is rendered above the action bar when the user
	// tries to submit a form with missing required fields. Cleared
	// on the next keystroke so it doesn't linger after the user
	// fixes the issue.
	wizFormError string

	// Wizard output terminal (shows command output after form submission)
	wizRunning bool
	wizRunIdx  int // which wizard is running
	wizOutput  []string
	wizScroll  int // lines from bottom (0 = pinned)
	// sinkEditorResume is set when a wizard command was kicked off
	// by the Audit Sinks editor. On CommandDoneMsg we refresh the
	// editor list and re-open it on ESC so operators don't lose
	// their place after e/d/r/t/m actions.
	sinkEditorResume bool

	// sinkEditor is the interactive Audit Sinks sub-mode (list mode
	// over defenseclaw setup observability list|enable|disable|remove|
	// test|migrate-splunk). Opened by pressing 'E' while the cursor
	// is on the Audit Sinks section in the Config Editor.
	sinkEditor SinkEditorModel

	// webhookEditorResume mirrors sinkEditorResume for the Webhooks
	// sub-mode — set when a webhook mutation was kicked off so the
	// editor gets re-opened with a fresh list on CommandDoneMsg.
	webhookEditorResume bool

	// webhookEditor is the interactive Webhooks sub-mode (list mode
	// over defenseclaw setup webhook list|enable|disable|remove|
	// test|show). Opened by pressing 'E' while the cursor is on the
	// Webhooks section in the Config Editor.
	webhookEditor WebhookEditorModel

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
		sinkEditor:    NewSinkEditorModel(),
		webhookEditor: NewWebhookEditorModel(),
	}
	p.loadSections()
	return p
}

// SetSize updates the panel dimensions.
func (p *SetupPanel) SetSize(w, h int) {
	p.width = w
	p.height = h
	p.editInput.SetWidth(w/2 - 4)
	p.sinkEditor.SetSize(w, h)
	p.webhookEditor.SetSize(w, h)
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
		// P2-#9: Scanner section now surfaces every field the CLI and
		// the Python scanners know about. Previous version hid 12 of
		// the 17 knobs (use_trigger / use_virustotal / use_aidefense /
		// llm_consensus_runs / policy / lenient / virustotal key pair
		// / enable_meta / mcp_scanner scan_prompts+resources+
		// instructions / plugin_scanner binary), which meant operators
		// had to `vim ~/.defenseclaw/config.yaml` for common tuning.
		// Sub-headers split the view into Skill / MCP / Plugin
		// families so a long scroll doesn't blur the scanner
		// ownership.
		{Name: "Scanners", Fields: []configField{
			{Label: "── Skill Scanner ──", Kind: "header"},
			{Label: "Binary", Key: "scanners.skill_scanner.binary", Kind: "string", Value: c.Scanners.SkillScanner.Binary},
			{Label: "Policy", Key: "scanners.skill_scanner.policy", Kind: "choice", Value: c.Scanners.SkillScanner.Policy, Options: []string{"permissive", "strict", "observe"}},
			{Label: "Lenient", Key: "scanners.skill_scanner.lenient", Kind: "bool", Value: fmt.Sprintf("%v", c.Scanners.SkillScanner.Lenient)},
			{Label: "Use LLM", Key: "scanners.skill_scanner.use_llm", Kind: "bool", Value: fmt.Sprintf("%v", c.Scanners.SkillScanner.UseLLM)},
			{Label: "LLM Consensus Runs", Key: "scanners.skill_scanner.llm_consensus_runs", Kind: "int", Value: fmt.Sprintf("%d", c.Scanners.SkillScanner.LLMConsensus)},
			{Label: "Use Behavioral", Key: "scanners.skill_scanner.use_behavioral", Kind: "bool", Value: fmt.Sprintf("%v", c.Scanners.SkillScanner.UseBehavioral)},
			{Label: "Enable Meta", Key: "scanners.skill_scanner.enable_meta", Kind: "bool", Value: fmt.Sprintf("%v", c.Scanners.SkillScanner.EnableMeta)},
			{Label: "Use Trigger", Key: "scanners.skill_scanner.use_trigger", Kind: "bool", Value: fmt.Sprintf("%v", c.Scanners.SkillScanner.UseTrigger)},
			{Label: "Use VirusTotal", Key: "scanners.skill_scanner.use_virustotal", Kind: "bool", Value: fmt.Sprintf("%v", c.Scanners.SkillScanner.UseVirusTotal)},
			{Label: "VirusTotal Key Env", Key: "scanners.skill_scanner.virustotal_api_key_env", Kind: "password", Value: c.Scanners.SkillScanner.VirusTotalKeyEnv},
			{Label: "Use AI Defense", Key: "scanners.skill_scanner.use_aidefense", Kind: "bool", Value: fmt.Sprintf("%v", c.Scanners.SkillScanner.UseAIDefense)},
			{Label: "── MCP Scanner ──", Kind: "header"},
			{Label: "Binary", Key: "scanners.mcp_scanner.binary", Kind: "string", Value: c.Scanners.MCPScanner.Binary},
			{Label: "Analyzers", Key: "scanners.mcp_scanner.analyzers", Kind: "string", Value: c.Scanners.MCPScanner.Analyzers},
			{Label: "Scan Prompts", Key: "scanners.mcp_scanner.scan_prompts", Kind: "bool", Value: fmt.Sprintf("%v", c.Scanners.MCPScanner.ScanPrompts)},
			{Label: "Scan Resources", Key: "scanners.mcp_scanner.scan_resources", Kind: "bool", Value: fmt.Sprintf("%v", c.Scanners.MCPScanner.ScanResources)},
			{Label: "Scan Instructions", Key: "scanners.mcp_scanner.scan_instructions", Kind: "bool", Value: fmt.Sprintf("%v", c.Scanners.MCPScanner.ScanInstructions)},
			{Label: "── Plugin / CodeGuard ──", Kind: "header"},
			{Label: "Plugin Scanner", Key: "scanners.plugin_scanner", Kind: "string", Value: c.Scanners.PluginScanner},
			{Label: "CodeGuard", Key: "scanners.codeguard", Kind: "string", Value: c.Scanners.CodeGuard},
		}},
		// P2-#9: Gateway inline watcher/watchdog live alongside the
		// gateway address settings — they're part of the same
		// process but logically distinct sub-concerns. Kept as a
		// separate section so operators can scroll to "just the
		// watcher" without wading past reconnect timers etc.
		{Name: "Gateway Watcher", Fields: []configField{
			{Label: "Enabled", Key: "gateway.watcher.enabled", Kind: "bool", Value: fmt.Sprintf("%v", c.Gateway.Watcher.Enabled)},
			{Label: "── Skill ──", Kind: "header"},
			{Label: "Enabled", Key: "gateway.watcher.skill.enabled", Kind: "bool", Value: fmt.Sprintf("%v", c.Gateway.Watcher.Skill.Enabled)},
			{Label: "Take Action", Key: "gateway.watcher.skill.take_action", Kind: "bool", Value: fmt.Sprintf("%v", c.Gateway.Watcher.Skill.TakeAction)},
			{Label: "Dirs", Key: "gateway.watcher.skill.dirs", Kind: "string", Value: strings.Join(c.Gateway.Watcher.Skill.Dirs, ",")},
			{Label: "── Plugin ──", Kind: "header"},
			{Label: "Enabled", Key: "gateway.watcher.plugin.enabled", Kind: "bool", Value: fmt.Sprintf("%v", c.Gateway.Watcher.Plugin.Enabled)},
			{Label: "Take Action", Key: "gateway.watcher.plugin.take_action", Kind: "bool", Value: fmt.Sprintf("%v", c.Gateway.Watcher.Plugin.TakeAction)},
			{Label: "Dirs", Key: "gateway.watcher.plugin.dirs", Kind: "string", Value: strings.Join(c.Gateway.Watcher.Plugin.Dirs, ",")},
			{Label: "── MCP ──", Kind: "header"},
			{Label: "Take Action", Key: "gateway.watcher.mcp.take_action", Kind: "bool", Value: fmt.Sprintf("%v", c.Gateway.Watcher.MCP.TakeAction)},
		}},
		{Name: "Gateway Watchdog", Fields: []configField{
			{Label: "Enabled", Key: "gateway.watchdog.enabled", Kind: "bool", Value: fmt.Sprintf("%v", c.Gateway.Watchdog.Enabled)},
			{Label: "Interval (s)", Key: "gateway.watchdog.interval", Kind: "int", Value: fmt.Sprintf("%d", c.Gateway.Watchdog.Interval)},
			{Label: "Debounce (failures)", Key: "gateway.watchdog.debounce", Kind: "int", Value: fmt.Sprintf("%d", c.Gateway.Watchdog.Debounce)},
		}},
		// Audit sinks live in their own list-based section editor (Phase
		// 3.3). The single-key-per-row form below cannot represent the
		// audit_sinks[] schema without losing per-sink kind/filter
		// metadata, so we surface a read-only summary here and direct
		// the operator to the dedicated editor.
		{Name: "Audit Sinks", Fields: auditSinkSummaryFields(c)},
		// Webhooks: notifier list (``webhooks[]``) is managed via the
		// ``setup webhook`` wizard + CLI. Inline single-key edits can't
		// represent the per-entry schema (type, secret_env, events,
		// etc.) and re-hydrating secrets in a TUI form is out of scope,
		// so we expose a read-only summary here and route operators to
		// the dedicated wizard.
		{Name: "Webhooks", Fields: webhookSummaryFields(c)},
		{Name: "OTel", Fields: otelFields(c)},
		// Actions matrix: three parallel 5×3 tables that drive the
		// admission gate's per-severity response. Rather than render
		// three separate 15-row blocks we build them with a shared
		// helper so the column layout, option lists, and key names
		// stay identical. When the CLI grows a new severity or
		// action column, this is the one place to change.
		{Name: "Skill Actions", Fields: actionMatrixFields("skill_actions", c.SkillActions)},
		{Name: "MCP Actions", Fields: actionMatrixFields("mcp_actions", c.MCPActions)},
		{Name: "Plugin Actions", Fields: actionMatrixFields("plugin_actions", c.PluginActions)},
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

// IsSinkEditorActive reports whether the Audit Sinks interactive
// sub-mode is currently visible. app.go routes keys through the
// setup panel whenever this is true so the editor owns bindings
// like 'e' / 'd' / 'r' / 't' / 'a' / 'm' that would otherwise be
// captured by the global palette or the panel-switch shortcuts.
func (p *SetupPanel) IsSinkEditorActive() bool {
	return p.sinkEditor.IsActive()
}

// IsWebhookEditorActive is the webhook counterpart to
// IsSinkEditorActive. Both sub-modes are mutually exclusive —
// IsEditorActive below hides this detail from app.go.
func (p *SetupPanel) IsWebhookEditorActive() bool {
	return p.webhookEditor.IsActive()
}

// IsEditorActive reports whether either list-mode editor is visible.
// Kept so app.go can gate panel-switch hotkeys with a single check.
func (p *SetupPanel) IsEditorActive() bool {
	return p.sinkEditor.IsActive() || p.webhookEditor.IsActive()
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
			// If the finished wizard was triggered from the sinks
			// editor, re-open the editor with a refreshed list so
			// the operator resumes where they left off.
			if p.sinkEditorResume {
				p.sinkEditorResume = false
				p.sinkEditor.ResumeAfterCommand()
				p.sinkEditor.DrainResume()
				p.sinkEditor.active = true
			}
			if p.webhookEditorResume {
				p.webhookEditorResume = false
				p.webhookEditor.ResumeAfterCommand()
				p.webhookEditor.DrainResume()
				p.webhookEditor.active = true
			}
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

	// Audit Sinks sub-mode editor runs inside the Setup panel.
	// Route all keys there when active.
	if p.sinkEditor.IsActive() {
		runCmd, binary, args, displayName = p.sinkEditor.HandleKey(key)
		// User pressed 'a' — open the Observability wizard and let
		// the editor handoff state drain naturally.
		if p.sinkEditor.WantsObservabilityWizard() {
			p.showWizardForm(wizardObservability)
			return false, "", nil, ""
		}
		if runCmd {
			// Re-use the wizard output terminal for streaming CLI
			// output — the editor itself is list-only, and making a
			// dedicated pty view would duplicate the wizard UI.
			p.wizRunning = true
			p.wizRunIdx = -1
			p.wizOutput = []string{
				fmt.Sprintf("-- Running: %s %s --", binary, strings.Join(args, " ")),
				"",
			}
			p.wizScroll = 0
			p.sinkEditorResume = true
			// Hide the editor while the command streams; it will
			// be re-opened on ESC after WizardFinished.
			p.sinkEditor.active = false
		}
		return runCmd, binary, args, displayName
	}

	// Webhooks sub-mode editor — same pattern as Audit Sinks.
	if p.webhookEditor.IsActive() {
		runCmd, binary, args, displayName = p.webhookEditor.HandleKey(key)
		if p.webhookEditor.WantsWebhookWizard() {
			p.showWizardForm(wizardWebhook)
			return false, "", nil, ""
		}
		if runCmd {
			p.wizRunning = true
			p.wizRunIdx = -1
			p.wizOutput = []string{
				fmt.Sprintf("-- Running: %s %s --", binary, strings.Join(args, " ")),
				"",
			}
			p.wizScroll = 0
			p.webhookEditorResume = true
			p.webhookEditor.active = false
		}
		return runCmd, binary, args, displayName
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
	p.wizFormError = ""
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

	// Any navigation/edit keystroke clears a stale validation banner
	// — the user is acting on the feedback, no need to keep shouting.
	p.wizFormError = ""

	switch key {
	case "esc":
		p.wizFormActive = false
		p.wizFormFields = nil
		p.wizFormError = ""
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
		case "preset":
			// Cycling the preset rebuilds the entire form so the
			// prompts match the selected destination. Cursor is
			// pinned to the preset row so the operator can keep
			// cycling without losing their place.
			if len(f.Options) > 0 {
				cur := 0
				for i, o := range f.Options {
					if o == f.Value {
						cur = i
						break
					}
				}
				next := f.Options[(cur+1)%len(f.Options)]
				p.wizFormFields = observabilityWizardFields(next)
				p.wizFormCursor = 0
			}
		case "whtype":
			// Same behaviour as "preset" but rebuilds via
			// webhookWizardFields so per-type prompts (room_id,
			// secret_env, etc.) come and go with the selection.
			if len(f.Options) > 0 {
				cur := 0
				for i, o := range f.Options {
					if o == f.Value {
						cur = i
						break
					}
				}
				next := f.Options[(cur+1)%len(f.Options)]
				p.wizFormFields = webhookWizardFields(next)
				p.wizFormCursor = 0
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

	// Validate required fields before shelling out. The non-interactive
	// CLI cannot prompt the user, so missing required inputs would
	// either produce a writer ValueError (template-rendered presets)
	// or write a half-broken sink. Block submit and surface the list
	// inline so the user can fix it without leaving the form.
	if missing := p.missingRequiredFields(); len(missing) > 0 {
		p.wizFormError = "Missing required field(s): " + strings.Join(missing, ", ")
		// Park the cursor on the first missing field so the user
		// can hit Enter and start typing immediately.
		for i, f := range p.wizFormFields {
			if f.Label == missing[0] {
				p.wizFormCursor = i
				break
			}
		}
		return false, "", nil, ""
	}
	p.wizFormError = ""

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

// missingRequiredFields returns labels of Required fields whose Value
// is empty. Bool/section/preset kinds are never required (booleans
// always have a defined yes/no value; presets are always set).
func (p *SetupPanel) missingRequiredFields() []string {
	var missing []string
	for _, f := range p.wizFormFields {
		if !f.Required {
			continue
		}
		switch f.Kind {
		case "section", "preset", "whtype", "bool":
			continue
		}
		if strings.TrimSpace(f.Value) == "" {
			missing = append(missing, f.Label)
		}
	}
	return missing
}

func (p *SetupPanel) buildWizardArgs(idx int) []string {
	base := make([]string, len(wizardCommands[idx]))
	copy(base, wizardCommands[idx])

	// Observability: extract the preset id and insert it positionally
	// before the --non-interactive flag. Dry-run is always last so the
	// preview lands at the end of the output pane.
	if idx == wizardObservability {
		presetID := ""
		for _, f := range p.wizFormFields {
			if f.Kind == "preset" {
				presetID = f.Value
				break
			}
		}
		if presetID != "" {
			base = append(base, presetID)
		}
	}

	// Webhook: extract the channel type (slack/pagerduty/webex/generic)
	// from the whtype picker and insert it positionally after ``add``.
	// The CLI surface is ``defenseclaw setup webhook add <type>``.
	if idx == wizardWebhook {
		channelType := ""
		for _, f := range p.wizFormFields {
			if f.Kind == "whtype" {
				channelType = f.Value
				break
			}
		}
		if channelType != "" {
			base = append(base, channelType)
		}
	}

	base = append(base, "--non-interactive")

	// For guardrail wizard, combine Provider + Model into --judge-model provider/model
	var judgeProvider, judgeModel string

	// Observability has different "skip" semantics: every non-bool
	// input feeds the writer's inputs dict verbatim, so we must pass
	// even values that match the form default — otherwise a user who
	// keeps `realm=us1` ends up with a CLI invocation missing
	// --realm and the writer raises KeyError when rendering the
	// endpoint template. Webhook follows the same rule so defaults
	// (min-severity=HIGH, events=…, timeout=10) land in the YAML
	// even when the user never moves the cursor.
	isObservability := idx == wizardObservability
	isWebhook := idx == wizardWebhook
	alwaysPassDefaults := isObservability || isWebhook

	for _, f := range p.wizFormFields {
		switch f.Kind {
		case "section", "preset", "whtype":
			// Section dividers are cosmetic; preset/whtype are
			// already consumed as positionals above.
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

		switch f.Kind {
		case "bool":
			// Bool defaults match the CLI's defaults, so we only
			// need to send the toggle when the user changed it.
			if f.Value == f.Default {
				continue
			}
			if f.Value == "yes" && f.Flag != "" {
				base = append(base, f.Flag)
			} else if f.Value == "no" && f.NoFlag != "" {
				base = append(base, f.NoFlag)
			}
		case "string", "int", "choice", "password":
			if f.Value == "" || f.Flag == "" {
				continue
			}
			if !alwaysPassDefaults && f.Value == f.Default && !f.Required {
				continue
			}
			base = append(base, f.Flag, f.Value)
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
	case "E":
		// Open the appropriate interactive editor based on the
		// active section. The config form can't represent the
		// per-entry schemas (see auditSinkSummaryFields /
		// webhookSummaryFields docstrings), so this key transitions
		// into a purpose-built list mode.
		switch sec := p.currentSection(); {
		case sec == nil:
			// nothing
		case sec.Name == "Audit Sinks":
			p.sinkEditor.Open()
			return false, "", nil, ""
		case sec.Name == "Webhooks":
			p.webhookEditor.Open()
			return false, "", nil, ""
		}
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
	case wizardObservability:
		return observabilityWizardFields("splunk-o11y")
	case wizardWebhook:
		return webhookWizardFields("slack")
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

// observabilityWizardFields builds the Observability wizard form for a
// given preset. The first field is always the preset picker (Kind
// "preset") followed by the preset-specific prompts and a secret field
// when the preset declares a token_env.
//
// Field schemas here mirror
// cli/defenseclaw/observability/presets.py. Drift between the two would
// show up as "unknown flag" errors from the CLI — the Python side is
// the source of truth, Go is the UI layer.
func observabilityWizardFields(presetID string) []wizardFormField {
	presetOpts := make([]string, 0, len(observabilityPresets))
	for _, p := range observabilityPresets {
		presetOpts = append(presetOpts, p[0])
	}
	fields := []wizardFormField{
		{
			Label:   "Preset",
			Flag:    "", // positional — handled in buildWizardArgs
			Kind:    "preset",
			Options: presetOpts,
			Value:   presetID,
			Default: presetID,
			Hint:    "Destination type. Changing this rebuilds the form below.",
		},
		{Label: "Name (optional)", Flag: "--name", Kind: "string", Hint: "Override auto-derived destination name"},
		{Label: "Enabled", Flag: "--enabled", NoFlag: "--disabled", Kind: "bool", Default: "yes", Value: "yes"},
		{Label: "Dry Run", Flag: "--dry-run", Kind: "bool", Default: "no", Value: "no", Hint: "Preview without writing"},
	}

	// Preset-specific prompts — keep in strict lockstep with
	// presets.py::Preset.prompts. Hints mirror the CLI descriptions.
	//
	// Required=true is reserved for inputs the writer cannot synthesize
	// from a default: template-rendered hostnames (realm/site/region/
	// dataset), the generic OTLP endpoint, and the webhook URL. The
	// writer raises ValueError for these when missing, so we block
	// submit before the user discovers it in the run pane.
	switch presetID {
	case "splunk-o11y":
		fields = append(fields,
			wizardFormField{Label: "Realm", Flag: "--realm", Kind: "string", Default: "us1", Value: "us1", Required: true, Hint: "Splunk O11y realm (us1, us0, eu0)"},
			wizardFormField{Label: "Signals", Flag: "--signals", Kind: "string", Default: "traces,metrics", Value: "traces,metrics", Hint: "Comma-separated: traces,metrics,logs"},
			wizardFormField{Label: "Access Token", Flag: "--token", Kind: "password", Hint: "Splunk Observability access token (leave blank if already in $SPLUNK_ACCESS_TOKEN)"},
		)
	case "splunk-hec":
		fields = append(fields,
			wizardFormField{Label: "Host", Flag: "--host", Kind: "string", Default: "localhost", Value: "localhost", Required: true},
			wizardFormField{Label: "Port", Flag: "--port", Kind: "int", Default: "8088", Value: "8088", Required: true},
			wizardFormField{Label: "Index", Flag: "--index", Kind: "string", Default: "defenseclaw", Value: "defenseclaw"},
			wizardFormField{Label: "Source", Flag: "--source", Kind: "string", Default: "defenseclaw", Value: "defenseclaw"},
			wizardFormField{Label: "Sourcetype", Flag: "--sourcetype", Kind: "string", Default: "_json", Value: "_json"},
			wizardFormField{Label: "Verify TLS", Flag: "--verify-tls", NoFlag: "--no-verify-tls", Kind: "bool", Default: "no", Value: "no"},
			wizardFormField{Label: "HEC Token", Flag: "--token", Kind: "password", Hint: "Splunk HEC token (leave blank if already in $DEFENSECLAW_SPLUNK_HEC_TOKEN)"},
		)
	case "datadog":
		fields = append(fields,
			wizardFormField{Label: "Site", Flag: "--site", Kind: "string", Default: "us5", Value: "us5", Required: true, Hint: "us1, us3, us5, eu, ap1"},
			wizardFormField{Label: "Signals", Flag: "--signals", Kind: "string", Default: "traces,metrics,logs", Value: "traces,metrics,logs"},
			wizardFormField{Label: "API Key", Flag: "--token", Kind: "password", Hint: "Datadog API key (leave blank if already in $DD_API_KEY)"},
		)
	case "honeycomb":
		fields = append(fields,
			wizardFormField{Label: "Dataset", Flag: "--dataset", Kind: "string", Default: "defenseclaw", Value: "defenseclaw", Required: true},
			wizardFormField{Label: "Signals", Flag: "--signals", Kind: "string", Default: "traces,metrics,logs", Value: "traces,metrics,logs"},
			wizardFormField{Label: "API Key", Flag: "--token", Kind: "password", Hint: "Honeycomb API key (leave blank if already in $HONEYCOMB_API_KEY)"},
		)
	case "newrelic":
		fields = append(fields,
			wizardFormField{Label: "Region", Flag: "--region", Kind: "choice", Options: []string{"us", "eu"}, Default: "us", Value: "us", Required: true},
			wizardFormField{Label: "Signals", Flag: "--signals", Kind: "string", Default: "traces,metrics,logs", Value: "traces,metrics,logs"},
			wizardFormField{Label: "License Key", Flag: "--token", Kind: "password", Hint: "New Relic license key (leave blank if already in $NEW_RELIC_LICENSE_KEY)"},
		)
	case "grafana-cloud":
		fields = append(fields,
			wizardFormField{Label: "Region/Zone", Flag: "--region", Kind: "string", Default: "prod-us-east-0", Value: "prod-us-east-0", Required: true},
			wizardFormField{Label: "Signals", Flag: "--signals", Kind: "string", Default: "traces,metrics,logs", Value: "traces,metrics,logs"},
			wizardFormField{Label: "OTLP Token", Flag: "--token", Kind: "password", Hint: "base64(instance_id:token) (leave blank if already in $GRAFANA_OTLP_TOKEN)"},
		)
	case "otlp":
		fields = append(fields,
			wizardFormField{Label: "Endpoint", Flag: "--endpoint", Kind: "string", Required: true, Hint: "host:port or full URL (e.g. otel.example.com:4317)"},
			wizardFormField{Label: "Protocol", Flag: "--protocol", Kind: "choice", Options: []string{"grpc", "http"}, Default: "grpc", Value: "grpc"},
			wizardFormField{Label: "Target", Flag: "--target", Kind: "choice", Options: []string{"otel", "audit_sinks"}, Default: "otel", Value: "otel", Hint: "otel=exporter, audit_sinks=log forwarder"},
			wizardFormField{Label: "Signals", Flag: "--signals", Kind: "string", Default: "traces,metrics,logs", Value: "traces,metrics,logs", Hint: "Only used when target=otel"},
		)
	case "webhook":
		fields = append(fields,
			wizardFormField{Label: "URL", Flag: "--url", Kind: "string", Required: true, Hint: "https://example.com/webhook"},
			wizardFormField{Label: "Method", Flag: "--method", Kind: "choice", Options: []string{"POST", "PUT"}, Default: "POST", Value: "POST"},
			wizardFormField{Label: "Verify TLS", Flag: "--verify-tls", NoFlag: "--no-verify-tls", Kind: "bool", Default: "yes", Value: "yes"},
			wizardFormField{Label: "Bearer Token (optional)", Flag: "--token", Kind: "password", Hint: "Sent as Authorization: Bearer <token>"},
		)
	}

	return fields
}

// webhookTypes mirrors cli/defenseclaw/webhooks/writer.py::VALID_TYPES.
// Ordering drives the default cursor position in the wizard picker and
// matches the CLI's ``add <type>`` argument choices so both front-ends
// feel identical.
var webhookTypes = [][2]string{
	{"slack", "Slack (incoming webhook)"},
	{"pagerduty", "PagerDuty (Events API v2)"},
	{"webex", "Cisco Webex (bot)"},
	{"generic", "Generic HMAC-signed"},
}

// webhookWizardFields builds the Webhooks wizard form for a given
// channel type. First field is the type picker ("whtype") — changing
// it rebuilds the form below via handleFormKey's rebuild branch.
//
// Required=true is reserved for inputs the writer cannot synthesize:
// the URL is always required; PagerDuty/Webex demand ``secret-env``;
// Webex additionally requires ``room-id``. These line up with
// webhooks/writer.py::apply_webhook's server-side validation so the
// TUI catches missing fields before the CLI ever runs.
func webhookWizardFields(channelType string) []wizardFormField {
	typeOpts := make([]string, 0, len(webhookTypes))
	for _, t := range webhookTypes {
		typeOpts = append(typeOpts, t[0])
	}

	fields := []wizardFormField{
		{
			Label:   "Type",
			Flag:    "", // positional — handled in buildWizardArgs
			Kind:    "whtype",
			Options: typeOpts,
			Value:   channelType,
			Default: channelType,
			Hint:    "Channel type. Changing this rebuilds the form below.",
		},
		{Label: "Name (optional)", Flag: "--name", Kind: "string", Hint: "Override auto-derived name (default: <type>-<host>)"},
		{Label: "URL", Flag: "--url", Kind: "string", Required: true, Hint: "Webhook endpoint URL (https)"},
		{Label: "Enabled", Flag: "--enabled", NoFlag: "--disabled", Kind: "bool", Default: "yes", Value: "yes"},
		{Label: "Min Severity", Flag: "--min-severity", Kind: "choice", Options: []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}, Default: "HIGH", Value: "HIGH"},
		{Label: "Events", Flag: "--events", Kind: "string", Default: "block,scan,guardrail,drift,health", Value: "block,scan,guardrail,drift,health", Hint: "Comma-separated (block,scan,guardrail,drift,health)"},
		{Label: "Timeout (seconds)", Flag: "--timeout-seconds", Kind: "int", Default: "10", Value: "10"},
		{Label: "Cooldown (seconds)", Flag: "--cooldown-seconds", Kind: "string", Hint: "Blank=runtime default (300s), 0=disabled, N=override"},
		{Label: "Dry Run", Flag: "--dry-run", Kind: "bool", Default: "no", Value: "no", Hint: "Preview without writing"},
	}

	// Type-specific prompts. Labels + defaults mirror the CLI prompts in
	// cmd_setup_webhook.py so users see consistent copy across front-ends.
	switch channelType {
	case "slack":
		fields = append(fields,
			wizardFormField{Label: "Secret env (optional)", Flag: "--secret-env", Kind: "string", Hint: "Env var NAME for signed-secret flow (optional for Slack)"},
		)
	case "pagerduty":
		fields = append(fields,
			wizardFormField{Label: "Routing key env", Flag: "--secret-env", Kind: "string", Default: "DEFENSECLAW_PD_ROUTING_KEY", Value: "DEFENSECLAW_PD_ROUTING_KEY", Required: true, Hint: "Env var NAME holding the PagerDuty Events API v2 routing key"},
		)
	case "webex":
		fields = append(fields,
			wizardFormField{Label: "Bot token env", Flag: "--secret-env", Kind: "string", Default: "DEFENSECLAW_WEBEX_TOKEN", Value: "DEFENSECLAW_WEBEX_TOKEN", Required: true, Hint: "Env var NAME holding the Webex bot token"},
			wizardFormField{Label: "Room ID", Flag: "--room-id", Kind: "string", Required: true, Hint: "Target Webex room/space ID"},
		)
	case "generic":
		fields = append(fields,
			wizardFormField{Label: "HMAC secret env (optional)", Flag: "--secret-env", Kind: "string", Default: "DEFENSECLAW_WEBHOOK_SECRET", Value: "DEFENSECLAW_WEBHOOK_SECRET", Hint: "Env var NAME for HMAC-SHA256 signing; blank disables signing"},
		)
	}

	return fields
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
	p.sinkEditor.SetSize(width, height)
	p.webhookEditor.SetSize(width, height)

	if p.wizFormActive {
		return p.renderWizardForm()
	}

	if p.wizRunning || len(p.wizOutput) > 0 {
		return p.renderWizardTerminal()
	}

	if p.sinkEditor.IsActive() {
		return p.sinkEditor.View()
	}
	if p.webhookEditor.IsActive() {
		return p.webhookEditor.View()
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
	b.WriteString(bold.Render("  -- " + wizName + " Setup --"))
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

		// Required-but-empty fields get a "•" marker in the label
		// gutter so the user can spot them while scrolling. We use
		// the '*' modifier for changed values as before, with a
		// red '!' winning when both apply (changed but empty —
		// e.g. user cleared a default).
		labelText := f.Label
		if f.Required && strings.TrimSpace(f.Value) == "" {
			labelText = "• " + labelText
		} else if f.Required {
			labelText = "  " + labelText
		}
		label := fmt.Sprintf("  %-24s", labelText)

		mod := " "
		switch {
		case f.Required && strings.TrimSpace(f.Value) == "":
			mod = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("196")).Render("!")
		case f.Value != f.Default && f.Default != "":
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
			case "preset":
				// Emphasise the picker so users see it's the row
				// that drives the rest of the form.
				label := f.Value
				for _, p := range observabilityPresets {
					if p[0] == f.Value {
						label = fmt.Sprintf("%s (%s)", p[1], p[0])
						break
					}
				}
				val = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("213")).Render(label)
			case "whtype":
				// Same as "preset" but for the webhook wizard; its
				// options come from webhookTypes so we look up the
				// display label there.
				label := f.Value
				for _, t := range webhookTypes {
					if t[0] == f.Value {
						label = fmt.Sprintf("%s (%s)", t[1], t[0])
						break
					}
				}
				val = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("213")).Render(label)
			case "password":
				// Secret-like field: render a mask so the value
				// doesn't leak into TUI screen recordings or bug
				// reports. The underlying CLI still sees the
				// plaintext value via --token.
				if f.Value == "" {
					val = dim.Render("(empty)")
				} else if len(f.Value) <= 4 {
					val = dim.Render("****")
				} else {
					val = dim.Render("****" + f.Value[len(f.Value)-4:])
				}
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

	if p.wizFormError != "" {
		errStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("230")).Background(lipgloss.Color("196")).Padding(0, 1)
		b.WriteString("  " + errStyle.Render(p.wizFormError))
		b.WriteString("\n\n")
	}

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

// otelFields builds the full OTel section — globals, TLS, per-signal
// overrides, batch tuning, and resource summary. Keeping this in one
// place makes it trivial to spot-check against config.OTelConfig when
// the schema grows a new knob.
//
// Per-signal protocol/url_path are exposed because OTLP-HTTP
// deployments commonly need one endpoint but three different
// `/v1/traces`, `/v1/logs`, `/v1/metrics` paths. Batch sizing shows up
// because it's the #1 tuning knob when an operator is trying to stop
// a collector from back-pressuring on high-throughput gates.
//
// Headers and Resource.Attributes are map-shaped; we render summaries
// here (with header values redacted so tokens don't end up in screen
// recordings) and route mutation through the CLI wizard, which is
// schema-aware and writes the full envelope.
func otelFields(c *config.Config) []configField {
	f := []configField{
		{Label: "── Globals ──", Kind: "header"},
		{Label: "Enabled", Key: "otel.enabled", Kind: "bool", Value: fmt.Sprintf("%v", c.OTel.Enabled)},
		{Label: "Protocol", Key: "otel.protocol", Kind: "choice", Options: []string{"grpc", "http/protobuf"}, Value: c.OTel.Protocol},
		{Label: "Endpoint", Key: "otel.endpoint", Kind: "string", Value: c.OTel.Endpoint},
		{Label: "TLS Insecure", Key: "otel.tls.insecure", Kind: "bool", Value: fmt.Sprintf("%v", c.OTel.TLS.Insecure)},
		{Label: "TLS CA Cert", Key: "otel.tls.ca_cert", Kind: "string", Value: c.OTel.TLS.CACert},
		{Label: "Headers (read-only)", Key: "otel.headers.summary", Kind: "header", Value: fmtOTelHeaders(c.OTel.Headers)},

		{Label: "── Traces ──", Kind: "header"},
		{Label: "Enabled", Key: "otel.traces.enabled", Kind: "bool", Value: fmt.Sprintf("%v", c.OTel.Traces.Enabled)},
		{Label: "Sampler", Key: "otel.traces.sampler", Kind: "choice", Options: []string{"always_on", "always_off", "traceidratio", "parentbased_always_on", "parentbased_always_off", "parentbased_traceidratio"}, Value: c.OTel.Traces.Sampler},
		{Label: "Sampler Arg", Key: "otel.traces.sampler_arg", Kind: "string", Value: c.OTel.Traces.SamplerArg},
		{Label: "Endpoint override", Key: "otel.traces.endpoint", Kind: "string", Value: c.OTel.Traces.Endpoint},
		{Label: "Protocol override", Key: "otel.traces.protocol", Kind: "choice", Options: []string{"", "grpc", "http/protobuf"}, Value: c.OTel.Traces.Protocol},
		{Label: "URL Path", Key: "otel.traces.url_path", Kind: "string", Value: c.OTel.Traces.URLPath},

		{Label: "── Logs ──", Kind: "header"},
		{Label: "Enabled", Key: "otel.logs.enabled", Kind: "bool", Value: fmt.Sprintf("%v", c.OTel.Logs.Enabled)},
		{Label: "Emit individual findings", Key: "otel.logs.emit_individual_findings", Kind: "bool", Value: fmt.Sprintf("%v", c.OTel.Logs.EmitIndividualFindings)},
		{Label: "Endpoint override", Key: "otel.logs.endpoint", Kind: "string", Value: c.OTel.Logs.Endpoint},
		{Label: "Protocol override", Key: "otel.logs.protocol", Kind: "choice", Options: []string{"", "grpc", "http/protobuf"}, Value: c.OTel.Logs.Protocol},
		{Label: "URL Path", Key: "otel.logs.url_path", Kind: "string", Value: c.OTel.Logs.URLPath},

		{Label: "── Metrics ──", Kind: "header"},
		{Label: "Enabled", Key: "otel.metrics.enabled", Kind: "bool", Value: fmt.Sprintf("%v", c.OTel.Metrics.Enabled)},
		{Label: "Export interval (s)", Key: "otel.metrics.export_interval_s", Kind: "int", Value: fmt.Sprintf("%d", c.OTel.Metrics.ExportIntervalS)},
		{Label: "Temporality", Key: "otel.metrics.temporality", Kind: "choice", Options: []string{"delta", "cumulative"}, Value: c.OTel.Metrics.Temporality},
		{Label: "Endpoint override", Key: "otel.metrics.endpoint", Kind: "string", Value: c.OTel.Metrics.Endpoint},
		{Label: "Protocol override", Key: "otel.metrics.protocol", Kind: "choice", Options: []string{"", "grpc", "http/protobuf"}, Value: c.OTel.Metrics.Protocol},
		{Label: "URL Path", Key: "otel.metrics.url_path", Kind: "string", Value: c.OTel.Metrics.URLPath},

		{Label: "── Batch ──", Kind: "header"},
		{Label: "Max export batch size", Key: "otel.batch.max_export_batch_size", Kind: "int", Value: fmt.Sprintf("%d", c.OTel.Batch.MaxExportBatchSize)},
		{Label: "Scheduled delay (ms)", Key: "otel.batch.scheduled_delay_ms", Kind: "int", Value: fmt.Sprintf("%d", c.OTel.Batch.ScheduledDelayMs)},
		{Label: "Max queue size", Key: "otel.batch.max_queue_size", Kind: "int", Value: fmt.Sprintf("%d", c.OTel.Batch.MaxQueueSize)},

		{Label: "── Resource ──", Kind: "header"},
		{Label: "Attributes (read-only)", Key: "otel.resource.summary", Kind: "header", Value: fmtOTelResource(c.OTel.Resource.Attributes)},
	}
	return f
}

// fmtOTelResource renders the resource attribute map as "k=v, k=v".
// service.* keys are shown in full since they're identity metadata
// and never secret; any other key is also shown verbatim because
// OTel resource attributes should not carry tokens.
func fmtOTelResource(attrs map[string]string) string {
	if len(attrs) == 0 {
		return "(none)"
	}
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+attrs[k])
	}
	return strings.Join(parts, ", ")
}

// fmtOTelHeaders renders the OTel headers map as a single summary
// line. Values are shown redacted — header values commonly carry
// tenant/bearer tokens that must not be splatted across a TUI
// snapshot that could end up in a screen recording or bug report.
func fmtOTelHeaders(h map[string]string) string {
	if len(h) == 0 {
		return "(none)"
	}
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ") + "  (values redacted)"
}

// actionMatrixConfig is the minimum surface actionMatrixFields needs
// from each of the three ${X}ActionsConfig types. The types are
// structurally identical but Go does not auto-promote them to a
// shared interface, so we declare an explicit trait here and let the
// concrete configs satisfy it via a type-specific accessor.
type actionMatrixConfig interface {
	severity(name string) config.SeverityAction
}

// Accessors — trivial but deliberate: they keep actionMatrixFields
// decoupled from any ordering / field-name change in the config
// structs. A compile error here is preferable to a silent wrong-field
// read under future renames.
type skillActionsView struct{ c config.SkillActionsConfig }

func (s skillActionsView) severity(name string) config.SeverityAction {
	switch name {
	case "critical":
		return s.c.Critical
	case "high":
		return s.c.High
	case "medium":
		return s.c.Medium
	case "low":
		return s.c.Low
	case "info":
		return s.c.Info
	}
	return config.SeverityAction{}
}

type mcpActionsView struct{ c config.MCPActionsConfig }

func (m mcpActionsView) severity(name string) config.SeverityAction {
	switch name {
	case "critical":
		return m.c.Critical
	case "high":
		return m.c.High
	case "medium":
		return m.c.Medium
	case "low":
		return m.c.Low
	case "info":
		return m.c.Info
	}
	return config.SeverityAction{}
}

type pluginActionsView struct{ c config.PluginActionsConfig }

func (p pluginActionsView) severity(name string) config.SeverityAction {
	switch name {
	case "critical":
		return p.c.Critical
	case "high":
		return p.c.High
	case "medium":
		return p.c.Medium
	case "low":
		return p.c.Low
	case "info":
		return p.c.Info
	}
	return config.SeverityAction{}
}

// actionMatrixFields renders the per-severity × per-column action
// matrix for skill_actions / mcp_actions / plugin_actions. The
// matrix is the admission gate's policy table — each severity maps
// to three independent knobs (file, runtime, install) that together
// decide what happens when the scanner returns a finding at that
// severity. We model it here as 15 choice rows (5 severities × 3
// columns) grouped by severity header. This is verbose but keeps the
// existing single-key configField form usable; a dedicated 2D grid
// editor would be a larger scope-creep win for not much UX gain.
//
// The keys use the same dotted path the Python / viper side uses
// (e.g. `skill_actions.critical.file`) so SaveConfig() writes back
// with no key translation.
//
// Dispatch routes `any` through a switch on the `prefix` argument to
// pick which config struct to read from. A generic function would
// save a few lines but the three types have no shared interface in
// internal/config and inventing one just for the TUI editor would
// bleed rendering concerns back into the model.
func actionMatrixFields(prefix string, cfg any) []configField {
	var view actionMatrixConfig
	switch prefix {
	case "skill_actions":
		view = skillActionsView{c: cfg.(config.SkillActionsConfig)}
	case "mcp_actions":
		view = mcpActionsView{c: cfg.(config.MCPActionsConfig)}
	case "plugin_actions":
		view = pluginActionsView{c: cfg.(config.PluginActionsConfig)}
	default:
		// Unknown prefix — return a single header so the TUI renders
		// something legible instead of an empty section. Defensive
		// against a future caller typo; callers in this package are
		// all compile-checked.
		return []configField{{Label: "(unknown actions prefix)", Key: prefix + ".error", Kind: "header"}}
	}

	// Severity order follows the scanner's severity enum (CRITICAL
	// first). Keeping display order == enum order avoids operator
	// confusion when the hint text says "most-severe → least".
	severities := []string{"critical", "high", "medium", "low", "info"}
	// Option sets are deliberately duplicated (not shared) because
	// install has three states while file/runtime have two. A single
	// `[]string{"none","quarantine","disable","enable","block","allow"}`
	// slice would compile but let the operator pick invalid
	// combinations per column.
	fileOpts := []string{string(config.FileActionNone), string(config.FileActionQuarantine)}
	runtimeOpts := []string{string(config.RuntimeEnable), string(config.RuntimeDisable)}
	installOpts := []string{string(config.InstallNone), string(config.InstallBlock), string(config.InstallAllow)}

	fields := make([]configField, 0, len(severities)*4+1)
	fields = append(fields, configField{
		Label: "──  " + strings.ToUpper(strings.ReplaceAll(prefix, "_", " ")) + " (severity → file · runtime · install)  ──",
		Key:   prefix + ".hint",
		Kind:  "header",
		Value: "file: quarantine/none · runtime: enable/disable · install: none/block/allow",
	})
	for _, sev := range severities {
		a := view.severity(sev)
		fields = append(fields,
			configField{
				Label:   strings.ToUpper(sev[:1]) + sev[1:] + " · file",
				Key:     prefix + "." + sev + ".file",
				Kind:    "choice",
				Value:   string(a.File),
				Options: fileOpts,
			},
			configField{
				Label:   strings.ToUpper(sev[:1]) + sev[1:] + " · runtime",
				Key:     prefix + "." + sev + ".runtime",
				Kind:    "choice",
				Value:   string(a.Runtime),
				Options: runtimeOpts,
			},
			configField{
				Label:   strings.ToUpper(sev[:1]) + sev[1:] + " · install",
				Key:     prefix + "." + sev + ".install",
				Kind:    "choice",
				Value:   string(a.Install),
				Options: installOpts,
			},
		)
	}
	return fields
}

// auditSinkSummaryFields renders one read-only row per declared audit
// sink. The single-key configField form cannot represent the
// audit_sinks[] schema (per-sink kind, filter, kind-specific block),
// so this view shows a summary and "no sinks configured" when empty.
func auditSinkSummaryFields(c *config.Config) []configField {
	// Always end with an edit-hint pointing operators to the YAML
	// path — in-TUI CRUD for nested list schemas is an explicit
	// non-goal for v1 and documented in docs/OBSERVABILITY.md.
	hint := configField{
		Label: "How to edit",
		Key:   "audit_sinks.hint",
		Kind:  "header",
		Value: "press E to open the interactive editor (enable/disable/remove/test) — or edit ~/.defenseclaw/config.yaml",
	}
	if len(c.AuditSinks) == 0 {
		return []configField{
			{
				Label: "Status",
				Key:   "audit_sinks.summary",
				Kind:  "header",
				Value: "no sinks configured",
			},
			hint,
		}
	}
	out := make([]configField, 0, len(c.AuditSinks)+1)
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
	out = append(out, hint)
	return out
}

// webhookSummaryFields renders one read-only row per notifier webhook
// (``webhooks[]``). Like audit sinks, the list-of-structs schema can't
// be represented as single-key configFields, and re-hydrating secrets
// (``secret_env``) inside a TUI form is out of scope for v1, so we
// show a summary and point at the wizard / CLI. See
// docs/OBSERVABILITY.md for the webhook vs audit-sink disambiguation.
func webhookSummaryFields(c *config.Config) []configField {
	hint := configField{
		Label: "How to edit",
		Key:   "webhooks.hint",
		Kind:  "header",
		Value: "press [E] for interactive editor, or run `defenseclaw setup webhook add|list|enable|disable|remove|test`",
	}
	if len(c.Webhooks) == 0 {
		return []configField{
			{
				Label: "Status",
				Key:   "webhooks.summary",
				Kind:  "header",
				Value: "no webhooks configured",
			},
			hint,
		}
	}
	out := make([]configField, 0, len(c.Webhooks)+1)
	for i, w := range c.Webhooks {
		state := "enabled"
		if !w.Enabled {
			state = "disabled"
		}
		kind := w.Type
		if kind == "" {
			kind = "webhook"
		}
		// Prefer the operator-chosen name (``defenseclaw setup webhook
		// add --name <slug>``) so the summary matches the CLI surface
		// used to edit it. Fall back to the ``kind[i]`` pattern only
		// for hand-edited configs that skipped ``name:`` entirely.
		label := w.Name
		if label == "" {
			label = fmt.Sprintf("%s[%d]", kind, i)
		} else {
			label = fmt.Sprintf("%s (%s)", label, kind)
		}
		summary := fmt.Sprintf("[%s] %s", state, w.URL)
		if w.MinSeverity != "" {
			summary += "  min=" + w.MinSeverity
		}
		if len(w.Events) > 0 {
			summary += "  events=" + strings.Join(w.Events, ",")
		}
		if w.SecretEnv != "" {
			summary += "  secret=$" + w.SecretEnv
		}
		if w.RoomID != "" {
			summary += "  room=" + w.RoomID
		}
		out = append(out, configField{
			Label: label,
			Key:   fmt.Sprintf("webhooks.%d", i),
			Kind:  "header",
			Value: summary,
		})
	}
	out = append(out, hint)
	return out
}
