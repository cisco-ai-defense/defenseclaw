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
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// applyConfigField writes a single field value back to the Config struct
// based on the dot-path key (e.g. "gateway.port").
func applyConfigField(c *config.Config, key, val string) {
	boolVal := val == "true"
	intVal, _ := strconv.Atoi(val)

	switch key {
	// General
	case "data_dir":
		c.DataDir = val
	case "audit_db":
		c.AuditDB = val
	case "quarantine_dir":
		c.QuarantineDir = val
	case "plugin_dir":
		c.PluginDir = val
	case "policy_dir":
		c.PolicyDir = val
	case "environment":
		c.Environment = val
	// Unified top-level llm: block — the single source of truth
	// consumed by guardrail (Bifrost), MCP scanner, skill scanner,
	// and plugin scanner via Config.ResolveLLM(...). Writes here
	// take effect on the next scanner/guardrail invocation that
	// calls ResolveLLM; existing in-flight requests keep the values
	// they were initialized with.
	//
	// The redacted llm.api_key field is accepted so operators can
	// paste-then-persist a key when they'd rather not shell out to
	// set an env var, but llm.api_key_env (pointing at
	// DEFENSECLAW_LLM_KEY or a custom var in ~/.defenseclaw/.env)
	// is strongly preferred so secrets never land in config.yaml.
	case "llm.provider":
		c.LLM.Provider = val
	case "llm.model":
		c.LLM.Model = val
	case "llm.api_key":
		c.LLM.APIKey = val
	case "llm.api_key_env":
		c.LLM.APIKeyEnv = val
	case "llm.base_url":
		c.LLM.BaseURL = val
	case "llm.timeout":
		c.LLM.Timeout = intVal
	case "llm.max_retries":
		c.LLM.MaxRetries = intVal

	// Legacy v4 fallbacks. Still accepted from older TUI snapshots /
	// config files; the load-time migration in config.load() copies
	// them into c.LLM when the unified block is empty. We keep the
	// setters alive so `defenseclaw config set default_llm_model ...`
	// still works during the deprecation window, but the TUI now
	// surfaces these as read-only.
	case "default_llm_api_key_env":
		c.DefaultLLMAPIKeyEnv = val
	case "default_llm_model":
		c.DefaultLLMModel = val

	// Claw
	case "claw.mode":
		c.Claw.Mode = config.ClawMode(val)
	case "claw.home_dir":
		c.Claw.HomeDir = val
	case "claw.config_file":
		c.Claw.ConfigFile = val

	// Gateway
	case "gateway.host":
		c.Gateway.Host = val
	case "gateway.port":
		c.Gateway.Port = intVal
	case "gateway.api_port":
		c.Gateway.APIPort = intVal
	case "gateway.api_bind":
		c.Gateway.APIBind = val
	case "gateway.auto_approve_safe":
		c.Gateway.AutoApprove = boolVal
	case "gateway.tls":
		c.Gateway.TLS = boolVal
	case "gateway.tls_skip_verify":
		c.Gateway.TLSSkipVerify = boolVal
	case "gateway.reconnect_ms":
		c.Gateway.ReconnectMs = intVal
	case "gateway.max_reconnect_ms":
		c.Gateway.MaxReconnectMs = intVal
	case "gateway.approval_timeout_s":
		c.Gateway.ApprovalTimeout = intVal
	case "gateway.token_env":
		c.Gateway.TokenEnv = val
	case "gateway.device_key_file":
		c.Gateway.DeviceKeyFile = val

	// Guardrail
	case "guardrail.enabled":
		c.Guardrail.Enabled = boolVal
	case "guardrail.mode":
		c.Guardrail.Mode = val
	case "guardrail.scanner_mode":
		c.Guardrail.ScannerMode = val
	case "guardrail.host":
		c.Guardrail.Host = val
	case "guardrail.port":
		c.Guardrail.Port = intVal
	case "guardrail.model":
		c.Guardrail.Model = val
	case "guardrail.model_name":
		c.Guardrail.ModelName = val
	case "guardrail.original_model":
		c.Guardrail.OriginalModel = val
	case "guardrail.api_key_env":
		c.Guardrail.APIKeyEnv = val
	case "guardrail.api_base":
		c.Guardrail.APIBase = val
	case "guardrail.block_message":
		c.Guardrail.BlockMessage = val
	case "guardrail.retain_judge_bodies":
		c.Guardrail.RetainJudgeBodies = boolVal
	case "guardrail.detection_strategy":
		c.Guardrail.DetectionStrategy = val
	case "guardrail.detection_strategy_prompt":
		c.Guardrail.DetectionStrategyPrompt = val
	case "guardrail.detection_strategy_completion":
		c.Guardrail.DetectionStrategyCompletion = val
	case "guardrail.detection_strategy_tool_call":
		c.Guardrail.DetectionStrategyToolCall = val
	case "guardrail.stream_buffer_bytes":
		c.Guardrail.StreamBufferBytes = intVal
	case "guardrail.rule_pack_dir":
		c.Guardrail.RulePackDir = val
	case "guardrail.judge_sweep":
		c.Guardrail.JudgeSweep = boolVal

	// Judge
	case "guardrail.judge.enabled":
		c.Guardrail.Judge.Enabled = boolVal
	case "guardrail.judge.model":
		c.Guardrail.Judge.Model = val
	case "guardrail.judge.api_key_env":
		c.Guardrail.Judge.APIKeyEnv = val
	case "guardrail.judge.api_base":
		c.Guardrail.Judge.APIBase = val
	case "guardrail.judge.timeout":
		if f, err := strconv.ParseFloat(val, 64); err == nil {
			c.Guardrail.Judge.Timeout = f
		}
	case "guardrail.judge.adjudication_timeout":
		if f, err := strconv.ParseFloat(val, 64); err == nil {
			c.Guardrail.Judge.AdjudicationTimeout = f
		}
	case "guardrail.judge.injection":
		c.Guardrail.Judge.Injection = boolVal
	case "guardrail.judge.pii":
		c.Guardrail.Judge.PII = boolVal
	case "guardrail.judge.pii_prompt":
		c.Guardrail.Judge.PIIPrompt = boolVal
	case "guardrail.judge.pii_completion":
		c.Guardrail.Judge.PIICompletion = boolVal
	case "guardrail.judge.tool_injection":
		c.Guardrail.Judge.ToolInjection = boolVal
	case "guardrail.judge.fallbacks":
		if val == "" {
			c.Guardrail.Judge.Fallbacks = nil
		} else {
			c.Guardrail.Judge.Fallbacks = strings.Split(val, ",")
		}

	// Scanners — expanded for P2-#9 to cover every SkillScanner /
	// MCPScanner / Plugin / CodeGuard field the YAML schema
	// exposes. If the struct ever grows a new knob, add a case here
	// too; the fallback silently drops unknown keys, which would
	// feel like a bug at the UI level.
	case "scanners.skill_scanner.binary":
		c.Scanners.SkillScanner.Binary = val
	case "scanners.skill_scanner.policy":
		c.Scanners.SkillScanner.Policy = val
	case "scanners.skill_scanner.lenient":
		c.Scanners.SkillScanner.Lenient = boolVal
	case "scanners.skill_scanner.use_llm":
		c.Scanners.SkillScanner.UseLLM = boolVal
	case "scanners.skill_scanner.llm_consensus_runs":
		c.Scanners.SkillScanner.LLMConsensus = intVal
	case "scanners.skill_scanner.use_behavioral":
		c.Scanners.SkillScanner.UseBehavioral = boolVal
	case "scanners.skill_scanner.enable_meta":
		c.Scanners.SkillScanner.EnableMeta = boolVal
	case "scanners.skill_scanner.use_trigger":
		c.Scanners.SkillScanner.UseTrigger = boolVal
	case "scanners.skill_scanner.use_virustotal":
		c.Scanners.SkillScanner.UseVirusTotal = boolVal
	case "scanners.skill_scanner.virustotal_api_key_env":
		c.Scanners.SkillScanner.VirusTotalKeyEnv = val
	case "scanners.skill_scanner.use_aidefense":
		c.Scanners.SkillScanner.UseAIDefense = boolVal
	case "scanners.mcp_scanner.binary":
		c.Scanners.MCPScanner.Binary = val
	case "scanners.mcp_scanner.analyzers":
		c.Scanners.MCPScanner.Analyzers = val
	case "scanners.mcp_scanner.scan_prompts":
		c.Scanners.MCPScanner.ScanPrompts = boolVal
	case "scanners.mcp_scanner.scan_resources":
		c.Scanners.MCPScanner.ScanResources = boolVal
	case "scanners.mcp_scanner.scan_instructions":
		c.Scanners.MCPScanner.ScanInstructions = boolVal
	case "scanners.plugin_scanner":
		c.Scanners.PluginScanner = val
	case "scanners.codeguard":
		c.Scanners.CodeGuard = val

	// Gateway inline watcher (P2-#9). The watcher runs inside the
	// gateway process; its config governs directory watch / auto-
	// quarantine behaviour per resource type. Dirs are CSV on the
	// wire — we split here so a blank entry clears the list.
	case "gateway.watcher.enabled":
		c.Gateway.Watcher.Enabled = boolVal
	case "gateway.watcher.skill.enabled":
		c.Gateway.Watcher.Skill.Enabled = boolVal
	case "gateway.watcher.skill.take_action":
		c.Gateway.Watcher.Skill.TakeAction = boolVal
	case "gateway.watcher.skill.dirs":
		c.Gateway.Watcher.Skill.Dirs = splitCSV(val)
	case "gateway.watcher.plugin.enabled":
		c.Gateway.Watcher.Plugin.Enabled = boolVal
	case "gateway.watcher.plugin.take_action":
		c.Gateway.Watcher.Plugin.TakeAction = boolVal
	case "gateway.watcher.plugin.dirs":
		c.Gateway.Watcher.Plugin.Dirs = splitCSV(val)
	case "gateway.watcher.mcp.take_action":
		c.Gateway.Watcher.MCP.TakeAction = boolVal

	// Gateway watchdog (P2-#9).
	case "gateway.watchdog.enabled":
		c.Gateway.Watchdog.Enabled = boolVal
	case "gateway.watchdog.interval":
		c.Gateway.Watchdog.Interval = intVal
	case "gateway.watchdog.debounce":
		c.Gateway.Watchdog.Debounce = intVal

	// Audit sinks: declarative list-based config (audit_sinks[]).
	// Inline single-key edits don't make sense for the new schema —
	// CRUD lives in the dedicated audit-sinks editor (Phase 3.3, see
	// SinkEditorModel below). The single-key form would re-introduce
	// the old "one Splunk only" assumption we just removed.

	// OTel
	case "otel.enabled":
		c.OTel.Enabled = boolVal
	case "otel.protocol":
		c.OTel.Protocol = val
	case "otel.endpoint":
		c.OTel.Endpoint = val
	case "otel.tls.insecure":
		c.OTel.TLS.Insecure = boolVal
	case "otel.tls.ca_cert":
		c.OTel.TLS.CACert = val
	case "otel.traces.enabled":
		c.OTel.Traces.Enabled = boolVal
	case "otel.traces.sampler":
		c.OTel.Traces.Sampler = val
	case "otel.traces.sampler_arg":
		c.OTel.Traces.SamplerArg = val
	case "otel.traces.endpoint":
		c.OTel.Traces.Endpoint = val
	case "otel.traces.protocol":
		c.OTel.Traces.Protocol = val
	case "otel.traces.url_path":
		c.OTel.Traces.URLPath = val
	case "otel.logs.enabled":
		c.OTel.Logs.Enabled = boolVal
	case "otel.logs.emit_individual_findings":
		c.OTel.Logs.EmitIndividualFindings = boolVal
	case "otel.logs.endpoint":
		c.OTel.Logs.Endpoint = val
	case "otel.logs.protocol":
		c.OTel.Logs.Protocol = val
	case "otel.logs.url_path":
		c.OTel.Logs.URLPath = val
	case "otel.metrics.enabled":
		c.OTel.Metrics.Enabled = boolVal
	case "otel.metrics.export_interval_s":
		c.OTel.Metrics.ExportIntervalS = intVal
	case "otel.metrics.temporality":
		c.OTel.Metrics.Temporality = val
	case "otel.metrics.endpoint":
		c.OTel.Metrics.Endpoint = val
	case "otel.metrics.protocol":
		c.OTel.Metrics.Protocol = val
	case "otel.metrics.url_path":
		c.OTel.Metrics.URLPath = val
	case "otel.batch.max_export_batch_size":
		c.OTel.Batch.MaxExportBatchSize = intVal
	case "otel.batch.scheduled_delay_ms":
		c.OTel.Batch.ScheduledDelayMs = intVal
	case "otel.batch.max_queue_size":
		c.OTel.Batch.MaxQueueSize = intVal

	// Watch
	case "watch.debounce_ms":
		c.Watch.DebounceMs = intVal
	case "watch.auto_block":
		c.Watch.AutoBlock = boolVal
	case "watch.allow_list_bypass_scan":
		c.Watch.AllowListBypassScan = boolVal
	case "watch.rescan_enabled":
		c.Watch.RescanEnabled = boolVal
	case "watch.rescan_interval_min":
		c.Watch.RescanIntervalMin = intVal

	// OpenShell
	case "openshell.binary":
		c.OpenShell.Binary = val
	case "openshell.policy_dir":
		c.OpenShell.PolicyDir = val
	case "openshell.mode":
		c.OpenShell.Mode = val
	case "openshell.version":
		c.OpenShell.Version = val
	case "openshell.sandbox_home":
		c.OpenShell.SandboxHome = val
	case "openshell.auto_pair":
		// Tristate: "" clears the override (nil → defer to
		// ShouldAutoPair default=true); "true"/"false" land an
		// explicit pointer. Any other string (malformed edit) is
		// treated as clear so we never write a bogus value.
		c.OpenShell.AutoPair = parseTristateBool(val)
	case "openshell.host_networking":
		c.OpenShell.HostNetworking = parseTristateBool(val)

	// Inspect LLM — editable. api_key is accepted here so the
	// operator can paste-then-persist a fresh value, but the
	// configField is rendered with Kind=password so View() masks it.
	// Prefer api_key_env in steady state to avoid writing the
	// cleartext to ~/.defenseclaw/config.yaml.
	case "inspect_llm.provider":
		c.InspectLLM.Provider = val
	case "inspect_llm.model":
		c.InspectLLM.Model = val
	case "inspect_llm.api_key":
		c.InspectLLM.APIKey = val
	case "inspect_llm.api_key_env":
		c.InspectLLM.APIKeyEnv = val
	case "inspect_llm.base_url":
		c.InspectLLM.BaseURL = val
	case "inspect_llm.timeout":
		c.InspectLLM.Timeout = intVal
	case "inspect_llm.max_retries":
		c.InspectLLM.MaxRetries = intVal

		// Cisco AI Defense + Firewall are deliberately read-only in
		// the TUI. Their rows use Kind=header so they are never
		// routed here — see ciscoAIDefenseFields / firewallFields.
	}

	// Actions matrices are handled with a dotted-prefix fallback
	// because the 45-case switch above would quadruple the length
	// of this function with zero additional precision. The key
	// shape is `${prefix}.${severity}.${column}` — any malformed
	// key silently falls through, which is fine: it will also
	// fail the `f.Value != f.Original` diff check and never be
	// committed if the viper layer rejects it on Save.
	if strings.HasPrefix(key, "skill_actions.") ||
		strings.HasPrefix(key, "mcp_actions.") ||
		strings.HasPrefix(key, "plugin_actions.") {
		applyActionsField(c, key, val)
	}
}

// applyActionsField writes back to the five-severity × three-action
// matrix. Kept separate from applyConfigField so the switch there
// stays readable; doing the parse here localises all the string-to-
// enum coercion in one place.
func applyActionsField(c *config.Config, key, val string) {
	parts := strings.Split(key, ".")
	if len(parts) != 3 {
		return
	}
	prefix, sev, col := parts[0], parts[1], parts[2]

	// Resolve the pointer to the SeverityAction we need to mutate.
	// Using a pointer avoids the copy-then-assign dance that would
	// otherwise double the switch cases.
	var target *config.SeverityAction
	switch prefix {
	case "skill_actions":
		target = severityPtr(&c.SkillActions.Critical, &c.SkillActions.High, &c.SkillActions.Medium, &c.SkillActions.Low, &c.SkillActions.Info, sev)
	case "mcp_actions":
		target = severityPtr(&c.MCPActions.Critical, &c.MCPActions.High, &c.MCPActions.Medium, &c.MCPActions.Low, &c.MCPActions.Info, sev)
	case "plugin_actions":
		target = severityPtr(&c.PluginActions.Critical, &c.PluginActions.High, &c.PluginActions.Medium, &c.PluginActions.Low, &c.PluginActions.Info, sev)
	}
	if target == nil {
		return
	}
	switch col {
	case "file":
		target.File = config.FileAction(val)
	case "runtime":
		target.Runtime = config.RuntimeAction(val)
	case "install":
		target.Install = config.InstallAction(val)
	}
}

// parseTristateBool converts the choice value back to a *bool for
// the OpenShell tristate knobs (AutoPair, HostNetworking). The TUI
// renders these as three-way choices because the underlying *bool
// distinguishes "unset → code default" from "explicit false", and
// we need to round-trip all three states. Malformed values clear
// the override instead of panicking so a corrupted keystroke can
// never wedge the panel.
func parseTristateBool(val string) *bool {
	switch strings.TrimSpace(strings.ToLower(val)) {
	case "true":
		t := true
		return &t
	case "false":
		f := false
		return &f
	}
	return nil
}

// splitCSV splits "a, b , c" into ["a","b","c"]. Empty input
// returns nil (rather than [""]) so the resulting YAML stays clean
// when the operator clears the field — an empty string slice is
// omitted by go-yaml whereas [""] would serialise as `["" ]` and
// fail schema checks on the next reload.
func splitCSV(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// severityPtr picks the *SeverityAction that matches the severity
// name. Using a variadic map would cost an allocation per call; an
// explicit switch is cheaper and keeps the call-sites single-lined.
func severityPtr(critical, high, medium, low, info *config.SeverityAction, name string) *config.SeverityAction {
	switch name {
	case "critical":
		return critical
	case "high":
		return high
	case "medium":
		return medium
	case "low":
		return low
	case "info":
		return info
	}
	return nil
}
