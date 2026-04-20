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
	case "gateway.reconnect_ms":
		c.Gateway.ReconnectMs = intVal
	case "gateway.max_reconnect_ms":
		c.Gateway.MaxReconnectMs = intVal
	case "gateway.token_env":
		c.Gateway.TokenEnv = val

	// Guardrail
	case "guardrail.enabled":
		c.Guardrail.Enabled = boolVal
	case "guardrail.mode":
		c.Guardrail.Mode = val
	case "guardrail.scanner_mode":
		c.Guardrail.ScannerMode = val
	case "guardrail.port":
		c.Guardrail.Port = intVal
	case "guardrail.model":
		c.Guardrail.Model = val
	case "guardrail.api_key_env":
		c.Guardrail.APIKeyEnv = val
	case "guardrail.block_message":
		c.Guardrail.BlockMessage = val
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

	// Scanners
	case "scanners.skill_scanner.binary":
		c.Scanners.SkillScanner.Binary = val
	case "scanners.skill_scanner.use_llm":
		c.Scanners.SkillScanner.UseLLM = boolVal
	case "scanners.skill_scanner.use_behavioral":
		c.Scanners.SkillScanner.UseBehavioral = boolVal
	case "scanners.mcp_scanner.binary":
		c.Scanners.MCPScanner.Binary = val
	case "scanners.mcp_scanner.analyzers":
		c.Scanners.MCPScanner.Analyzers = val
	case "scanners.codeguard":
		c.Scanners.CodeGuard = val

	// Splunk
	case "splunk.enabled":
		c.Splunk.Enabled = boolVal
	case "splunk.hec_endpoint":
		c.Splunk.HECEndpoint = val
	case "splunk.hec_token_env":
		c.Splunk.HECTokenEnv = val
	case "splunk.index":
		c.Splunk.Index = val
	case "splunk.source":
		c.Splunk.Source = val
	case "splunk.verify_tls":
		c.Splunk.VerifyTLS = boolVal
	case "splunk.batch_size":
		c.Splunk.BatchSize = intVal

	// OTel
	case "otel.enabled":
		c.OTel.Enabled = boolVal
	case "otel.protocol":
		c.OTel.Protocol = val
	case "otel.endpoint":
		c.OTel.Endpoint = val
	case "otel.traces.enabled":
		c.OTel.Traces.Enabled = boolVal
	case "otel.logs.enabled":
		c.OTel.Logs.Enabled = boolVal
	case "otel.metrics.enabled":
		c.OTel.Metrics.Enabled = boolVal

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
	}
}
