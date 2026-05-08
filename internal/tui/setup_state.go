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
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

type ReadinessStatus string

const (
	ReadinessPass ReadinessStatus = "pass"
	ReadinessWarn ReadinessStatus = "warn"
	ReadinessFail ReadinessStatus = "fail"
)

type ReadinessCheck struct {
	Title  string
	Detail string
	Status ReadinessStatus
	Fix    *CommandIntent
}

type CredentialRow struct {
	EnvName     string `json:"env_name"`
	Feature     string `json:"feature"`
	Requirement string `json:"requirement"`
	Source      string `json:"source"`
	Set         bool   `json:"set"`
	Description string `json:"description"`
}

type CredentialSnapshot struct {
	Rows      []CredentialRow
	LoadedAt  time.Time
	Err       error
	Loading   bool
	ExitError string
}

type RestartQueue struct {
	Pending       bool
	Reason        string
	QueuedAt      time.Time
	LastStartedAt string
}

type ValidationSeverity string

const (
	ValidationOK      ValidationSeverity = "ok"
	ValidationWarning ValidationSeverity = "warning"
	ValidationError   ValidationSeverity = "error"
)

type ValidationResult struct {
	Severity ValidationSeverity
	Message  string
}

type ConfigDiffEntry struct {
	Key    string
	Before string
	After  string
	Secret bool
}

func ParseCredentialRows(raw []byte) ([]CredentialRow, error) {
	payload := trimCredentialJSON(raw)
	if len(strings.TrimSpace(string(payload))) == 0 {
		return nil, nil
	}
	var rows []CredentialRow
	if err := json.Unmarshal(payload, &rows); err != nil {
		return nil, err
	}
	for i := range rows {
		rows[i].Requirement = strings.ToLower(strings.TrimSpace(rows[i].Requirement))
		rows[i].Source = strings.TrimSpace(rows[i].Source)
	}
	return rows, nil
}

func trimCredentialJSON(raw []byte) []byte {
	s := strings.TrimSpace(string(raw))
	if s == "" || strings.HasPrefix(s, "[") {
		return []byte(s)
	}
	idx := strings.Index(s, "\n[")
	if idx >= 0 {
		return []byte(strings.TrimSpace(s[idx+1:]))
	}
	return []byte(s)
}

func MissingCredentialRows(rows []CredentialRow) []CredentialRow {
	var out []CredentialRow
	for _, row := range rows {
		if strings.EqualFold(row.Requirement, "required") && !row.Set {
			out = append(out, row)
		}
	}
	return out
}

func BuildReadinessChecks(cfg *config.Config, health *HealthSnapshot, doctor *DoctorCache, creds []CredentialRow, queue RestartQueue) []ReadinessCheck {
	intent := func(binary string, args []string, display, category string) *CommandIntent {
		i := NewCommandIntent(binary, args, display, category, "readiness")
		return &i
	}
	checks := []ReadinessCheck{}

	connector := ""
	if cfg != nil {
		connector = strings.TrimSpace(string(cfg.Claw.Mode))
	}
	if connector == "" {
		checks = append(checks, ReadinessCheck{
			Title:  "Active Connector",
			Detail: "No connector mode is configured.",
			Status: ReadinessFail,
			Fix:    intent("defenseclaw", []string{"setup"}, "setup Connector Setup", "setup"),
		})
	} else {
		checks = append(checks, ReadinessCheck{
			Title:  "Active Connector",
			Detail: connector + " configured",
			Status: ReadinessPass,
		})
	}

	if health == nil {
		checks = append(checks, ReadinessCheck{
			Title:  "Gateway / API Health",
			Detail: "Gateway health endpoint is offline.",
			Status: ReadinessFail,
			Fix:    intent("defenseclaw-gateway", []string{"start"}, "start", "daemon"),
		})
	} else if !stateHealthy(health.Gateway.State) || !stateHealthy(health.API.State) {
		checks = append(checks, ReadinessCheck{
			Title:  "Gateway / API Health",
			Detail: fmt.Sprintf("gateway=%s api=%s", health.Gateway.State, health.API.State),
			Status: ReadinessWarn,
			Fix:    intent("defenseclaw-gateway", []string{"restart"}, "restart", "daemon"),
		})
	} else {
		checks = append(checks, ReadinessCheck{
			Title:  "Gateway / API Health",
			Detail: "Gateway and API are healthy.",
			Status: ReadinessPass,
		})
	}

	if cfg == nil || !cfg.Guardrail.Enabled {
		checks = append(checks, ReadinessCheck{
			Title:  "Guardrail",
			Detail: "Guardrail is disabled or config is unavailable.",
			Status: ReadinessWarn,
			Fix:    intent("defenseclaw", []string{"setup", "guardrail"}, "setup guardrail", "setup"),
		})
	} else {
		mode := cfg.Guardrail.Mode
		if mode == "" {
			mode = "observe"
		}
		checks = append(checks, ReadinessCheck{Title: "Guardrail", Detail: "enabled in " + mode + " mode", Status: ReadinessPass})
	}

	missing := MissingCredentialRows(creds)
	if len(missing) == 0 && doctor != nil {
		for _, env := range doctor.MissingRequiredCredentials() {
			missing = append(missing, CredentialRow{EnvName: env, Requirement: "required"})
		}
	}
	if len(missing) > 0 {
		checks = append(checks, ReadinessCheck{
			Title:  "Required Credentials",
			Detail: fmt.Sprintf("%d required credential(s) missing", len(missing)),
			Status: ReadinessFail,
			Fix:    intent("defenseclaw", []string{"keys", "fill-missing"}, "keys fill-missing", "setup"),
		})
	} else {
		checks = append(checks, ReadinessCheck{Title: "Required Credentials", Detail: "No missing required credentials detected.", Status: ReadinessPass})
	}

	if cfg == nil || strings.TrimSpace(cfg.LLM.Provider) == "" || strings.TrimSpace(cfg.LLM.Model) == "" {
		checks = append(checks, ReadinessCheck{
			Title:  "LLM Config",
			Detail: "Unified llm.provider/model is incomplete.",
			Status: ReadinessWarn,
			Fix:    intent("defenseclaw", []string{"setup", "llm"}, "setup llm", "setup"),
		})
	} else {
		checks = append(checks, ReadinessCheck{Title: "LLM Config", Detail: cfg.LLM.Provider + "/" + cfg.LLM.Model, Status: ReadinessPass})
	}

	if cfg == nil || (strings.TrimSpace(cfg.Scanners.SkillScanner.Binary) == "" && strings.TrimSpace(cfg.Scanners.MCPScanner.Binary) == "" && strings.TrimSpace(cfg.Scanners.CodeGuard) == "") {
		checks = append(checks, ReadinessCheck{
			Title:  "Scanner Availability",
			Detail: "Scanner binaries are not configured.",
			Status: ReadinessWarn,
			Fix:    intent("defenseclaw", []string{"doctor", "--fix", "--yes"}, "doctor --fix", "setup"),
		})
	} else {
		checks = append(checks, ReadinessCheck{Title: "Scanner Availability", Detail: "Scanner config present.", Status: ReadinessPass})
	}

	if cfg == nil || (!cfg.OTel.Enabled && len(cfg.AuditSinks) == 0) {
		checks = append(checks, ReadinessCheck{
			Title:  "Observability / Audit Sinks",
			Detail: "No OTel exporter or audit sink is configured.",
			Status: ReadinessWarn,
			Fix:    intent("defenseclaw", []string{"setup", "local-observability", "status"}, "setup local-observability status", "setup"),
		})
	} else {
		checks = append(checks, ReadinessCheck{Title: "Observability / Audit Sinks", Detail: "Telemetry or audit sink configured.", Status: ReadinessPass})
	}

	if cfg != nil && cfg.AssetPolicy.Enabled && registryRequiredButEmpty(cfg) {
		checks = append(checks, ReadinessCheck{
			Title:  "Registry / Asset Policy",
			Detail: "Registry-required asset policy has no promoted registry entries.",
			Status: ReadinessWarn,
			Fix:    intent("defenseclaw", []string{"registry", "sync", "--all"}, "registry sync --all", "setup"),
		})
	} else {
		checks = append(checks, ReadinessCheck{Title: "Registry / Asset Policy", Detail: "Registry policy is ready or not required.", Status: ReadinessPass})
	}

	if queue.Pending {
		checks = append(checks, ReadinessCheck{
			Title:  "Restart Pending",
			Detail: queue.Reason,
			Status: ReadinessWarn,
			Fix:    intent("defenseclaw-gateway", []string{"restart"}, "restart", "daemon"),
		})
	} else {
		checks = append(checks, ReadinessCheck{Title: "Restart Pending", Detail: "No queued restart.", Status: ReadinessPass})
	}

	return checks
}

func stateHealthy(state string) bool {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "running", "ok", "healthy", "ready":
		return true
	default:
		return false
	}
}

func registryRequiredButEmpty(cfg *config.Config) bool {
	for _, p := range []config.AssetTypePolicy{cfg.AssetPolicy.Skill, cfg.AssetPolicy.MCP, cfg.AssetPolicy.Plugin} {
		if p.RegistryRequired && len(p.Registry) == 0 {
			return true
		}
	}
	return false
}

func ValidateConfigField(f configField) ValidationResult {
	v := strings.TrimSpace(f.Value)
	if f.Kind == "header" {
		return ValidationResult{Severity: ValidationOK}
	}
	switch f.Kind {
	case "bool":
		if v != "true" && v != "false" {
			return ValidationResult{Severity: ValidationError, Message: "expected true or false"}
		}
	case "choice":
		if len(f.Options) > 0 && !containsConfigOption(f.Options, v) {
			return ValidationResult{Severity: ValidationError, Message: "choose one of: " + strings.Join(f.Options, ", ")}
		}
	case "int":
		n, err := strconv.Atoi(v)
		if err != nil {
			return ValidationResult{Severity: ValidationError, Message: "expected an integer"}
		}
		if strings.Contains(f.Key, "port") && (n < 1 || n > 65535) {
			return ValidationResult{Severity: ValidationError, Message: "port must be between 1 and 65535"}
		}
		if strings.Contains(f.Key, "timeout") || strings.Contains(f.Key, "interval") || strings.Contains(f.Key, "retries") || strings.Contains(f.Key, "max_") {
			if n < 0 {
				return ValidationResult{Severity: ValidationError, Message: "value must be zero or greater"}
			}
		}
	}
	if IsConfigEnvNameField(f) {
		if v != "" && !LooksLikeEnvName(v) {
			if LooksLikeSecretValue(v) {
				return ValidationResult{Severity: ValidationWarning, Message: "this looks like a secret value, not an env var name"}
			}
			return ValidationResult{Severity: ValidationError, Message: "env var names must match A-Z, 0-9, and underscores"}
		}
	}
	if looksLikeURLField(f.Key) && v != "" {
		u, err := url.Parse(v)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return ValidationResult{Severity: ValidationError, Message: "expected a URL with scheme and host"}
		}
		if u.User != nil {
			return ValidationResult{Severity: ValidationError, Message: "URL must not embed credentials"}
		}
		if u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "grpc" {
			return ValidationResult{Severity: ValidationWarning, Message: "uncommon URL scheme"}
		}
	}
	if strings.Contains(f.Key, "dedup_window") && v != "" {
		if _, err := time.ParseDuration(v); err != nil {
			if _, atoiErr := strconv.Atoi(v); atoiErr != nil {
				return ValidationResult{Severity: ValidationError, Message: "duration must be like 30s, 1m, or a seconds integer"}
			}
		}
	}
	if strings.Contains(f.Key, "tls_skip_verify") && v == "true" {
		return ValidationResult{Severity: ValidationWarning, Message: "TLS verification is disabled; dev-only"}
	}
	if IsSecretConfigField(f) && f.Kind != "password" && LooksLikeSecretValue(v) {
		return ValidationResult{Severity: ValidationWarning, Message: "secret-like value will be saved inline"}
	}
	return ValidationResult{Severity: ValidationOK}
}

func looksLikeURLField(key string) bool {
	for _, marker := range []string{"url", "endpoint", "api_base", "base_url"} {
		if strings.Contains(key, marker) {
			return true
		}
	}
	return false
}

func containsConfigOption(options []string, value string) bool {
	for _, option := range options {
		if option == value {
			return true
		}
	}
	return false
}
