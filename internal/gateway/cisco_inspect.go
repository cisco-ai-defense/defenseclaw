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

package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

var defaultEnabledRules = []map[string]string{
	{"rule_name": "Prompt Injection"},
	{"rule_name": "Harassment"},
	{"rule_name": "Hate Speech"},
	{"rule_name": "Profanity"},
	{"rule_name": "Sexual Content & Exploitation"},
	{"rule_name": "Social Division & Polarization"},
	{"rule_name": "Violence & Public Safety Threats"},
	{"rule_name": "Code Detection"},
}

// CiscoInspectClient calls the Cisco AI Defense Chat Inspection API.
type CiscoInspectClient struct {
	apiKey       string
	endpoint     string
	timeout      time.Duration
	enabledRules []map[string]string
	client       *http.Client
}

// NewCiscoInspectClient creates a client from the config. Returns nil if no
// API key is available.
func NewCiscoInspectClient(cfg *config.CiscoAIDefenseConfig, dotenvPath string) *CiscoInspectClient {
	apiKey := cfg.ResolvedAPIKey()
	if apiKey == "" {
		apiKey = ResolveAPIKey(cfg.APIKeyEnv, dotenvPath)
	}
	if apiKey == "" {
		return nil
	}

	endpoint := strings.TrimRight(cfg.Endpoint, "/")
	if endpoint == "" {
		endpoint = DefaultCiscoAIDefenseEndpoint
	}

	timeout := time.Duration(cfg.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = DefaultCiscoInspectTimeout
	}

	var rules []map[string]string
	if len(cfg.EnabledRules) > 0 {
		for _, r := range cfg.EnabledRules {
			rules = append(rules, map[string]string{"rule_name": r})
		}
	} else {
		rules = defaultEnabledRules
	}

	return &CiscoInspectClient{
		apiKey:       apiKey,
		endpoint:     endpoint,
		timeout:      timeout,
		enabledRules: rules,
		client:       &http.Client{Timeout: timeout},
	}
}

// Inspect sends messages to Cisco AI Defense and returns a normalized verdict.
// Returns nil on any error so the caller can fall back to local-only scanning.
func (c *CiscoInspectClient) Inspect(messages []ChatMessage) *ScanVerdict {
	if c == nil || c.apiKey == "" {
		return nil
	}

	chatMsgs := make([]map[string]string, len(messages))
	for i, m := range messages {
		chatMsgs[i] = map[string]string{"role": m.Role, "content": m.Content}
	}

	payload := map[string]interface{}{"messages": chatMsgs}
	if len(c.enabledRules) > 0 {
		payload["config"] = map[string]interface{}{"enabled_rules": c.enabledRules}
	}

	url := c.endpoint + CiscoInspectChatPath

	// Retry once without rules config if the key has pre-configured rules.
	triedWithoutRules := false
	for attempt := 0; attempt < 2; attempt++ {
		body, err := json.Marshal(payload)
		if err != nil {
			return nil
		}

		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return nil
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set(HeaderCiscoAIDefenseAPIKey, c.apiKey)

		resp, err := c.client.Do(req)
		if err != nil {
			fmt.Fprintf(defaultLogWriter, "  [cisco-ai-defense] error: %v\n", err)
			return nil
		}

		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, MaxCiscoResponseSize))
		resp.Body.Close()

		if resp.StatusCode == http.StatusBadRequest && !triedWithoutRules {
			lower := strings.ToLower(string(respBody))
			if strings.Contains(lower, "already has rules configured") ||
				strings.Contains(lower, "pre-configured") {
				delete(payload, "config")
				triedWithoutRules = true
				fmt.Fprintf(defaultLogWriter, "  [cisco-ai-defense] key has pre-configured rules, retrying without config\n")
				continue
			}
		}

		if resp.StatusCode != http.StatusOK {
			fmt.Fprintf(defaultLogWriter, "  [cisco-ai-defense] error: HTTP %d: %s\n",
				resp.StatusCode, string(respBody[:minInt(len(respBody), 200)]))
			return nil
		}

		var data map[string]interface{}
		if err := json.Unmarshal(respBody, &data); err != nil {
			return nil
		}
		return normalizeCiscoResponse(data)
	}
	return nil
}

func normalizeCiscoResponse(data map[string]interface{}) *ScanVerdict {
	isSafe, _ := data["is_safe"].(bool)
	apiAction, _ := data["action"].(string)
	apiAction = strings.ToLower(apiAction)

	var findings []string

	if classRaw, ok := data["classifications"].([]interface{}); ok {
		for _, c := range classRaw {
			if s, ok := c.(string); ok && s != "" && s != "NONE_VIOLATION" {
				findings = append(findings, s)
			}
		}
	}
	if rulesRaw, ok := data["rules"].([]interface{}); ok {
		for _, rr := range rulesRaw {
			if r, ok := rr.(map[string]interface{}); ok {
				class, _ := r["classification"].(string)
				if class == "NONE_VIOLATION" {
					continue
				}
				if name, ok := r["rule_name"].(string); ok && name != "" {
					findings = append(findings, name)
				}
			}
		}
	}

	if isSafe && apiAction != "block" {
		return &ScanVerdict{
			Action:   "allow",
			Severity: "NONE",
			Scanner:  "ai-defense",
		}
	}

	severity := "MEDIUM"
	action := "alert"
	if apiAction == "block" {
		severity = "HIGH"
		action = "block"
	}

	reason := "cisco: content flagged"
	if len(findings) > 0 {
		top := findings
		if len(top) > MaxFindingsInReason {
			top = top[:MaxFindingsInReason]
		}
		reason = "cisco: " + strings.Join(top, ", ")
	}

	return &ScanVerdict{
		Action:   action,
		Severity: severity,
		Reason:   reason,
		Findings: findings,
		Scanner:  "ai-defense",
	}
}
