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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

var defaultEnabledRules = []map[string]string{
	{"rule_name": "Prompt Injection"},
	{"rule_name": "Jailbreak"},
	{"rule_name": "PII Detection"},
	{"rule_name": "Sensitive Data"},
	{"rule_name": "Data Leakage"},
	{"rule_name": "Harassment"},
	{"rule_name": "Hate Speech"},
	{"rule_name": "Profanity"},
	{"rule_name": "Sexual Content & Exploitation"},
	{"rule_name": "Social Division & Polarization"},
	{"rule_name": "Violence & Public Safety Threats"},
	{"rule_name": "Code Detection"},
}

// inspectCall carries the per-endpoint pieces doInspectHTTP() needs. The
// payload map is mutated in place on 400-drop-config retry, so callers
// that reuse the map must marshal a fresh copy per call.
type inspectCall struct {
	client         *http.Client
	endpoint       string
	urlPath        string                     // e.g. "/api/v1/inspect/chat"
	payload        map[string]interface{}     // mutated on 400 retry (delete "config")
	setAuth        func(req *http.Request)    // set auth header on each attempt
	onUnauthorized func(context.Context) bool // nil: 401 is terminal (opensource default)
}

// doInspectHTTP executes an AID inspection HTTP call, applying the shared
// transport, generated-v8 metrics, and 4xx-drop-config retry logic. The
// caller owns the request context and any surrounding generated phase span.
// This helper must not create an independent trace root.
//
// The 401 branch depends on whether call.onUnauthorized is set:
//   - nil (opensource / API-key path): 401 is a terminal error, emitted
//     via EmitCiscoError and returning nil. Retry cap stays at 2 attempts
//     (initial + at most one 400-drop-config retry) — byte-for-byte
//     identical to the pre-extraction behavior.
//   - non-nil (managed / CMID path): 401 triggers onUnauthorized. If it
//     reports shouldRetry, doInspectHTTP loops once more; setAuth is
//     invoked on the fresh attempt, giving the caller a chance to attach
//     a refreshed token. Retry cap widens to 3 attempts (initial + 400
//     retry + 401 retry).
func doInspectHTTP(ctx context.Context, runtime hookLifecycleMetricV8Runtime, call inspectCall) *ScanVerdict {
	if ctx == nil {
		ctx = context.Background()
	}
	if call.client == nil || call.setAuth == nil {
		EmitCiscoError(ctx, gatewaylog.ErrCodeInvalidResponse, "inspection client is unavailable")
		recordCiscoInspectV8(ctx, runtime, -1, observability.OutcomeFailed, gatewaylog.ErrCodeInvalidResponse)
		return nil
	}
	url := call.endpoint + call.urlPath

	maxAttempts := 2
	if call.onUnauthorized != nil {
		maxAttempts = 3
	}
	triedWithoutRules := false
	retriedAfter401 := false
	for attempt := 0; attempt < maxAttempts; attempt++ {
		body, err := json.Marshal(call.payload)
		if err != nil {
			EmitCiscoError(ctx, gatewaylog.ErrCodeInvalidResponse, "request encoding failed")
			recordCiscoInspectV8(ctx, runtime, -1, observability.OutcomeFailed, gatewaylog.ErrCodeInvalidResponse)
			return nil
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			EmitCiscoError(ctx, gatewaylog.ErrCodeInvalidResponse, "request construction failed")
			recordCiscoInspectV8(ctx, runtime, -1, observability.OutcomeFailed, gatewaylog.ErrCodeInvalidResponse)
			return nil
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		call.setAuth(req)

		start := time.Now()
		resp, err := call.client.Do(req)
		if err != nil {
			fmt.Fprintf(defaultLogWriter, "  [cisco-ai-defense] error: %v\n", err)
			outcome := observability.OutcomeFailed
			var networkError net.Error
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) ||
				errors.As(err, &networkError) && networkError.Timeout() {
				outcome = observability.OutcomeTimedOut
			}
			EmitCiscoError(ctx, gatewaylog.ErrCodeUpstreamError, err.Error())
			recordCiscoInspectV8(ctx, runtime, time.Since(start), outcome, gatewaylog.ErrCodeUpstreamError)
			return nil
		}

		respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		_ = resp.Body.Close()
		elapsed := time.Since(start)
		if readErr != nil {
			EmitCiscoError(ctx, gatewaylog.ErrCodeInvalidResponse, "response body read failed")
			recordCiscoInspectV8(ctx, runtime, elapsed, observability.OutcomeFailed, gatewaylog.ErrCodeInvalidResponse)
			return nil
		}

		if resp.StatusCode == http.StatusBadRequest && !triedWithoutRules {
			lower := strings.ToLower(string(respBody))
			// Multiple known 400 shapes from AID across deployments:
			//   1. legacy: "already has rules configured" /
			//      "pre-configured"
			//   2. preview-2026: "invalid rule name: <X>" (the
			//      preview deployment validates the names in our
			//      defaultEnabledRules slice against the operator's
			//      configured rule catalog, and emits this when our
			//      hard-coded names don't exist there)
			//   3. catch-all on rules / configuration / enabled_rules
			// In every case the right retry is to drop the `config`
			// block — the operator's pre-configured rules on the AID
			// side still apply; we just stop trying to override them.
			if strings.Contains(lower, "already has rules configured") ||
				strings.Contains(lower, "pre-configured") ||
				strings.Contains(lower, "invalid rule") ||
				strings.Contains(lower, "rules") ||
				strings.Contains(lower, "enabled_rules") ||
				strings.Contains(lower, "configuration") {
				delete(call.payload, "config")
				triedWithoutRules = true
				fmt.Fprintf(defaultLogWriter, "  [cisco-ai-defense] HTTP 400 with rules-related body, retrying without config\n")
				recordCiscoInspectV8(ctx, runtime, elapsed, observability.OutcomeRejected, "")
				continue
			}
		}

		if resp.StatusCode == http.StatusUnauthorized && call.onUnauthorized != nil && !retriedAfter401 {
			if call.onUnauthorized(ctx) {
				retriedAfter401 = true
				fmt.Fprintf(defaultLogWriter, "  [cisco-ai-defense] HTTP 401, refreshed credentials and retrying\n")
				recordCiscoInspectV8(ctx, runtime, elapsed, observability.OutcomeRejected, "")
				continue
			}
		}

		if resp.StatusCode != http.StatusOK {
			bodySnippet := string(respBody[:minInt(len(respBody), 200)])
			fmt.Fprintf(defaultLogWriter, "  [cisco-ai-defense] error: HTTP %d: %s\n",
				resp.StatusCode, redaction.MessageContent(bodySnippet))
			EmitCiscoError(ctx, gatewaylog.ErrCodeInvalidResponse,
				fmt.Sprintf("HTTP %d: %s", resp.StatusCode, redaction.MessageContent(bodySnippet)))
			recordCiscoInspectV8(ctx, runtime, elapsed, observability.OutcomeFailed, gatewaylog.ErrCodeInvalidResponse)
			return nil
		}

		var data map[string]interface{}
		if err := json.Unmarshal(respBody, &data); err != nil {
			EmitCiscoError(ctx, gatewaylog.ErrCodeInvalidResponse, "json: "+err.Error())
			recordCiscoInspectV8(ctx, runtime, elapsed, observability.OutcomeFailed, gatewaylog.ErrCodeInvalidResponse)
			return nil
		}
		recordCiscoInspectV8(ctx, runtime, elapsed, observability.OutcomeCompleted, "")
		return normalizeCiscoResponse(data)
	}
	return nil
}

// CiscoInspectClient calls the Cisco AI Defense Chat Inspection API using
// an opensource API key. Managed-mode installs use
// CiscoDefenseClawInspectClient instead — see cisco_inspect_defense_claw.go.
//
// Field layout preserved verbatim: existing tests
// (inspect_aid_lane_test.go) construct literals like
// &CiscoInspectClient{apiKey, endpoint, client}, so these must remain
// direct fields rather than promoted via an embedded struct.
type CiscoInspectClient struct {
	apiKey       string
	endpoint     string
	timeout      time.Duration
	enabledRules []map[string]string
	client       *http.Client

	observabilityV8Mu sync.RWMutex
	observabilityV8   hookLifecycleMetricV8Runtime
}

// bindObservabilityV8 replaces the old Provider pointer with the
// generation-pinned generated metric capability. The request context passed to
// Inspect owns trace construction; the client must never create a second root
// span for the same network operation.
func (c *CiscoInspectClient) bindObservabilityV8(runtime hookLifecycleMetricV8Runtime) {
	if c == nil {
		return
	}
	c.observabilityV8Mu.Lock()
	c.observabilityV8 = runtime
	c.observabilityV8Mu.Unlock()
}

func (c *CiscoInspectClient) observabilityV8Runtime() hookLifecycleMetricV8Runtime {
	if c == nil {
		return nil
	}
	c.observabilityV8Mu.RLock()
	defer c.observabilityV8Mu.RUnlock()
	return c.observabilityV8
}

func ciscoInspectRuntimeFromContext(ctx context.Context, fallback hookLifecycleMetricV8Runtime) hookLifecycleMetricV8Runtime {
	if ctx != nil {
		if phaseRuntime, ok := ctx.Value(ciscoInspectMetricRuntimeContextKey{}).(hookLifecycleMetricV8Runtime); ok {
			return phaseRuntime
		}
	}
	return fallback
}

// EmitCiscoError records the structured gateway error for Cisco Inspect. The
// caller records the matching generated metric in the same request scope so it
// retains W3C and DefenseClaw correlation.
// ctx supplies request correlation (request_id / session_id / trace_id)
// and agent identity; pass context.Background() only from boot / test
// harnesses where no request exists. Routes through emitError so the
// stampEventCorrelation choke point populates the envelope.
func EmitCiscoError(ctx context.Context, code gatewaylog.ErrorCode, detail string) {
	if ctx == nil {
		ctx = context.Background()
	}
	var cause error
	if detail != "" {
		cause = fmt.Errorf("%s", detail)
	}
	emitError(ctx,
		string(gatewaylog.SubsystemCiscoInspect),
		string(code),
		"cisco ai defense inspect",
		cause,
	)
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
		endpoint = "https://us.api.inspect.aidefense.security.cisco.com"
	}

	timeout := time.Duration(cfg.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 3 * time.Second
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
// The caller's context is mandatory for cancellation and W3C parentage. The
// generated guardrail ai_defense CLIENT phase owns the span; this client only
// records the two canonical Cisco metric families. Returns nil on any error so
// the caller can fall back to local-only scanning.
func (c *CiscoInspectClient) Inspect(ctx context.Context, messages []ChatMessage) *ScanVerdict {
	if c == nil || c.apiKey == "" {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	runtime := ciscoInspectRuntimeFromContext(ctx, c.observabilityV8Runtime())

	chatMsgs := make([]map[string]string, len(messages))
	for i, m := range messages {
		chatMsgs[i] = map[string]string{"role": m.Role, "content": m.Content}
	}

	payload := map[string]interface{}{"messages": chatMsgs}
	if len(c.enabledRules) > 0 {
		payload["config"] = map[string]interface{}{"enabled_rules": c.enabledRules}
	}

	return doInspectHTTP(ctx, runtime, inspectCall{
		client:   c.client,
		endpoint: c.endpoint,
		urlPath:  "/api/v1/inspect/chat",
		payload:  payload,
		setAuth: func(req *http.Request) {
			req.Header.Set("X-Cisco-AI-Defense-API-Key", c.apiKey)
		},
	})
}

func normalizeCiscoResponse(data map[string]interface{}) *ScanVerdict {
	isSafe, _ := data["is_safe"].(bool)
	apiAction, _ := data["action"].(string)
	apiAction = strings.ToLower(apiAction)

	var findings []string

	// Cloud-controlled per-inspection redaction directive. Only the
	// managed DefenseClawInspect response carries is_redaction_enabled;
	// the OSS InspectResponse lacks the key, so redactionEnabled stays
	// nil (no directive) there. true => redact, false => store raw.
	var redactionEnabled *bool
	if v, ok := data["is_redaction_enabled"].(bool); ok {
		redactionEnabled = &v
	}

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
			Action:           "allow",
			Severity:         "NONE",
			Scanner:          "ai-defense",
			RedactionEnabled: redactionEnabled,
		}
	}

	severity := "MEDIUM"
	action := "alert"
	if apiAction == "block" {
		severity = "HIGH"
		action = "block"
	}

	// Reason text explicitly names Cisco AI Defense (and the
	// custom-policy lane) rather than the legacy "cisco: content
	// flagged" string, so operators reading the verdict in the
	// agent UI / audit log can tell an AID block apart from a regex
	// or judge block on the same surface. When AID returns rule
	// names we surface the top few; when it returns Block with no
	// named rules (which the preview deployment sometimes does on
	// custom-policy paths) we still credit the lane explicitly.
	reason := "Cisco AI Defense custom policy block"
	if len(findings) > 0 {
		top := findings
		if len(top) > 5 {
			top = top[:5]
		}
		reason = "Cisco AI Defense: " + strings.Join(top, ", ")
	}

	return &ScanVerdict{
		Action:           action,
		Severity:         severity,
		Reason:           reason,
		Findings:         findings,
		Scanner:          "ai-defense",
		RedactionEnabled: redactionEnabled,
	}
}
