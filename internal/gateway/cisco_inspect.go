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
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/modelusage"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

const ciscoUnknownFindingID = "CISCO-UNKNOWN"

// canonicalCiscoFindingID converts cloud-controlled classification and rule
// labels into a closed set of inert identities. Human-readable reasons are
// separately reconstructed from fixed display labels, so arbitrary API bytes
// cannot enter either the generic UNKNOWN-* fallback or persisted reason text.
func canonicalCiscoFindingID(value string) string {
	canonical := strings.ToUpper(strings.TrimSpace(value))
	canonical = strings.NewReplacer("_", " ", "-", " ", "&", " ").Replace(canonical)
	canonical = strings.Join(strings.Fields(canonical), " ")
	switch canonical {
	case "PROMPT INJECTION":
		return "CISCO-PROMPT-INJECTION"
	case "JAILBREAK":
		return "CISCO-JAILBREAK"
	case "PII", "PII DETECTION":
		return "CISCO-PII"
	case "SENSITIVE DATA":
		return "CISCO-SENSITIVE-DATA"
	case "DATA LEAKAGE":
		return "CISCO-DATA-LEAKAGE"
	case "HARASSMENT":
		return "CISCO-HARASSMENT"
	case "HATE SPEECH":
		return "CISCO-HATE-SPEECH"
	case "PROFANITY":
		return "CISCO-PROFANITY"
	case "SEXUAL CONTENT EXPLOITATION":
		return "CISCO-SEXUAL-CONTENT"
	case "SOCIAL DIVISION POLARIZATION":
		return "CISCO-SOCIAL-DIVISION"
	case "VIOLENCE PUBLIC SAFETY THREATS":
		return "CISCO-VIOLENCE"
	case "CODE DETECTION":
		return "CISCO-CODE"
	default:
		return ciscoUnknownFindingID
	}
}

func ciscoFindingDisplayLabel(canonicalID string) string {
	switch canonicalID {
	case "CISCO-PROMPT-INJECTION":
		return "Prompt Injection"
	case "CISCO-JAILBREAK":
		return "Jailbreak"
	case "CISCO-PII":
		return "PII Detection"
	case "CISCO-SENSITIVE-DATA":
		return "Sensitive Data"
	case "CISCO-DATA-LEAKAGE":
		return "Data Leakage"
	case "CISCO-HARASSMENT":
		return "Harassment"
	case "CISCO-HATE-SPEECH":
		return "Hate Speech"
	case "CISCO-PROFANITY":
		return "Profanity"
	case "CISCO-SEXUAL-CONTENT":
		return "Sexual Content & Exploitation"
	case "CISCO-SOCIAL-DIVISION":
		return "Social Division & Polarization"
	case "CISCO-VIOLENCE":
		return "Violence & Public Safety Threats"
	case "CISCO-CODE":
		return "Code Detection"
	default:
		return "Custom Policy Violation"
	}
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
	// onValidationError switches an API-key tool-call request to its text
	// form, or returns an already inspected text verdict. Managed callers
	// leave it nil.
	onValidationError func() *ScanVerdict
	// acceptShapeValidation records a cached structured shape's 400/422 as
	// a rejected format, leaving the concurrently inspected text verdict.
	acceptShapeValidation bool
	// onOutcome receives the call's final outcome: nil for a verdict, the
	// failure otherwise. nil: nothing is reported (every client but the
	// standalone AI Defense client, whose outcomes feed /health).
	onOutcome func(error)
}

// doInspectHTTP executes an AID inspection HTTP call, applying the shared
// transport, generated-v8 metrics, and 4xx-drop-config retry logic. The
// caller owns the request context and any surrounding generated phase span.
// This helper must not create an independent trace root.
//
// The 401 branch depends on whether call.onUnauthorized is set:
//   - nil (opensource / API-key path): 401 is a terminal error, emitted
//     via EmitCiscoError and returning nil. The retry cap is 2 attempts,
//     or 3 when a tool-call request can retry as text after validation.
//   - non-nil (managed / CMID path): 401 triggers onUnauthorized. If it
//     reports shouldRetry, doInspectHTTP loops once more; setAuth is
//     invoked on the fresh attempt, giving the caller a chance to attach
//     a refreshed token. Retry cap widens to 3 attempts (initial + 400
//     retry + 401 retry).
func doInspectHTTP(ctx context.Context, runtime hookLifecycleMetricV8Runtime, call inspectCall) *ScanVerdict {
	if ctx == nil {
		ctx = context.Background()
	}
	// report publishes the final outcome to call.onOutcome. A request the
	// caller abandoned says nothing about the service, so it is dropped.
	report := func(err error) {
		if call.onOutcome == nil || (err != nil && errors.Is(ctx.Err(), context.Canceled)) {
			return
		}
		call.onOutcome(err)
	}
	if call.client == nil || call.setAuth == nil {
		EmitCiscoError(ctx, gatewaylog.ErrCodeInvalidResponse, "inspection client is unavailable")
		recordCiscoInspectV8(ctx, runtime, -1, observability.OutcomeFailed, gatewaylog.ErrCodeInvalidResponse)
		report(errors.New("inspection client is unavailable"))
		return nil
	}
	url := call.endpoint + call.urlPath

	maxAttempts := 2
	if call.onUnauthorized != nil {
		maxAttempts = 3
	}
	if call.onValidationError != nil {
		maxAttempts = 3
	}
	retriedAfter401 := false
	retriedAsText := false
	for attempt := 0; attempt < maxAttempts; attempt++ {
		body, err := json.Marshal(call.payload)
		if err != nil {
			EmitCiscoError(ctx, gatewaylog.ErrCodeInvalidResponse, "request encoding failed")
			recordCiscoInspectV8(ctx, runtime, -1, observability.OutcomeFailed, gatewaylog.ErrCodeInvalidResponse)
			report(errors.New("request encoding failed"))
			return nil
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			EmitCiscoError(ctx, gatewaylog.ErrCodeInvalidResponse, "request construction failed")
			recordCiscoInspectV8(ctx, runtime, -1, observability.OutcomeFailed, gatewaylog.ErrCodeInvalidResponse)
			report(errors.New("request construction failed"))
			return nil
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		call.setAuth(req)

		start := time.Now()
		usage := beginGatewayCallUsage(ctx, modelusage.RoleAIDefense, "ai_defense", "inspect")
		resp, err := call.client.Do(req)
		if err != nil {
			usage.End(err)
		} else {
			usage.UpstreamHeader(resp.StatusCode, nil)
			usage.End(nil)
		}
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
			report(fmt.Errorf("endpoint or egress proxy unreachable: %w", err))
			return nil
		}

		respBody, responseTruncated, readErr := readCiscoInspectResponseBody(resp.Body)
		_ = resp.Body.Close()
		elapsed := time.Since(start)
		if readErr != nil {
			emitCiscoInspectFailure(ctx, gatewaylog.ErrCodeInvalidResponse, ciscoInspectFailureDiagnostic{
				stage:             ciscoInspectStageResponseBody,
				classification:    classifyCiscoInspectBodyReadError(readErr),
				httpStatus:        resp.StatusCode,
				responseBody:      respBody,
				responseTruncated: responseTruncated,
			})
			recordCiscoInspectV8(ctx, runtime, elapsed, observability.OutcomeFailed, gatewaylog.ErrCodeInvalidResponse)
			report(fmt.Errorf("HTTP %d response could not be read: %w", resp.StatusCode, readErr))
			return nil
		}
		if responseTruncated && resp.StatusCode == http.StatusOK {
			emitCiscoInspectFailure(ctx, gatewaylog.ErrCodeInvalidResponse, ciscoInspectFailureDiagnostic{
				stage:             ciscoInspectStageResponseBody,
				classification:    ciscoInspectClassResponseBodyTooLarge,
				httpStatus:        resp.StatusCode,
				responseBody:      respBody,
				responseTruncated: true,
			})
			recordCiscoInspectV8(ctx, runtime, elapsed, observability.OutcomeFailed, gatewaylog.ErrCodeInvalidResponse)
			report(errors.New("response exceeded the size limit"))
			return nil
		}

		// A rules-related 400 is retried without the config block, so it is
		// retried only while the request still carries one: a request that
		// sent no enabled_rules (or already dropped them) would be re-sent
		// byte-for-byte (GAP-0660).
		_, sentConfig := call.payload["config"]
		if resp.StatusCode == http.StatusBadRequest && sentConfig {
			lower := strings.ToLower(string(respBody))
			// Multiple known 400 shapes from AID across deployments:
			//   1. legacy: "already has rules configured" /
			//      "pre-configured"
			//   2. preview-2026: "invalid rule name: <X>" (the
			//      preview deployment validates the rule names this client
			//      sends from cisco_ai_defense.enabled_rules against the
			//      connection's rule catalog)
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
				fmt.Fprintf(defaultLogWriter, "  [cisco-ai-defense] HTTP 400 with rules-related body, retrying without config\n")
				recordCiscoInspectV8(ctx, runtime, elapsed, observability.OutcomeRejected, "")
				continue
			}
		}
		if (resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnprocessableEntity) &&
			call.onValidationError != nil && !retriedAsText && attempt+1 < maxAttempts {
			fallbackVerdict := call.onValidationError()
			recordCiscoInspectV8(ctx, runtime, elapsed, observability.OutcomeRejected, "")
			if fallbackVerdict != nil {
				report(nil)
				return fallbackVerdict
			}
			retriedAsText = true
			continue
		}
		if (resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnprocessableEntity) &&
			call.acceptShapeValidation {
			recordCiscoInspectV8(ctx, runtime, elapsed, observability.OutcomeRejected, "")
			report(ciscoInspectStatusError(resp.StatusCode))
			return nil
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
			emitCiscoInspectFailure(ctx, gatewaylog.ErrCodeInvalidResponse, ciscoInspectFailureDiagnostic{
				stage:             ciscoInspectStageResponseStatus,
				classification:    classifyCiscoInspectErrorResponse(respBody, resp.StatusCode),
				httpStatus:        resp.StatusCode,
				responseBody:      respBody,
				responseTruncated: responseTruncated,
			})
			recordCiscoInspectV8(ctx, runtime, elapsed, observability.OutcomeFailed, gatewaylog.ErrCodeInvalidResponse)
			report(ciscoInspectStatusError(resp.StatusCode))
			return nil
		}

		var data map[string]interface{}
		if err := json.Unmarshal(respBody, &data); err != nil {
			emitCiscoInspectFailure(ctx, gatewaylog.ErrCodeInvalidResponse, ciscoInspectFailureDiagnostic{
				stage:          ciscoInspectStageResponseDecode,
				classification: classifyCiscoInspectJSONError(err),
				httpStatus:     resp.StatusCode,
				responseBody:   respBody,
				parseOffset:    ciscoInspectJSONErrorOffset(err),
			})
			recordCiscoInspectV8(ctx, runtime, elapsed, observability.OutcomeFailed, gatewaylog.ErrCodeInvalidResponse)
			report(errors.New("response is not valid JSON"))
			return nil
		}
		recordCiscoInspectV8(ctx, runtime, elapsed, observability.OutcomeCompleted, "")
		report(nil)
		return normalizeCiscoResponse(data)
	}
	report(errors.New("no verdict after retrying"))
	return nil
}

// ciscoInspectHTTPStatusError retains the status so a cached format check can
// distinguish shape validation from an unavailable inspection endpoint.
type ciscoInspectHTTPStatusError struct{ status int }

func (e *ciscoInspectHTTPStatusError) Error() string {
	switch e.status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Sprintf("the API key was rejected (HTTP %d)", e.status)
	case http.StatusProxyAuthRequired:
		return fmt.Sprintf("the egress proxy requires authentication (HTTP %d)", e.status)
	}
	return fmt.Sprintf("inspection failed (HTTP %d)", e.status)
}

// ciscoInspectStatusError describes a final non-200 inspection reply for
// /health. A rejected key and a proxy that wants credentials name the
// setting to fix; any other status is reported as is.
func ciscoInspectStatusError(status int) error {
	return &ciscoInspectHTTPStatusError{status: status}
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
	apiKey   string
	endpoint string
	timeout  time.Duration
	// enabledRules is nil unless an operator configured cisco_ai_defense.enabled_rules.
	enabledRules []map[string]string
	client       *http.Client

	observabilityV8Mu sync.RWMutex
	observabilityV8   hookLifecycleMetricV8Runtime

	// availabilityObserver receives every inspection's outcome (see
	// inspectCall.onOutcome). Only the standalone AI Defense client binds
	// one; opensource clients leave it nil and report nothing.
	availabilityMu       sync.RWMutex
	availabilityObserver func(error)
}

// A validation response can apply to one request rather than every tool call
// at an endpoint. A blocking text retry can be reused briefly for an identical
// API-key request. Non-blocking results recheck the structured form because
// endpoint capabilities and policies can change. Secure Client does not use
// this preference.
const ciscoAPIKeyTextPreferenceLifetime = 30 * time.Second

type ciscoAPIKeyTextPreference struct {
	key     [32]byte
	expires time.Time
}

var ciscoAPIKeyTextOnlyRequests = struct {
	sync.Mutex
	keys  map[[32]byte]*ciscoAPIKeyTextPreference
	order [1024]*ciscoAPIKeyTextPreference
	next  int
	size  int
}{keys: make(map[[32]byte]*ciscoAPIKeyTextPreference)}
var ciscoAPIKeyTextOnlyLogOnce sync.Once

func ciscoAPIKeyTextOnlyRequestKnown(key [32]byte, now time.Time) bool {
	ciscoAPIKeyTextOnlyRequests.Lock()
	defer ciscoAPIKeyTextOnlyRequests.Unlock()
	entry := ciscoAPIKeyTextOnlyRequests.keys[key]
	if entry == nil {
		return false
	}
	if !now.Before(entry.expires) {
		delete(ciscoAPIKeyTextOnlyRequests.keys, key)
		return false
	}
	return true
}

func ciscoRememberAPIKeyTextOnlyRequest(key [32]byte, now time.Time) bool {
	ciscoAPIKeyTextOnlyRequests.Lock()
	defer ciscoAPIKeyTextOnlyRequests.Unlock()
	if entry := ciscoAPIKeyTextOnlyRequests.keys[key]; entry != nil && now.Before(entry.expires) {
		return false
	}
	if ciscoAPIKeyTextOnlyRequests.size == len(ciscoAPIKeyTextOnlyRequests.order) {
		old := ciscoAPIKeyTextOnlyRequests.order[ciscoAPIKeyTextOnlyRequests.next]
		if ciscoAPIKeyTextOnlyRequests.keys[old.key] == old {
			delete(ciscoAPIKeyTextOnlyRequests.keys, old.key)
		}
	} else {
		ciscoAPIKeyTextOnlyRequests.size++
	}
	entry := &ciscoAPIKeyTextPreference{key: key, expires: now.Add(ciscoAPIKeyTextPreferenceLifetime)}
	ciscoAPIKeyTextOnlyRequests.order[ciscoAPIKeyTextOnlyRequests.next] = entry
	ciscoAPIKeyTextOnlyRequests.next = (ciscoAPIKeyTextOnlyRequests.next + 1) % len(ciscoAPIKeyTextOnlyRequests.order)
	ciscoAPIKeyTextOnlyRequests.keys[key] = entry
	return true
}

// bindAvailabilityObserver installs the callback that receives every
// inspection's outcome: nil after a verdict, the failure otherwise.
func (c *CiscoInspectClient) bindAvailabilityObserver(observer func(error)) {
	if c == nil {
		return
	}
	c.availabilityMu.Lock()
	c.availabilityObserver = observer
	c.availabilityMu.Unlock()
}

func (c *CiscoInspectClient) availabilityCallback() func(error) {
	if c == nil {
		return nil
	}
	c.availabilityMu.RLock()
	defer c.availabilityMu.RUnlock()
	return c.availabilityObserver
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
	for _, r := range cfg.EnabledRules {
		rules = append(rules, map[string]string{"rule_name": r})
	}

	return &CiscoInspectClient{
		apiKey:       apiKey,
		endpoint:     endpoint,
		timeout:      timeout,
		enabledRules: rules,
		client:       &http.Client{Timeout: timeout},
	}
}

// ciscoMessageToolCallHasTextForm recognizes the unlabelled text form used by
// the message hook. The user message must match the carried arguments so an
// unrelated message cannot be substituted for the tool call on retry.
func ciscoMessageToolCallHasTextForm(messages []ChatMessage) bool {
	var calls []struct {
		Type     string `json:"type"`
		Function struct {
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
		} `json:"function"`
	}
	return json.Unmarshal(messages[0].ToolCalls, &calls) == nil && len(calls) == 1 &&
		calls[0].Type == "function" && calls[0].Function.Name == "message" &&
		calls[0].Function.Arguments == messages[1].Content
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

	chatMsgs := make([]map[string]interface{}, len(messages))
	for i, m := range messages {
		msg := map[string]interface{}{"role": m.Role, "content": m.Content}
		if len(m.ToolCalls) > 0 {
			msg["tool_calls"] = m.ToolCalls
		}
		chatMsgs[i] = msg
	}
	// PreToolUse supplies its complete text form after an empty assistant
	// tool-call message. The message hook omits the usual tool label.
	// Other message lists keep their original shape on a validation error.
	canUseText := len(messages) == 2 &&
		messages[0].Role == "assistant" && messages[0].Content == "" && len(messages[0].ToolCalls) > 0 &&
		messages[1].Role == "user" && len(messages[1].ToolCalls) == 0 &&
		(strings.HasPrefix(messages[1].Content, "Tool call: ") || ciscoMessageToolCallHasTextForm(messages))
	var textMsgs []map[string]interface{}
	if canUseText {
		textMsgs = []map[string]interface{}{{"role": "user", "content": messages[1].Content}}
	}
	payload := map[string]interface{}{"messages": chatMsgs}
	if len(c.enabledRules) > 0 {
		payload["config"] = map[string]interface{}{"enabled_rules": c.enabledRules}
	}
	var requestKey [32]byte
	preferredText := false
	if canUseText {
		// Tool-use IDs change on each invocation. Exclude only those IDs
		// from the preference key; keep the tool, arguments, text, rules,
		// endpoint, and credential so an unrelated request is still probed.
		var calls []map[string]json.RawMessage
		if err := json.Unmarshal(messages[0].ToolCalls, &calls); err == nil && len(calls) > 0 {
			for _, call := range calls {
				delete(call, "id")
			}
			if normalizedCalls, err := json.Marshal(calls); err == nil {
				keyMessages := append([]map[string]interface{}(nil), chatMsgs...)
				keyMessages[0] = map[string]interface{}{
					"role":       messages[0].Role,
					"content":    messages[0].Content,
					"tool_calls": json.RawMessage(normalizedCalls),
				}
				keyPayload := make(map[string]interface{}, len(payload))
				for name, value := range payload {
					keyPayload[name] = value
				}
				keyPayload["messages"] = keyMessages
				if body, err := json.Marshal(keyPayload); err == nil {
					hash := sha256.New()
					_, _ = hash.Write([]byte(c.endpoint))
					_, _ = hash.Write([]byte{0})
					_, _ = hash.Write([]byte(c.apiKey))
					_, _ = hash.Write([]byte{0})
					_, _ = hash.Write(body)
					copy(requestKey[:], hash.Sum(nil))
					if ciscoAPIKeyTextOnlyRequestKnown(requestKey, time.Now()) {
						payload["messages"] = textMsgs
						canUseText = false
						preferredText = true
					}
				}
			}
		}
	}

	// A retry shares the original request's configured time budget. The
	// client's per-attempt timeout alone would otherwise allow two budgets.
	if (canUseText || preferredText) && c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}
	retriedAsText := false
	call := inspectCall{
		client:   c.client,
		endpoint: c.endpoint,
		urlPath:  "/api/v1/inspect/chat",
		payload:  payload,
		setAuth: func(req *http.Request) {
			req.Header.Set("X-Cisco-AI-Defense-API-Key", c.apiKey)
		},
		onOutcome: c.availabilityCallback(),
	}
	if preferredText {
		// The preference is only a shape hint. Check both forms within the
		// same deadline: waiting for a slow text allow before starting the
		// structured request could discard a timely structured block.
		type shapeResult struct {
			verdict    *ScanVerdict
			outcome    error
			structured bool
		}
		results := make(chan shapeResult, 2)
		checkCtx, stop := context.WithCancel(ctx)
		defer stop()
		check := func(messages []map[string]interface{}, structured bool) {
			shapeCall := call
			shapeCall.acceptShapeValidation = structured
			shapeCall.payload = make(map[string]interface{}, len(payload))
			for name, value := range payload {
				shapeCall.payload[name] = value
			}
			shapeCall.payload["messages"] = messages
			var outcome error
			shapeCall.onOutcome = func(err error) { outcome = err }
			verdict := doInspectHTTP(checkCtx, runtime, shapeCall)
			results <- shapeResult{verdict: verdict, outcome: outcome, structured: structured}
		}
		go check(textMsgs, false)
		go check(chatMsgs, true)

		var textResult, structuredResult shapeResult
		for range 2 {
			result := <-results
			if result.verdict != nil && result.verdict.Action == "block" {
				stop()
				if call.onOutcome != nil {
					call.onOutcome(nil)
				}
				return result.verdict
			}
			if result.structured {
				structuredResult = result
			} else {
				textResult = result
			}
		}
		// A 400/422 from one shape is a compatibility signal when the
		// other shape returned a verdict. Any other failed shape leaves an
		// inspection incomplete, so the caller applies its outage mode.
		var incomplete error
		for _, result := range []shapeResult{textResult, structuredResult} {
			if result.verdict != nil {
				continue
			}
			if result.outcome == nil {
				if ctx.Err() != nil {
					incomplete = ctx.Err()
					break
				}
				continue
			}
			var status *ciscoInspectHTTPStatusError
			if errors.As(result.outcome, &status) &&
				(status.status == http.StatusBadRequest || status.status == http.StatusUnprocessableEntity) {
				continue
			}
			incomplete = result.outcome
			break
		}
		if incomplete != nil {
			if call.onOutcome != nil && !errors.Is(ctx.Err(), context.Canceled) {
				call.onOutcome(incomplete)
			}
			return nil
		}
		if structuredResult.verdict != nil {
			if call.onOutcome != nil {
				call.onOutcome(nil)
			}
			return structuredResult.verdict
		}
		if textResult.verdict != nil {
			if call.onOutcome != nil {
				call.onOutcome(nil)
			}
			return textResult.verdict
		}
		if call.onOutcome != nil && !errors.Is(ctx.Err(), context.Canceled) {
			if structuredResult.outcome != nil {
				call.onOutcome(structuredResult.outcome)
			} else {
				call.onOutcome(textResult.outcome)
			}
		}
		return nil
	}
	if canUseText {
		call.onValidationError = func() *ScanVerdict {
			payload["messages"] = textMsgs
			retriedAsText = true
			return nil
		}
	}
	verdict := doInspectHTTP(ctx, runtime, call)
	if retriedAsText && verdict != nil && verdict.Action == "block" && requestKey != ([32]byte{}) {
		if ciscoRememberAPIKeyTextOnlyRequest(requestKey, time.Now()) {
			ciscoAPIKeyTextOnlyLogOnce.Do(func() {
				fmt.Fprintln(defaultLogWriter, "  [cisco-ai-defense] API-key endpoint accepted a text retry; briefly remembering that format for identical blocked requests")
			})
		}
	}
	return verdict
}

func normalizeCiscoResponse(data map[string]interface{}) *ScanVerdict {
	isSafe, _ := data["is_safe"].(bool)
	apiAction, _ := data["action"].(string)
	apiAction = strings.ToLower(apiAction)

	var findings []string
	var findingLabels []string
	seenFindingIDs := make(map[string]struct{})
	appendFinding := func(rawLabel string) {
		canonicalID := canonicalCiscoFindingID(rawLabel)
		if _, duplicate := seenFindingIDs[canonicalID]; duplicate {
			return
		}
		seenFindingIDs[canonicalID] = struct{}{}
		findings = append(findings, canonicalID)
		findingLabels = append(findingLabels, ciscoFindingDisplayLabel(canonicalID))
	}

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
				appendFinding(s)
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
					appendFinding(name)
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
	if len(findingLabels) > 0 {
		top := findingLabels
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
