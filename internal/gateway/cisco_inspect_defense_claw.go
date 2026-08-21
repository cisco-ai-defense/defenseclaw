// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/managed/cloudreg"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

// tokenUnavailableWarnCooldown throttles the operator-visible stderr
// warning that warnTokenUnavailable emits when the managed cloud
// token cannot be minted. Without a cooldown, every hook inspection
// on a box with a broken CMID library would repeat the same warning
// (potentially thousands of times per hour). Once per minute is
// enough to make the fail-open condition visible in `tail -f
// gateway.err.log` without flooding the log.
const tokenUnavailableWarnCooldown = 60 * time.Second

// CiscoDefenseClawInspectClient calls the Cisco AI Defense DefenseClaw
// Inspection API at POST /api/v1/inspect/defense_claw, authenticating
// with a bearer token sourced from cloudreg.Provider (registered by the
// managed release build; a no-op stub on OSS builds).
//
// This client is the managed_enterprise counterpart to
// CiscoInspectClient. Both return the same *ScanVerdict shape, so
// downstream guardrail wiring is identical. The two differences from
// the API-key path are:
//
//  1. Auth: Authorization: Bearer <token> instead of
//     X-Cisco-AI-Defense-API-Key.
//
//  2. Payload: messages[].content is an object {"text": "..."} matching
//     the DefenseClaw proto's MessageContent, rather than a plain
//     string. device_id and dc_metadata are intentionally omitted —
//     the cloud derives them server-side from the token.
//
// The client also handles HTTP 401 by invalidating the provider's
// cached token and retrying once. See doInspectHTTP for the shared
// retry mechanics.
type CiscoDefenseClawInspectClient struct {
	provider cloudreg.Provider
	endpoint string
	timeout  time.Duration
	client   *http.Client

	observabilityV8Mu sync.RWMutex
	observabilityV8   hookLifecycleMetricV8Runtime

	// tokenWarnMu guards tokenLastWarn, the rate-limit clock for
	// warnTokenUnavailable's stderr emission. See the cooldown
	// constant tokenUnavailableWarnCooldown for the rationale.
	tokenWarnMu   sync.Mutex
	tokenLastWarn time.Time
}

// Compile-time assertion: the managed client satisfies Inspector.
var _ Inspector = (*CiscoDefenseClawInspectClient)(nil)

// NewCiscoDefenseClawInspectClient constructs the managed-mode client.
// Returns nil when the required inputs are absent (provider or endpoint
// missing), matching the opensource NewCiscoInspectClient's contract:
// caller nil-checks the concrete pointer BEFORE assigning to an
// Inspector-typed variable. See G1 in the design doc.
func NewCiscoDefenseClawInspectClient(cfg *config.CiscoAIDefenseConfig, provider cloudreg.Provider) *CiscoDefenseClawInspectClient {
	if provider == nil {
		return nil
	}
	if cfg == nil {
		return nil
	}
	endpoint := strings.TrimRight(cfg.Endpoint, "/")
	if endpoint == "" {
		// The installer renders cisco_ai_defense.endpoint per
		// environment. If it's missing, we refuse to construct — the
		// picker fallback in sidecar.go turns this into a nil
		// inspector and disables the remote lane, matching the
		// fail-closed managed posture.
		return nil
	}

	timeout := time.Duration(cfg.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	// NOTE: cfg.EnabledRules is intentionally ignored for the
	// defense_claw path — the cloud-side tenant owns the rule catalog
	// for managed calls. See the payload comment in Inspect for the
	// rationale.

	return &CiscoDefenseClawInspectClient{
		provider: provider,
		endpoint: endpoint,
		timeout:  timeout,
		client:   &http.Client{Timeout: timeout},
	}
}

// bindObservabilityV8 installs the active generated-v8 metric capability.
// The request context remains authoritative when a guardrail phase supplies
// a narrower runtime so metrics join that exact phase span.
func (c *CiscoDefenseClawInspectClient) bindObservabilityV8(runtime hookLifecycleMetricV8Runtime) {
	if c == nil {
		return
	}
	c.observabilityV8Mu.Lock()
	c.observabilityV8 = runtime
	c.observabilityV8Mu.Unlock()
}

func (c *CiscoDefenseClawInspectClient) observabilityV8Runtime() hookLifecycleMetricV8Runtime {
	if c == nil {
		return nil
	}
	c.observabilityV8Mu.RLock()
	defer c.observabilityV8Mu.RUnlock()
	return c.observabilityV8
}

// warnTokenUnavailable emits a rate-limited operator-visible stderr
// warning when the managed cloud lane cannot mint a bearer token at
// inspect time. Meant to make the fail-open condition visible to
// anyone tailing gateway.err.log — EmitCiscoError alone lands in the
// structured events pipeline, which is not what operators watch
// during live triage.
//
// Every call to Inspect that reaches this branch means the current
// prompt / tool call was allowed through WITHOUT AI Defense
// adjudication (managed_enterprise's local detectors are demoted at
// sidecar.go:runGuardrail, so the cloud lane is the sole enforcement
// path; a missing token collapses that path to fail-open). Flagging
// this in the log is the difference between "silent-allow" showing
// up in a support ticket and 24h of live-fire bypass no one noticed.
//
// Rate-limited to once per tokenUnavailableWarnCooldown per client
// instance so that a persistently unavailable CMID library does not
// produce thousands of duplicate log lines per hour. The first
// warning after each cooldown window is emitted; the rest are
// suppressed until the window elapses.
func (c *CiscoDefenseClawInspectClient) warnTokenUnavailable(err error) {
	if c == nil {
		return
	}
	now := time.Now()
	c.tokenWarnMu.Lock()
	emit := now.Sub(c.tokenLastWarn) >= tokenUnavailableWarnCooldown
	if emit {
		c.tokenLastWarn = now
	}
	c.tokenWarnMu.Unlock()
	if !emit {
		return
	}
	detail := "unknown"
	if err != nil {
		detail = err.Error()
	}
	fmt.Fprintf(defaultLogWriter,
		"  [cisco-ai-defense] WARNING: managed cloud token unavailable — AID inspection SKIPPED for this call (fail-open).\n"+
			"  [cisco-ai-defense]          Cause: %s\n"+
			"  [cisco-ai-defense]          Enforcement is currently NOT running end-to-end for managed_enterprise.\n"+
			"  [cisco-ai-defense]          Confirm the Cisco Cloud Management identity library (libcmidapi.dylib on\n"+
			"  [cisco-ai-defense]          macOS, cmidapi.dll on Windows) is installed and readable by this daemon.\n"+
			"  [cisco-ai-defense]          The lane self-heals on the next inspect once the library becomes loadable;\n"+
			"  [cisco-ai-defense]          no daemon restart required.\n",
		detail)
}

// Inspect sends messages to the DefenseClaw AID endpoint and returns a
// normalized verdict. Returns nil on any error so the caller falls back
// to local-only scanning — same fail-open contract as the API-key path.
func (c *CiscoDefenseClawInspectClient) Inspect(ctx context.Context, messages []ChatMessage) *ScanVerdict {
	if c == nil {
		// Programming-error defensive path. Cannot rate-limit through
		// receiver state; call the package-level logger directly so
		// the condition still surfaces to operators.
		logManagedAIDSkip("aid-client-nil", "CiscoDefenseClawInspectClient receiver is nil")
		return nil
	}
	if c.provider == nil {
		// Constructor guards this at NewCiscoDefenseClawInspectClient
		// so we should never reach here in practice, but a defensive
		// log keeps the "no silent skip" invariant intact even under
		// future refactors that could leave provider nil.
		logManagedAIDSkip("aid-provider-nil", "credential provider is nil on the AID inspect client")
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	runtime := ciscoInspectRuntimeFromContext(ctx, c.observabilityV8Runtime())

	// Refresh the token per call — cheap in-memory cache read after
	// the first successful load. Caching semantics live in the managed
	// cloud auth module registered via internal/managed/cloudreg.
	tokenCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	tok, err := c.provider.Token(tokenCtx)
	if err != nil || strings.TrimSpace(tok) == "" {
		detail := "managed cloud token unavailable"
		if err != nil {
			detail += ": " + err.Error()
		}
		EmitCiscoError(ctx, gatewaylog.ErrCodeUpstreamError, detail)
		recordCiscoInspectV8(ctx, runtime, -1, observability.OutcomeFailed, gatewaylog.ErrCodeUpstreamError)
		// Rate-limited operator warning: every request that hits
		// this branch is a fail-open decision. Making it visible in
		// gateway.err.log is what distinguishes "enforcement is off"
		// from "enforcement allowed this prompt". EmitCiscoError
		// above lands in the structured events pipeline; this line
		// is for humans reading the log live.
		c.warnTokenUnavailable(err)
		return nil
	}

	// Body: messages[].content is the DefenseClaw MessageContent shape
	// ({"text": ...}), matching the proto and the sample curl in the
	// task description. No device_id, no dc_metadata — cloud derives
	// both from the bearer token.
	chatMsgs := make([]map[string]interface{}, len(messages))
	for i, m := range messages {
		chatMsgs[i] = map[string]interface{}{
			"role":    m.Role,
			"content": map[string]interface{}{"text": m.Content},
		}
	}
	// The defense_claw endpoint's cloud-side tenant is the authoritative
	// source of the enabled-rules catalog for managed calls. Sending our
	// own hard-coded 12-rule list triggers a 400 on every request
	// ("invalid rule name") which forced the shared HTTP helper into a
	// two-round-trip retry cycle per inspection. Dropping the config
	// block entirely on this path removes the retry — the cloud applies
	// whatever rules the tenant has configured for managed callers.
	// The API-key path (CiscoInspectClient / /api/v1/inspect/chat) still
	// sends enabled_rules because opensource tenants rely on our default
	// catalog when they haven't configured their own.
	payload := map[string]interface{}{"messages": chatMsgs}

	// currentToken is captured by both setAuth and onUnauthorized so
	// the retry can attach the refreshed token without re-invoking
	// Provider from inside doInspectHTTP.
	currentToken := tok

	verdict := doInspectHTTP(ctx, runtime, inspectCall{
		client:   c.client,
		endpoint: c.endpoint,
		urlPath:  "/api/v1/inspect/defense_claw",
		payload:  payload,
		setAuth: func(req *http.Request) {
			req.Header.Set("Authorization", "Bearer "+currentToken)
		},
		onUnauthorized: func(retryCtx context.Context) bool {
			c.provider.Invalidate()
			ctx, cancel := context.WithTimeout(retryCtx, c.timeout)
			defer cancel()
			fresh, err := c.provider.Token(ctx)
			if err != nil || fresh == "" || fresh == currentToken {
				// No new credential available; don't loop.
				return false
			}
			currentToken = fresh
			return true
		},
	})
	if verdict == nil {
		// Any nil verdict from doInspectHTTP means the AID call did
		// not produce an enforceable decision (marshal error, request
		// build error, transport error, non-2xx, body read error, or
		// JSON parse error — each of these already emit their own
		// [cisco-ai-defense] line inside doInspectHTTP, but this
		// consolidated skip warning ensures the fail-open contract
		// itself is visible even when the underlying cause is only
		// captured in the structured event stream).
		logManagedAIDSkip("aid-http-no-verdict", "doInspectHTTP returned no verdict — see prior [cisco-ai-defense] error / structured event for cause")
	}
	return verdict
}
