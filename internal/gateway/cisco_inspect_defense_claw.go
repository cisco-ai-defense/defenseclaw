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
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/managed/cloudreg"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

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

// Inspect sends messages to the DefenseClaw AID endpoint and returns a
// normalized verdict. Returns nil on any error so the caller falls back
// to local-only scanning — same fail-open contract as the API-key path.
func (c *CiscoDefenseClawInspectClient) Inspect(ctx context.Context, messages []ChatMessage) *ScanVerdict {
	if c == nil || c.provider == nil {
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

	return doInspectHTTP(ctx, runtime, inspectCall{
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
}
