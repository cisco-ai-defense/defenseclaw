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
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
)

// handleEgressEvent accepts a single EgressPayload from the TS fetch
// interceptor and re-emits it through the same gatewaylog.Writer the
// Go-side passthrough uses. The endpoint exists so the TS layer can
// report events the proxy never sees (known-provider fetches that
// bypass the proxy because the host+port were listed directly, or
// requests that the interceptor explicitly chose to pass through
// unchanged — Layer 3's silent-bypass early-warning rail).
//
// Authentication: the request MUST present a valid X-DC-Auth token
// because the endpoint is mounted on the same mux as the proxy
// traffic. A rogue local process cannot spoof egress events without
// the token.
//
// Shape:
//
//	POST /v1/events/egress
//	X-DC-Auth: Bearer <OPENCLAW_GATEWAY_TOKEN>
//	Content-Type: application/json
//	{
//	  "target_host": "api.novelai.net",
//	  "target_path": "/v1/chat/completions",
//	  "body_shape": "messages",
//	  "looks_like_llm": true,
//	  "branch": "shape",
//	  "decision": "allow",
//	  "reason": "shape-match"
//	}
//
// The body_shape, looks_like_llm, reason, target_host, and
// target_path fields are all optional; branch + decision are
// required so runtime alerts have enough to fire on.
func (p *GuardrailProxy) handleEgressEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !p.authenticateRequest(w, r) {
		// authenticateRequest only emits the auth-failure audit event;
		// it does not write a status. Emitting the 401 here ensures the
		// TS reporter (and operators) get an actionable response rather
		// than a misleading default-200 silent-success.
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// Reject non-JSON content types explicitly. Any caller that
	// hits /v1/events/egress is a cooperating integration (TS
	// interceptor, tests); refusing text/plain / form encoded /
	// octet-stream here makes the contract narrower and prevents
	// a confused-deputy that expects form fields from writing into
	// gateway.jsonl by accident. We accept bare "application/json"
	// as well as parameterized variants like "application/json;
	// charset=utf-8" and the vendor form "application/*+json".
	if ct := r.Header.Get("Content-Type"); ct != "" {
		mt := strings.TrimSpace(strings.ToLower(ct))
		if i := strings.IndexByte(mt, ';'); i >= 0 {
			mt = strings.TrimSpace(mt[:i])
		}
		if mt != "application/json" && !strings.HasSuffix(mt, "+json") {
			http.Error(w, "unsupported content-type", http.StatusUnsupportedMediaType)
			return
		}
	}

	// 8 KiB cap — every valid egress payload is a few hundred bytes,
	// a hostile caller flooding us can still saturate throughput but
	// cannot exhaust process memory.
	body, err := io.ReadAll(io.LimitReader(r.Body, 8*1024))
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	var payload gatewaylog.EgressPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	// Force source="ts" on this endpoint. Any caller with the auth
	// token could otherwise forge source="go" and poison telemetry
	// that dashboards / alerting treat as proxy-observed ground
	// truth (vs interceptor-reported). The Go proxy never uses this
	// round-trip — it invokes emitEgress in-process with source="go"
	// directly — so unconditional override here is safe.
	payload.Source = "ts"
	// Validate the branch/decision enums server-side so a malformed
	// TS client can't push garbage into gateway.jsonl.
	if !validEgressBranch(payload.Branch) || !validEgressDecision(payload.Decision) {
		http.Error(w, "invalid branch or decision", http.StatusBadRequest)
		return
	}

	emitEgress(r.Context(), payload)
	w.WriteHeader(http.StatusNoContent)
}

func validEgressBranch(b string) bool {
	switch b {
	case "known", "shape", "passthrough":
		return true
	default:
		return false
	}
}

func validEgressDecision(d string) bool {
	switch d {
	case "allow", "block":
		return true
	default:
		return false
	}
}
