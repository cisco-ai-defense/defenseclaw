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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// One Copilot tool call can reach the gateway twice:
//
//   - VS Code's Local harness runs both DefenseClaw's per-user hook file and
//     its plugin (same stdin, same tool_use_id);
//   - the Copilot CLI runs its machine policy hooks (camelCase) and also the
//     per-user hook file through its command fallback (PascalCase, without a
//     tool_use_id).
//
// copilotHookDedupe answers the second delivery with the first one's
// verdict, re-rendered for the second delivery's profile, so the call is
// evaluated and audited once. It matches the exact tool_use_id, or, across
// the two CLI dialects only, the same session, phase, tool and arguments
// within a few seconds. A second delivery that finds no finished verdict in
// time is evaluated normally: deduplication never lets a call through
// unevaluated.

const (
	copilotDedupeExactTTL   = 30 * time.Second
	copilotDedupeContentTTL = 10 * time.Second
	copilotDedupeWait       = 5 * time.Second
	copilotDedupeMaxEntries = 4096
)

type copilotHookDedupe struct {
	mu      sync.Mutex
	entries map[string]*copilotDedupeEntry
}

type copilotDedupeEntry struct {
	done    chan struct{}
	resp    agentHookResponse
	ok      bool
	dialect string
	expires time.Time
}

// copilotDedupeTicket is one delivery's claim on its keys. A zero ticket
// (no keys) is inert.
type copilotDedupeTicket struct {
	d       *copilotHookDedupe
	entries []*copilotDedupeEntry
	once    sync.Once
}

// copilotDedupeScope is the caller the verdict may be reused for: the
// verified caller on a standalone gateway, the gateway's own user on a
// per-user gateway. A service-account gateway with no verified caller
// never deduplicates.
func copilotDedupeScope(ctx context.Context) string {
	if caller, ok := verifiedAuditCaller(ctx); ok {
		return caller.IDKind + ":" + caller.ID
	}
	if serviceAccountGatewayFromContext(ctx) {
		return ""
	}
	return "self"
}

// copilotDedupeKeys returns the exact (tool_use_id) key, the content key
// and the delivery's dialect ("camel" or "snake"). Empty keys do not apply.
func copilotDedupeKeys(ctx context.Context, connectorName string, req agentHookRequest) (exact, content, dialect string) {
	if connectorName != "copilot" || isSandboxHookRequest(ctx) {
		return "", "", ""
	}
	phase := canonicalEvent(req.HookEventName)
	if phase != "pretooluse" && phase != "posttooluse" {
		return "", "", ""
	}
	scope := copilotDedupeScope(ctx)
	session := strings.TrimSpace(req.SessionID)
	if scope == "" || session == "" {
		return "", "", ""
	}
	dialect = "snake"
	if firstValue(req.Payload, "toolArgs", "toolName") != nil {
		dialect = "camel"
	}
	tool := strings.ToLower(strings.TrimSpace(req.ToolName))
	digest, ok := copilotToolArgsDigest(req.ToolArgs)
	if !ok || tool == "" {
		return "", "", ""
	}
	// Both keys carry the call itself, so a reused or colliding id never
	// answers a different call.
	call := scope + "\x00" + session + "\x00" + phase + "\x00" + tool + "\x00" + digest
	if id := firstString(req.Payload, "tool_use_id", "toolUseId"); id != "" {
		exact = "id\x00" + id + "\x00" + call
	}
	return exact, "args\x00" + call, dialect
}

// copilotToolArgsDigest hashes the call's arguments in one form for both
// dialects: the camelCase toolArgs is a JSON string, the snake_case
// tool_input an object. Re-marshalling sorts object keys.
func copilotToolArgsDigest(raw json.RawMessage) (string, bool) {
	var value any
	if len(raw) == 0 || json.Unmarshal(raw, &value) != nil {
		return "", false
	}
	if text, ok := value.(string); ok {
		var inner any
		if json.Unmarshal([]byte(text), &inner) == nil {
			value = inner
		}
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return "", false
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), true
}

// begin looks up this delivery's keys. On a hit it returns the earlier
// verdict; otherwise it claims the free keys and returns a ticket whose
// complete stores the verdict (release frees the claim on every path).
func (d *copilotHookDedupe) begin(ctx context.Context, connectorName string, req agentHookRequest) (agentHookResponse, bool, *copilotDedupeTicket) {
	ticket := &copilotDedupeTicket{d: d}
	exact, content, dialect := copilotDedupeKeys(ctx, connectorName, req)
	if exact == "" && content == "" {
		return agentHookResponse{}, false, ticket
	}
	now := time.Now()
	d.mu.Lock()
	if d.entries == nil {
		d.entries = map[string]*copilotDedupeEntry{}
	}
	for key, entry := range d.entries {
		if entry.expires.Before(now) {
			delete(d.entries, key)
		}
	}
	var earlier *copilotDedupeEntry
	if entry := d.entries[exact]; exact != "" && entry != nil {
		earlier = entry
	} else if entry := d.entries[content]; content != "" && entry != nil && entry.dialect != dialect {
		earlier = entry
	}
	if earlier == nil {
		for _, claim := range []struct {
			key string
			ttl time.Duration
		}{{exact, copilotDedupeExactTTL}, {content, copilotDedupeContentTTL}} {
			if claim.key == "" || d.entries[claim.key] != nil || len(d.entries) >= copilotDedupeMaxEntries {
				continue
			}
			entry := &copilotDedupeEntry{done: make(chan struct{}), dialect: dialect, expires: now.Add(claim.ttl)}
			d.entries[claim.key] = entry
			ticket.entries = append(ticket.entries, entry)
		}
	}
	d.mu.Unlock()
	if earlier == nil {
		return agentHookResponse{}, false, ticket
	}
	timer := time.NewTimer(copilotDedupeWait)
	defer timer.Stop()
	select {
	case <-earlier.done:
	case <-timer.C:
		return agentHookResponse{}, false, ticket
	case <-ctx.Done():
		return agentHookResponse{}, false, ticket
	}
	d.mu.Lock()
	resp, ok := earlier.resp, earlier.ok
	d.mu.Unlock()
	return resp, ok, ticket
}

// complete stores the delivery's final verdict for its claimed keys.
func (t *copilotDedupeTicket) complete(resp agentHookResponse) {
	if t == nil || len(t.entries) == 0 {
		return
	}
	t.once.Do(func() {
		t.d.mu.Lock()
		for _, entry := range t.entries {
			entry.resp, entry.ok = resp, true
		}
		t.d.mu.Unlock()
		for _, entry := range t.entries {
			close(entry.done)
		}
	})
}

// release wakes waiters without a verdict when the delivery ended some
// other way (rejected, panicked); they evaluate on their own.
func (t *copilotDedupeTicket) release() {
	if t == nil || len(t.entries) == 0 {
		return
	}
	t.once.Do(func() {
		t.d.mu.Lock()
		for key, entry := range t.d.entries {
			for _, mine := range t.entries {
				if entry == mine {
					delete(t.d.entries, key)
				}
			}
		}
		t.d.mu.Unlock()
		for _, entry := range t.entries {
			close(entry.done)
		}
	})
}

// copilotDedupedResponse re-renders an earlier delivery's verdict for this
// delivery's profile (the CLI and Local dialects answer differently).
func copilotDedupedResponse(profile connector.HookProfile, req agentHookRequest, earlier agentHookResponse) agentHookResponse {
	next := agentHookResponseForProfile(
		profile,
		req,
		earlier.Action,
		earlier.RawAction,
		earlier.Severity,
		hookSourceReason(earlier),
		earlier.Findings,
		earlier.Mode,
		earlier.WouldBlock,
		profile.Capabilities,
	)
	next.EvaluationID = earlier.EvaluationID
	next.RuleIDs = append([]string(nil), earlier.RuleIDs...)
	next.RedactionEnabled = earlier.RedactionEnabled
	next.laneVerdict = earlier.laneVerdict
	return next
}
