// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/historystore"
)

const missingPreToolRuleID = "HOOK-PRE-TOOL-MISSING"

// A post-tool hook can observe a call whose pre-tool hook never reached the
// gateway. This bounded ring holds only decisions whose audit row persisted;
// it does not claim to prevent a tool that the agent already ran.
const maxPendingPreToolDecisions = 4096

// preToolDecisionKey names one tool call of one caller. The caller is the
// verified hook caller (copilotDedupeScope), never the correlation-minted
// connector instance: concurrent hooks of one session can leave one of a
// call's two deliveries without its correlation, and a key that differed
// between them reported the audited PreToolUse as missing (GAP-1228).
type preToolDecisionKey struct {
	caller    string
	connector string
	session   string
	toolUse   string
}

type preToolDecisionSlot struct {
	key      preToolDecisionKey
	sequence uint64
}

type preToolDecisionTracker struct {
	mu       sync.Mutex
	seen     map[preToolDecisionKey]uint64
	slots    [maxPendingPreToolDecisions]preToolDecisionSlot
	sequence uint64
}

// record adds key and reports whether it was not held yet.
func (tracker *preToolDecisionTracker) record(key preToolDecisionKey) bool {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	if tracker.seen == nil {
		tracker.seen = make(map[preToolDecisionKey]uint64)
	}
	if tracker.seen[key] != 0 {
		return false
	}
	tracker.sequence++
	index := tracker.sequence % maxPendingPreToolDecisions
	previous := tracker.slots[index]
	if tracker.seen[previous.key] == previous.sequence {
		delete(tracker.seen, previous.key)
	}
	tracker.slots[index] = preToolDecisionSlot{key: key, sequence: tracker.sequence}
	tracker.seen[key] = tracker.sequence
	return true
}

func (tracker *preToolDecisionTracker) forget(key preToolDecisionKey) {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	delete(tracker.seen, key)
}

func (tracker *preToolDecisionTracker) contains(key preToolDecisionKey) bool {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	return tracker.seen[key] != 0
}

// On Agent Substrate the hooks of one actor are spread over the gateway
// replicas, so a PostToolUse can land on another replica than its PreToolUse
// and this process's ring alone reported the audited PreToolUse as missing
// (substrate-1 GAP-0267). An actor's decisions are also kept in the record
// every replica shares on the leader (the inspect-once record's store, by
// hash only: the tool invocation id never crosses the wire). A decision
// forgotten here (its answer unconfirmed, its audit row not written) is
// marked forgotten there, and stays so for the other replicas if it is
// recorded again (one more alert, never a missed one). The record is
// audit-only: it is written in the background, so no hook answer waits on
// the leader, and a leader that cannot be reached leaves the replica's own
// ring, so the alert is written rather than missed.
const preToolSharedTimeout = 2 * time.Second

var preToolSharedLastWarn atomic.Int64

// preToolShared is the shared record of ctx's call: the leader's store for
// a verified actor's call on a Substrate gateway, else nil.
func preToolShared(ctx context.Context) historystore.Store {
	if _, ok := substrateActorFrom(ctx); !ok {
		return nil
	}
	if shared := substrateHistoryStore.Load(); shared != nil {
		return *shared
	}
	return nil
}

// sharedScope is the key's scope in the shared record: a digest of the
// caller, connector and session, so its length is bounded.
func (key preToolDecisionKey) sharedScope() string {
	sum := sha256.Sum256([]byte(key.caller + "\x00" + key.connector + "\x00" + key.session))
	return "\x00defenseclaw-pre-tool\x00" + hex.EncodeToString(sum[:16])
}

func (key preToolDecisionKey) sharedHashes() (decided, forgotten historystore.Hash) {
	return historyHashOf("decided\x00" + key.toolUse), historyHashOf("forgotten\x00" + key.toolUse)
}

func preToolSharedWarn(op string, err error) {
	now := time.Now().UnixNano()
	last := preToolSharedLastWarn.Load()
	if now-last < int64(time.Minute) || !preToolSharedLastWarn.CompareAndSwap(last, now) {
		return
	}
	fmt.Fprintf(os.Stderr, "[gateway] warning: the replicas' pre-tool decision record could not be %s (%v); this replica's own record is used\n", op, err)
}

func preToolSharedWrite(ctx context.Context, key preToolDecisionKey, forgotten bool) {
	shared := preToolShared(ctx)
	if shared == nil {
		return
	}
	decided, forgot := key.sharedHashes()
	h := decided
	if forgotten {
		h = forgot
	}
	ctx = context.WithoutCancel(ctx)
	go func() {
		ctx, cancel := context.WithTimeout(ctx, preToolSharedTimeout)
		defer cancel()
		if err := shared.Record(ctx, key.caller, key.sharedScope(), []historystore.Hash{h},
			historystore.Entry{Verdict: historystore.Allowed}, maxPendingPreToolDecisions); err != nil {
			preToolSharedWarn("written", err)
		}
	}()
}

// recordPreToolDecision keeps an audited PreToolUse decision, on every
// replica of a Substrate gateway.
func (a *APIServer) recordPreToolDecision(ctx context.Context, key preToolDecisionKey) {
	if a.preToolDecisions.record(key) {
		preToolSharedWrite(ctx, key, false)
	}
}

// forgetPreToolDecision drops a decision whose answer was unconfirmed or
// whose audit row was not written.
func (a *APIServer) forgetPreToolDecision(ctx context.Context, key preToolDecisionKey) {
	a.preToolDecisions.forget(key)
	preToolSharedWrite(ctx, key, true)
}

// preToolDecided reports an audited PreToolUse decision of key: this
// replica's, or, for an actor's call, one another replica recorded.
func (a *APIServer) preToolDecided(ctx context.Context, key preToolDecisionKey) bool {
	if a.preToolDecisions.contains(key) {
		return true
	}
	shared := preToolShared(ctx)
	if shared == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), preToolSharedTimeout)
	defer cancel()
	decided, forgotten := key.sharedHashes()
	known, err := shared.Seen(ctx, key.sharedScope(), []historystore.Hash{decided, forgotten})
	if err != nil {
		preToolSharedWarn("read", err)
		return false
	}
	_, isDecided := known[decided]
	_, isForgotten := known[forgotten]
	return isDecided && !isForgotten
}

// preToolDecisionKeyFor is the key of a tracked hook call and its event, or
// false for a call the tracker does not follow.
func (a *APIServer) preToolDecisionKeyFor(ctx context.Context, req agentHookRequest) (preToolDecisionKey, string, bool) {
	if a == nil || a.logger == nil || (a.scannerCfg != nil && a.scannerCfg.SecureClientIntegration()) {
		return preToolDecisionKey{}, "", false
	}
	connector := connName(req.ConnectorName)
	if connector != "claudecode" && connector != "codex" {
		return preToolDecisionKey{}, "", false
	}
	event := strings.TrimSpace(req.HookEventName)
	if event != "PreToolUse" && event != "PostToolUse" && event != "PostToolUseFailure" {
		return preToolDecisionKey{}, "", false
	}
	return preToolDecisionKey{
		caller:    copilotDedupeScope(ctx),
		connector: connector,
		session:   strings.TrimSpace(req.SessionID),
		toolUse:   strings.TrimSpace(req.ToolInvocationID),
	}, event, true
}

// notePreToolDecision records a PreToolUse whose verdict is final before its
// answer is offered: the agent can run the tool and its PostToolUse can be
// finalized before this call's audit commit, which reported the audited
// PreToolUse as missing (GAP-1228). The caller forgets the key when the
// answer is unconfirmed or its audit row is not written.
func (a *APIServer) notePreToolDecision(ctx context.Context, req agentHookRequest, resp agentHookResponse) (preToolDecisionKey, bool) {
	key, event, ok := a.preToolDecisionKeyFor(ctx, req)
	if !ok || event != "PreToolUse" || key.session == "" || key.toolUse == "" ||
		resp.Action == hookActionUnconfirmed || a.preToolDecisions.contains(key) {
		return preToolDecisionKey{}, false
	}
	a.recordPreToolDecision(ctx, key)
	return key, true
}

func (a *APIServer) auditMissingPreToolDecision(ctx context.Context, req agentHookRequest, resp agentHookResponse) {
	key, event, ok := a.preToolDecisionKeyFor(ctx, req)
	if !ok {
		return
	}
	connector := key.connector
	if event == "PreToolUse" {
		if key.session != "" && key.toolUse != "" && resp.Action != hookActionUnconfirmed {
			a.recordPreToolDecision(ctx, key)
		}
		return
	}
	if key.session != "" && key.toolUse != "" && a.preToolDecided(ctx, key) {
		return
	}
	// A missing exact ID cannot establish a safe match. Keep the post-tool
	// verdict observational and persist the gap under the same caller scope.
	alertCtx := contextWithHookCorrelation(ctx, req, "")
	if err := a.logger.LogAlertCtx(alertCtx, missingPreToolRuleID, "HIGH",
		"Tool result arrived without an audited PreToolUse decision", map[string]any{
			"connector": connector, "event": event,
			"session_id": key.session, "tool_use_id": key.toolUse,
			"rule_id": missingPreToolRuleID,
		}); err != nil {
		fmt.Fprintf(os.Stderr, "[gateway] missing pre-tool decision alert failed connector=%s: %v\n", connector, err)
	}
}
