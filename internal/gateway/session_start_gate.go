// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// sessionStartGate holds each agent session's start verdict in this gateway
// process (GAP-0806). A session start can take long (a slow scan, a
// registration repair, a starting Windows service) while the agent goes on
// to its first prompt and tool call: an agent does not stop when its start
// hook times out. A call of a session whose start the gateway is still
// judging therefore waits for that verdict, and is refused when it does not
// come in time. A start the gateway blocked keeps refusing the session's
// calls until the agent starts the session again.
//
// A call can also reach the gateway before its session's start does (the
// agent does not wait for its start hook, GAP-0973). A call of a session
// whose start this process has not seen waits a short while for one to
// arrive (await's arrival), where a start verdict can block. A start that
// does not arrive in that time is not an allowed start (GAP-1448): the call
// judges the session's start in its place, and that verdict holds the
// session until a start of the session replaces it.
type sessionStartGate struct {
	mu      sync.Mutex
	entries map[string]*sessionStartEntry
	// started are the sessions whose start this process has seen or judged
	// in its place; arrivals wake calls waiting for a start.
	started  map[string]time.Time
	arrivals map[string]chan struct{}
}

type sessionStartEntry struct {
	// done is closed once blocked and reason are final.
	done    chan struct{}
	blocked bool
	reason  string
	at      time.Time
}

// sessionStartTicket is one session start being judged.
type sessionStartTicket struct {
	gate  *sessionStartGate
	key   string
	entry *sessionStartEntry
	once  sync.Once
}

const (
	// sessionStartGateLimit bounds the sessions kept. A start being judged
	// is never dropped; a blocked one is dropped oldest first.
	sessionStartGateLimit = 4096
	// sessionStartGateTTL is how long a blocked start keeps refusing.
	sessionStartGateTTL = 7 * 24 * time.Hour
	// sessionStartPendingReason refuses a call whose session start is still
	// being judged after the wait.
	sessionStartPendingReason = "DefenseClaw has not finished checking this agent session's start, so it blocks this call. Try again in a moment; if this repeats, restart the agent."
	// sessionStartUnfinishedReason is a start that ended without a verdict.
	sessionStartUnfinishedReason = "the session start check did not finish"
)

// sessionStartGateMaxWait bounds how long a call waits for its session's
// start verdict (a variable for tests).
var sessionStartGateMaxWait = 10 * time.Second

// sessionStartArrivalWait is how long a call of a session whose start this
// process has not seen waits for that start to arrive. The gateway tests
// set it to zero (TestMain); the gate's own tests set it.
var sessionStartArrivalWait = time.Second

// sessionStartGateKey names a session for the gate: the connector, the
// verified caller and the session ID (scoped to a sandbox binding). "" when
// the call names no session.
func sessionStartGateKey(ctx context.Context, connectorName, sessionID string) string {
	session := sandboxSessionStateKey(ctx, strings.TrimSpace(sessionID))
	if session == "" {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(connectorName)) + "\x00" + verifiedSessionCaller(ctx) + "\x00" + session
}

// verifiedSessionCaller names the verified caller a session's state is
// scoped to: the kernel-verified uid of a managed hook-socket caller, else
// the verified user-scoped identity (a managed Windows caller's), else ""
// (a per-user gateway has one user).
func verifiedSessionCaller(ctx context.Context) string {
	if peer, ok := managedHookPeerFromContext(ctx); ok {
		return "uid:" + strconv.Itoa(peer.UID)
	}
	if identity, _ := ctx.Value(verifiedUserScopedIdentityContextKey{}).(string); identity != "" {
		return "user:" + identity
	}
	return ""
}

// sessionStartGateEvent reports a call the gate holds back: a prompt or a
// tool call. Lifecycle and result events cannot run anything.
func sessionStartGateEvent(event string) bool {
	switch canonicalHookLifecycleEvent(event) {
	case "turn_start", "tool_start":
		return true
	}
	return false
}

// sessionStartGateWait is how long a call waits: half of its hook's request
// budget, at most sessionStartGateMaxWait, so the refusal reaches the agent
// before the hook gives up.
func sessionStartGateWait(connectorName, event string) time.Duration {
	wait := hookexec.RequestTimeout(connectorName, event) / 2
	if wait <= 0 || wait > sessionStartGateMaxWait {
		wait = sessionStartGateMaxWait
	}
	return wait
}

// begin records a session start being judged. A later start of the same
// session replaces the earlier verdict.
func (g *sessionStartGate) begin(key string) *sessionStartTicket {
	if g == nil || key == "" {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.beginLocked(key)
}

func (g *sessionStartGate) beginLocked(key string) *sessionStartTicket {
	entry := &sessionStartEntry{done: make(chan struct{}), at: time.Now()}
	if g.entries == nil {
		g.entries = make(map[string]*sessionStartEntry)
	}
	if len(g.entries) >= sessionStartGateLimit {
		g.evictLocked(time.Now())
	}
	g.entries[key] = entry
	g.seenLocked(key, entry.at)
	return &sessionStartTicket{gate: g, key: key, entry: entry}
}

// evictLocked drops expired blocks, then the oldest finished ones until the
// gate is under its limit.
func (g *sessionStartGate) evictLocked(now time.Time) {
	var oldestKey string
	var oldest time.Time
	for key, entry := range g.entries {
		select {
		case <-entry.done:
		default:
			continue
		}
		if now.Sub(entry.at) > sessionStartGateTTL {
			delete(g.entries, key)
			continue
		}
		if oldestKey == "" || entry.at.Before(oldest) {
			oldestKey, oldest = key, entry.at
		}
	}
	if len(g.entries) >= sessionStartGateLimit && oldestKey != "" {
		delete(g.entries, oldestKey)
	}
}

// seenLocked records that key's start was seen or judged, and wakes the calls waiting for it. It keeps at most
// sessionStartGateLimit sessions, dropping the oldest.
func (g *sessionStartGate) seenLocked(key string, at time.Time) {
	if g.started == nil {
		g.started = make(map[string]time.Time)
	}
	if _, known := g.started[key]; !known && len(g.started) >= sessionStartGateLimit {
		oldestKey, oldest := "", time.Time{}
		for seen, seenAt := range g.started {
			if oldestKey == "" || seenAt.Before(oldest) {
				oldestKey, oldest = seen, seenAt
			}
		}
		delete(g.started, oldestKey)
	}
	g.started[key] = at
	if arrival := g.arrivals[key]; arrival != nil {
		close(arrival)
		delete(g.arrivals, key)
	}
}

// finish records the start's verdict and releases the calls waiting for it.
// Only the first call counts. An allowed start leaves nothing behind.
func (t *sessionStartTicket) finish(blocked bool, reason string) {
	if t == nil {
		return
	}
	t.once.Do(func() {
		g := t.gate
		g.mu.Lock()
		t.entry.blocked, t.entry.reason, t.entry.at = blocked, reason, time.Now()
		if !blocked && g.entries[t.key] == t.entry {
			delete(g.entries, t.key)
		}
		g.mu.Unlock()
		close(t.entry.done)
	})
}

// await returns the reason to refuse a call of the session: its start was
// blocked, or is still being judged after wait (or when ctx ends). A call of
// a session whose start this process has not seen first waits up to arrival
// for it (zero: not at all, where no start verdict can block). When no start
// comes in that time the call does not run on a timer (GAP-1448): it judges
// the session's start with startCheck, as that start would be judged, and
// the verdict is the session's start verdict for this call and the later
// ones, until a start of the session replaces it.
func (g *sessionStartGate) await(ctx context.Context, key string, wait, arrival time.Duration, startCheck func(context.Context) (bool, string)) (string, bool) {
	if g == nil || key == "" {
		return "", false
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		g.mu.Lock()
		entry := g.entries[key]
		if entry == nil {
			_, seen := g.started[key]
			if seen || arrival <= 0 {
				g.mu.Unlock()
				return "", false
			}
			if g.arrivals == nil {
				g.arrivals = make(map[string]chan struct{})
			}
			arrived := g.arrivals[key]
			if arrived == nil {
				arrived = make(chan struct{})
				g.arrivals[key] = arrived
			}
			g.mu.Unlock()
			// The wait uses no gateway CPU: the call gives up its caller's
			// run slot for it, so unseen sessions of one account do not
			// queue behind each other's windows (GAP-1822).
			resume := pauseHookRunSlot(ctx)
			window := time.NewTimer(min(arrival, wait))
			timedOut := false
			select {
			case <-arrived:
			case <-window.C:
				timedOut = true
			case <-ctx.Done():
				window.Stop()
				resume()
				return sessionStartPendingReason, true
			}
			window.Stop()
			resume()
			// A request that ended while it waited to take its run slot
			// back is not judged: a start check (or a Codex registration
			// repair) run with a done context would record a sticky
			// start block for a live session.
			if ctx.Err() != nil {
				return sessionStartPendingReason, true
			}
			if timedOut {
				g.judgeMissingStart(ctx, key, startCheck)
			}
			arrival = 0
			continue
		}
		g.mu.Unlock()
		select {
		case <-entry.done:
			if entry.blocked {
				if time.Since(entry.at) > sessionStartGateTTL {
					g.mu.Lock()
					if g.entries[key] == entry {
						delete(g.entries, key)
					}
					g.mu.Unlock()
					return "", false
				}
				return sessionStartBlockedReason(entry.reason), true
			}
			// The verdict allowed the start; a newer start may be pending.
			continue
		default:
		}
		select {
		case <-entry.done:
		case <-timer.C:
			return sessionStartPendingReason, true
		case <-ctx.Done():
			return sessionStartPendingReason, true
		}
	}
}

// judgeMissingStart judges the start of a session whose start did not
// arrive, unless one arrived meanwhile, and records the verdict as that
// start's. A check that is missing or does not finish blocks, as a start
// without a verdict does.
func (g *sessionStartGate) judgeMissingStart(ctx context.Context, key string, startCheck func(context.Context) (bool, string)) {
	g.mu.Lock()
	if _, seen := g.started[key]; seen || g.entries[key] != nil {
		g.mu.Unlock()
		return
	}
	ticket := g.beginLocked(key)
	g.mu.Unlock()
	blocked, reason := true, sessionStartUnfinishedReason
	defer func() {
		_ = recover()
		ticket.finish(blocked, reason)
	}()
	if startCheck != nil {
		blocked, reason = startCheck(ctx)
	}
}

// sessionStartArrival is how long a call of a session whose start the gate
// has not seen waits for it: only where a start verdict can block, in action
// mode (sessionStartVerdictBlocks), for a connector that sends a start.
//
// A session whose start an earlier gateway process recorded (its saved
// instruction record knows its startup) will not send that start again: it
// was running when this gateway started or upgraded. Waiting for it would
// only delay the call by the whole window (GAP-1459), so its start is judged
// in its place at once, as a start that does not arrive is (GAP-1448), and
// the call goes on with that verdict.
func (a *APIServer) sessionStartArrival(ctx context.Context, profile connector.HookProfile, connectorName string) time.Duration {
	if sandboxHookMode(ctx, connectorName, a.agentHookMode(ctx, connectorName)) != "action" ||
		!slices.ContainsFunc(profile.SupportedEvents, func(event string) bool {
			return canonicalHookLifecycleEvent(event) == "session_start"
		}) {
		return 0
	}
	sessionID := strings.TrimSpace(SessionIDFromContext(ctx))
	if key := sessionStartGateKey(ctx, connectorName, sessionID); key != "" &&
		!a.sessionStartGate.known(key) && a.sessionStartRecordedEarlier(ctx, connectorName, sessionID) {
		a.sessionStartGate.judgeMissingStart(ctx, key, a.sessionStartCheck(connectorName))
	}
	return sessionStartArrivalWait
}

// known reports a session whose start this process has seen, judged or is
// judging.
func (g *sessionStartGate) known(key string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	_, seen := g.started[key]
	return seen || g.entries[key] != nil
}

// sessionStartRecordedEarlier reports a session whose saved instruction
// record holds a startup an earlier gateway process recorded.
func (a *APIServer) sessionStartRecordedEarlier(ctx context.Context, connectorName, sessionID string) bool {
	dir := a.instructionLoadDir()
	if dir == "" {
		return false
	}
	key, ok := instructionStartupKey(ctx, connectorName, sessionID)
	if !ok {
		return false
	}
	record, ok := readInstructionLoadRecord(instructionLoadRecordPath(dir, key), key)
	return ok && record.StartupKnown
}

// codexStartRegistrationUnavailable is the start verdict of a Codex session
// whose managed runtime registration could not be repaired.
const codexStartRegistrationUnavailable = "Codex runtime registration is unavailable"

// codexStartRegistrationRefusal repairs a missing managed runtime
// registration for a Codex session start and returns the refusal when it
// cannot ("" otherwise, and for every other connector and a sandboxed
// Codex).
func (a *APIServer) codexStartRegistrationRefusal(ctx context.Context, connectorName string) string {
	if connectorName != "codex" || isSandboxHookRequest(ctx) {
		return ""
	}
	if err := a.ensureHookRegistration(ctx, connectorName); err != nil {
		fmt.Fprintf(os.Stderr, "[gateway] Codex SessionStart registration recovery failed: %v\n", err)
		if step := registrationRepairStep(err); step != "" {
			return codexStartRegistrationUnavailable + ": " + step
		}
		return codexStartRegistrationUnavailable
	}
	return ""
}

// registrationRepairStep is the text of the error in err's chain that names
// the command the user runs to repair the registration ("...; run:
// defenseclaw setup codex --yes", connector.ErrCodexExecutableChanged after
// a Codex self-update, GAP-1884), so the refusal and the 503 body name the
// step instead of only "run doctor". The innermost such error is taken: it
// is the cause, without the wrapping detail (paths, digests). Any other
// error gives "".
func registrationRepairStep(err error) string {
	step := ""
	for ; err != nil; err = errors.Unwrap(err) {
		if text := err.Error(); strings.Contains(text, "run: defenseclaw ") {
			step = text
		}
	}
	return step
}

// sessionStartCheck judges, for a call, the start of its session that did
// not reach this gateway (GAP-1448), with the checks a start runs and a call
// does not: a Codex session's registration repair. The call itself still
// runs the profile refusal, the require-sandbox gate and its own evaluation.
// It cannot judge a start payload it never received.
func (a *APIServer) sessionStartCheck(connectorName string) func(context.Context) (bool, string) {
	return func(ctx context.Context) (bool, string) {
		if refusal := a.codexStartRegistrationRefusal(ctx, connectorName); refusal != "" {
			return true, refusal
		}
		return false, ""
	}
}

func sessionStartBlockedReason(reason string) string {
	reason = strings.TrimSpace(reason)
	if len(reason) > 400 {
		reason = reason[:400]
	}
	if reason == "" {
		reason = sessionStartUnfinishedReason
	}
	return "DefenseClaw blocked this agent session when it started (" + reason + "), so it blocks this call. Restart the agent."
}

// sessionStartVerdictBlocks reports a start verdict that blocks the session:
// an enforced block, whether or not the agent's start event can stop it.
func sessionStartVerdictBlocks(resp agentHookResponse) bool {
	return strings.EqualFold(resp.RawAction, guardrailActionBlock) && resp.Mode == "action"
}

// sessionStartGateRefusal answers a call the gate refuses, in the
// connector's verdict shape and mode.
func (a *APIServer) sessionStartGateRefusal(
	ctx context.Context,
	profile connector.HookProfile,
	connectorName string,
	req agentHookRequest,
	payload map[string]interface{},
	reason string,
) agentHookResponse {
	finding := "SESSION-START-BLOCKED"
	if reason == sessionStartPendingReason {
		finding = "SESSION-START-PENDING"
	}
	mode := sandboxHookMode(ctx, connectorName, a.agentHookMode(ctx, connectorName))
	action, wouldBlock := mapHookActionForProfile("block", mode, req.HookEventName, profile.Capabilities, profile, payload)
	return agentHookResponseForProfile(profile, req, action, "block", "HIGH", reason,
		[]string{finding}, mode, wouldBlock, profile.Capabilities)
}
