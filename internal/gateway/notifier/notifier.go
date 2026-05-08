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

// Package notifier centralizes user-session OS notification dispatch
// for hook blocks, guardrail blocks, asset-policy denials, and HITL
// approval requests.
//
// All block-decision sites in the gateway (claude_code_hook,
// codex_hook, GuardrailProxy, asset_policy_runtime,
// HILTApprovalManager) call OnBlock / OnWouldBlock / OnApprovalPending
// instead of dialing the OS notification API directly. The Dispatcher
// applies four layers of filtering before anything is delivered:
//
//  1. Master switch (config.NotificationsConfig.Enabled).
//  2. Per-category gate (BlockEnforced / BlockWouldBlock / HITLApproval).
//  3. Per-source gate (Sources.Hook / Sources.Guardrail / Sources.AssetPolicy).
//  4. Dedup window + global rate limit.
//
// Delivery itself is delegated to internal/notify (osascript on
// darwin, notify-send on linux) and runs in a goroutine so request
// latency on the block path is unaffected by the OS call. Failures
// are deliberately swallowed: the audit/webhook/system-message
// channels are the authoritative records of every block, and a
// missing toast is never a security event.
package notifier

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/notify"
)

// Source identifies which subsystem decided the block / approval.
// Used by Sources gating in NotificationsConfig and rendered in the
// notification subtitle so operators can tell at a glance which
// surface tripped.
type Source string

const (
	SourceHook        Source = "hook"
	SourceGuardrail   Source = "guardrail"
	SourceAssetPolicy Source = "asset_policy"
)

// Category labels the kind of event for per-category gating and
// dedup keying.
type Category string

const (
	CategoryBlock      Category = "block"
	CategoryWouldBlock Category = "would_block"
	CategoryApproval   Category = "approval"
)

// BlockEvent describes a single block / would-block decision.
//
// Target is the most user-meaningful identifier available for the
// blocked thing — typically a tool name (PreToolUse), the model
// name (LLM proxy block), or a typed asset id like "mcp:github" /
// "skill:my-helper". Connector and Event are optional context that
// flows into the audit-friendly subtitle but never appears in the
// dedup hash (so the same rule fired across many sessions still
// collapses to one notification per dedup window).
//
// WouldAsk repurposes the would-block category for verdicts that
// are technically "confirm" upstream but never reach the user as a
// chat ask. Two cases hit this:
//
//  1. Observe mode — mapHookAction downgrades a confirm verdict to
//     action=allow, so no chat prompt is issued.
//  2. Connectors that cannot natively ask for the event (e.g.
//     cursor's beforeReadFile is blockable but not askable).
//
// In both cases the notification reads "DefenseClaw would ask X"
// rather than the misleading "Approval needed: X / reply in chat",
// AND it goes through the would-block category gate so a single
// `notifications.block_would_block: false` switch silences every
// observe-mode hook notification (would-block + would-ask) without
// touching real native asks (which still flow through
// OnApprovalPending and the HITLApproval gate).
type BlockEvent struct {
	Source    Source
	Target    string
	Reason    string
	Severity  string
	Connector string
	Event     string
	WouldAsk  bool
}

// ApprovalEvent describes a HITL/confirm prompt that is now waiting
// for the user on a real chat surface. Callers MUST only fire this
// when the connector will actually surface a native ask — observe
// mode and "confirm-but-not-askable" cases route through
// Dispatcher.OnWouldBlock with BlockEvent.WouldAsk=true instead, so
// the user does not get an "Approval needed: reply in chat" toast
// for an action that was already allowed through.
//
// Connector and Event are optional context that flows into the
// audit-friendly subtitle so the operator can tell at a glance
// which framework + hook event raised the approval — symmetric
// with BlockEvent. They never appear in the dedup hash so the
// same approval prompt fired across multiple sessions still
// collapses to one toast per dedup window.
type ApprovalEvent struct {
	Subject   string
	Reason    string
	Severity  string
	Source    Source
	Connector string
	Event     string
}

// Dispatcher is the single fan-in point for OS notifications.
// Construct one per gateway with New(cfg) and pass it to every block
// emission site. Concurrency-safe — methods can be called from any
// number of request-handling goroutines.
type Dispatcher struct {
	cfg config.NotificationsConfig

	// sender delivers a Notification to the OS. Tests inject a fake
	// to assert what would have been shown without touching a real
	// display server. Production wiring uses notify.SendNotification.
	sender func(notify.Notification) error

	// nowFn lets tests advance time deterministically. Production
	// wiring uses time.Now.
	nowFn func() time.Time

	mu              sync.Mutex
	seen            map[string]time.Time
	bucketWindowEnd time.Time
	bucketRemaining int
	suppressedInWin int
	rollupAnnounced bool
	lastSweep       time.Time
}

// New constructs a Dispatcher wired to the production OS notifier.
// The dispatcher is safe to keep enabled even when notifications are
// disabled in cfg — the master-switch check is the cheapest path and
// short-circuits before any allocation or locking.
func New(cfg config.NotificationsConfig) *Dispatcher {
	return NewWithSender(cfg, notify.SendNotification)
}

// NewWithSender allows tests (and any future non-OS sink) to inject
// the delivery channel. Pass nil to fall back to the production
// notify.SendNotification path.
func NewWithSender(cfg config.NotificationsConfig, sender func(notify.Notification) error) *Dispatcher {
	if sender == nil {
		sender = notify.SendNotification
	}
	return &Dispatcher{
		cfg:    cfg,
		sender: sender,
		nowFn:  time.Now,
		seen:   make(map[string]time.Time),
	}
}

// SetClock replaces the time source. Tests use this to make dedup +
// rate-limit windows deterministic.
func (d *Dispatcher) SetClock(now func() time.Time) {
	if d == nil || now == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.nowFn = now
}

// OnBlock fires for an enforced (mode=action, action=block) decision.
// Returns silently when the dispatcher is nil or notifications are
// disabled — callers do not need to guard at the call site.
func (d *Dispatcher) OnBlock(ev BlockEvent) {
	if d == nil || !d.cfg.Enabled || !d.cfg.BlockEnforced {
		return
	}
	if !d.allowSource(ev.Source) {
		return
	}
	n := blockNotification(ev, false)
	d.dispatch(CategoryBlock, ev.Source, ev.Target, ev.Reason, n)
}

// OnWouldBlock fires for an observe-mode "would have blocked"
// decision. Silenced when BlockWouldBlock is off in config so
// operators tuning a strict policy in observe mode can opt out
// without disabling the rest of the dispatcher.
func (d *Dispatcher) OnWouldBlock(ev BlockEvent) {
	if d == nil || !d.cfg.Enabled || !d.cfg.BlockWouldBlock {
		return
	}
	if !d.allowSource(ev.Source) {
		return
	}
	n := blockNotification(ev, true)
	d.dispatch(CategoryWouldBlock, ev.Source, ev.Target, ev.Reason, n)
}

// OnApprovalPending fires when a HITL/confirm prompt has been issued
// to the user via the chat surface. The notification is purely
// informational ("reply in chat") — it does not provide
// approve/deny buttons; that requires a bundled helper app that is
// out of scope for v1.
func (d *Dispatcher) OnApprovalPending(ev ApprovalEvent) {
	if d == nil || !d.cfg.Enabled || !d.cfg.HITLApproval {
		return
	}
	if !d.allowSource(ev.Source) {
		return
	}
	n := approvalNotification(ev)
	d.dispatch(CategoryApproval, ev.Source, ev.Subject, ev.Reason, n)
}

func (d *Dispatcher) allowSource(s Source) bool {
	switch s {
	case SourceHook:
		return d.cfg.Sources.Hook
	case SourceGuardrail:
		return d.cfg.Sources.Guardrail
	case SourceAssetPolicy:
		return d.cfg.Sources.AssetPolicy
	case "":
		// Unspecified source — let it through. The dispatcher is
		// behind the master Enabled gate already, and silent-drop
		// for unrouted events would mask wiring bugs.
		return true
	default:
		return true
	}
}

// dispatch is the choke point that applies dedup + rate limit and
// hands off to the goroutine sender. All counter / map mutation
// happens under d.mu; the actual sender.Run is dispatched outside
// the lock so a slow osascript invocation cannot serialize block
// requests.
func (d *Dispatcher) dispatch(cat Category, src Source, target, reason string, n notify.Notification) {
	if d == nil || d.sender == nil {
		return
	}
	now := d.now()
	key := dedupKey(cat, src, target, reason)
	dedupWindow := d.cfg.EffectiveDedupWindow()
	maxPerMin := d.cfg.EffectiveMaxPerMinute()

	var toSend []notify.Notification

	d.mu.Lock()
	d.sweepLocked(now, dedupWindow)
	if last, ok := d.seen[key]; ok && now.Sub(last) < dedupWindow {
		d.mu.Unlock()
		return
	}
	d.seen[key] = now

	d.advanceBucketLocked(now, maxPerMin)
	if d.bucketRemaining <= 0 {
		d.suppressedInWin++
		// Allow exactly one rollup per minute window so operators
		// see "the dispatcher is throttling" without flooding.
		if !d.rollupAnnounced && d.suppressedInWin == 1 {
			// Reserve a slot for the rollup at window roll. We do not
			// emit it now — a real notification might still be more
			// useful than a count — but the announce flag prevents
			// double rollups inside the same minute.
			d.rollupAnnounced = true
		}
		d.mu.Unlock()
		return
	}
	d.bucketRemaining--
	toSend = append(toSend, n)
	d.mu.Unlock()

	for _, item := range toSend {
		go d.send(item)
	}
}

// sweepLocked drops dedup entries older than the window so the
// map cannot grow without bound under sustained traffic.
// Called inside dispatch under d.mu.
func (d *Dispatcher) sweepLocked(now time.Time, window time.Duration) {
	if now.Sub(d.lastSweep) < window {
		return
	}
	d.lastSweep = now
	cutoff := now.Add(-window)
	for k, t := range d.seen {
		if t.Before(cutoff) {
			delete(d.seen, k)
		}
	}
}

// advanceBucketLocked rolls the per-minute token bucket forward and
// emits a single rollup notification when the previous window saw
// any suppressed events. Called inside dispatch under d.mu.
func (d *Dispatcher) advanceBucketLocked(now time.Time, maxPerMin int) {
	if maxPerMin <= 0 {
		// Defensive: EffectiveMaxPerMinute already enforces a floor,
		// but a hostile config or a future change could regress this.
		// Treat zero as "unlimited" — never suppress.
		d.bucketRemaining = 1<<31 - 1
		return
	}
	if d.bucketWindowEnd.IsZero() || !now.Before(d.bucketWindowEnd) {
		// New minute window. If we suppressed anything in the
		// previous window, schedule a rollup notification on the
		// caller side via toSend; we do this by piggy-backing in
		// the calling dispatch — but emitting here keeps the
		// rollup decoupled from the caller's notification.
		if d.suppressedInWin > 0 {
			suppressed := d.suppressedInWin
			rollup := rollupNotification(suppressed)
			// Send the rollup outside the lock to keep dispatch
			// fast. Doing the goroutine spawn here avoids forcing
			// every dispatch caller to think about it.
			go d.send(rollup)
		}
		d.bucketWindowEnd = now.Add(time.Minute)
		d.bucketRemaining = maxPerMin
		d.suppressedInWin = 0
		d.rollupAnnounced = false
	}
}

func (d *Dispatcher) send(n notify.Notification) {
	if d == nil || d.sender == nil {
		return
	}
	// We deliberately drop the error: notify failures are noisy on
	// CI machines without display servers, and the audit pipeline
	// is the authoritative log for blocks. Surface stays quiet.
	_ = d.sender(n)
}

func (d *Dispatcher) now() time.Time {
	if d == nil {
		return time.Now()
	}
	d.mu.Lock()
	fn := d.nowFn
	d.mu.Unlock()
	if fn == nil {
		return time.Now()
	}
	return fn()
}

// blockNotification renders a block / would-block toast.
// Body is truncated to keep the toast readable; the full reason is
// always present in the audit log.
func blockNotification(ev BlockEvent, wouldBlock bool) notify.Notification {
	target := strings.TrimSpace(ev.Target)
	if target == "" {
		target = "request"
	}
	// WouldAsk is the "confirm verdict that never reached the chat
	// surface" case — observe mode or a connector that cannot
	// natively ask. The toast still flows through the would-block
	// category gate (so block_would_block=false silences it
	// alongside observe-mode would-blocks) but reads honestly as
	// "would ask" rather than "would block".
	verb := "blocked"
	switch {
	case ev.WouldAsk:
		verb = "would ask about"
	case wouldBlock:
		verb = "would block"
	}
	title := fmt.Sprintf("DefenseClaw %s %s", verb, target)
	subtitle := buildSubtitle(string(ev.Source), ev.Severity, ev.Connector, ev.Event, wouldBlock || ev.WouldAsk)
	return notify.Notification{
		Title:    title,
		Subtitle: subtitle,
		Body:     truncateReason(ev.Reason),
	}
}

func approvalNotification(ev ApprovalEvent) notify.Notification {
	subject := strings.TrimSpace(ev.Subject)
	if subject == "" {
		subject = "agent action"
	}
	subtitle := buildSubtitle(string(ev.Source), ev.Severity, ev.Connector, ev.Event, false)
	if subtitle == "" {
		subtitle = "reply in chat"
	} else {
		subtitle += " · reply in chat"
	}
	return notify.Notification{
		Title:    "Approval needed: " + subject,
		Subtitle: subtitle,
		Body:     truncateReason(ev.Reason),
	}
}

func rollupNotification(suppressed int) notify.Notification {
	return notify.Notification{
		Title:    "DefenseClaw notifications throttled",
		Subtitle: "rate limit",
		Body:     fmt.Sprintf("Suppressed %d notification(s) in the last minute. Tune notifications.max_per_minute or sources.* to dial down.", suppressed),
	}
}

func buildSubtitle(source, severity, connector, event string, wouldBlock bool) string {
	parts := make([]string, 0, 4)
	if source != "" {
		parts = append(parts, source)
	}
	if severity != "" && !strings.EqualFold(severity, "NONE") {
		parts = append(parts, severity)
	}
	if connector != "" {
		parts = append(parts, connector)
	}
	if event != "" {
		parts = append(parts, event)
	}
	subtitle := strings.Join(parts, " · ")
	if wouldBlock {
		if subtitle == "" {
			return "observe mode"
		}
		return subtitle + " · observe"
	}
	return subtitle
}

func truncateReason(reason string) string {
	// Collapse CR/LF/TAB into a single space before sizing. AppleScript
	// (osascript on darwin) renders an embedded "\n" as the literal two
	// characters because json.Marshal escapes the byte; libnotify on
	// linux honors \n but a multi-line body in a toast is awkward
	// regardless. One pass of normalisation here keeps the toast
	// readable on every back-end without each caller having to know.
	r := strings.NewReplacer("\r\n", " ", "\r", " ", "\n", " ", "\t", " ").Replace(reason)
	r = strings.TrimSpace(r)
	if r == "" {
		return ""
	}
	const maxLen = 140
	if len(r) <= maxLen {
		return r
	}
	// Truncate on a rune boundary to avoid producing invalid UTF-8
	// when the reason contains multi-byte characters near the cap.
	if maxLen-3 < 0 {
		return r[:maxLen]
	}
	end := maxLen - 3
	for end > 0 && !validRuneStart(r[end]) {
		end--
	}
	return r[:end] + "..."
}

// validRuneStart reports whether the byte is the leading byte of a
// UTF-8 sequence (ASCII or 11xxxxxx). Used by truncateReason to
// avoid splitting a multi-byte rune.
func validRuneStart(b byte) bool {
	return b < 0x80 || b >= 0xC0
}

func dedupKey(cat Category, src Source, target, reason string) string {
	h := sha256.New()
	h.Write([]byte(string(cat)))
	h.Write([]byte{0})
	h.Write([]byte(string(src)))
	h.Write([]byte{0})
	h.Write([]byte(strings.ToLower(target)))
	h.Write([]byte{0})
	h.Write([]byte(strings.ToLower(reason)))
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:8])
}
