// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed/refusalpipe"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// The Windows standalone hook refuses, by itself, a call from an account the
// administrator excludes or has not enrolled yet, and reports the refusal on
// the gateway's refusal pipe (refusalpipe). The gateway writes the audit row
// an administrator reviews to see a leaver still trying to run agents
// (GAP-1242): a hook decision naming the account, the connector, the event
// and the tool, with action block and the refusal reason.
//
// The account is not trusted, so its reports are coalesced: the first
// refusal of an account and connector in a window is written at once, and
// the refusals that follow in the same window become one row with their
// count when the window ends. Each account holds at most one entry per
// connector and reason, and the table is bounded, so a refusal loop writes
// at most two rows a window per account and connector.
//
// The managed CLI reports, on the same pipe, the commands it refuses an
// account (GAP-2639); those reports are coalesced the same way per account
// and command and become the refused-command row (auditManagedCommandRefusal).
const (
	unenrolledRefusalWindow     = time.Minute
	unenrolledRefusalMaxEntries = 512
	unenrolledRefusalSubject    = "named_pipe_client"
	// unenrolledRefusalDrainTimeout bounds how long a stopping API server
	// waits for the last refusal rows: naming a domain account can wait on a
	// domain controller.
	unenrolledRefusalDrainTimeout = 5 * time.Second
	// unenrolledRefusalStopTimeout bounds the whole stop: the pipe clients
	// still being read (a second each), then the drain.
	unenrolledRefusalStopTimeout = unenrolledRefusalDrainTimeout + 2*time.Second
)

type unenrolledRefusalKey struct {
	sid, connector, command, reason string
}

func newUnenrolledRefusalKey(sid string, report refusalpipe.Report) unenrolledRefusalKey {
	return unenrolledRefusalKey{sid: sid, connector: report.Connector, command: report.Command, reason: report.Reason}
}

type unenrolledRefusalEntry struct {
	start   time.Time
	pending int
	last    refusalpipe.Report
}

// unenrolledRefusalRow is one row to write: attempts refusals of sid.
type unenrolledRefusalRow struct {
	SID      string
	Report   refusalpipe.Report
	Attempts int
}

type unenrolledRefusalAuditor struct {
	mu      sync.Mutex
	now     func() time.Time
	entries map[unenrolledRefusalKey]*unenrolledRefusalEntry
	write   func(unenrolledRefusalRow)
}

func newUnenrolledRefusalAuditor(write func(unenrolledRefusalRow)) *unenrolledRefusalAuditor {
	return &unenrolledRefusalAuditor{
		now:     time.Now,
		entries: make(map[unenrolledRefusalKey]*unenrolledRefusalEntry),
		write:   write,
	}
}

// record takes one verified report.
func (u *unenrolledRefusalAuditor) record(sid string, report refusalpipe.Report) {
	now := u.now()
	key := newUnenrolledRefusalKey(sid, report)
	var rows []unenrolledRefusalRow
	u.mu.Lock()
	entry := u.entries[key]
	if entry != nil && now.Sub(entry.start) < unenrolledRefusalWindow {
		entry.pending++
		entry.last = report
		u.mu.Unlock()
		return
	}
	if entry != nil && entry.pending > 0 {
		rows = append(rows, unenrolledRefusalRow{SID: sid, Report: entry.last, Attempts: entry.pending})
	}
	if entry == nil && len(u.entries) >= unenrolledRefusalMaxEntries {
		rows = append(rows, u.expireLocked(now, false)...)
		if len(u.entries) >= unenrolledRefusalMaxEntries {
			u.mu.Unlock()
			u.writeAll(rows)
			return
		}
	}
	u.entries[key] = &unenrolledRefusalEntry{start: now, last: report}
	rows = append(rows, unenrolledRefusalRow{SID: sid, Report: report, Attempts: 1})
	u.mu.Unlock()
	u.writeAll(rows)
}

// flush writes the counts of the windows that have ended.
func (u *unenrolledRefusalAuditor) flush() {
	u.mu.Lock()
	rows := u.expireLocked(u.now(), false)
	u.mu.Unlock()
	u.writeAll(rows)
}

// drain writes the counts of every window, ended or not. A stop calls it so
// the refusals coalesced into an open window are not lost (GAP-1253).
func (u *unenrolledRefusalAuditor) drain() {
	u.mu.Lock()
	rows := u.expireLocked(u.now(), true)
	u.mu.Unlock()
	u.writeAll(rows)
}

func (u *unenrolledRefusalAuditor) expireLocked(now time.Time, all bool) []unenrolledRefusalRow {
	var rows []unenrolledRefusalRow
	for key, entry := range u.entries {
		if !all && now.Sub(entry.start) < unenrolledRefusalWindow {
			continue
		}
		if entry.pending > 0 {
			rows = append(rows, unenrolledRefusalRow{SID: key.sid, Report: entry.last, Attempts: entry.pending})
		}
		delete(u.entries, key)
	}
	return rows
}

func (u *unenrolledRefusalAuditor) writeAll(rows []unenrolledRefusalRow) {
	for _, row := range rows {
		u.write(row)
	}
}

// run flushes ended windows until ctx ends.
func (u *unenrolledRefusalAuditor) run(ctx context.Context) {
	ticker := time.NewTicker(unenrolledRefusalWindow / 4)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			u.flush()
			return
		case <-ticker.C:
			u.flush()
		}
	}
}

// runUnenrolledRefusalAudit serves refusal reports until ctx ends and then,
// before it returns, writes what a stop would otherwise lose: the rows still
// queued and the counts of the windows still open (GAP-1253). serve returns
// once ctx ends and the pipe handlers it started have returned. Rows are
// written off the serving goroutines, since naming a domain account can wait
// on a domain controller, and with a context that a stop does not cancel, so
// the last rows still reach the audit log.
func runUnenrolledRefusalAudit(
	ctx context.Context,
	serve func(context.Context, *unenrolledRefusalAuditor),
	write func(context.Context, unenrolledRefusalRow),
) {
	runUnenrolledRefusalAuditQueue(ctx, newUnenrolledRefusalQueue(unenrolledRefusalMaxEntries), serve, write)
}

func runUnenrolledRefusalAuditQueue(
	ctx context.Context,
	queue *unenrolledRefusalQueue,
	serve func(context.Context, *unenrolledRefusalAuditor),
	write func(context.Context, unenrolledRefusalRow),
) {
	writeCtx := context.WithoutCancel(ctx)
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for {
			rows, more := queue.take()
			for _, row := range rows {
				write(writeCtx, row)
			}
			if !more {
				return
			}
		}
	}()
	// The open windows' counts the stop drains go to the queue even when a
	// stalled writer has filled it: the auditor's table bounds them.
	var stopping atomic.Bool
	auditor := newUnenrolledRefusalAuditor(func(row unenrolledRefusalRow) { queue.push(row, stopping.Load()) })
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		auditor.run(ctx)
	}()
	serve(ctx, auditor)
	<-runDone
	stopping.Store(true)
	auditor.drain()
	queue.close()
	select {
	case <-writerDone:
	case <-time.After(unenrolledRefusalDrainTimeout):
		rows, attempts := queue.pending()
		fmt.Fprintf(os.Stderr, "[sidecar-api] unenrolled-account refusal audit: %d rows (%d refusals) still queued: "+
			"the audit writer did not finish within %s of the stop\n", rows, attempts, unenrolledRefusalDrainTimeout)
	}
	if rows, attempts := queue.lost(); rows > 0 {
		fmt.Fprintf(os.Stderr, "[sidecar-api] unenrolled-account refusal audit: %d rows (%d refusals) dropped "+
			"while the audit writer was behind\n", rows, attempts)
	}
}

// unenrolledRefusalQueue holds the refusal rows waiting for the writer. A
// row for a key that already has one waiting is merged into it, so a stalled
// writer costs rows but not counts. Past its bound a new key's row is
// dropped and counted; the stop's drain is never dropped.
type unenrolledRefusalQueue struct {
	mu           sync.Mutex
	limit        int
	rows         []unenrolledRefusalRow
	index        map[unenrolledRefusalKey]int
	ready        chan struct{}
	closed       bool
	lostRows     int
	lostAttempts int
}

func newUnenrolledRefusalQueue(limit int) *unenrolledRefusalQueue {
	return &unenrolledRefusalQueue{
		limit: limit,
		index: make(map[unenrolledRefusalKey]int),
		ready: make(chan struct{}, 1),
	}
}

func (q *unenrolledRefusalQueue) push(row unenrolledRefusalRow, drain bool) {
	key := newUnenrolledRefusalKey(row.SID, row.Report)
	q.mu.Lock()
	switch at, waiting := q.index[key]; {
	case q.closed:
		q.lostRows, q.lostAttempts = q.lostRows+1, q.lostAttempts+row.Attempts
	case waiting:
		q.rows[at].Attempts += row.Attempts
		q.rows[at].Report = row.Report
	case !drain && len(q.rows) >= q.limit:
		q.lostRows, q.lostAttempts = q.lostRows+1, q.lostAttempts+row.Attempts
	default:
		q.index[key] = len(q.rows)
		q.rows = append(q.rows, row)
	}
	q.mu.Unlock()
	select {
	case q.ready <- struct{}{}:
	default:
	}
}

// take waits for rows and returns them all; more is false once the queue
// is closed and empty.
func (q *unenrolledRefusalQueue) take() (rows []unenrolledRefusalRow, more bool) {
	for {
		q.mu.Lock()
		if len(q.rows) > 0 || q.closed {
			rows, more = q.rows, len(q.rows) > 0 || !q.closed
			q.rows, q.index = nil, make(map[unenrolledRefusalKey]int)
			q.mu.Unlock()
			return rows, more
		}
		q.mu.Unlock()
		<-q.ready
	}
}

func (q *unenrolledRefusalQueue) close() {
	q.mu.Lock()
	q.closed = true
	q.mu.Unlock()
	select {
	case q.ready <- struct{}{}:
	default:
	}
}

func (q *unenrolledRefusalQueue) pending() (rows, attempts int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, row := range q.rows {
		attempts += row.Attempts
	}
	return len(q.rows), attempts
}

func (q *unenrolledRefusalQueue) lost() (rows, attempts int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.lostRows, q.lostAttempts
}

// auditUnenrolledRefusal writes one refusal row for an account the pipe
// client token identified.
func (a *APIServer) auditUnenrolledRefusal(ctx context.Context, row unenrolledRefusalRow) {
	if a == nil || ctx == nil {
		return
	}
	defer func() { _ = recover() }()
	if row.Report.Command != "" {
		a.auditManagedCommandRefusal(ctx, row)
		return
	}
	sid := row.SID
	name := sanitizeLLMEventUser(userScopedIdentityName(sid))
	ctx = context.WithValue(ctx, verifiedUserScopedIdentityContextKey{}, sid)
	identity := AgentIdentityFromContext(ctx)
	identity.UserID, identity.UserIDKind, identity.UserName = sid, useridentity.KindForID(sid), verifiedAccountName(sid, name)
	ctx = ContextWithAgentIdentity(ctx, identity)
	ctx = attachVerifiedSubject(ctx, a.observabilityV8RuntimeEmitter(), sid, name, unenrolledRefusalSubject)
	extra := map[string]string{
		"refusal":  "unenrolled_account",
		"attempts": strconv.Itoa(row.Attempts),
	}
	if row.Report.Tool != "" {
		extra["tool"] = row.Report.Tool
	}
	event := row.Report.Event
	if event == "" {
		event = "unenrolled_refusal"
	}
	env := HookAuditEnvelope{
		Connector:  row.Report.Connector,
		Event:      event,
		Result:     "ok",
		Action:     "block",
		RawAction:  "block",
		Severity:   "MEDIUM",
		Mode:       "action",
		Reason:     row.Report.Reason,
		WouldBlock: true,
		Enforced:   true,
		Extra:      extra,
	}
	a.emitHookDecisionObservabilityV8(ctx, agentHookRequest{
		ConnectorName: row.Report.Connector,
		HookEventName: event,
		ToolName:      row.Report.Tool,
	}, agentHookResponse{
		Action: env.Action, RawAction: env.RawAction, Severity: env.Severity,
		Mode: env.Mode, Reason: env.Reason,
	}, env, false)
	if a.logger != nil {
		_ = a.logConnectorHookAuditEnvelope(ctx, env)
	}
}

// auditManagedCommandRefusal writes the row of a command the managed CLI
// refused an account, in the form of the Unix refused-command row
// (handleManagedRefusalAudit): action "action", the command as the target and
// outcome=refused, the reason, the account the pipe client token named and
// the coalesced count.
func (a *APIServer) auditManagedCommandRefusal(ctx context.Context, row unenrolledRefusalRow) {
	if a.logger == nil {
		return
	}
	details := fmt.Sprintf("outcome=refused reason=%s actor=sid:%s", row.Report.Reason, row.SID)
	if name := strings.TrimSpace(stripLogInjectionRunes(sanitizeLLMEventUser(userScopedIdentityName(row.SID)))); name != "" {
		details += " user=" + strings.ReplaceAll(name, " ", "_")
	}
	details += " command=" + row.Report.Command + " attempts=" + strconv.Itoa(row.Attempts)
	if err := a.logger.LogCLIAction(ctx, "action", row.Report.Command, details); err != nil {
		fmt.Fprintf(os.Stderr, "[sidecar-api] managed command refusal by %s was not recorded: %v\n", row.SID, err)
	}
}
