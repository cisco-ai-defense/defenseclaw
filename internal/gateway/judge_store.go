// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// Async judge-persistence queue tuning. The defaults are picked so a
// single-writer worker can serve the realistic burst rate
// (~100 RPS of tool-call inspections during an MCP-heavy session)
// without ever entering the BUSY retry loop on audit.db. See
// docs/OBSERVABILITY.md for the operator-facing tuning guide.
const (
	// defaultJudgePersistQueueDepth is the fallback when neither the
	// config field nor the env override supplies a positive value.
	// Sized to absorb a ~10-second burst at 100 RPS while bounding
	// memory to MaxJudgeRawBytes * 1024 ≈ 64 MiB worst case.
	defaultJudgePersistQueueDepth = 1024

	// judgePersistBatchMax is the upper bound on rows committed in a
	// single transaction. SQLite's write cost is dominated by the
	// per-tx fsync, so amortizing 32 INSERTs over one tx is ~32x
	// cheaper than the synchronous one-write-per-judge baseline.
	judgePersistBatchMax = 32

	// judgePersistFlushInterval bounds how long the worker waits
	// before flushing a partial batch. Picked so an idle-after-burst
	// row never sits in the queue longer than a TUI refresh tick.
	judgePersistFlushInterval = 100 * time.Millisecond

	// judgePersistShutdownTimeout caps how long Shutdown waits for
	// the worker to drain. If we exceed this, drops are recorded
	// for the remainder so dashboards reflect data loss honestly.
	judgePersistShutdownTimeout = 5 * time.Second

	// judgePersistFlushTimeout bounds the SQLite work for a single
	// batch (BeginTx + inserts + Commit). Picked to be longer than
	// the DSN-resident busy_timeout=5000 so retryBusy can absorb
	// transient contention, but short enough that a wedged DB
	// surfaces as drops within one Shutdown window
	// (judgePersistShutdownTimeout) instead of pinning the worker
	// forever. Combined with the sidecar's "skip Close on Shutdown
	// timeout" guard this also bounds the use-after-close exposure
	// of the underlying *sql.Tx.
	judgePersistFlushTimeout = 8 * time.Second
)

// JudgeBodyInserter is the minimal surface a JudgeStore needs from
// its backing SQLite store. Defining it as an interface lets Phase 4
// swap audit.Store for a dedicated audit.JudgeBodyStore without
// touching the queue/worker — and lets unit tests inject a counting
// fake.
type JudgeBodyInserter interface {
	InsertJudgeResponse(audit.JudgeResponse) error
	// BeginJudgeBatch starts a transaction that the worker
	// uses to commit a batch of rows atomically. Returning a
	// concrete handle keeps the interface tight; callers that
	// can't batch (e.g. tests) return a single-row helper.
	BeginJudgeBatch(ctx context.Context) (JudgeBatch, error)
}

// JudgeBatch is the per-transaction write handle returned from
// JudgeBodyInserter.BeginJudgeBatch. Commit and Rollback are mutually
// exclusive terminal calls.
type JudgeBatch interface {
	InsertJudgeResponse(audit.JudgeResponse) error
	Commit() error
	Rollback() error
}

// judgePersistJob is the unit of work queued by Enqueue. We keep
// just the inputs to BuildJudgeRow so the worker — not the proxy
// goroutine — does the SHA-256 + provenance work.
type judgePersistJob struct {
	ctx        context.Context
	dir        gatewaylog.Direction
	payload    gatewaylog.JudgePayload
	toolName   string
	toolID     string
	policyID   string
	destApp    string
	identity   AgentIdentity
	requestID  string
	traceID    string
	sessionID  string
	runID      string
	enqueuedAt time.Time
}

// JudgeStore persists LLM judge bodies asynchronously through a
// bounded buffered channel + single-writer goroutine.
//
// Why async: the legacy synchronous path fired two SQLite writes
// (judge_responses INSERT, then audit_events INSERT via
// logger.LogEvent) inline with the proxy hot path. Under burst
// load the two writes serialized on SQLite's write lock,
// surfaced as SQLITE_BUSY (`database is locked`), and dropped
// judge rows entirely. The async path:
//
//   - lets the proxy return as soon as the row is queued,
//   - amortizes fsync cost by batching up to judgePersistBatchMax
//     rows per transaction,
//   - drops with telemetry instead of blocking when the queue is
//     full, so the proxy SLO is always respected.
type JudgeStore struct {
	store  JudgeBodyInserter
	logger *audit.Logger // fan-out for redacted summary; may be nil in tests

	queue chan judgePersistJob

	stopOnce sync.Once
	stopCh   chan struct{}
	doneCh   chan struct{}

	// enqueueMu serializes producers against Shutdown so a send can
	// never race past the worker exit. Producers take RLock for the
	// brief moment they touch j.queue; Shutdown takes the write
	// Lock, flips `closed`, and *then* signals the worker. After the
	// Lock is held no producer can be mid-send, so by the time the
	// worker observes the stop signal the queue is the authoritative
	// snapshot of work-in-flight. Drop-on-shutdown is recorded for
	// every producer that arrives after `closed` is true.
	enqueueMu sync.RWMutex
	closed    bool

	// shutdownRequested flips to true on the first Shutdown call so
	// concurrent Shutdown calls share the same drain wait without
	// closing stopCh twice. Distinct from `closed` because that flag
	// is observed by producers under enqueueMu, whereas this one
	// gates the lifecycle transition itself.
	shutdownRequested atomic.Bool
}

// NewJudgeStore wires the async queue on top of the supplied audit
// store. queueDepth <= 0 falls back to defaultJudgePersistQueueDepth.
//
// logger may be nil when the caller does not want the redacted
// audit fan-out (e.g. unit tests). Passing a real *audit.Logger
// ensures every retained body also produces an `llm-judge-response`
// audit event that flows through the normal sink pipeline (Splunk,
// OTLP, webhooks).
func NewJudgeStore(store JudgeBodyInserter, logger *audit.Logger, queueDepth int) *JudgeStore {
	if store == nil {
		return nil
	}
	if queueDepth <= 0 {
		queueDepth = defaultJudgePersistQueueDepth
	}
	js := &JudgeStore{
		store:  store,
		logger: logger,
		queue:  make(chan judgePersistJob, queueDepth),
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
	go js.run()
	return js
}

// NewJudgeStoreFromAudit is the legacy constructor preserved for
// callers (and tests) that still pass an *audit.Store directly. It
// adapts the store to the new JudgeBodyInserter contract via
// auditStoreInserter and defaults the queue depth.
//
// Production code should prefer NewJudgeStore with the explicit
// JudgeBodyStore (Phase 4) so judge bodies write to their own DB.
func NewJudgeStoreFromAudit(s *audit.Store) *JudgeStore {
	if s == nil {
		return nil
	}
	return NewJudgeStore(&auditStoreInserter{s: s}, nil, defaultJudgePersistQueueDepth)
}

// NewJudgeStoreFromBodyStore constructs a JudgeStore that writes
// judge bodies to the Phase 4 dedicated *audit.JudgeBodyStore. This
// is the production-shape constructor exposed for end-to-end tests
// that need to bypass NewSidecar (which depends on a full config +
// gateway client + connector wiring).
func NewJudgeStoreFromBodyStore(s *audit.JudgeBodyStore, logger *audit.Logger, queueDepth int) *JudgeStore {
	if s == nil {
		return nil
	}
	return NewJudgeStore(&judgeBodyStoreInserter{s: s}, logger, queueDepth)
}

// PersistJudgeEvent is the public API the gateway emit paths use. It
// performs the cheap, per-call work synchronously (capture the
// request-scoped identifiers off ctx) and hands the rest of the
// build + INSERT to the background worker. RawResponse == "" is the
// "retention off / no-op" guard, identical to the synchronous path.
func (j *JudgeStore) PersistJudgeEvent(ctx context.Context, dir gatewaylog.Direction, p gatewaylog.JudgePayload, toolName, toolID, policyID, destinationApp string) error {
	if j == nil || j.store == nil || p.RawResponse == "" {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	job := judgePersistJob{
		ctx:        ctx,
		dir:        dir,
		payload:    p,
		toolName:   toolName,
		toolID:     toolID,
		policyID:   policyID,
		destApp:    destinationApp,
		identity:   AgentIdentityFromContext(ctx),
		requestID:  RequestIDFromContext(ctx),
		traceID:    TraceIDFromContext(ctx),
		sessionID:  SessionIDFromContext(ctx),
		runID:      gatewaylog.ProcessRunID(),
		enqueuedAt: time.Now(),
	}
	return j.enqueue(job)
}

// enqueue is the non-blocking submit. We choose drop-on-full over
// block-on-full because the proxy hot path must never wait on the
// audit DB — a wedged DB would otherwise wedge the proxy.
//
// Concurrency: the RLock + `closed` flag pair guarantees no producer
// can send into j.queue after Shutdown has released the work-in-
// flight snapshot to the worker. Without this gate, a Shutdown that
// ran between the legacy shutdownRequested.Load() check and the
// channel send could leave a job stuck in the queue with no worker
// to drain it (and no drop telemetry to surface the loss).
func (j *JudgeStore) enqueue(job judgePersistJob) error {
	j.enqueueMu.RLock()
	defer j.enqueueMu.RUnlock()
	if j.closed {
		telemetry.RecordJudgePersistDrop(job.ctx, "shutdown")
		return nil
	}
	select {
	case j.queue <- job:
		telemetry.RecordJudgePersistQueueDepth(job.ctx, int64(len(j.queue)))
		return nil
	default:
		telemetry.RecordJudgePersistDrop(job.ctx, "queue_full")
		return nil
	}
}

// run is the single-writer worker goroutine. It loops on three
// channels: the work queue (build a batch), a flush timer (commit a
// partial batch on idle), and the stop signal (drain + exit).
//
// We deliberately use a single goroutine — multiple workers would
// race for SQLite's write lock and undo the very contention fix
// this rewrite is supposed to deliver.
func (j *JudgeStore) run() {
	defer close(j.doneCh)

	batch := make([]judgePersistJob, 0, judgePersistBatchMax)
	timer := time.NewTimer(judgePersistFlushInterval)
	timer.Stop()
	timerRunning := false

	stopTimer := func() {
		if timerRunning {
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timerRunning = false
		}
	}
	armTimer := func() {
		if !timerRunning {
			timer.Reset(judgePersistFlushInterval)
			timerRunning = true
		}
	}

	flush := func() {
		if len(batch) == 0 {
			return
		}
		j.flushBatch(batch)
		batch = batch[:0]
		stopTimer()
	}

	for {
		select {
		case <-j.stopCh:
			// Drain remaining work non-blockingly so Shutdown
			// honors the bounded timeout. We accept a tail of
			// drops if the queue is still being fed.
			for {
				select {
				case job := <-j.queue:
					batch = append(batch, job)
					if len(batch) >= judgePersistBatchMax {
						flush()
					}
				default:
					flush()
					return
				}
			}

		case job := <-j.queue:
			batch = append(batch, job)
			telemetry.RecordJudgePersistQueueDepth(job.ctx, int64(len(j.queue)))
			if len(batch) == 1 {
				armTimer()
			}
			if len(batch) >= judgePersistBatchMax {
				flush()
			}

		case <-timer.C:
			timerRunning = false
			flush()
		}
	}
}

// flushBatch commits the buffered jobs in a single SQLite
// transaction.
//
// Three failure modes the worker has to surface honestly:
//
//   - BeginJudgeBatch failed → the whole batch is lost; every job
//     records a drop with reason="tx_begin_failed".
//   - Per-row Insert failed → that row's body never landed; drop
//     with reason="insert_failed" and we MUST NOT fan out the
//     redacted audit row, otherwise SIEM rows out-live their
//     forensic body. This is the partial-failure case the original
//     implementation silently lost.
//   - Commit failed → every row in the batch is rolled back; drop
//     all with reason="tx_commit_failed" and skip fan-out for the
//     whole batch.
//
// Errors are logged once at the source (via the audit logger so
// operators see a structured event, not a stderr line) and never
// re-queued: a wedged DB would otherwise reload the same poison
// batch forever and starve the queue.
//
// The tx itself runs under judgePersistFlushTimeout so a wedged DB
// can never pin the worker longer than one Shutdown window —
// keeping the use-after-close blast radius bounded.
func (j *JudgeStore) flushBatch(jobs []judgePersistJob) {
	ctx, cancel := context.WithTimeout(context.Background(), judgePersistFlushTimeout)
	defer cancel()

	tx, err := j.store.BeginJudgeBatch(ctx)
	if err != nil {
		j.logErrorEvent("judge_persist.begin_batch", err, map[string]string{
			"batch_size": strconv.Itoa(len(jobs)),
		})
		for _, jb := range jobs {
			telemetry.RecordJudgePersistDrop(jb.ctx, "tx_begin_failed")
		}
		return
	}

	// Track each job's outcome so post-commit fan-out only fires for
	// rows that actually made it to disk.
	committed := make([]judgePersistJob, 0, len(jobs))
	for _, jb := range jobs {
		row := buildJudgeRow(jb)
		if err := tx.InsertJudgeResponse(row); err != nil {
			j.logErrorEvent("judge_persist.insert", err, map[string]string{
				"kind": string(jb.payload.Kind),
			})
			telemetry.RecordJudgePersistDrop(jb.ctx, "insert_failed")
			continue
		}
		committed = append(committed, jb)
	}

	if err := tx.Commit(); err != nil {
		// Best-effort rollback; ignore secondary error so we don't
		// shadow the commit failure for the operator.
		_ = tx.Rollback()
		j.logErrorEvent("judge_persist.commit", err, map[string]string{
			"batch_size":      strconv.Itoa(len(jobs)),
			"committed_count": strconv.Itoa(len(committed)),
		})
		// A failed Commit means the whole tx rolled back — every job
		// (including the ones whose per-row Insert succeeded inside
		// the tx) is now lost. Record drops for the full batch so
		// dashboards reflect reality, and skip the audit fan-out:
		// SIEM rows must never out-race the local forensic copy.
		for _, jb := range jobs {
			telemetry.RecordJudgePersistDrop(jb.ctx, "tx_commit_failed")
		}
		return
	}
	telemetry.RecordJudgePersistBatchSize(ctx, int64(len(committed)))

	// Fan out the redacted summary AFTER the body commit succeeds so
	// SIEM rows never out-race the local forensic copy. Iterate over
	// `committed` (not `jobs`) so a row that failed its INSERT but
	// landed inside an otherwise-successful batch does not produce a
	// dangling audit_events row.
	if j.logger != nil {
		for _, jb := range committed {
			j.fanoutAudit(jb)
		}
	}
}

// logErrorEvent routes worker-level failures through the configured
// audit logger when present, falling back to stderr only when the
// store was constructed without one (unit tests). The structured
// path keeps Splunk/OTLP/webhook sinks in sync with the in-process
// `defenseclaw.judge.persist.*` counters that already track the
// same failure modes.
func (j *JudgeStore) logErrorEvent(action string, err error, details map[string]string) {
	if j.logger != nil {
		parts := make([]string, 0, 1+len(details))
		parts = append(parts, "error="+err.Error())
		for k, v := range details {
			parts = append(parts, k+"="+v)
		}
		_ = j.logger.LogEvent(audit.Event{
			Action:   action,
			Actor:    "defenseclaw-gateway",
			Severity: "ERROR",
			Details:  strings.Join(parts, " "),
		})
		return
	}
	fmt.Fprintf(os.Stderr, "[judge_store] %s: %v (%v)\n", action, err, details)
}

// fanoutAudit emits the redacted audit event for one job. Mirrors
// the historical sidecar closure (sidecar.go:354-374) so existing
// sink consumers see no behavioral change.
func (j *JudgeStore) fanoutAudit(jb judgePersistJob) {
	env := audit.MergeEnvelope(audit.EnvelopeFromContext(jb.ctx), audit.CorrelationEnvelope{
		ToolName:       jb.toolName,
		ToolID:         jb.toolID,
		PolicyID:       jb.policyID,
		DestinationApp: jb.destApp,
	})
	evt := audit.Event{
		Action:   string(audit.ActionLLMJudgeResponse),
		Target:   jb.payload.Model,
		Actor:    "defenseclaw-gateway",
		Severity: string(jb.payload.Severity),
		Details: fmt.Sprintf(
			"kind=%s direction=%s action=%s latency_ms=%d input_bytes=%d parse_error=%q",
			jb.payload.Kind, jb.dir, jb.payload.Action, jb.payload.LatencyMs, jb.payload.InputBytes, jb.payload.ParseError,
		),
	}
	audit.ApplyEnvelope(&evt, env)
	_ = j.logger.LogEvent(evt)
}

// buildJudgeRow assembles the audit.JudgeResponse from the queued
// job. Pulled out for testability and so the SHA-256 cost of the
// raw body runs on the worker goroutine instead of the proxy
// goroutine.
func buildJudgeRow(jb judgePersistJob) audit.JudgeResponse {
	prov := version.Current()
	body := jb.payload.RawResponse
	h := sha256.Sum256([]byte(body))
	return audit.JudgeResponse{
		Kind:              jb.payload.Kind,
		Direction:         string(jb.dir),
		Model:             jb.payload.Model,
		Action:            jb.payload.Action,
		Severity:          string(jb.payload.Severity),
		LatencyMs:         jb.payload.LatencyMs,
		ParseError:        jb.payload.ParseError,
		Raw:               body,
		RequestID:         jb.requestID,
		TraceID:           jb.traceID,
		RunID:             jb.runID,
		SessionID:         jb.sessionID,
		InputHash:         "sha256:" + hex.EncodeToString(h[:]),
		InspectedModel:    jb.payload.Model,
		SchemaVersion:     prov.SchemaVersion,
		ContentHash:       prov.ContentHash,
		Generation:        prov.Generation,
		BinaryVersion:     prov.BinaryVersion,
		AgentID:           jb.identity.AgentID,
		AgentInstanceID:   jb.identity.AgentInstanceID,
		SidecarInstanceID: jb.identity.SidecarInstanceID,
		PolicyID:          jb.policyID,
		DestinationApp:    jb.destApp,
		ToolName:          jb.toolName,
		ToolID:            jb.toolID,
	}
}

// Shutdown signals the worker to drain and exit, blocking up to
// judgePersistShutdownTimeout for the drain to complete. Sidecar
// stop wires this in front of the audit.Store close so every
// queued body lands on disk before the DB handle is released.
//
// Concurrency contract: by the time Shutdown returns, either
//
//   - j.doneCh is closed and the worker is no longer running (safe
//     to close the underlying DB), OR
//   - the returned error is non-nil and the worker MAY still be
//     running, in which case the caller MUST NOT close the DB
//     handle the worker is writing into (see sidecar.go Stop()
//     for the "skip close on drain error" guard).
//
// We take enqueueMu.Lock before signaling the worker so producers
// in-flight at the moment Shutdown is called either (a) finish
// their send before stopCh is closed (worker drains them) or (b)
// see j.closed=true and record a "shutdown" drop. There is no
// third path where a job is silently leaked into the channel.
func (j *JudgeStore) Shutdown(ctx context.Context) error {
	if j == nil {
		return nil
	}
	if !j.shutdownRequested.CompareAndSwap(false, true) {
		// Already shutting down — wait on the existing drain.
		return j.waitForDrain(ctx)
	}
	j.enqueueMu.Lock()
	j.closed = true
	j.enqueueMu.Unlock()
	j.stopOnce.Do(func() { close(j.stopCh) })
	return j.waitForDrain(ctx)
}

// IsClosed reports whether the worker goroutine has finished
// draining. Exposed so the sidecar (and tests) can verify the
// "safe to close the underlying DB" precondition without racing
// the worker. Returns true ONLY after the worker has exited.
func (j *JudgeStore) IsClosed() bool {
	if j == nil {
		return true
	}
	select {
	case <-j.doneCh:
		return true
	default:
		return false
	}
}

func (j *JudgeStore) waitForDrain(ctx context.Context) error {
	// Default budget if the caller passes a bare Background.
	deadlineCh := time.After(judgePersistShutdownTimeout)
	// ctxDone reflects EITHER cancellation OR deadline; we honor both
	// so a SIGTERM-driven shutdown propagating context.WithCancel
	// terminates promptly instead of waiting out the 5 s budget.
	var ctxDone <-chan struct{}
	if ctx != nil {
		ctxDone = ctx.Done()
		if dl, ok := ctx.Deadline(); ok {
			if d := time.Until(dl); d > 0 {
				deadlineCh = time.After(d)
			}
		}
	}
	select {
	case <-j.doneCh:
		return nil
	case <-deadlineCh:
		return fmt.Errorf("judge_store: shutdown timed out after %s", judgePersistShutdownTimeout)
	case <-ctxDone:
		// ctx.Err() is non-nil here per the contract of Done().
		return ctx.Err()
	}
}

// QueueDepth is an introspection helper for tests.
func (j *JudgeStore) QueueDepth() int {
	if j == nil || j.queue == nil {
		return 0
	}
	return len(j.queue)
}

// ---------------------------------------------------------------------------
// audit.Store adapter
// ---------------------------------------------------------------------------

// auditStoreInserter adapts the existing *audit.Store to the
// JudgeBodyInserter contract. The synchronous single-row helper is
// the fallback when a transaction cannot be opened (e.g. a future
// store backend that does not expose BeginTx); for audit.Store
// proper we route through the real *sql.Tx via BeginJudgeBatch.
type auditStoreInserter struct {
	s *audit.Store
}

func (a *auditStoreInserter) InsertJudgeResponse(row audit.JudgeResponse) error {
	return a.s.InsertJudgeResponse(row)
}

func (a *auditStoreInserter) BeginJudgeBatch(ctx context.Context) (JudgeBatch, error) {
	batch, err := a.s.BeginJudgeBatch(ctx)
	if err != nil {
		return nil, err
	}
	// *audit.JudgeBatch satisfies the local JudgeBatch interface
	// (InsertJudgeResponse + Commit + Rollback) — the explicit
	// nil-error path keeps the cast crisp instead of relying on
	// implicit conversion semantics.
	return batch, nil
}

// ---------------------------------------------------------------------------
// audit.JudgeBodyStore adapter (Phase 4)
// ---------------------------------------------------------------------------

// judgeBodyStoreInserter adapts the Phase 4 dedicated
// *audit.JudgeBodyStore (judge_bodies.db) to the JudgeBodyInserter
// contract. The semantics match auditStoreInserter exactly — the
// only difference is the underlying SQLite file. Routing through
// this adapter is what isolates the highest-volume write path
// (judge_responses) from audit_events / activity_events writers
// on audit.db.
type judgeBodyStoreInserter struct {
	s *audit.JudgeBodyStore
}

func (a *judgeBodyStoreInserter) InsertJudgeResponse(row audit.JudgeResponse) error {
	return a.s.InsertJudgeResponse(row)
}

func (a *judgeBodyStoreInserter) BeginJudgeBatch(ctx context.Context) (JudgeBatch, error) {
	batch, err := a.s.BeginJudgeBatch(ctx)
	if err != nil {
		return nil, err
	}
	return batch, nil
}
