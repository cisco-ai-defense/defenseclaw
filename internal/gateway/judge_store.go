// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
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

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
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
	judgePersistShutdownTimeout  = 5 * time.Second
	judgePersistDrainCancelAfter = 4 * time.Second

	// judgePersistFlushTimeout bounds the SQLite work for a single
	// batch (BeginTx + inserts + Commit). It is deliberately shorter
	// than judgePersistShutdownTimeout so cancellation of a busy
	// transaction still leaves time for the worker to account the
	// queued tail and exit before the sidecar closes SQLite.
	judgePersistFlushTimeout = judgePersistDrainCancelAfter
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

// JudgeStore emits LLM judge completions asynchronously through a bounded
// buffered channel + single-writer goroutine. The body store is optional:
// canonical completion logging is always driven by logger when present, while
// raw-response persistence is attempted only when store is non-nil.
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
	store  JudgeBodyInserter // optional forensic-body sink
	logger *audit.Logger     // canonical completion fan-out; optional in body-only tests

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

	// workerCtx is inherited by every database transaction. Shutdown waits a
	// bounded grace period and then cancels it, which rolls back a busy SQL
	// transaction and lets the worker account every queued tail job before the
	// outer shutdown deadline. drainCancelAfter is configurable only in tests.
	workerCtx        context.Context
	workerCancel     context.CancelFunc
	drainCancelAfter time.Duration
	shutdownTimeout  time.Duration

	observabilityV8Mu sync.RWMutex
	observabilityV8   hookLifecycleMetricV8Runtime
}

// NewJudgeStore wires the async completion queue. queueDepth <= 0 falls back to
// defaultJudgePersistQueueDepth. At least one output is required: store enables
// optional forensic-body persistence and logger enables canonical completion
// emission. Passing neither returns nil.
//
// Production always supplies logger. Retention-off production supplies a nil
// store, so allow/block/error completions still flow through the canonical
// runtime without creating judge_responses rows.
func NewJudgeStore(store JudgeBodyInserter, logger *audit.Logger, queueDepth int) *JudgeStore {
	if store == nil && logger == nil {
		return nil
	}
	if queueDepth <= 0 {
		queueDepth = defaultJudgePersistQueueDepth
	}
	workerCtx, workerCancel := context.WithCancel(context.Background())
	js := &JudgeStore{
		store:            store,
		logger:           logger,
		queue:            make(chan judgePersistJob, queueDepth),
		stopCh:           make(chan struct{}),
		doneCh:           make(chan struct{}),
		workerCtx:        workerCtx,
		workerCancel:     workerCancel,
		drainCancelAfter: judgePersistDrainCancelAfter,
		shutdownTimeout:  judgePersistShutdownTimeout,
	}
	go js.run()
	return js
}

// RetainsJudgeBodies reports whether this queue has a forensic-body sink.
// Canonical completion logging is deliberately independent of this value.
func (j *JudgeStore) RetainsJudgeBodies() bool { return j != nil && j.store != nil }

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

// openAuthoritativeJudgeBodyStore is the only gateway startup path for raw judge
// bodies. It returns a cutover-complete dedicated store or an error; callers must
// abort startup on error and must never substitute audit.Store.
func openAuthoritativeJudgeBodyStore(ctx context.Context, path string, legacy *audit.Store) (*audit.JudgeBodyStore, error) {
	store, err := audit.NewJudgeBodyStoreForCutover(path)
	if err != nil {
		return nil, fmt.Errorf("initialize authoritative judge-body store: %w", err)
	}
	if err := store.CutoverLegacyJudgeBodies(ctx, legacy); err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("cut over authoritative judge-body store: %w", err)
	}
	return store, nil
}

// PersistJudgeEvent is the public API the gateway emit paths use. It
// performs the cheap, per-call work synchronously (capture the
// request-scoped identifiers off ctx) and hands the rest of the
// build + optional body INSERT to the background worker. Every queued job is
// eligible for canonical completion fan-out even when store is nil or
// RawResponse is empty. This makes observability independent of the forensic
// retention policy.
func (j *JudgeStore) PersistJudgeEvent(ctx context.Context, dir gatewaylog.Direction, p gatewaylog.JudgePayload, toolName, toolID, policyID, destinationApp string) error {
	if j == nil {
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
		j.recordPersistDropV8(job.ctx, "shutdown")
		return nil
	}
	select {
	case j.queue <- job:
		j.recordPersistQueueDepthV8(job.ctx, int64(len(j.queue)))
		return nil
	default:
		j.recordPersistDropV8(job.ctx, "queue_full")
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
	defer j.workerCancel()

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

	flush := func() bool {
		if len(batch) == 0 {
			return true
		}
		if j.workerCtx.Err() != nil {
			j.recordPersistDropsV8(batch, "shutdown")
			batch = batch[:0]
			stopTimer()
			return false
		}
		j.flushBatch(j.workerCtx, batch)
		batch = batch[:0]
		stopTimer()
		return j.workerCtx.Err() == nil
	}
	dropQueuedTail := func() {
		if len(batch) > 0 {
			j.recordPersistDropsV8(batch, "shutdown")
			batch = batch[:0]
		}
		for {
			select {
			case job := <-j.queue:
				j.recordPersistDropV8(job.ctx, "shutdown")
			default:
				return
			}
		}
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
						if !flush() {
							dropQueuedTail()
							return
						}
					}
				default:
					if !flush() {
						dropQueuedTail()
					}
					return
				}
			}

		case <-j.workerCtx.Done():
			dropQueuedTail()
			return

		case job := <-j.queue:
			batch = append(batch, job)
			j.recordPersistQueueDepthV8(job.ctx, int64(len(j.queue)))
			if len(batch) == 1 {
				armTimer()
			}
			if len(batch) >= judgePersistBatchMax {
				if !flush() {
					dropQueuedTail()
					return
				}
			}

		case <-timer.C:
			timerRunning = false
			if !flush() {
				dropQueuedTail()
				return
			}
		}
	}
}

// flushBatch attempts optional body persistence and then emits every canonical
// completion exactly once. Body persistence runs first so a successful body is
// durable before its completion is exported, but body failure never suppresses
// the ordinary completion: the two are separate retention domains.
//
// Three failure modes the worker has to surface honestly:
//
//   - BeginJudgeBatch failed → every body records a drop with
//     reason="tx_begin_failed"; canonical completions still emit.
//   - Per-row Insert failed → that row's body never landed; drop
//     with reason="insert_failed"; canonical completion still emits.
//   - Commit failed → every row in the batch is rolled back; drop
//     all bodies with reason="tx_commit_failed"; canonical completions emit.
//
// Errors are logged once at the source (via the audit logger so
// operators see a structured event, not a stderr line) and never
// re-queued: a wedged DB would otherwise reload the same poison
// batch forever and starve the queue.
//
// The tx itself runs under judgePersistFlushTimeout so a wedged DB
// can never pin the worker longer than one Shutdown window —
// keeping the use-after-close blast radius bounded.
func (j *JudgeStore) flushBatch(parent context.Context, jobs []judgePersistJob) {
	// Completion fan-out is independent from the optional forensic body. Defer
	// it so every body failure/rollback return below still emits once, after the
	// body attempt and its bounded health signal have completed.
	if j.logger != nil {
		defer j.fanoutAuditBatch(jobs)
	}
	if j.store == nil {
		return
	}
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, judgePersistFlushTimeout)
	defer cancel()

	tx, err := j.store.BeginJudgeBatch(ctx)
	if err != nil {
		j.logErrorEvent(firstJudgeJobContext(jobs), "judge_persist.begin_batch", err, map[string]string{
			"batch_size": strconv.Itoa(len(jobs)),
		})
		reason := "tx_begin_failed"
		if j.shutdownRequested.Load() && ctx.Err() != nil {
			reason = "shutdown"
		}
		j.recordPersistDropsV8(jobs, reason)
		return
	}

	// Track successful body inserts for body-persistence telemetry only.
	committed := make([]judgePersistJob, 0, len(jobs))
	for _, jb := range jobs {
		row := buildJudgeRow(jb)
		if err := tx.InsertJudgeResponse(row); err != nil {
			if j.shutdownRequested.Load() && ctx.Err() != nil {
				_ = tx.Rollback()
				j.recordPersistDropsV8(jobs, "shutdown")
				return
			}
			j.logErrorEvent(jb.ctx, "judge_persist.insert", err, map[string]string{
				"kind": string(jb.payload.Kind),
			})
			j.recordPersistDropV8(jb.ctx, "insert_failed")
			continue
		}
		committed = append(committed, jb)
	}

	if err := tx.Commit(); err != nil {
		// Best-effort rollback; ignore secondary error so we don't
		// shadow the commit failure for the operator.
		_ = tx.Rollback()
		j.logErrorEvent(firstJudgeJobContext(jobs), "judge_persist.commit", err, map[string]string{
			"batch_size":      strconv.Itoa(len(jobs)),
			"committed_count": strconv.Itoa(len(committed)),
		})
		// A failed Commit means every optional body row rolled back,
		// including rows whose Insert succeeded inside the transaction.
		// Record a body-persistence drop for the full batch. The deferred
		// canonical fan-out still emits every completion exactly once.
		reason := "tx_commit_failed"
		if j.shutdownRequested.Load() && ctx.Err() != nil {
			reason = "shutdown"
		}
		j.recordPersistDropsV8(jobs, reason)
		return
	}
	j.recordPersistBatchSizeV8(firstJudgeJobContext(jobs), int64(len(committed)))
}

func (j *JudgeStore) fanoutAuditBatch(jobs []judgePersistJob) {
	for _, jb := range jobs {
		if err := j.fanoutAudit(jb); err != nil {
			j.logErrorEvent(jb.ctx, "judge_audit.emit", err, map[string]string{
				"failure_class": string(jb.payload.FailureClass),
				"kind":          jb.payload.Kind,
			})
		}
	}
}

// logErrorEvent routes worker-level failures through the configured
// audit logger when present, falling back to stderr only when the
// store was constructed without one (unit tests). The structured
// path keeps Splunk/OTLP/webhook sinks in sync with the in-process
// `defenseclaw.judge.persist.*` counters that already track the
// same failure modes.
func (j *JudgeStore) logErrorEvent(ctx context.Context, action string, err error, details map[string]string) {
	if j.logger != nil {
		fields := make(map[string]any, 2+len(details))
		fields["operation"] = boundedJudgeHealthValue(action, 128)
		fields["error"] = boundedJudgeHealthValue(err.Error(), 4096)
		for k, v := range details {
			fields[boundedJudgeHealthValue(k, 128)] = boundedJudgeHealthValue(v, 256)
		}
		_ = j.logger.LogAlertCtx(ctx, "judge_store", "HIGH", action, fields)
		return
	}
	fmt.Fprintf(os.Stderr, "[judge_store] %s: %s\n", boundedJudgeHealthValue(action, 128),
		boundedJudgeHealthValue(err.Error(), 4096))
}

func firstJudgeJobContext(jobs []judgePersistJob) context.Context {
	if len(jobs) > 0 && jobs[0].ctx != nil {
		return jobs[0].ctx
	}
	return context.Background()
}

func boundedJudgeHealthValue(value string, maxBytes int) string {
	value = strings.ToValidUTF8(value, "\uFFFD")
	if maxBytes > 0 && len(value) > maxBytes {
		return truncateToRuneBoundary(value, maxBytes)
	}
	return value
}

// fanoutAudit emits the redacted audit event for one job. Mirrors
// the historical sidecar closure (sidecar.go:354-374) so existing
// sink consumers see no behavioral change.
func (j *JudgeStore) fanoutAudit(jb judgePersistJob) error {
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
			"kind=%s direction=%s action=%s latency_ms=%d input_bytes=%d failure_class=%s error_summary=%q parse_error=%q",
			jb.payload.Kind, jb.dir, jb.payload.Action, jb.payload.LatencyMs, jb.payload.InputBytes,
			jb.payload.FailureClass, jb.payload.ErrorSummary, jb.payload.ParseError,
		),
	}
	audit.ApplyEnvelope(&evt, env)
	return j.logger.LogJudgeCompletion(jb.ctx, evt, audit.JudgeCompletionInput{
		Kind:         jb.payload.Kind,
		Action:       jb.payload.Action,
		LatencyMS:    jb.payload.LatencyMs,
		InputBytes:   int64(jb.payload.InputBytes),
		FailureClass: jb.payload.FailureClass,
		ErrorSummary: jb.payload.ErrorSummary,
		ParseError:   jb.payload.ParseError,
	})
}

// buildJudgeRow assembles the audit.JudgeResponse from the queued
// job. Pulled out for testability and so the SHA-256 cost of the
// raw body runs on the worker goroutine instead of the proxy
// goroutine.
func buildJudgeRow(jb judgePersistJob) audit.JudgeResponse {
	prov := version.Current()
	body := jb.payload.RawResponse
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
		InputHash:         jb.payload.InputHash,
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
	shutdownBudget := j.shutdownTimeout
	if shutdownBudget <= 0 {
		shutdownBudget = judgePersistShutdownTimeout
	}
	grace := j.drainCancelAfter
	if grace <= 0 || grace >= shutdownBudget {
		grace = shutdownBudget * 4 / 5
		if grace <= 0 {
			grace = shutdownBudget
		}
	}
	time.AfterFunc(grace, j.workerCancel)
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
	// Shutdown's own cap is authoritative. A caller deadline can shorten the
	// wait through ctx.Done, but a longer deadline must never extend the
	// documented bounded drain.
	budget := j.shutdownTimeout
	if budget <= 0 {
		budget = judgePersistShutdownTimeout
	}
	timer := time.NewTimer(budget)
	defer timer.Stop()
	// ctxDone reflects EITHER cancellation OR deadline; we honor both
	// so a SIGTERM-driven shutdown propagating context.WithCancel
	// terminates promptly instead of waiting out the 5 s budget.
	var ctxDone <-chan struct{}
	if ctx != nil {
		ctxDone = ctx.Done()
	}
	select {
	case <-j.doneCh:
		return nil
	case <-timer.C:
		return fmt.Errorf("judge_store: shutdown timed out after %s", budget)
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
// audit.JudgeBodyStore adapter (Phase 4)
// ---------------------------------------------------------------------------

// judgeBodyStoreInserter adapts the Phase 4 dedicated
// *audit.JudgeBodyStore (judge_bodies.db) to the JudgeBodyInserter
// contract. Routing through this adapter isolates the highest-volume
// write path (judge_responses) from audit_events / activity_events
// writers on audit.db.
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
