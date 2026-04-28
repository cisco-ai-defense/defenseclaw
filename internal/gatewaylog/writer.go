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

package gatewaylog

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"
)

// Writer persists gateway events. The default implementation fans
// every event out to a JSONL file (rotated by size) and a
// human-readable stderr pretty-printer. Additional fanout targets
// (OTel logs, sinks.Manager) are installed via WithFanout.
type Writer struct {
	mu      sync.Mutex
	jsonl   io.WriteCloser
	pretty  io.Writer
	fanout  []func(Event)
	encoder *json.Encoder
	closed  bool

	// validator is the runtime JSON Schema gate. Nil when operators
	// opted out (DEFENSECLAW_SCHEMA_VALIDATION=off or never wired
	// up). Non-nil means "strict mode": invalid events are dropped
	// from JSONL/pretty/fanout and a single EventError surfaces the
	// violation exactly once.
	validator *Validator

	// schemaViolations is an atomic counter of dropped events. Used
	// by Provider.RecordSchemaViolation (installed via
	// OnSchemaViolation) to emit the Prometheus metric without
	// pulling a full telemetry dependency into gatewaylog.
	schemaViolations atomic.Int64

	// onSchemaViolation is an optional observer invoked synchronously
	// from the Emit path (outside w.mu) so operators can wire a
	// counter increment via telemetry.Provider without gatewaylog
	// importing telemetry. Nil is a no-op.
	onSchemaViolation func(eventType EventType, code, message string)

	// emitDepth guards against recursion: when the validator
	// rejects an event, Emit turns it into an EventError and
	// recurses; if the EventError itself fails validation we must
	// NOT recurse a second time or we lock up the hot path.
	emitDepth atomic.Int32
}

// Config controls writer construction. JSONLPath is required; when
// empty the JSONL tier is disabled and only Pretty is used (useful
// for unit tests).
type Config struct {
	// JSONLPath is the on-disk location of the structured log. An
	// empty path disables the JSONL tier entirely.
	JSONLPath string

	// MaxSizeMB, MaxBackups, MaxAgeDays, Compress are forwarded to
	// lumberjack. Zero values get safe defaults (50MB, 5 backups,
	// 30 days, compressed).
	MaxSizeMB  int
	MaxBackups int
	MaxAgeDays int
	Compress   bool

	// Pretty is the stderr-style sink (usually os.Stderr). A nil
	// Pretty disables human-readable output, which is the right
	// default inside the daemonized sidecar where stderr is already
	// captured by the supervising daemon.
	Pretty io.Writer

	// Validator, when non-nil, enforces the
	// gateway-event-envelope.json schema on every Emit call.
	// Invalid events are dropped; an EventError surfaces the
	// violation to the operator. Nil disables validation entirely
	// (legacy behavior) — callers opt in by constructing a
	// *Validator via NewValidatorFromDir and passing it here.
	Validator *Validator
}

// New constructs a Writer. Callers must hold the returned Writer
// across the full gateway lifetime and invoke Close on shutdown so
// the final batch flushes to disk.
func New(cfg Config) (*Writer, error) {
	w := &Writer{pretty: cfg.Pretty, validator: cfg.Validator}

	if cfg.JSONLPath != "" {
		lj := &lumberjack.Logger{
			Filename:   cfg.JSONLPath,
			MaxSize:    pickPositive(cfg.MaxSizeMB, 50),
			MaxBackups: pickPositive(cfg.MaxBackups, 5),
			MaxAge:     pickPositive(cfg.MaxAgeDays, 30),
			Compress:   cfg.Compress,
		}
		w.jsonl = lj
		w.encoder = json.NewEncoder(lj)
	}

	return w, nil
}

// WithFanout registers an additional per-event callback. Callbacks
// run synchronously on the Emit goroutine, but OUTSIDE the writer's
// mutex — so a slow callback cannot stall other Emit callers. The
// trade-off is that a concurrent Emit may interleave fanout
// delivery order across callbacks; implementations that require
// strict ordering should marshal onto a dedicated goroutine via a
// buffered channel. The canonical use case is mapping events onto
// OTel LogRecords.
func (w *Writer) WithFanout(fn func(Event)) {
	if w == nil || fn == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.fanout = append(w.fanout, fn)
}

// Emit writes a single event to every configured tier. The Timestamp
// is defaulted to time.Now() if unset so callers don't have to
// sprinkle clock calls.
//
// Fanout callbacks run OUTSIDE the writer mutex. A slow OTel
// exporter or sinks.Manager should not be able to stall the
// guardrail hot path — if multiple concurrent Emit calls happen
// they may arrive at a single fanout callback in an interleaved
// order, which is the fanout's responsibility to handle (typically
// via a buffered channel). Under-mutex file/stderr writes keep the
// JSONL tier strictly append-ordered per-emit.
func (w *Writer) Emit(e Event) {
	if w == nil {
		return
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	if e.Severity == "" {
		e.Severity = SeverityInfo
	}
	// v7: stamp provenance at the choke point so every event on
	// every tier (JSONL, pretty, OTel fanout, sinks.Manager)
	// reflects a consistent snapshot of config state. Callers who
	// pre-stamped (tests pinning a historical generation) keep
	// their values — StampProvenance is idempotent-ish, the last
	// writer wins, which matches the invariant "the sidecar that
	// serialized the event is authoritative for provenance".
	if e.SchemaVersion == 0 {
		e.StampProvenance()
	}
	// v7: stamp the per-process sidecar UUID on every event whose
	// caller did not set one. This is the last-line defense for the
	// "every event MUST carry sidecar_instance_id" contract — the
	// hot-path emitVerdict/emitJudge helpers stamp from context,
	// but a library caller that forgets (or runs outside a request
	// context such as boot/shutdown) still gets a valid row. Never
	// overwrites a caller-supplied value so tests can pin their own.
	if e.SidecarInstanceID == "" {
		e.SidecarInstanceID = SidecarInstanceID()
	}
	// Plan B6 / S0.10: stamp HMAC over the canonical JSON of the
	// payload using the per-boot device-key-derived HMAC key. No-op
	// when SetTelemetryHMACSeed has not been called (boot ordering
	// race / unit tests) — the field stays empty and downstream
	// auditors skip verification. Computed AFTER provenance stamping
	// so the canonicalized bytes are stable across reboots that
	// would otherwise advance Generation.
	if e.PayloadHMAC == "" {
		e.StampPayloadHMAC()
	}

	// Strict schema gate. Runs AFTER provenance/sidecar stamping so
	// a missing provenance or sidecar_instance_id becomes a normal
	// validation error instead of a silent drop. emitDepth guards
	// recursion: when we're already inside a schema-violation
	// EventError emit, we skip re-validation to guarantee the
	// operator sees *exactly one* violation per offending event.
	// A nil validator short-circuits with zero allocations so
	// legacy tests / callers get legacy behavior for free.
	if w.validator != nil && w.emitDepth.Load() == 0 {
		if err := w.validator.Validate(e); err != nil {
			w.handleSchemaViolation(e, err)
			return
		}
	}

	var fanout []func(Event)
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	if w.encoder != nil {
		// encoder writes a trailing newline, giving us JSONL natively.
		// Encode failures are visible to the operator via the pretty
		// sink when available; otherwise we fall back to stderr so
		// the error never vanishes silently in a daemonised sidecar.
		if err := w.encoder.Encode(e); err != nil {
			if w.pretty != nil {
				fmt.Fprintf(w.pretty, "[gatewaylog] write failed: %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "[gatewaylog] write failed: %v\n", err)
			}
		}
	}
	if w.pretty != nil {
		writePretty(w.pretty, e)
	}
	if len(w.fanout) > 0 {
		// Snapshot under the lock so a concurrent WithFanout /
		// Close cannot race with our iteration. The slice header
		// is copied but the backing array is the same — fanout
		// callbacks are append-only in WithFanout so this is safe.
		fanout = make([]func(Event), len(w.fanout))
		copy(fanout, w.fanout)
	}
	w.mu.Unlock()

	// Fanout callbacks run outside the writer mutex so a slow or
	// misbehaving OTel exporter cannot stall other Emit calls.
	// We also guard each callback with recover() — a panic inside
	// a third-party exporter must not take down the gateway hot
	// path. The recovered error is surfaced on the pretty sink
	// (or stderr) so operators can triage the offending callback.
	pretty := w.pretty
	for _, fn := range fanout {
		safeFanout(fn, e, pretty)
	}
}

// OnSchemaViolation installs a synchronous observer invoked every
// time the validator rejects an event. The observer must be
// non-blocking and allocation-light — it runs on the guardrail hot
// path and gatewaylog intentionally does not queue it. The typical
// implementation increments a Prometheus counter via
// telemetry.Provider.RecordSchemaViolation.
func (w *Writer) OnSchemaViolation(fn func(eventType EventType, code, message string)) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.onSchemaViolation = fn
}

// SchemaViolationsCount returns the cumulative count of events
// rejected by the validator since construction. Safe for concurrent
// reads. Primarily used by tests and the `doctor` debug surface.
func (w *Writer) SchemaViolationsCount() int64 {
	if w == nil {
		return 0
	}
	return w.schemaViolations.Load()
}

// handleSchemaViolation is the centralised strict-mode reaction
// path: drop the offending event, increment the counter, notify
// the observer, and emit a single EventError on the standard Emit
// path so operators can see it on every tier (JSONL / pretty /
// OTel fanout). The emitDepth guard ensures the violation error
// itself cannot recurse if, somehow, it fails validation too.
func (w *Writer) handleSchemaViolation(src Event, cause error) {
	w.schemaViolations.Add(1)

	msg := "schema validation failed"
	if cause != nil {
		msg = cause.Error()
	}

	w.mu.Lock()
	observer := w.onSchemaViolation
	pretty := w.pretty
	w.mu.Unlock()

	if observer != nil {
		func() {
			defer func() {
				if r := recover(); r != nil {
					p := pretty
					if p == nil {
						p = os.Stderr
					}
					fmt.Fprintf(p, "[gatewaylog] schema-violation observer panic: %v\n", r)
				}
			}()
			observer(src.EventType, string(ErrCodeSchemaViolation), msg)
		}()
	}

	// Always surface a human-readable hint on the pretty tier so an
	// operator tailing stderr sees *why* events are missing. We
	// keep this short to avoid double-reporting when the EventError
	// path below also renders to stderr.
	if pretty != nil {
		fmt.Fprintf(pretty, "[gatewaylog] DROP (schema violation, event_type=%s): %s\n", src.EventType, truncate(msg, 200))
	}

	// Build the operator-facing violation event. We deliberately
	// echo the dropped event's correlation + provenance so the
	// error is attributable to the exact request that produced the
	// bad emission. event_type=error puts us on the `error`
	// oneOf branch of the envelope.
	viol := Event{
		Timestamp:         time.Now().UTC(),
		EventType:         EventError,
		Severity:          SeverityMedium,
		TraceID:           src.TraceID,
		RunID:             src.RunID,
		SessionID:         src.SessionID,
		RequestID:         src.RequestID,
		AgentID:           src.AgentID,
		AgentInstanceID:   src.AgentInstanceID,
		SidecarInstanceID: src.SidecarInstanceID,
		Error: &ErrorPayload{
			Subsystem: string(SubsystemGatewaylog),
			Code:      string(ErrCodeSchemaViolation),
			Message:   truncate(fmt.Sprintf("dropped %s event: %s", src.EventType, msg), 1024),
			Cause:     string(src.EventType),
		},
	}

	// Recursion guard: bump emitDepth so the nested Emit skips the
	// validator. Even if the crafted violation event somehow fails
	// validation (should not happen — EventError is a well-formed
	// oneOf branch) we still want it to appear on sinks so the
	// operator is not left blind.
	w.emitDepth.Add(1)
	defer w.emitDepth.Add(-1)
	w.Emit(viol)
}

// truncate caps s at n runes and appends an ellipsis if we clipped.
// Used to keep the schema-violation message compact on sinks that
// charge per byte (OTLP, Splunk HEC).
func truncate(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// safeFanout invokes fn(e) with a recover() guard so a panic in
// any downstream fanout target cannot unwind into Emit's caller
// (which is always the guardrail hot path).
func safeFanout(fn func(Event), e Event, pretty io.Writer) {
	defer func() {
		if r := recover(); r != nil {
			w := pretty
			if w == nil {
				w = os.Stderr
			}
			fmt.Fprintf(w, "[gatewaylog] fanout panic: %v\n", r)
		}
	}()
	fn(e)
}

// Close flushes and releases the underlying file handles. Safe to
// call multiple times.
func (w *Writer) Close() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	if w.jsonl != nil {
		return w.jsonl.Close()
	}
	return nil
}

func pickPositive(v, fallback int) int {
	if v > 0 {
		return v
	}
	return fallback
}
