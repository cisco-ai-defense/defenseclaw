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
}

// New constructs a Writer. Callers must hold the returned Writer
// across the full gateway lifetime and invoke Close on shutdown so
// the final batch flushes to disk.
func New(cfg Config) (*Writer, error) {
	w := &Writer{pretty: cfg.Pretty}

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
