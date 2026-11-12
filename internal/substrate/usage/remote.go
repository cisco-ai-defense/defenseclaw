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

package usage

import (
	"context"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

type appendIn struct {
	Records []Record `json:"records"`
}

type scopeOut struct {
	Tokens int64 `json:"tokens"`
}

// Serve registers the usage methods of s on the leader server.
func Serve(srv *leader.Server, s Store) {
	srv.Handle(leader.MethodUsageAppend, leader.Typed(func(ctx context.Context, in appendIn) (AppendResult, error) {
		if len(in.Records) > MaxBatch {
			return AppendResult{}, &leader.WireError{Code: leader.CodeBadRequest, Message: "too many records"}
		}
		return s.Append(ctx, in.Records)
	}))
	srv.Handle(leader.MethodUsageSummary, leader.Typed(func(ctx context.Context, f Filter) (Summary, error) {
		if err := f.check(); err != nil {
			return Summary{}, &leader.WireError{Code: leader.CodeBadRequest, Message: err.Error()}
		}
		return s.Summary(ctx, f)
	}))
	srv.Handle(leader.MethodUsageScope, leader.Typed(func(ctx context.Context, q ScopeQuery) (scopeOut, error) {
		n, err := s.ScopeTotal(ctx, q)
		if err != nil {
			return scopeOut{}, &leader.WireError{Code: leader.CodeBadRequest, Message: err.Error()}
		}
		return scopeOut{Tokens: n}, nil
	}))
}

// MaxBatch is the most records one append carries.
const MaxBatch = 256

// Remote is Store over the leader transport.
type Remote struct {
	Client *leader.Client
}

// Append implements Store.
func (s *Remote) Append(ctx context.Context, recs []Record) (AppendResult, error) {
	var out AppendResult
	err := s.Client.Call(ctx, leader.MethodUsageAppend, leader.NewRequestID(), appendIn{Records: recs}, &out)
	return out, err
}

// Summary implements Store.
func (s *Remote) Summary(ctx context.Context, f Filter) (Summary, error) {
	if err := f.check(); err != nil {
		return Summary{}, err
	}
	var out Summary
	err := s.Client.Call(ctx, leader.MethodUsageSummary, leader.NewRequestID(), f, &out)
	return out, err
}

// ScopeTotal implements Store.
func (s *Remote) ScopeTotal(ctx context.Context, q ScopeQuery) (int64, error) {
	var out scopeOut
	err := s.Client.Call(ctx, leader.MethodUsageScope, leader.NewRequestID(), q, &out)
	return out.Tokens, err
}

// Writer appends records in the background, so a model call never waits
// on the leader: Add queues (dropping when the queue is full) and a single
// goroutine sends batches. OnResult sees every append's scope totals (the
// budget check); OnDrop counts records lost to a full queue or a failed
// append.
type Writer struct {
	Store    Store
	OnResult func(AppendResult)
	OnDrop   func(n int, reason string)
	// Interval is the longest a record waits to be sent (default 250 ms).
	Interval time.Duration

	once sync.Once
	ch   chan Record
	done chan struct{}
	mu   sync.Mutex
	stop bool
}

// QueueSize is the most records waiting to be sent.
const QueueSize = 4096

func (w *Writer) start() {
	w.once.Do(func() {
		if w.Interval <= 0 {
			w.Interval = 250 * time.Millisecond
		}
		w.ch = make(chan Record, QueueSize)
		w.done = make(chan struct{})
		go w.run()
	})
}

// Add queues r; false when the queue is full or the writer closed.
func (w *Writer) Add(r Record) bool {
	w.start()
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stop {
		w.drop(1, "closed")
		return false
	}
	select {
	case w.ch <- r:
		return true
	default:
		w.drop(1, "queue_full")
		return false
	}
}

func (w *Writer) drop(n int, reason string) {
	if w.OnDrop != nil {
		w.OnDrop(n, reason)
	}
}

func (w *Writer) run() {
	defer close(w.done)
	t := time.NewTicker(w.Interval)
	defer t.Stop()
	var batch []Record
	flush := func() {
		if len(batch) == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		res, err := w.Store.Append(ctx, batch)
		cancel()
		if err != nil {
			w.drop(len(batch), "append_failed")
		} else if w.OnResult != nil {
			w.OnResult(res)
		}
		batch = batch[:0]
	}
	for {
		select {
		case r, ok := <-w.ch:
			if !ok {
				flush()
				return
			}
			batch = append(batch, r)
			if len(batch) >= MaxBatch {
				flush()
			}
		case <-t.C:
			flush()
		}
	}
}

// Close sends what is queued and stops the writer.
func (w *Writer) Close() {
	w.start()
	w.mu.Lock()
	if w.stop {
		w.mu.Unlock()
		<-w.done
		return
	}
	w.stop = true
	close(w.ch)
	w.mu.Unlock()
	<-w.done
}
