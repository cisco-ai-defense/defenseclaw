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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"
)

// RouterFeedback sends post-response metrics to the semantic router.
type RouterFeedback struct {
	endpoint string // e.g. "http://127.0.0.1:8080"
	client   *http.Client
	ch       chan feedbackEntry

	// Rate-limited error logging.
	errMu        sync.Mutex
	lastErrLog   time.Time
	errsSinceLog int
	errLogBudget time.Duration
}

type feedbackEntry struct {
	Model     string `json:"model"`
	Decision  string `json:"decision"`
	LatencyMs int64  `json:"latency_ms"`
	Tokens    int    `json:"tokens"`
	Success   bool   `json:"success"`
	SessionID string `json:"session_id,omitempty"`
}

// NewRouterFeedback creates a feedback sender. Starts a background goroutine
// that drains the channel and sends to SR. The goroutine stops when ctx is cancelled.
func NewRouterFeedback(ctx context.Context, endpoint string) *RouterFeedback {
	rf := &RouterFeedback{
		endpoint:     endpoint,
		client:       &http.Client{Timeout: 5 * time.Second},
		ch:           make(chan feedbackEntry, 100),
		errLogBudget: 10 * time.Second,
	}
	go rf.drain(ctx)
	return rf
}

// Record queues a feedback entry. Non-blocking — drops if channel is full.
func (rf *RouterFeedback) Record(model, decision string, latency time.Duration, tokens int, success bool, sessionID string) {
	entry := feedbackEntry{
		Model:     model,
		Decision:  decision,
		LatencyMs: latency.Milliseconds(),
		Tokens:    tokens,
		Success:   success,
		SessionID: sessionID,
	}
	select {
	case rf.ch <- entry:
	default:
		// Channel full — drop silently (non-critical telemetry)
	}
}

func (rf *RouterFeedback) drain(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case entry := <-rf.ch:
			rf.send(ctx, entry)
		}
	}
}

func (rf *RouterFeedback) send(ctx context.Context, entry feedbackEntry) {
	body, err := json.Marshal(entry)
	if err != nil {
		return
	}

	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, rf.endpoint+"/v1/feedback", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := rf.client.Do(req)
	if err != nil {
		// SR unreachable for feedback — non-critical, rate-limit logging.
		rf.logError("feedback send failed: %v", err)
		return
	}
	// Drain response body before closing to allow HTTP connection reuse.
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

// logError rate-limits error logging so transient SR failures don't spam stderr.
func (rf *RouterFeedback) logError(format string, args ...interface{}) {
	rf.errMu.Lock()
	defer rf.errMu.Unlock()

	rf.errsSinceLog++
	now := time.Now()

	if now.Sub(rf.lastErrLog) < rf.errLogBudget {
		// Within budget — suppress.
		return
	}

	// Budget expired — emit aggregated log.
	if rf.errsSinceLog > 1 {
		fmt.Fprintf(os.Stderr, "[routing] %s (%d errors since last log)\n", fmt.Sprintf(format, args...), rf.errsSinceLog)
	} else {
		fmt.Fprintf(os.Stderr, "[routing] %s\n", fmt.Sprintf(format, args...))
	}

	rf.lastErrLog = now
	rf.errsSinceLog = 0
}
