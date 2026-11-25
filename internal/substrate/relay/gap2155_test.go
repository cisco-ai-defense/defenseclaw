// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptrace"
	"testing"
)

// rel-1-0-10:GAP-2155 (P4, CHK-OPUS on GAP-1771): net/http retries a POST
// once when its first attempt on a reused connection wrote nothing. When
// that attempt's request write failed and the retry wrote it whole, then
// got no answer, the first attempt's failure decided: the chunk was
// reported unsent though the relay may have handed it to the agent (the
// user types it twice). Each attempt is judged on its own: the last one
// decides.
func TestGAP2155PollWriteRetriedAttemptDecides(t *testing.T) {
	live := context.Background()
	noAnswer := errors.New("connection reset with no answer")
	attempts := func(writes ...error) func(context.Context) (*http.Response, error) {
		return func(ctx context.Context) (*http.Response, error) {
			tr := httptrace.ContextClientTrace(ctx)
			for _, w := range writes {
				tr.GotConn(httptrace.GotConnInfo{Reused: true})
				tr.WroteRequest(httptrace.WroteRequestInfo{Err: w})
			}
			return nil, noAnswer
		}
	}
	// First attempt's write failed, the retry wrote whole: unanswered (Sent).
	if err := pollWrite(live, live, attempts(errors.New("write: broken pipe"), nil)); !errors.Is(err, errWriteUnanswered) {
		t.Fatalf("retried write that went out whole, no answer: %v, want errWriteUnanswered (counted in Sent)", err)
	}
	// The last attempt's write failed: nothing whole reached the relay (unsent).
	if err := pollWrite(live, live, attempts(nil, errors.New("write: broken pipe"))); err != noAnswer {
		t.Fatalf("last attempt's write failed: %v, want its own error (reported unsent)", err)
	}
}
