// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// GAP-1711, GAP-1812: the gateway, not the hook, applies a clean scan again
// when its session store could not apply it, so it audits only the final
// answer. The hook sends the exchange once, with retry_until: its answer
// deadline less the time its own request needs. A hook that resent the
// exchange left a HIGH block row for every denial the gateway gave before
// the allow.
func TestForeignHookSessionExchangeIsSentOnceWithRetryUntil(t *testing.T) {
	const busy = `{"deny":true,"reason":"enterprise_foreign_hook_blocked: DefenseClaw cannot verify this agent session's hook record. Remove any unapproved hook and restart the agent."}`
	var calls atomic.Int32
	var sent map[string]json.RawMessage
	started := time.Now()
	opts := Options{
		ManagedEnterprise: true, ManagedStandalone: true, APIAddr: "127.0.0.1:18970",
		StartedAt: started, Connector: "claudecode", Event: "PreToolUse",
	}
	opts.HTTPClient = &http.Client{Transport: foreignSessionRoundTrip(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		body, _ := io.ReadAll(req.Body)
		_ = json.Unmarshal(body, &sent)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(busy))}, nil
	})}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	body, err := ExchangeForeignHookSession(ctx, opts, "claudecode",
		[]byte(`{"key":{"connector":"claudecode","session":"s-1"},"session_start":false,"decision":{"deny":false}}`))
	if err != nil || string(body) != busy {
		t.Fatalf("the gateway's answer must be returned as is: %q %v", body, err)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("the hook sent the exchange %d times; the gateway retries, the hook sends it once", n)
	}
	var until time.Time
	if err := json.Unmarshal(sent["retry_until"], &until); err != nil {
		t.Fatalf("the exchange carries no retry_until: %v (%s)", err, sent["retry_until"])
	}
	want := started.Add(hookAnswerBudget - foreignHookSessionRetryReserve)
	if !until.Equal(want) {
		t.Fatalf("retry_until = %v, want the answer deadline less the hook request's reserve (%v)", until, want)
	}
	for _, key := range []string{"key", "session_start", "decision"} {
		if _, ok := sent[key]; !ok {
			t.Fatalf("the exchange lost %q: %v", key, sent)
		}
	}
}
