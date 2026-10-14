// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The audit store has one writer connection. The WAL guard must relinquish
// that connection before a hook client's deadline even when a checkpoint
// cannot complete on this pass.
func TestAuditWALGuardReleasesWriterForHook(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	api := &APIServer{store: store, logger: logger}
	entered := make(chan struct{})
	checkpointDone := make(chan error, 1)
	go func() {
		checkpointDone <- checkpointAuditWALWithin(t.Context(), func(ctx context.Context) error {
			// Reserve the same single writer connection that the real WAL
			// checkpoint and hook correlation/audit share.
			batch, err := store.BeginJudgeBatch(ctx)
			if err != nil {
				return err
			}
			defer batch.Rollback() //nolint:errcheck
			close(entered)
			<-ctx.Done()
			return ctx.Err()
		})
	}()
	select {
	case <-entered:
	case err := <-checkpointDone:
		t.Fatalf("checkpoint did not reserve the audit writer: %v", err)
	}
	started := time.Now()
	hookDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook",
			strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"date"}}`))
		api.handleAgentHook("claudecode").ServeHTTP(response, request)
		hookDone <- response
	}()
	select {
	case response := <-hookDone:
		if response.Code != http.StatusOK || strings.Contains(response.Body.String(), `"deny"`) {
			t.Fatalf("benign hook after writer release: status=%d body=%s", response.Code, response.Body.String())
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("hook waited more than 500ms for the checkpoint writer")
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("hook took %s, want under 500ms", elapsed)
	}
	if err := <-checkpointDone; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("checkpoint error = %v, want deadline", err)
	}
}
