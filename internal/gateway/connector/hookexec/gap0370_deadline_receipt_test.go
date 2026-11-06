// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bufio"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The receipt follows the answer even when both local record paths are
// delayed. A gateway that accepted the call can record this receipt directly.
func TestGAP0370DeadlineReceiptSurvivesDelayedLocalRecord(t *testing.T) {
	shortAnswerBudget(t, 350*time.Millisecond)
	shortAnswerFloor(t)
	stall := make(chan struct{})
	previous := openHookFailureLog
	openHookFailureLog = func(path string, flag int, perm os.FileMode) (*os.File, error) {
		if strings.HasSuffix(path, "hook-failures.jsonl") || strings.HasSuffix(path, "hook-failures.dropped") {
			<-stall
		}
		return previous(path, flag, perm)
	}
	defer func() {
		close(stall)
		openHookFailureLog = previous
	}()

	token := make(chan string, 1)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		controller := http.NewResponseController(w)
		if err := controller.EnableFullDuplex(); err != nil {
			token <- err.Error()
			return
		}
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusEarlyHints)
		length, _ := strconv.Atoi(r.Header.Get(HookDeliveryPayloadBytesHeader))
		body := bufio.NewReader(r.Body)
		if _, err := io.ReadFull(body, make([]byte, length)); err != nil {
			token <- err.Error()
			return
		}
		line, err := body.ReadString('\n')
		if err != nil {
			token <- err.Error()
		} else {
			token <- line
		}
		<-release
	}))
	defer server.Close()
	defer close(release)
	result, elapsed := runAgainstGateway(t, "codex", server.Listener.Addr().String(), func(opts *Options) {
		opts.FailMode = "closed"
		if err := os.MkdirAll(filepath.Join(opts.Home, "logs"), 0o700); err != nil {
			t.Fatal(err)
		}
		opts.Exit = func(int) {}
	})
	if !blocked(result) || elapsed > time.Second {
		t.Fatalf("watchdog result code=%d elapsed=%s, want bounded block", result.code, elapsed)
	}
	select {
	case got := <-token:
		if got != "late\n" {
			t.Fatalf("gateway receipt = %q, want delivered block", got)
		}
	case <-time.After(time.Second):
		t.Fatal("gateway received no deadline receipt")
	}
}
