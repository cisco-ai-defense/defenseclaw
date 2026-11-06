// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

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

// A caller that the gateway has accepted can spend the capability wait in
// admission work. The watchdog must still leave its delivered block witness
// when local failure-log opens are delayed.
func TestReviewG271LateCapabilityStillCarriesDeadlineBlock(t *testing.T) {
	shortAnswerBudget(t, time.Second)
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
		time.Sleep(500 * time.Millisecond)
		openHookFailureLog = previous
	}()

	token := make(chan string, 1)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set(HookDeliveryCapabilityHeader, "1")
			w.WriteHeader(http.StatusOK)
			return
		}
		controller := http.NewResponseController(w)
		if err := controller.EnableFullDuplex(); err != nil {
			token <- err.Error()
			return
		}
		// The request is admitted, but the 103 follows slow early work.
		time.Sleep(300 * time.Millisecond)
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
	result, _ := runAgainstGateway(t, "codex", server.Listener.Addr().String(), func(opts *Options) {
		opts.FailMode = "closed"
		if err := os.MkdirAll(filepath.Join(opts.Home, "logs"), 0o700); err != nil {
			t.Fatal(err)
		}
		opts.Exit = func(int) {}
	})
	if !blocked(result) {
		t.Fatalf("agent did not receive a block: code=%d stdout=%q stderr=%q", result.code, result.stdout, result.stderr)
	}
	select {
	case got := <-token:
		if got != HookDeliveryReceiptLate {
			t.Fatalf("gateway saw %q after agent block; want deadline block receipt %q", got, HookDeliveryReceiptLate)
		}
	case <-time.After(time.Second):
		t.Fatal("gateway saw no deadline receipt")
	}
}
