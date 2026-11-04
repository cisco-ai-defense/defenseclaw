// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGAP0407IncompleteResponseRecordMatchesDeliveredBlock(t *testing.T) {
	home := t.TempDir()
	if err := os.Mkdir(filepath.Join(home, "logs"), 0o700); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	type result struct {
		code             int
		output           string
		ordinary, marker []byte
	}
	exited := make(chan result, 1)
	opts := withDefaults(Options{
		Home: home, Event: "PreToolUse", FailMode: "open",
		Stdout: &output, Stderr: io.Discard,
		Exit: func(code int) {
			ordinary, _ := os.ReadFile(filepath.Join(home, "logs", "hook-failures.jsonl"))
			marker, _ := os.ReadFile(filepath.Join(home, "logs", "hook-failures.dropped"))
			exited <- result{code, output.String(), ordinary, marker}
		},
	})
	opts.failurePayload = []byte(`{"session_id":"s","tool_use_id":"response-error"}`)
	sp := specs["claudecode"]
	deadline := time.Now().Add(450 * time.Millisecond)
	w := startAnswerWatchdog(&opts, sp, "open", deadline, deadline)
	w.gatewayAnsweredError(opts, sp, 200)
	select {
	case got := <-exited:
		if !claudeBlocked(runResult{code: got.code, stdout: got.output}) {
			t.Fatalf("incomplete gateway response was not blocked: code=%d", got.code)
		}
		line := got.ordinary
		if bytes.HasPrefix(got.marker, []byte("DCID")) {
			line = got.marker[4:]
		}
		if len(line) == 0 {
			t.Fatal("missing local block record")
		}
		var entry hookFailureEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			t.Fatal(err)
		}
		if entry.ToolID != "response-error" || entry.Reason != "incomplete gateway response" || entry.Category != "response" || entry.Outcome != "fail_closed" {
			t.Fatalf("incomplete response delivered a block but record describes another failure: %+v", entry)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watchdog did not exit")
	}
}
