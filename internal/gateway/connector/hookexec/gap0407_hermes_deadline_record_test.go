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

func TestGAP0407HermesClosedDeadlineRecordMatchesNativeBlock(t *testing.T) {
	home := t.TempDir()
	if err := os.Mkdir(filepath.Join(home, "logs"), 0o700); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	type result struct {
		code             int
		out              string
		ordinary, marker []byte
	}
	exited := make(chan result, 1)
	opts := withDefaults(Options{
		Connector: "hermes", Home: home, Event: "pre_tool_call", FailMode: "closed",
		Stdout: &output, Stderr: io.Discard,
		Exit: func(code int) {
			ordinary, _ := os.ReadFile(filepath.Join(home, "logs", "hook-failures.jsonl"))
			marker, _ := os.ReadFile(filepath.Join(home, "logs", "hook-failures.dropped"))
			exited <- result{code, output.String(), ordinary, marker}
		},
	})
	opts.failurePayload = []byte(`{"session_id":"s","tool_call_id":"hermes-closed-deadline"}`)
	deadline := time.Now().Add(450 * time.Millisecond)
	startAnswerWatchdog(&opts, specs["hermes"], "closed", deadline, deadline)
	select {
	case got := <-exited:
		if !bytes.Contains([]byte(got.out), []byte(`"action":"block"`)) {
			t.Fatalf("Hermes did not receive a native block: code=%d output=%q", got.code, got.out)
		}
		line := got.marker
		if bytes.HasPrefix(line, []byte("DCID")) {
			line = line[4:]
		} else {
			line = got.ordinary
		}
		if len(line) == 0 {
			t.Fatal("native block has no local outcome record")
		}
		var entry hookFailureEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			t.Fatal(err)
		}
		if entry.ToolID != "hermes-closed-deadline" || entry.Outcome != "fail_closed" || entry.FailMode != "closed" {
			t.Fatalf("Hermes native block recorded as another outcome: %+v", entry)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watchdog did not exit")
	}
}

func TestGAP0407NativeNonToolDeadlineStaysAllowed(t *testing.T) {
	for _, tc := range []struct {
		connector string
		event     string
	}{
		{"hermes", "post_tool_call"},
		{"copilot", "postToolUse"},
	} {
		t.Run(tc.connector, func(t *testing.T) {
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
				Connector: tc.connector, Home: home, Event: tc.event, FailMode: "closed",
				Stdout: &output, Stderr: io.Discard,
				Exit: func(code int) {
					ordinary, _ := os.ReadFile(filepath.Join(home, "logs", "hook-failures.jsonl"))
					marker, _ := os.ReadFile(filepath.Join(home, "logs", "hook-failures.dropped"))
					exited <- result{code, output.String(), ordinary, marker}
				},
			})
			deadline := time.Now().Add(450 * time.Millisecond)
			startAnswerWatchdog(&opts, specs[tc.connector], "closed", deadline, deadline)
			select {
			case got := <-exited:
				if nativeAnswerBlocks(got.code, got.output) {
					t.Fatalf("non-tool event was blocked: code=%d output=%q", got.code, got.output)
				}
				line := got.ordinary
				if bytes.HasPrefix(got.marker, []byte("DCID")) {
					line = got.marker[4:]
				}
				if len(line) == 0 {
					t.Fatal("missing local outcome record")
				}
				var entry hookFailureEntry
				if err := json.Unmarshal(line, &entry); err != nil {
					t.Fatal(err)
				}
				if entry.Outcome != "fail_open" || entry.FailMode != "open" {
					t.Fatalf("allowed event recorded as another outcome: %+v", entry)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("watchdog did not exit")
			}
		})
	}
}
