// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"strings"
	"testing"
	"time"
)

// TestBenignBraceRangeAnswersInsideHookDeadline is rel-1-0-2 GAP-0568: a
// benign echo {1..N} | wc -c under the 65536-word bound was expanded in full
// by every word reader of the hook client and the gateway, about 3 s for
// N=60000, so the hook client gave up at its deadline and denied it. A word
// whose brace range makes several fields is now refused by the readers
// that want one field (or a few) before it expands. The benign ranges allow
// well inside the deadline, per-user and managed, both connectors; protected
// brace forms and the over-bound range still block.
func TestBenignBraceRangeAnswersInsideHookDeadline(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	const perCall = time.Second // the hook deadline is about 3 s, the client process takes about 1 s
	benign := []string{
		"echo {1..40000} | wc -c",
		"echo {1..60000} | wc -c",
		"echo {1..65000} | wc -c",
		"printf '%s\\n' {a..z}{1..2000} | wc -l",
		"echo {a,b}{1..30000} > out.txt",
	}
	blocked := []struct {
		command, rule string
		perUserOnly   bool
	}{
		{"echo {1..60000} > ../.ssh/authorized_keys", "", false},
		{"cp README.md {ordinary/a,keylink}", "", false},
		{"tee ../.ssh/authorized_keys < ../.ssh/id.pub", "", false},
		// A brace tee onto the keys file: per-user only, the managed
		// header does not carry it (pre-existing, filed separately).
		{"tee ../.ssh/authorized_key{r..t} < ../.ssh/id.pub", "", true},
		{"tee ../.ssh/authorized_key{s,x} < ../.ssh/id.pub", "", true},
		{"echo {1..65537} | wc -c", "ACTION-COMPOUND-LIMIT", false},
	}
	run := func(command string) (calls []*hookCall, slowest time.Duration) {
		payload := f.payload(t, command)
		start := time.Now()
		header := f.clientHeader(t, payload)
		client := time.Since(start)
		for _, call := range everyMode(command, payload, header) {
			mode := os.FileMode(0o700)
			if call.managed {
				mode = 0
			}
			if err := os.Chmod(f.homes, mode); err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			call.verdict, call.body = f.serve(call)
			slowest = max(slowest, client+time.Since(start))
			calls = append(calls, call)
		}
		if err := os.Chmod(f.homes, 0o700); err != nil {
			t.Fatal(err)
		}
		return calls, slowest
	}
	for _, command := range benign {
		calls, slowest := run(command)
		for _, call := range calls {
			if call.verdict != "allow" {
				t.Errorf("%s: verdict %s, want allow; body %.200s", call.name, call.verdict, call.body)
			}
		}
		t.Logf("%s: slowest call %s", command, slowest.Round(time.Millisecond))
		if slowest > perCall {
			t.Errorf("%s: slowest call took %s (client header included), want under %s", command, slowest.Round(time.Millisecond), perCall)
		}
	}
	for _, tc := range blocked {
		calls, slowest := run(tc.command)
		for _, call := range calls {
			if tc.perUserOnly && call.managed {
				continue
			}
			if call.verdict != "block" || !strings.Contains(call.body, tc.rule) {
				t.Errorf("%s: verdict %s, want block %s; body %.200s", call.name, call.verdict, tc.rule, call.body)
			}
		}
		if slowest > perCall {
			t.Errorf("%s: slowest call took %s, want under %s", tc.command, slowest.Round(time.Millisecond), perCall)
		}
	}
}
