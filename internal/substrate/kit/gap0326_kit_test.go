// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package kit

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// GAP-0326: after a 100 s gateway outage an unattended --task run ended with
// exit 0 although a step never ran. A hook the gateway did not answer now
// records the call in the run's fault file, which the relay reads.

func TestGAP0326UnansweredHookIsRecordedForTheRelay(t *testing.T) {
	faults := filepath.Join(t.TempDir(), "faults")
	if err := os.WriteFile(faults, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"DEFENSECLAW_ACTOR_MODE": "unattended", "DEFENSECLAW_TASK_FAULTS": faults}
	run := func(send func(context.Context, Request) (Response, string, error)) int {
		var out, errb bytes.Buffer
		return RunHook(context.Background(), HookOptions{Connector: "claudecode", Config: testConfig("https://gw"),
			Stdin: strings.NewReader(ccPre), Stdout: &out, Stderr: &errb, Getenv: func(k string) string { return env[k] }, Send: send})
	}
	if code := run(func(context.Context, Request) (Response, string, error) { return Response{}, "", ErrUnreachable }); code != 2 {
		t.Fatalf("unattended outage: exit %d, want 2", code)
	}
	b, _ := os.ReadFile(faults)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 1 || !strings.HasSuffix(lines[0], " PreToolUse") {
		t.Fatalf("fault file after an unanswered hook = %q, want one line naming PreToolUse", b)
	}
	at, _, _ := strings.Cut(lines[0], " ")
	if _, err := time.Parse(time.RFC3339, at); err != nil {
		t.Fatalf("fault line %q has no RFC 3339 time: %v", lines[0], err)
	}
	// A call the gateway answered is not a fault.
	run(func(context.Context, Request) (Response, string, error) {
		return Response{Status: 200, Body: []byte(`{"action":"allow"}`)}, "", nil
	})
	if b2, _ := os.ReadFile(faults); !bytes.Equal(b2, b) {
		t.Fatalf("an answered hook call changed the fault file: %q", b2)
	}
}
