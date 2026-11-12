//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A `--version` run that fails for a moment (here: the first run exits with an
// error status and prints nothing, as an agent can while the host applies a
// policy change) is run again, and the answer of the second run counts.
func TestExecUnixAgentVersionRetriesAFailedRun(t *testing.T) {
	old := unixAgentVersionRetryDelay
	unixAgentVersionRetryDelay = time.Millisecond
	t.Cleanup(func() { unixAgentVersionRetryDelay = old })
	dir := t.TempDir()
	marker := filepath.Join(dir, "second")
	script := filepath.Join(dir, "opencode")
	body := "#!/bin/sh\nif [ ! -e " + marker + " ]; then : > " + marker + "; exit 3; fi\necho 'opencode 2.2.3'\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := execUnixAgentVersion(context.Background(), script, dir, ""); got != "2.2.3" {
		t.Fatalf("version = %q, want the retried run's 2.2.3", got)
	}
}

// A CLI that keeps failing is run a bounded number of times and still reports
// no version, so a copy that really cannot answer stays unverified. A CLI that
// answers with something that is not a version, and exits cleanly, is run once.
func TestExecUnixAgentVersionFailedRunsAreBounded(t *testing.T) {
	old := unixAgentVersionRetryDelay
	unixAgentVersionRetryDelay = time.Millisecond
	t.Cleanup(func() { unixAgentVersionRetryDelay = old })
	dir := t.TempDir()
	count := filepath.Join(dir, "count")
	for name, body := range map[string]string{
		"broken":  "echo run >> " + count + "\nexit 1",
		"silent":  "echo run >> " + count,
		"unknown": "echo run >> " + count + "\necho no version here",
	} {
		script := filepath.Join(dir, name)
		if err := os.WriteFile(script, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		_ = os.Remove(count)
		if got := execUnixAgentVersion(context.Background(), script, dir, ""); got != "" {
			t.Fatalf("%s: version = %q", name, got)
		}
		data, _ := os.ReadFile(count)
		want := map[string]int{"broken": unixAgentVersionMaxAttempts, "silent": unixAgentVersionMaxAttempts, "unknown": 1}[name]
		if runs := len(data) / len("run\n"); runs != want {
			t.Fatalf("%s: ran %d times, want %d", name, runs, want)
		}
	}
}
