// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// GAP-1061: right after install agy's cold --version ran past the probe
// timeout, and the agent stayed unprotected until the next cycle. A timed
// out run is retried at once; the warm run answers.
func TestExecUnixAgentVersionRetriesATimedOutColdStart(t *testing.T) {
	old := unixAgentVersionAttemptTimeout
	// Long enough for a loaded host to start the script both times; the cold
	// run sleeps well past it.
	unixAgentVersionAttemptTimeout = 3 * time.Second
	t.Cleanup(func() { unixAgentVersionAttemptTimeout = old })
	dir := t.TempDir()
	marker := filepath.Join(dir, "warm")
	script := filepath.Join(dir, "agy")
	body := "#!/bin/sh\nif [ ! -e " + marker + " ]; then : > " + marker + "; exec sleep 30; fi\necho 'agy 1.30.2'\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := execUnixAgentVersion(context.Background(), script, dir, ""); got != "1.30.2" {
		t.Fatalf("version = %q, want the retried run's 1.30.2", got)
	}
	// A CLI that answers without a version is not run again.
	quiet := filepath.Join(dir, "devin")
	count := filepath.Join(dir, "count")
	if err := os.WriteFile(quiet, []byte("#!/bin/sh\necho run >> "+count+"\necho no version here\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := execUnixAgentVersion(context.Background(), quiet, dir, ""); got != "" {
		t.Fatalf("version = %q", got)
	}
	if data, _ := os.ReadFile(count); string(data) != "run\n" {
		t.Fatalf("runs = %q, want one", data)
	}
}
