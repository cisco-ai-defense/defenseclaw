// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// GAP-0945: the gateway puts no time limit on a migration (a long one-time
// migration of a large database must finish, not fail Init on every
// restart); a test binary's store keeps one well under go test's 10 minute
// default; an explicit limit wins.
func TestMigrationLimitGAP0945(t *testing.T) {
	if got := migrationLimit(0, false); got != 0 {
		t.Fatalf("gateway migration limit = %v, want none", got)
	}
	if got := migrationLimit(0, true); got != migrationTestTimeout || got <= 0 || got > 5*time.Minute {
		t.Fatalf("test-store migration limit = %v, want migrationTestTimeout under 5 min", got)
	}
	if got := migrationLimit(7*time.Second, false); got != 7*time.Second {
		t.Fatalf("explicit limit = %v", got)
	}
	// The migration a test binary runs is bounded; Init still works.
	r := startMigration("audit", 1, "x", 0)
	defer r.finish()
	if _, ok := r.ctx.Deadline(); !ok {
		t.Fatal("a test binary's migration has no deadline")
	}
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// GAP-0945: the watchdog of a running migration reports that it still runs
// and how many statements finished, names a report with no new statement,
// and stops when the migration ends.
func TestMigrationWatchdogReportsProgressAndStalls(t *testing.T) {
	r := &migrationRun{done: make(chan struct{})}
	r.ctx, r.cancel = context.WithCancel(context.Background())
	var out lockedBuffer
	stopped := make(chan struct{})
	go func() {
		r.watch(&out, "audit", 42, "purge history", time.Now(), 20*time.Millisecond)
		close(stopped)
	}()
	waitFor := func(what string, ok func(string) bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for !ok(out.String()) {
			if time.Now().After(deadline) {
				t.Fatalf("watchdog never reported %s: %q", what, out.String())
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	r.statements.Add(3)
	waitFor("progress", func(s string) bool {
		return strings.Contains(s, "[audit] migration 42 (purge history) still running after") && strings.Contains(s, "3 statements done: running")
	})
	waitFor("a stall", func(s string) bool {
		return strings.Contains(s, "3 statements done: no statement finished since the last report")
	})
	r.finish()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("the watchdog did not stop with its migration")
	}
}
