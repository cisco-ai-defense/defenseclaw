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

package cli

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
	"github.com/defenseclaw/defenseclaw/internal/substrate/revocation"
)

type b51NopSource struct{}

func (b51NopSource) Put(context.Context, revocation.Entry) (revocation.Entry, error) {
	return revocation.Entry{}, nil
}

func (b51NopSource) Since(context.Context, string, uint64) (revocation.Delta, error) {
	return revocation.Delta{}, nil
}

// syncLoops counts the running revocation pull loops (other tests'
// goroutines do not count).
func syncLoops() int {
	buf := make([]byte, 1<<20)
	return strings.Count(string(buf[:runtime.Stack(buf, true)]), "revocation.(*Snapshot).Sync(")
}

// B5.1 (M-PERF-1): revocation off starts no pull goroutine and serves no
// leader methods; on starts exactly one, which ends with its context.
func TestRevocationOffNoSyncGoroutine(t *testing.T) {
	off := false
	before := syncLoops()
	w := newSubstrateRevocation(context.Background(), config.SubstrateRevocationConfig{Enabled: &off}, b51NopSource{})
	if w.snap != nil || w.src != nil || w.streams != nil {
		t.Fatalf("off: wiring %+v, want all nil", w)
	}
	time.Sleep(20 * time.Millisecond)
	if n := syncLoops(); n > before {
		t.Fatalf("off: %d goroutines, was %d", n, before)
	}
	ctx, cancel := context.WithCancel(context.Background())
	w = newSubstrateRevocation(ctx, config.SubstrateRevocationConfig{}, b51NopSource{})
	if w.snap == nil || w.streams == nil || w.snap.MaxStale != time.Minute {
		t.Fatalf("on: wiring %+v", w)
	}
	time.Sleep(20 * time.Millisecond)
	if n := syncLoops(); n != before+1 {
		t.Fatalf("on: %d goroutines, want %d", n, before+1)
	}
	cancel()
	deadline := time.Now().Add(2 * time.Second)
	for syncLoops() > before && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if n := syncLoops(); n > before {
		t.Fatalf("after cancel: %d goroutines, was %d", n, before)
	}

	srv := &leader.Server{IsLeader: func() bool { return true }}
	c := &config.Config{}
	c.Substrate.Identity.Revocation.Enabled = &off
	offDir := t.TempDir()
	if err := serveSubstrateRevocations(srv, c, offDir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(offDir, "revocations")); !os.IsNotExist(err) {
		t.Fatalf("off: the leader opened a store: %v", err)
	}
	dir := t.TempDir()
	c.Substrate.Identity.Revocation.Enabled = nil
	if err := serveSubstrateRevocations(srv, c, dir); err != nil {
		t.Fatal(err)
	}
	if _, err := revocation.OpenFileStore(dir + "/revocations"); err != nil {
		t.Fatalf("on: leader store not created: %v", err)
	}
}
