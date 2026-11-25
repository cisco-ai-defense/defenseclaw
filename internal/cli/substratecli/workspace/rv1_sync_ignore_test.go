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

//go:build unix

package workspace

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// RV1 P3-4: sync neither watches nor batches what git ignores: a build
// writing into build/ starts no batch, and build/ holds no watch.
func TestSyncLeavesGitIgnoredOut(t *testing.T) {
	o, sb, _ := copyInActor(t)
	write(t, o.project, "build/out/app.bin", "bin\n", 0o644)
	ev := make(chan string, 16)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := startSync(ctx, SyncOptions{Push: pushOpts(o, sb), Events: ev, Label: "agent-1"})
	waitFor(t, "the start", func() bool { return strings.Contains(r.text(), "Saved restore point") })
	write(t, o.project, "build/out/app.bin", "bin2\n", 0o644)
	ev <- filepath.Join(o.project, "build", "out", "app.bin")
	ev <- filepath.Join(o.project, "debug.log")
	time.Sleep(700 * time.Millisecond)
	if n := pushes(t, o); n != 0 {
		t.Fatalf("an ignored path started %d batch(es):\n%s", n, r.text())
	}
	cancel()
	<-r.done

	tw, err := newTreeWatcher(o.project, newIgnoreCache(context.Background(), o.project, true))
	if err != nil {
		t.Fatal(err)
	}
	defer tw.close()
	for _, w := range tw.w.WatchList() {
		if rel, _ := filepath.Rel(o.project, w); strings.HasPrefix(filepath.ToSlash(rel), "build") {
			t.Fatalf("watches the ignored %s", rel)
		}
	}
}
