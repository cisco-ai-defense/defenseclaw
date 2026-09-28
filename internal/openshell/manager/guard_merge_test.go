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

package manager

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/nestguard"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// One `git init` is one quarantine on status, the feed and the summary: the
// guard's merge of the recreated .git goes on the record's detection
// without a second finding or feed line, and undo is told every
// quarantined name so it removes all of them.
func TestMergedQuarantineIsOneDetection(t *testing.T) {
	e := newEnv(t, nil)
	e.run()
	sb := e.create(sandboxapi.CreateRequest{Name: "gitinit"})
	opts := e.guard.waitActive(t, e.project, true)
	first := nestguard.Detection{Kind: nestguard.KindRepository, Dir: "vendor/tool",
		Quarantined: "vendor/tool/.git.defenseclaw-quarantine-20260928T054445Z", At: time.Now()}
	opts.OnDetect(first)
	merged := first
	merged.Also = []string{first.Quarantined + "-1"}
	opts.OnMerge(merged)

	got, _ := e.m.Get(context.Background(), sb.Name)
	if len(got.NestedRepos) != 1 || !slices.Equal(got.NestedRepos[0].Also, merged.Also) {
		t.Fatalf("nested repos = %+v", got.NestedRepos)
	}
	var lines int
	for _, ev := range e.m.ActivitySince(0, sb.Name) {
		if ev.Reason == sandboxapi.ReasonNestedRepo {
			lines++
		}
	}
	if lines != 1 {
		t.Fatalf("nested-repo feed lines = %d, want 1", lines)
	}

	if _, err := e.m.Undo(context.Background(), sb.Name, sandboxapi.UndoRequest{Stop: true}); err != nil {
		t.Fatal(err)
	}
	e.ws.mu.Lock()
	quarantined := e.ws.lastUndo.Quarantined
	e.ws.mu.Unlock()
	if !slices.Equal(quarantined, []string{first.Quarantined, first.Quarantined + "-1"}) {
		t.Fatalf("undo was told %v", quarantined)
	}
}
