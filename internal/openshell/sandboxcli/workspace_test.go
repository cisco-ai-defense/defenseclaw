// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package sandboxcli

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

// overlappingPulls is a copy whose pull takes a moment and counts how many
// run at once.
type overlappingPulls struct {
	*fakeCopy
	mu      sync.Mutex
	in, max int
}

func (o *overlappingPulls) Pull(context.Context, workspace.PullOptions) (*workspace.PullResult, error) {
	o.mu.Lock()
	o.in++
	o.max = max(o.max, o.in)
	o.mu.Unlock()
	time.Sleep(150 * time.Millisecond)
	o.mu.Lock()
	o.in--
	o.mu.Unlock()
	return &workspace.PullResult{}, nil
}

// Two pulls of one sandbox (a session's end and a `sandbox pull` from
// another terminal) run one after the other: at once, both ran git in the
// sandbox copy and the second failed on git's index lock (r105 X1 GAP-0756
// verify observation).
func TestPullsOfOneSandboxDoNotOverlap(t *testing.T) {
	ta := newTestApp(t, "")
	pulls := &overlappingPulls{fakeCopy: ta.copy}
	ta.Workspace = pulls
	api, err := ta.api()
	if err != nil {
		t.Fatal(err)
	}
	sb := sandboxapi.Sandbox{Name: "copybox"}
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			local := sb
			if _, err := ta.pull(bg, api, ta.cli("gw"), &local, false); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if pulls.max != 1 {
		t.Fatalf("%d pulls of one sandbox ran at once, want 1", pulls.max)
	}
}
