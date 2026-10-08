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

//go:build !windows

package manager

import (
	"context"
	"fmt"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/sandboxfeed"
)

// GAP-0098 (TS r5): after a restart of the feed every sandbox that was
// already running went back to hook calls in full (jq, id, curl rows), and
// nothing said so. The tree counts the runs of the hook script the feed
// shows in full since it last folded one; ps prints the count and the fix.
func TestUnfoldedHookCallsAreCounted(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the kernel feed is Linux only")
	}
	var sample atomic.Pointer[string]
	e, b, id := kernelBox(t, "unfoldbox", &sample)
	e.m.kfeed.up(sandboxfeed.Header{Protocol: sandboxfeed.ProtocolVersion, Build: "1.2.3", Tetragon: sandboxfeed.TetragonConnected})
	ctx := context.Background()
	unfolded := func() int64 {
		t.Helper()
		list, err := e.m.Processes(ctx, "unfoldbox")
		if err != nil || list.Kernel == nil {
			t.Fatalf("processes = %+v, %v", list, err)
		}
		return list.Kernel.UnfoldedHookCalls
	}
	at := time.Now().Add(-time.Minute)
	for i := range 3 {
		name := fmt.Sprintf("full-%d", i)
		e.m.observeKernelFrame(ctx, b, execFrame(id, name, "", 9600+i, 0, sandboxfeed.ClaudeHookScript,
			sandboxfeed.ClaudeHookScript+" -p "+sandboxfeed.ClaudeHookScript, at.Add(time.Duration(i)*time.Second)))
		e.m.observeKernelFrame(ctx, b, execFrame(id, name+"-jq", name, 9700+i, 0, "/usr/bin/jq", "/usr/bin/jq -r .x", at.Add(time.Duration(i)*time.Second)))
	}
	if n := unfolded(); n != 3 {
		t.Fatalf("unfolded = %d, want 3", n)
	}
	// After a stop and start the feed folds the calls again.
	folded := execFrame(id, "folded", "", 9800, 0, sandboxfeed.ClaudeHookScript, sandboxfeed.ClaudeHookScript, at.Add(10*time.Second))
	folded.Hook = true
	e.m.observeKernelFrame(ctx, b, folded)
	if n := unfolded(); n != 0 {
		t.Fatalf("unfolded after a folded call = %d", n)
	}
}
