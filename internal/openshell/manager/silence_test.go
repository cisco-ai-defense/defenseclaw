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
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell/ocsf"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// TestHookSilenceCountsOnlyTheHarness pins that commands the harness did
// not run (the CLI's probe, a copy-mode pull, the user's `sandbox exec`)
// never raise hook_silence, while the harness's own traffic without a hook
// still does.
func TestHookSilenceCountsOnlyTheHarness(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil)
	var nowMu sync.Mutex
	now := time.Now()
	clock := func() time.Time { nowMu.Lock(); defer nowMu.Unlock(); return now }
	e.m.opts.Now, e.m.now = clock, clock
	e.create(sandboxapi.CreateRequest{Name: "quietbox"})
	e.m.mu.Lock()
	b := e.m.boxes["quietbox"]
	e.m.mu.Unlock()
	nowMu.Lock()
	now = now.Add(15 * time.Minute)
	nowMu.Unlock()
	silence := func() int {
		e.m.checkHookSilence(ctx)
		e.tel.mu.Lock()
		defer e.tel.mu.Unlock()
		n := 0
		for _, f := range e.tel.findings {
			if f.Kind == audit.SandboxFindingHookSilence {
				n++
			}
		}
		return n
	}

	e.m.ocsfEvent(ctx, b, ocsf.Record{Class: ocsf.ClassProcess, Binary: "/usr/bin/git"}, clock())
	e.m.ocsfEvent(ctx, b, ocsf.Record{Class: ocsf.ClassNetwork, Binary: "/usr/bin/curl", Host: "example.org", Port: 443}, clock())
	e.m.ocsfEvent(ctx, b, ocsf.Record{Class: ocsf.ClassNetwork, Binary: "/opt/defenseclaw-harness-evil/bin/claude", Host: "example.org", Port: 443}, clock())
	if n := silence(); n != 0 {
		t.Fatalf("commands outside the harness raised %d hook_silence finding(s)", n)
	}
	e.m.ocsfEvent(ctx, b, ocsf.Record{Class: ocsf.ClassNetwork, Binary: testClaudeBin, Host: "api.anthropic.com", Port: 443}, clock())
	if n := silence(); n != 1 {
		t.Fatalf("the harness active without hooks raised %d hook_silence finding(s), want 1", n)
	}
}
