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

package gateway

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// fireOpenClawInstallPolicyRetryNow fires the armed retry timer at once.
func fireOpenClawInstallPolicyRetryNow(t *testing.T) {
	t.Helper()
	openClawInstallPolicyRetryTimerMu.Lock()
	defer openClawInstallPolicyRetryTimerMu.Unlock()
	if openClawInstallPolicyRetryTimer == nil {
		t.Fatal("no retry is armed")
	}
	openClawInstallPolicyRetryTimer.Reset(0)
}

// GAP-1235: the cache reads 2026.8.34 and the watcher's refresh fails (the
// openclaw.json lock is busy), so a retry is armed. While it waits, the user
// reinstalls 2026.11.5 (the watcher skips its look: a retry is armed), then
// a discovery from a shell without openclaw caches "". The retry judges under
// 2026.11.5, the last version the watcher parsed. Before, it judged under the
// 2026.8.34 captured when it was scheduled and removed the registered block.
func TestOpenClawInstallPolicyRetryJudgesUnderTheLastVersionTheWatcherSaw(t *testing.T) {
	resetOpenClawInstallPolicyRetryState(t)
	s, dataDir, _ := registeredOpenClawInstallPolicy(t, "2026.11.3")
	var calls atomic.Int32
	retried := make(chan string, 8)
	openClawInstallPolicyRetryDelays = []time.Duration{time.Hour}
	openClawInstallPolicyRefresher = func(opts connector.SetupOpts) (string, error) {
		if calls.Add(1) == 1 {
			return "", errors.New("lock_busy")
		}
		retried <- opts.AgentVersion
		return "registered", nil
	}
	openClawInstallPolicyVersionPoll = 2 * time.Millisecond
	stop := s.startOpenClawInstallPolicyWatch(context.Background())
	defer stop()

	writeOpenClawDiscoveryVersion(t, dataDir, "2026.8.34")
	deadline := time.Now().Add(5 * time.Second)
	for !(calls.Load() == 1 && openClawInstallPolicyRetrying.Load()) && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if calls.Load() != 1 || !openClawInstallPolicyRetrying.Load() {
		t.Fatalf("the failed refresh under 2026.8.34 did not arm a retry (calls=%d)", calls.Load())
	}
	writeOpenClawDiscoveryVersion(t, dataDir, "2026.11.5")
	// The watcher looks every 2 ms; give it many looks at 2026.11.5 (a
	// black-box wait, so the test also runs against the code before the fix).
	time.Sleep(500 * time.Millisecond)
	writeOpenClawDiscoveryVersion(t, dataDir, "")
	fireOpenClawInstallPolicyRetryNow(t)
	select {
	case got := <-retried:
		if got != "2026.11.5" {
			t.Fatalf("the retry judged under OpenClaw %q, want 2026.11.5 (the last version the watcher parsed)", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the retry did not run")
	}
}
