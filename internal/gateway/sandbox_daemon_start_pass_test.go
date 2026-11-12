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

//go:build linux || darwin

package gateway

import (
	"context"
	"testing"
	"time"
)

// The fixture's run returns once the daemon's pass at start (a count of the
// running sandboxes under the lifecycle) is over, so a supervision pass the
// test makes next never finds the lifecycle taken and does nothing. On a
// loaded runner that pass can outlast the test's first check, which then
// reported no idle exit (GAP-0864).
func TestSandboxDaemonFixtureRunWaitsOutThePassAtStart(t *testing.T) {
	hold := make(chan struct{})
	f := newSandboxDaemonFixture(t, func(o *SandboxDaemonOptions) {
		o.IdleAfter = time.Millisecond
		o.countRunning = func(context.Context) (int, error) {
			<-hold
			return 0, nil
		}
	})
	time.AfterFunc(150*time.Millisecond, func() { close(hold) })
	f.run(t)
	if !f.d.tryLockLifecycle() {
		t.Fatal("run returned while the daemon's pass at start still held the lifecycle")
	}
	f.d.unlockLifecycle()
	f.d.lastActive.Store(time.Now().Add(-time.Hour).UnixNano())
	if stop, err := f.d.check(context.Background()); !stop || err != nil {
		t.Fatalf("idle exit: %v %v", stop, err)
	}
}
