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
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWaitForWatchdogStartWaitsForOwnedPIDLock(t *testing.T) {
	pidPath := filepath.Join(t.TempDir(), watchdogPIDFile)
	info := watchdogPIDInfo{
		PID:           os.Getpid(),
		StartIdentity: watchdogProcessStartIdentity(os.Getpid()),
	}

	release := make(chan struct{})
	ready := make(chan struct{})
	go func() {
		time.Sleep(25 * time.Millisecond)
		holder, err := acquireWatchdogPIDFile(pidPath, info)
		if err != nil {
			close(ready)
			return
		}
		close(ready)
		<-release
		_ = holder.Close()
	}()

	if err := waitForWatchdogStart(pidPath, info.PID, time.Second, 5*time.Millisecond); err != nil {
		close(release)
		t.Fatalf("waitForWatchdogStart: %v", err)
	}
	<-ready
	close(release)
}

func TestWaitForWatchdogStartRejectsDifferentOwner(t *testing.T) {
	pidPath := filepath.Join(t.TempDir(), watchdogPIDFile)
	info := watchdogPIDInfo{
		PID:           os.Getpid(),
		StartIdentity: watchdogProcessStartIdentity(os.Getpid()),
	}
	holder, err := acquireWatchdogPIDFile(pidPath, info)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()

	if err := waitForWatchdogStart(pidPath, info.PID+1, time.Second, 5*time.Millisecond); err == nil {
		t.Fatal("waitForWatchdogStart accepted an ownership lock held by another PID")
	}
}
