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

//go:build windows

package cli

import (
	"os"
	"testing"
	"time"
)

// reapCLIProbe kills the probe when the test ends and waits for it, whatever
// d.Stop managed (GAP-1056).
func reapCLIProbe(t *testing.T, pid int) {
	t.Helper()
	if pid <= 0 {
		return
	}
	t.Cleanup(func() {
		p, err := os.FindProcess(pid)
		if err != nil {
			return
		}
		defer p.Release() //nolint:errcheck // closes the handle.
		_ = p.Kill()
		done := make(chan struct{})
		go func() { _, _ = p.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
		}
	})
}
