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

package gateway

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// P3-3: a read of the git config that stalls (a network home, a stuck mount) is
// cut at its deadline and the session has no git hosts; the hook is not held.
func TestIntentScopeGitReadHasATimeout(t *testing.T) {
	repo := scopeGitTestRepo(t, "git@github.example:org/repo.git")
	cfg := filepath.Join(repo, ".git", "config")
	if err := removeAndMakeFIFO(cfg); err != nil {
		t.Skipf("no named pipe here: %v", err)
	}
	start := time.Now()
	hosts := scopeGitRemoteHostsWithin(repo, 80*time.Millisecond)
	if d := time.Since(start); d > 2*time.Second || len(hosts) != 0 {
		t.Errorf("a stalled read took %s and returned %v", d, hosts)
	}
}

func removeAndMakeFIFO(path string) error {
	if err := syscall.Unlink(path); err != nil {
		return err
	}
	return syscall.Mkfifo(path, 0o644)
}
