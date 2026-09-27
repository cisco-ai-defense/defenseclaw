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

package workspace

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
)

func TestGitVersionCacheKeepsOnlySuccessfulProbes(t *testing.T) {
	t.Parallel()
	calls := 0
	fail := errors.New("exec: git not found")
	var c gitVersionCache

	// A probe cut short by the caller's context must not stick.
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.get(cancelled, func(ctx context.Context) ([]byte, error) { calls++; return nil, ctx.Err() })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled probe: %v", err)
	}
	// Neither does a missing git (it can be installed while we run).
	if _, err := c.get(bg, func(context.Context) ([]byte, error) { calls++; return nil, fail }); !errors.Is(err, fail) {
		t.Fatalf("missing git: %v", err)
	}
	if _, err := c.get(bg, func(context.Context) ([]byte, error) { calls++; return []byte("hg 6.0\n"), nil }); err == nil {
		t.Fatal("unrecognized output accepted")
	}
	v, err := c.get(bg, func(context.Context) ([]byte, error) { calls++; return []byte("git version 2.43.1\n"), nil })
	if err != nil || v != (gitVersion{2, 43, 1}) {
		t.Fatalf("version = %v, %v", v, err)
	}
	// A success is kept: later callers, cancelled or not, reuse it.
	v, err = c.get(cancelled, func(context.Context) ([]byte, error) { calls++; return nil, fail })
	if err != nil || v != (gitVersion{2, 43, 1}) || calls != 4 {
		t.Fatalf("cached version = %v, %v after %d probes", v, err, calls)
	}
}

func TestHostGitVersionAfterCancelledCaller(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	t.Parallel()
	var c gitVersionCache
	probe := func(ctx context.Context) ([]byte, error) { return gitCmd{dir: os.TempDir()}.strict(ctx, "version") }
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.get(cancelled, probe); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled probe: %v", err)
	}
	if v, err := c.get(bg, probe); err != nil || !v.atLeast(minGitMajor, minGitMinor) {
		t.Fatalf("git unusable after a cancelled first probe: %v, %v", v, err)
	}
}
