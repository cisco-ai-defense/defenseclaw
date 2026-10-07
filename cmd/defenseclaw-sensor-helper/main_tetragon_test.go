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

package main

import (
	"bytes"
	"io"
	"log/slog"
	"runtime"
	"strings"
	"testing"
)

// --tetragon-cleanup --check answers without touching anything: supported
// on Linux, not applicable elsewhere.
func TestTetragonCleanupCheck(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	var out bytes.Buffer
	if err := runTetragonCleanup(true, &out, logger); err != nil {
		t.Fatal(err)
	}
	want := "supported"
	if runtime.GOOS != "linux" {
		want = "not applicable"
	}
	if !strings.Contains(out.String(), want) {
		t.Fatalf("--check printed %q", out.String())
	}
}

// TestCleanupFlagsThroughMain runs the helper binary the way preremove.sh
// does: --check alone is refused, and --tetragon-cleanup never opens the
// broker socket.
func TestCleanupFlagsThroughMain(t *testing.T) {
	if _, stderr, code := runHelperBinary(t, "--check"); code == 0 || !strings.Contains(stderr, "--check needs --tetragon-cleanup") {
		t.Fatalf("--check alone exited %d: %q", code, stderr)
	}
	stdout, stderr, code := runHelperBinary(t, "--tetragon-cleanup", "--check")
	switch {
	case runtime.GOOS == "linux":
		if code != 0 || !strings.Contains(stdout, "supported") {
			t.Fatalf("--tetragon-cleanup --check exited %d: %q %q", code, stdout, stderr)
		}
	default:
		if code != 0 || !strings.Contains(stdout, "not applicable") {
			t.Fatalf("--tetragon-cleanup --check exited %d: %q %q", code, stdout, stderr)
		}
	}
}
