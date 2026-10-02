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

package connector

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// GAP-1587: a Hermes version probe that runs out of time is marked as a slow
// probe, so a gateway start keeps the existing hooks instead of removing them.
func TestHermesVersionProbeTimeoutIsMarkedSlow(t *testing.T) {
	if hermesVersionProbeTimeout < 30*time.Second {
		t.Fatalf("hermesVersionProbeTimeout = %s, want at least 30s for a busy Windows host", hermesVersionProbeTimeout)
	}
	script := filepath.Join(t.TempDir(), "hermes")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexec sleep 5\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	previous := hermesVersionProbeTimeout
	hermesVersionProbeTimeout = 50 * time.Millisecond
	t.Cleanup(func() { hermesVersionProbeTimeout = previous })

	_, err := probeHermesAgentVersion(context.Background(), script)
	if !errors.Is(err, ErrAgentVersionProbeTimeout) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("probeHermesAgentVersion() error = %v, want a slow-probe timeout", err)
	}
}
