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

package connector

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// GAP-1714: a Codex app-server that runs out of time on a busy host is a slow
// probe (keep the hooks, retry), not a setup failure that rolls them back.
func TestCodexPolicyInspectionTimeoutIsASlowProbe(t *testing.T) {
	previous := codexPolicyInspector
	t.Cleanup(func() { codexPolicyInspector = previous })
	codexPolicyInspector = func(context.Context, SetupOpts) (codexEffectivePolicy, error) {
		return codexEffectivePolicy{}, fmt.Errorf("configRequirements/read: timed out waiting for response 1: %w", context.DeadlineExceeded)
	}
	err := enforceCodexUserHookPolicy(context.Background(), SetupOpts{})
	if !errors.Is(err, ErrAgentVersionProbeTimeout) {
		t.Fatalf("timeout = %v, want ErrAgentVersionProbeTimeout", err)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := enforceCodexUserHookPolicy(cancelled, SetupOpts{}); errors.Is(err, ErrAgentVersionProbeTimeout) {
		t.Fatalf("a cancelled start = %v, want no retry marker", err)
	}
	codexPolicyInspector = func(context.Context, SetupOpts) (codexEffectivePolicy, error) {
		return codexEffectivePolicy{}, errors.New("app-server response stream closed")
	}
	if err := enforceCodexUserHookPolicy(context.Background(), SetupOpts{}); err == nil || errors.Is(err, ErrAgentVersionProbeTimeout) {
		t.Fatalf("other failure = %v, want a plain setup failure", err)
	}
}
