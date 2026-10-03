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
	"fmt"
	"reflect"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// slowOnceConnector's agent probe runs out of time on its first setups.
type slowOnceConnector struct {
	bootStubConnector
	slowSetups int
}

func (c *slowOnceConnector) Setup(ctx context.Context, opts connector.SetupOpts) error {
	if c.setupCalls < c.slowSetups {
		c.setupCalls++
		return fmt.Errorf("fresh version probe failed: %w", connector.ErrAgentVersionProbeTimeout)
	}
	return c.bootStubConnector.Setup(ctx, opts)
}

// GAP-1714: a restart on a loaded host left Hermes (or Codex) unenforced when
// one probe ran out of time; setup now tries again before skipping it.
func TestSetupConnectorsIsolated_RetriesASlowProbe(t *testing.T) {
	s := multiBootSidecar(t)
	slow := &slowOnceConnector{bootStubConnector: bootStubConnector{stubConnector: stubConnector{name: "claudecode"}}, slowSetups: 1}
	peer := &bootStubConnector{stubConnector: stubConnector{name: "codex"}}
	got, err := s.setupConnectorsIsolated(
		context.Background(), []connector.Connector{slow, peer},
		"tok", "127.0.0.1:0", "127.0.0.1:0", "master", guardrail.NewRulePackCache(),
	)
	if err != nil {
		t.Fatalf("setupConnectorsIsolated: %v", err)
	}
	if want := []string{"claudecode", "codex"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("survivors=%v, want %v", got, want)
	}
	if slow.setupCalls != 2 || slow.teardownCalls != 0 {
		t.Fatalf("slow connector setupCalls=%d teardownCalls=%d, want 2 and 0", slow.setupCalls, slow.teardownCalls)
	}

	// A probe that never answers is tried a bounded number of times.
	stuck := &slowOnceConnector{bootStubConnector: bootStubConnector{stubConnector: stubConnector{name: "claudecode"}}, slowSetups: 99}
	got, err = s.setupConnectorsIsolated(
		context.Background(), []connector.Connector{stuck},
		"tok", "127.0.0.1:0", "127.0.0.1:0", "master", guardrail.NewRulePackCache(),
	)
	if err != nil || len(got) != 0 || stuck.setupCalls != connectorProbeTimeoutAttempts || stuck.teardownCalls != 0 {
		t.Fatalf("stuck probe: survivors=%v err=%v setupCalls=%d teardownCalls=%d", got, err, stuck.setupCalls, stuck.teardownCalls)
	}
	if missing := connectorsNotStarted([]connector.Connector{stuck, peer}, []string{"codex"}); !reflect.DeepEqual(missing, []string{"claudecode"}) {
		t.Fatalf("connectorsNotStarted = %v, want [claudecode]", missing)
	}
}
