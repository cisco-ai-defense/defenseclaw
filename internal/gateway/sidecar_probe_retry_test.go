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
	"fmt"
	"reflect"
	"testing"
	"time"

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

// errSettingsInUse stands for the Windows sharing violation an agent that
// holds its settings file open causes (connector.FileBusyError).
var errSettingsInUse = errors.New("A file cannot be opened because the share access flags are incompatible") //nolint:staticcheck // the Windows sharing-violation text as the system writes it

// busyOnceConnector finds its settings file in use on its first setups.
type busyOnceConnector struct {
	bootStubConnector
	busySetups int
}

func (c *busyOnceConnector) Setup(ctx context.Context, opts connector.SetupOpts) error {
	if c.setupCalls < c.busySetups {
		c.setupCalls++
		return fmt.Errorf("claudecode otel env: %w", errSettingsInUse)
	}
	return c.bootStubConnector.Setup(ctx, opts)
}

// GAP-2524: Claude Code held settings.json open for a moment while the
// upgraded gateway started, the claudecode refresh failed on the sharing
// violation, and the installer rolled the upgrade back. Setup now tries
// again for a bounded time; a file that stays in use still fails the start.
func TestSetupConnectorsIsolated_RetriesSettingsInUse(t *testing.T) {
	busy, budget, delay := connectorSettingsBusy, connectorSettingsBusyBudget, connectorSettingsBusyDelay
	t.Cleanup(func() {
		connectorSettingsBusy, connectorSettingsBusyBudget, connectorSettingsBusyDelay = busy, budget, delay
	})
	connectorSettingsBusy = func(err error) bool { return errors.Is(err, errSettingsInUse) }
	// The three-busy case gets a budget it cannot run out of: under -race
	// one setupOneConnector (rule pack load + compile) can take longer than
	// a short budget, which rolled claudecode back after one retry. It still
	// ends after four setups. Only the stuck case below uses a short budget.
	connectorSettingsBusyBudget, connectorSettingsBusyDelay = 30*time.Second, time.Millisecond

	s := multiBootSidecar(t)
	held := &busyOnceConnector{bootStubConnector: bootStubConnector{stubConnector: stubConnector{name: "claudecode"}}, busySetups: 3}
	peer := &bootStubConnector{stubConnector: stubConnector{name: "codex"}}
	got, err := s.setupConnectorsIsolated(
		context.Background(), []connector.Connector{held, peer},
		"tok", "127.0.0.1:0", "127.0.0.1:0", "master", guardrail.NewRulePackCache(),
	)
	if err != nil {
		t.Fatalf("setupConnectorsIsolated: %v", err)
	}
	if want := []string{"claudecode", "codex"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("survivors=%v, want %v", got, want)
	}
	if held.setupCalls != 4 || held.teardownCalls != 0 {
		t.Fatalf("held connector setupCalls=%d teardownCalls=%d, want 4 and 0", held.setupCalls, held.teardownCalls)
	}

	// A file that stays in use is not waited on forever.
	connectorSettingsBusyBudget = 200 * time.Millisecond
	stuck := &busyOnceConnector{bootStubConnector: bootStubConnector{stubConnector: stubConnector{name: "claudecode"}}, busySetups: 1 << 20}
	started := time.Now()
	got, _ = s.setupConnectorsIsolated(
		context.Background(), []connector.Connector{stuck},
		"tok", "127.0.0.1:0", "127.0.0.1:0", "master", guardrail.NewRulePackCache(),
	)
	if len(got) != 0 || stuck.setupCalls < 2 || time.Since(started) > 5*time.Second {
		t.Fatalf("stuck settings: survivors=%v setupCalls=%d after %s", got, stuck.setupCalls, time.Since(started))
	}

	// Other failures are not retried.
	other := &busyOnceConnector{bootStubConnector: bootStubConnector{stubConnector: stubConnector{name: "claudecode"}}}
	other.setupErr = errors.New("claudecode settings hooks: parse claude settings: bad json")
	_, _ = s.setupConnectorsIsolated(
		context.Background(), []connector.Connector{other},
		"tok", "127.0.0.1:0", "127.0.0.1:0", "master", guardrail.NewRulePackCache(),
	)
	if other.setupCalls != 1 {
		t.Fatalf("a parse failure was set up %d times, want 1", other.setupCalls)
	}
}
