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
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// GAP-1510: the refusal of MCP servers whose Claude Code state the enrolled
// watcher could not read goes when the watcher is disabled, or no longer
// watches the enrolled users' folders, as at a cold start with that config.
func TestWatcherWithoutEnrolledFoldersClearsTheUnreadableMCPRefusal(t *testing.T) {
	const home = "/home/dcl-std1"
	stale := func() {
		publishMCPStatesUnreadable(map[string]enterprisehooks.ClaudeStateUnreadable{
			mcpUnreadableKey("claudecode", home): {Path: home + "/.claude.json", Reason: "access denied"},
		})
		if _, ok := mcpStateUnreadableFor("claudecode", home); !ok {
			t.Fatal("setup: the refusal was not published")
		}
	}
	t.Cleanup(func() { publishMCPStatesUnreadable(nil) })

	for _, enabled := range []bool{false, true} {
		stale()
		cfg := config.DefaultConfig()
		cfg.Claw.Mode = ""
		cfg.Guardrail.Connector = ""
		cfg.Guardrail.Connectors = nil
		cfg.Gateway.Watcher.Enabled = enabled
		cfg.Gateway.Watcher.Skill.Enabled = false
		cfg.Gateway.Watcher.Plugin.Enabled = false
		s := &Sidecar{cfg: cfg, health: NewSidecarHealth()}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := s.runWatcher(ctx); err != nil {
			t.Fatalf("enabled=%v: runWatcher: %v", enabled, err)
		}
		if state, ok := mcpStateUnreadableFor("claudecode", home); ok {
			t.Fatalf("enabled=%v: the watcher kept the stale refusal %+v", enabled, state)
		}
	}
}
