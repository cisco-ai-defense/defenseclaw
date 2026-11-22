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
	"path/filepath"
	"testing"
)

// kiro-cli 3.x can run two engines: the v3 default reads the agent file's
// hooks and ~/.kiro/hooks together, and --v2 (chat.agentEngine=v2) reads the
// agent file alone. Setup on a 3.x banner must therefore register DefenseClaw
// in both files, or a user on the v2 engine is unprotected (GAP-0165: the
// duplicate audit row of the v3 engine is removed in the gateway instead).
func TestKiroSetupOnV3CLIKeepsBothHookSurfaces(t *testing.T) {
	for _, version := range []string{"kiro-cli 3.3.0", "kiro-cli 3.0.0", "kiro-cli 2.27.1", ""} {
		home := t.TempDir()
		KiroHomeOverride = home
		opts := SetupOpts{DataDir: t.TempDir(), APIAddr: "127.0.0.1:18970", AgentVersion: version}
		conn := NewKiroConnector()
		if err := conn.Setup(context.Background(), opts); err != nil {
			t.Fatalf("Setup %q: %v", version, err)
		}
		// The agent file is what kiro-cli --v2 loads: it must carry the hooks.
		assertKiroV2AgentHooks(t, filepath.Join(home, "agents", kiroManagedAgentName+".json"), conn.hookCommand(opts))
		// The hooks file is what the v3 engine loads.
		assertKiroV3Hooks(t, filepath.Join(home, "hooks", kiroManagedHooksName), conn.hookCommandForV3Surface(opts))
		if present, err := conn.ownedHookContractPresent(opts); err != nil || !present {
			t.Fatalf("%q: ownedHookContractPresent = %v, %v, want true", version, present, err)
		}
		KiroHomeOverride = ""
	}
}
