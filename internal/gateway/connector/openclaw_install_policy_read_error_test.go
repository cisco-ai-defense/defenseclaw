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
	"os"
	"strings"
	"testing"
)

// GAP-1234: only a missing openclaw.json is "not yet". Another error of the
// look at it (on Windows access denied or delete pending while OpenClaw
// rewrites it on its first start; here a path the OS refuses, the same on
// every platform) fails the refresh, so the gateway retries it. Before, it
// returned "not changed" with no error, the gateway took that for a refresh
// that ran, and a downgrade was never re-checked.
func TestOpenClawInstallPolicyRefreshFailsWhenOpenClawJSONCannotBeLookedAt(t *testing.T) {
	configPath, _, opts := unknownVersionFixture(t)
	if state := setupOpenClawInstallPolicy(t, configPath, opts); state != openClawInstallPolicyRegistered {
		t.Fatalf("setup: %q", state)
	}
	broken := opts
	broken.OpenClawConfigPath = configPath + "\x00"
	state, err := NewOpenClawConnector().RefreshInstallPolicy(broken)
	if err == nil {
		t.Fatalf("a refresh that could not look at openclaw.json reported %q and no error: the gateway would not retry it", state)
	}
	if strings.HasPrefix(state, "not changed") {
		t.Fatalf("state %q with error %v", state, err)
	}
	if _, present := installPolicyIn(t, configPath); !present {
		t.Fatal("the registered install policy is gone")
	}
}

// GAP-1234: a record that is there but cannot be read is not "no record".
// Before, the refresh took the registered block for one setup never wrote
// ("setup has not registered the DefenseClaw plugin yet", no error) and
// nothing retried it; now it fails, keeps the block and the record.
func TestOpenClawInstallPolicyRefreshFailsOnAnUnreadableRecord(t *testing.T) {
	configPath, _, opts := unknownVersionFixture(t)
	if state := setupOpenClawInstallPolicy(t, configPath, opts); state != openClawInstallPolicyRegistered {
		t.Fatalf("setup: %q", state)
	}
	recordPath := openClawInstallPolicyRecordPath(opts.DataDir)
	if err := os.Remove(recordPath); err != nil {
		t.Fatal(err)
	}
	// A folder in its place: reading it fails on every platform, and the
	// error is not "does not exist".
	if err := os.Mkdir(recordPath, 0o700); err != nil {
		t.Fatal(err)
	}
	down := opts
	down.AgentVersion = "2026.8.34"
	state, err := NewOpenClawConnector().RefreshInstallPolicy(down)
	if err == nil {
		t.Fatalf("a refresh with an unreadable record reported %q and no error", state)
	}
	if _, present := installPolicyIn(t, configPath); !present {
		t.Fatal("the registered install policy was removed while its record could not be read")
	}
	if info, err := os.Stat(recordPath); err != nil || !info.IsDir() {
		t.Fatalf("the unreadable record was dropped: %v", err)
	}
}
