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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// #1199: after a regroup re-matched a registration, policy/current gave the
// new digest but not the profile it came with, and the daemon kept the
// profile the sandbox was created under: status and the refusals named the
// old profile next to the new digest. The poll's answer carries the
// profile, and the daemon's record takes it (and keeps it across a
// restart).
func TestDaemonRegistrationTakesTheRematchedProfile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registrations.json")
	regs, err := loadDaemonRegistrations(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := regs.put(daemonRegistration{ID: "reg-1", Sandbox: "dc-a", Profile: "engineering", Digest: "sha256:old",
		UpdatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if !regs.applyLive("dc-a", sandboxrelay.CurrentPolicy{V: 1, Digest: "sha256:new", Profile: "contractors"}) {
		t.Fatal("the re-matched answer changed nothing")
	}
	if r, _ := regs.get("dc-a"); r.Profile != "contractors" || r.Digest != "sha256:new" {
		t.Fatalf("registration after the regroup = %+v", r)
	}
	// An answer without a profile (an older gateway) keeps the one it had.
	regs.applyLive("dc-a", sandboxrelay.CurrentPolicy{V: 1, Digest: "sha256:new"})
	reloaded, err := loadDaemonRegistrations(path)
	if err != nil {
		t.Fatal(err)
	}
	if r, _ := reloaded.get("dc-a"); r.Profile != "contractors" {
		t.Fatalf("after a restart = %+v", r)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}
