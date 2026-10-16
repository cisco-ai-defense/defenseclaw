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

//go:build linux || darwin

package gateway

import (
	"context"
	"slices"
	"testing"
	"time"
)

// #1204: `sandbox connect` of a stopped MicroVM starts it under its
// registration, which Start reports running first. The MicroVM is listed
// stopped until it is up, and a policy poll in between reported it stopped,
// so the agent's first prompt was refused with a 403. While a Start is
// starting a sandbox, the poll reports it running.
func TestSandboxDaemonPollReportsAStartingSandboxRunning(t *testing.T) {
	f := newSandboxDaemonFixture(t)
	if err := f.d.regs.put(daemonRegistration{ID: "reg-1", Sandbox: "dc-a", UpdatedAt: time.Now(), Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	f.d.starting.Store("dc-a", struct{}{})
	f.d.pollOnce(context.Background())
	if got := f.relay.reported(); !slices.Equal(got, []string{"reg-1=running"}) {
		t.Fatalf("reports while starting = %v", got)
	}
	f.d.starting.Delete("dc-a")
	f.d.pollOnce(context.Background())
	if got := f.relay.reported(); !slices.Equal(got, []string{"reg-1=running", "reg-1=stopped"}) {
		t.Fatalf("reports after the start = %v", got)
	}
}
