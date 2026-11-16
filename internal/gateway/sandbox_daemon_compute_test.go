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
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// TestSandboxDaemonKeepsTheGatewayForComputeThatMayStillRun: the daemon
// stops the account's OpenShell gateway, or exits for a pending restart
// (the managed pin migration's, for one), only once no sandbox may hold
// compute: only OpenShell's own state releases a MicroVM (stopped,
// deleting, missing, or its VM gone). One that completed or is in any
// other error state counts, its provisioning timed out included: the
// rounds before let it go after two minutes, then on its user's stop,
// which OpenShell does not make for it. A docker sandbox in those phases
// is an exited container.
func TestSandboxDaemonKeepsTheGatewayForComputeThatMayStillRun(t *testing.T) {
	for _, tc := range []struct {
		list []sandboxapi.Sandbox
		want int
	}{
		{[]sandboxapi.Sandbox{{Phase: "ready", Driver: "vm"}, {Phase: "stopped", Driver: "vm"}}, 1},
		{[]sandboxapi.Sandbox{{Phase: "error", Driver: "vm"}}, 1},
		{[]sandboxapi.Sandbox{{Phase: "error", Driver: "docker"}, {Phase: "error"}}, 0},
		{[]sandboxapi.Sandbox{{Phase: "stopping", Driver: "vm"}, {Phase: "creating", Driver: "docker"}}, 2},
		{[]sandboxapi.Sandbox{{Phase: "stopped"}, {Phase: "completed"}, {Phase: "deleting", Driver: "vm"}}, 0},
		// A MicroVM whose workload ended still runs (GAP-0012), with what
		// its workload left running, until OpenShell reports it stopped.
		{[]sandboxapi.Sandbox{{Phase: "completed", Driver: "vm"}}, 1},
		{[]sandboxapi.Sandbox{{Phase: "completed", Driver: "vm"}, {Phase: "error", Driver: "vm"}, {Phase: "completed", Driver: "firecracker"}}, 3},
		{[]sandboxapi.Sandbox{{Phase: "error", Driver: "vm", PhaseReason: "ProcessPollFailed: Bad file descriptor"}}, 1},
		{[]sandboxapi.Sandbox{{Phase: "error", Driver: "vm", PhaseReason: "MainProcessFailed: Canonical main process exited with status 1"}}, 1},
		{[]sandboxapi.Sandbox{{Phase: "error", Driver: "vm", PhaseReason: "ProcessExited: VM process exited with status 1"}}, 0},
		// OpenShell does not report one whose provisioning timed out
		// stopped; a missing one is gone.
		{[]sandboxapi.Sandbox{{Phase: "error", Driver: "vm", PhaseReason: "ProvisioningTimedOut: Provisioning repair window expired after 300 seconds"}, {Phase: "missing", Driver: "vm"}}, 1},
		{[]sandboxapi.Sandbox{{Phase: "unknown", Driver: "docker"}, {Phase: "provisioning"}}, 2},
	} {
		if got := sandboxesHoldingCompute(tc.list); got != tc.want {
			t.Errorf("%+v: %d, want %d", tc.list, got, tc.want)
		}
	}
}
