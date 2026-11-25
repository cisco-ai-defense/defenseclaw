// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package sandboxcli

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// `sandbox run` for an account whose profile denies sandboxes, while the
// organization has turned sandboxes off: the organization's switch comes
// first, as it does in `sandbox status`, and the daemon is not started
// either way.
func TestRunSaysTheOrganizationTurnedSandboxesOffBeforeAnAccountRefusal(t *testing.T) {
	for _, tc := range []struct {
		name       string
		orgOff     bool
		asked      bool
		want, lack string
	}{
		{"organization off and account denied", true, true, "turned off by your organization", "doesn't allow sandboxes for your account"},
		{"account denied only", false, true, "doesn't allow sandboxes for your account", "turned off by your organization"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withManagedHost(t)
			forbidden := managedExplainFixture()
			forbidden.Allowed = false
			ta := newTestApp(t, "")
			ta.daemon.status.Enabled, ta.daemon.status.Available, ta.daemon.status.Gateway = false, false, nil
			ta.daemon.status.Managed = managedFromJSON(t, orgOffJSON)
			ta.ManagedAccountPolicy = func(context.Context, string) (*sandboxapi.ManagedExplain, error) { return forbidden, nil }
			ta.ManagedOrganizationOff = func(context.Context) bool { return tc.orgOff }
			err := ta.Run(bg, RunOptions{Harness: "claude"})
			if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), tc.lack) {
				t.Fatalf("run = %v, want %q and not %q", err, tc.want, tc.lack)
			}
			ta.daemon.mu.Lock()
			reached := len(ta.daemon.calls)
			ta.daemon.mu.Unlock()
			if reached != 0 {
				t.Fatalf("the refused run reached the sandbox daemon %d times", reached)
			}
		})
	}
}
