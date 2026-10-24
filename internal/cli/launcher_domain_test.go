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

package cli

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// TestLauncherStartsTheAgentInTheDomainItIsLoadedIn (GAP-0863): a fresh
// AD account's first GUI sign-in left the sandbox and OpenShell jobs loaded
// in its background domain (user/<uid>). The launcher, in the GUI Terminal,
// bootstrapped them into gui/<uid>, which launchd refuses for a label the
// account already has ("Bootstrap failed: 5: Input/output error"), so no
// sandbox command could start the daemon. It now starts the job in the
// domain that has it, and bootstraps nothing.
func TestLauncherStartsTheAgentInTheDomainItIsLoadedIn(t *testing.T) {
	const idle = "state = not running\nruns = 0\nlast exit code = (never exited)\n"
	listed := "user/501 = {\n\tservices = {\n\t\t0\t-\t" + launcherAgentLabel + "\n\t\t0\t-\t" + launcherGatewayLabel + "\n\t}\n}\n"
	var calls []string
	old := launcherRun
	launcherRun = func(_ context.Context, name string, args ...string) (string, error) {
		line := strings.Join(args, " ")
		calls = append(calls, line)
		switch {
		case line == "print gui/501":
			return "gui/501 = {\n\tservices = {\n\t}\n}\n", nil
		case line == "print user/501":
			return listed, nil
		case line == "print user/501/"+launcherAgentLabel, line == "print user/501/"+launcherGatewayLabel:
			return idle, nil
		case strings.HasPrefix(line, "print gui/501/"):
			return "Could not find service", errors.New("exit status 113")
		case strings.HasPrefix(line, "bootstrap gui/501 "):
			return "Bootstrap failed: 5: Input/output error", errors.New("exit status 5")
		}
		return "", nil
	}
	t.Cleanup(func() { launcherRun = old })
	if err := launcherStartDaemon(context.Background(), "darwin", 501); err != nil {
		t.Fatalf("start: %v (calls %q)", err, calls)
	}
	want := []string{"print gui/501", "print user/501", "print user/501/" + launcherAgentLabel, "print user/501/" + launcherGatewayLabel,
		"kickstart user/501/" + launcherAgentLabel}
	if strings.Join(calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("launchctl calls:\n%s\nwant:\n%s", strings.Join(calls, "\n"), strings.Join(want, "\n"))
	}
}
