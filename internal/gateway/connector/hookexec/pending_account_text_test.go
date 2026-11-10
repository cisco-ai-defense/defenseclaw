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

package hookexec

import (
	"bytes"
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-1026: a Windows standalone account the guardian enrolled before and that
// is pending now (ManagedEnrolledPending) is told its agent is blocked until it
// signs in, in every machine-hook agent. The line is between that account and
// one that was never enrolled: the second keeps the enrollment wait text and,
// with the gateway service stopped, the service-not-running text of GAP-1010.
// The unregistered account and Secure Client keep their text.
func TestPendingAccountRefusalSaysTheAgentIsBlockedUntilSignIn(t *testing.T) {
	events := map[string]string{"claudecode": "PreToolUse", "codex": "PreToolUse", "cursor": "beforeShellExecution"}
	type cell struct {
		reason       string
		enrolled     bool
		stopped      bool
		secureClient bool
	}
	refusal := func(t *testing.T, connector string, c cell) (int, string) {
		t.Helper()
		previous := managedGatewayServiceStopped
		managedGatewayServiceStopped = func(service string) bool { return c.stopped && service == "DefenseClawGateway" }
		t.Cleanup(func() { managedGatewayServiceStopped = previous })
		var out, errb bytes.Buffer
		home := t.TempDir()
		rt := ok(`{"action":"allow"}`)
		code := Run(context.Background(), Options{
			Connector:                connector,
			Event:                    events[connector],
			APIAddr:                  "127.0.0.1:1",
			Home:                     home,
			HookDir:                  filepath.Join(home, "hooks"),
			FailMode:                 "closed",
			StrictAvailability:       true,
			ManagedEnterprise:        true,
			SecureClient:             c.secureClient,
			ManagedRuntimeFailure:    c.reason,
			ManagedEnrolledPending:   c.enrolled,
			ExplainUnenrolledAccount: true,
			Stdin:                    strings.NewReader("{}"),
			Stdout:                   &out,
			Stderr:                   &errb,
			HTTPClient:               &http.Client{Transport: rt},
		})
		if rt.requests != 0 {
			t.Fatalf("%s: a refusal must not contact the gateway", connector)
		}
		return code, out.String() + errb.String()
	}
	const blocked = "this account is not enrolled; blocked until you sign in"
	for connector := range events {
		t.Run(connector, func(t *testing.T) {
			code, text := refusal(t, connector, cell{reason: managedEnrollmentPendingReason, enrolled: true})
			for _, want := range []string{
				blocked,
				"A disconnected or signed-out account stays blocked until it signs in or reconnects",
				"once you have signed in and the agent is installed",
			} {
				if !strings.Contains(text, want) {
					t.Errorf("enrolled+pending refusal lacks %q: %q", want, text)
				}
			}
			if code == 0 && !strings.Contains(text, `"deny"`) && !strings.Contains(text, `"block"`) && !strings.Contains(text, `"permission":"deny"`) {
				t.Errorf("an enrolled+pending account was not blocked: code %d %q", code, text)
			}
			// A never-enrolled account, the gateway service running: the enrollment wait text.
			_, never := refusal(t, connector, cell{reason: managedEnrollmentPendingReason})
			if strings.Contains(never, "blocked until you sign in") || !strings.Contains(never, "not enrolled yet") {
				t.Errorf("a never-enrolled account: %q", never)
			}
			// The gateway service stopped: the service-not-running text, for both, never the blocked text.
			for _, enrolled := range []bool{false, true} {
				_, stopped := refusal(t, connector, cell{reason: managedEnrollmentPendingReason, enrolled: enrolled, stopped: true})
				if strings.Contains(stopped, "blocked until you sign in") || !strings.Contains(stopped, "service is not running") {
					t.Errorf("enrolled=%t, service stopped: %q", enrolled, stopped)
				}
			}
			// The unregistered account never takes the pending text, even with the flag.
			if _, other := refusal(t, connector, cell{reason: managedSIDUnregisteredReason, enrolled: true}); strings.Contains(other, "blocked until you sign in") {
				t.Errorf("the unregistered account took the pending text: %q", other)
			}
			// Secure Client keeps the explanation it had.
			if _, sc := refusal(t, connector, cell{reason: managedEnrollmentPendingReason, enrolled: true, secureClient: true}); strings.Contains(sc, "blocked until you sign in") {
				t.Errorf("Secure Client took the standalone pending text: %q", sc)
			}
		})
	}
}
