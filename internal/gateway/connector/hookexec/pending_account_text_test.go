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

// GAP-1026: a Windows standalone account the machine policy registers but that
// has no runtime yet is blocked, and the refusal of every machine-hook agent
// says so and what ends it; the unregistered account and Secure Client keep
// their text.
func TestPendingAccountRefusalSaysTheAgentIsBlockedUntilSignIn(t *testing.T) {
	events := map[string]string{"claudecode": "PreToolUse", "codex": "PreToolUse", "cursor": "beforeShellExecution"}
	refusal := func(connector, reason string, secureClient bool) (int, string) {
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
			SecureClient:             secureClient,
			ManagedRuntimeFailure:    reason,
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
	for connector := range events {
		code, text := refusal(connector, managedEnrollmentPendingReason, false)
		for _, want := range []string{
			"this account is not enrolled; blocked until you sign in",
			"A disconnected or signed-out account stays blocked until it signs in or reconnects",
			"once you have signed in and the agent is installed",
		} {
			if !strings.Contains(text, want) {
				t.Errorf("%s pending refusal lacks %q: %q", connector, want, text)
			}
		}
		if code == 0 && !strings.Contains(text, `"deny"`) && !strings.Contains(text, `"block"`) && !strings.Contains(text, `"permission":"deny"`) {
			t.Errorf("%s pending account was not blocked: code %d %q", connector, code, text)
		}
		if _, other := refusal(connector, managedSIDUnregisteredReason, false); strings.Contains(other, "stays blocked until it signs in") {
			t.Errorf("%s: the unregistered account took the pending text: %q", connector, other)
		}
	}
	// Secure Client keeps the explanation it had.
	if _, text := refusal("claudecode", managedEnrollmentPendingReason, true); strings.Contains(text, "stays blocked until it signs in") {
		t.Errorf("Secure Client took the standalone pending text: %q", text)
	}
}
