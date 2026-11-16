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
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// rel-1-0-2:GAP-0170 (#1202 part a): a gateway unit that fails to start
// reaches the person as a sentence, never the service manager's command line
// or job text: the account-busy notice when another account's gateway holds
// the port, otherwise the unit's state and the doctor hint. The raw text is
// logged.
func TestAccountOpenShellStartFailureIsWordedForThePerson(t *testing.T) {
	fastGatewayWaits(t)
	const job = "Job for defenseclaw-openshell-gateway.service failed because the control process exited with error code."
	for _, tc := range []struct {
		name   string
		holder func(call int) int
		want   string
	}{
		{"another account holds the port", func(call int) int {
			if call == 1 {
				return 0
			}
			return 5002
		}, sandboxAccountBusyMessage},
		{"nothing holds the port", func(int) int { return 0 }, "your OpenShell gateway could not be started; "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newOpenShellRig(t, "linux")
			var mu sync.Mutex
			var logged []string
			r.o.logf = func(format string, args ...any) {
				mu.Lock()
				defer mu.Unlock()
				logged = append(logged, fmt.Sprintf(format, args...))
			}
			r.holder = tc.holder
			r.fail["systemctl --user start "] = job
			_, err := r.o.ensureRunning(context.Background(), 17670, "")
			var apiErr *sandboxapi.Error
			if !errors.As(err, &apiErr) {
				t.Fatalf("start failure = %v, want a sandbox API refusal", err)
			}
			text := apiErr.Message + " " + apiErr.Detail
			if !strings.Contains(text, tc.want) {
				t.Fatalf("refusal = %q, want it to contain %q", text, tc.want)
			}
			if strings.Contains(text, "systemctl") || strings.Contains(text, "Job for") || strings.Contains(text, "the unit is") ||
				strings.Contains(text, "its state is") {
				t.Fatalf("refusal shows the service manager's text: %q", text)
			}
			mu.Lock()
			defer mu.Unlock()
			if !strings.Contains(strings.Join(logged, "\n"), job) {
				t.Fatalf("the raw start failure was not logged: %q", logged)
			}
		})
	}
}
