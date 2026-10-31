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

package sandboxapi

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strings"
	"testing"
)

// #1202 part d (GAP-2437): a request that reached no daemon is worded as a
// cause in plain words. The daemon's internal URL and Go's transport text
// ("Get http://sandbox-daemon/api/v1/sandbox/status: context deadline
// exceeded") never reach the person.
func TestUnreachableErrorIsInPlainWords(t *testing.T) {
	const daemonURL = "http://sandbox-daemon/api/v1/sandbox/status"
	for _, tc := range []struct {
		name string
		raw  error
		want string
	}{
		{"deadline", &url.Error{Op: "Get", URL: daemonURL, Err: context.DeadlineExceeded}, "it did not answer in time"},
		{"refused", &url.Error{Op: "Get", URL: daemonURL, Err: &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connect: connection refused")}},
			"nothing accepted the connection on its port"},
		{"unverified", errors.New(`Get "` + daemonURL + `": the port belongs to another account`),
			"the program on its port could not be proven to be this account's DefenseClaw daemon"},
		{"other", errors.New(`Get "` + daemonURL + `": EOF`), "the connection failed before it answered"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := unreachableError(tc.raw)
			if e.Code != CodeUnavailable || e.Detail != tc.want {
				t.Fatalf("code = %q, detail = %q, want %q", e.Code, e.Detail, tc.want)
			}
			for _, raw := range []string{"http://", "sandbox-daemon", "deadline", "dial", "tcp", "EOF"} {
				if strings.Contains(e.Error(), raw) {
					t.Fatalf("%q shows %q", e.Error(), raw)
				}
			}
		})
	}
}
