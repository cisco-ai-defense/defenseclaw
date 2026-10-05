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

package openshell_test

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// The lines harnesses print when localhost does not resolve in a MicroVM
// are recognised; other name failures and mentions of localhost are not.
func TestLocalhostLookupFailure(t *testing.T) {
	for _, tc := range []struct {
		output, want string
	}{
		// Antigravity CLI 1.2.12 in an OpenShell 0.1.1 MicroVM.
		{"banner\nFailed to start: listen tcp: lookup localhost on 127.0.0.53:53: server misbehaving\n",
			"Failed to start: listen tcp: lookup localhost on 127.0.0.53:53: server misbehaving"},
		{"dial tcp: lookup localhost: no such host", "dial tcp: lookup localhost: no such host"},
		{"lookup app.localhost on 127.0.0.53:53: server misbehaving", "lookup app.localhost on 127.0.0.53:53: server misbehaving"},
		{"Error: getaddrinfo EAI_AGAIN localhost\n    at GetAddrInfoReqWrap", "Error: getaddrinfo EAI_AGAIN localhost"},
		{"  getaddrinfo ENOTFOUND localhost  ", "getaddrinfo ENOTFOUND localhost"},
		{"curl: (6) Could not resolve host: localhost", "curl: (6) Could not resolve host: localhost"},
		{"ok\nno trouble here", ""},
		{"lookup api.example.com on 127.0.0.53:53: server misbehaving", ""},
		{"listening on http://localhost:3000", ""},
		{"getaddrinfo EAI_AGAIN localhostile.example", ""},
	} {
		got, ok := openshell.LocalhostLookupFailure(tc.output)
		if got != tc.want || ok != (tc.want != "") {
			t.Errorf("LocalhostLookupFailure(%q) = %q, %v; want %q", tc.output, got, ok, tc.want)
		}
	}
	long := "lookup localhost on 127.0.0.53:53: " + strings.Repeat("é", 300)
	if got, ok := openshell.LocalhostLookupFailure(long); !ok || len(got) > 250 || !strings.HasSuffix(got, "…") || !strings.HasPrefix(got, "lookup localhost") {
		t.Fatalf("long line = %q (%d bytes), %v", got, len(got), ok)
	}
}
