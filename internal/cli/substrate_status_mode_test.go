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
	"net/http"
	"strings"
	"testing"
)

// GAP-0388: status NAME of an unattended run says what its asks do, as the
// profile's unattended_asks says: queued for approval, or denied.
func TestSubstrateStatusModeFollowsUnattendedAsks(t *testing.T) {
	for _, tc := range []struct {
		name  string
		actor map[string]any
		want  string
		not   string
	}{
		{"queue", map[string]any{"unattended_asks": "queue", "ask_timeout_seconds": 1800},
			"Mode:      unattended (asks are queued for approval: profile ops has unattended_asks: queue, denied after 30m " +
				"without an answer; answer them with defenseclaw substrate approvals)", "asks are denied"},
		{"deny", map[string]any{"unattended_asks": "deny"},
			"Mode:      unattended (asks are denied: profile ops has unattended_asks: deny)", "queued"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := map[string]any{"atespace": "eng-web", "name": "nightly-3", "profile": "ops", "connector": "claudecode", "unattended": true}
			for k, v := range tc.actor {
				a[k] = v
			}
			useFakeAdmin(t, &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){
				"GET actors": jsonReply(map[string]any{"actors": []map[string]any{a}}),
			}})
			out, _, err := runSubstrate(t, newSubstrateStatusCmd(), "nightly-3")
			if err != nil || !strings.Contains(out, tc.want) || strings.Contains(out, tc.not) {
				t.Fatalf("status = %q, %v; want %q", out, err, tc.want)
			}
		})
	}
}
