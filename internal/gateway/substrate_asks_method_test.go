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

import "testing"

// TestURLRuleApprovalCoversItsMethodsGAP0177: an url rule approval answers
// the same rule asking for some of the methods the person approved, and
// never a method they did not see (STEER 03:40Z).
func TestURLRuleApprovalCoversItsMethodsGAP0177(t *testing.T) {
	for _, c := range []struct {
		approved, asked string
		want            bool
	}{
		{"url_rules:writes DELETE,POST", "url_rules:writes DELETE,POST", true},
		{"url_rules:writes DELETE,POST", "url_rules:writes POST", true},
		{"url_rules:writes DELETE,POST", "url_rules:writes DELETE", true},
		{"url_rules:writes POST", "url_rules:writes DELETE,POST", false},
		{"url_rules:writes POST", "url_rules:writes DELETE", false},
		{"url_rules:writes DELETE,POST", "url_rules:writes DELETE,PUT", false},
		{"url_rules:writes POST", "url_rules:other POST", false},
		{"url_rules:a b POST", "url_rules:a b POST", true},
		{"url_rules:a b DELETE,POST", "url_rules:a POST", false},
		{"ask_hosts:x.example", "url_rules:writes POST", false},
		{"url_rules:writes POST", "ask_hosts:x.example", false},
		{"url_rules:writes", "url_rules:writes POST", false},
	} {
		if got := urlRuleApprovalCovers(c.approved, c.asked); got != c.want {
			t.Errorf("approval %q answers %q: %v, want %v", c.approved, c.asked, got, c.want)
		}
	}
}
