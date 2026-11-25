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

package asks

import "testing"

// B2 2.4: approving a git_push ask is about one push; it never joins the
// actor's approved hosts (OnApprove skips what is not host-wide).
func TestB2GitPushAskIsNotHostWide(t *testing.T) {
	if HostWide(GitPushRule("team/app", "")) {
		t.Fatal("a git_push approval would open the host's egress")
	}
	if !HostWide("ask_hosts:git.example.test") || HostWide("url_rules:x POST") {
		t.Fatal("host-wide rules changed")
	}
}
