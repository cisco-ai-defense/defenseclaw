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

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// GAP-1509: a re-check of a recreated group that finishes after the hook
// stopped waiting for it is used by the next request, not a minute later.
func TestSlowGroupRecheckIsUsedByTheNextRequest(t *testing.T) {
	var current atomic.Value
	current.Store("S-1-5-21-860-1-2-1117")
	release := make(chan struct{})
	var slow atomic.Bool
	lookup := func(string) (string, error) {
		if slow.Load() {
			<-release
		}
		return current.Load().(string), nil
	}
	assignments := []config.ProfileAssignment{
		{Profile: "strict", Match: config.ProfileMatch{Groups: []string{`w5-contractors`}}},
	}
	set := &guardrailProfileSet{
		defaultProfile: "default", assignments: assignments, matches: newProfileMatchCache(),
		profiles:  map[string]config.DerivedGuardrailProfile{"default": {}, "strict": {}},
		groupSIDs: newProfileGroupSIDs(assignments, lookup, time.Second),
	}
	subject := &profileSubject{UserID: "S-1-5-21-860-1-2-1001", IDKind: useridentity.KindWindowsSID,
		Groups: []string{"S-1-5-21-860-1-2-1119"}}
	if got := set.match(subject, profileSubjectVerified, "codex", ""); got.Name != "default" {
		t.Fatalf("before the group was recreated: %+v, want default", got)
	}
	// The group is recreated; its re-check stalls past the hook's short wait.
	current.Store("S-1-5-21-860-1-2-1119")
	slow.Store(true)
	set.groupSIDs.nextCheck.Store(0)
	set.groupSIDs.mu.Lock()
	set.groupSIDs.entries[foldKey(`w5-contractors`)].checkAt = time.Time{}
	set.groupSIDs.mu.Unlock()
	if got := set.match(subject, profileSubjectVerified, "codex", ""); got.Name != "default" {
		t.Fatalf("while the re-check stalls: %+v, want default", got)
	}
	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if got := set.match(subject, profileSubjectVerified, "codex", ""); got.Name == "strict" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the finished re-check was not used before the next minute's re-check")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
