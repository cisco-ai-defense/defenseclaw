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

package notifier

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestCompactionRiskSessionDedupKeepsPrivateIdentityOutOfPayload(t *testing.T) {
	rec := &recorder{}
	cfg := enabledConfig()
	cfg.DedupWindow = time.Minute
	d := NewWithSender(cfg, rec.Send)

	first := NewCompactionRiskEvent("claudecode", "private-session-one")
	second := NewCompactionRiskEvent("claudecode", "private-session-two")
	if first.sessionHash == "" || first.sessionHash == second.sessionHash ||
		strings.Contains(first.sessionHash, "private-session-one") {
		t.Fatalf("compaction session identities were not hashed independently")
	}
	serialized, err := json.Marshal(first)
	if err != nil || string(serialized) != `{"Connector":"claudecode"}` {
		t.Fatalf("compaction event serialized private identity: %s (%v)", serialized, err)
	}

	d.OnCompactionRisk(first)
	d.OnCompactionRisk(first) // one toast per session within the dedup window
	d.OnCompactionRisk(second)
	got := rec.Drain(2, time.Second)
	if len(got) != 2 {
		t.Fatalf("compaction alerts=%d, want one per distinct session", len(got))
	}
	for _, n := range got {
		body := n.Title + n.Subtitle + n.Body
		if strings.Contains(body, "private-session-") || strings.Contains(body, first.sessionHash) ||
			strings.Contains(body, second.sessionHash) {
			t.Fatalf("compaction toast exposed session identity: %+v", n)
		}
	}
}
