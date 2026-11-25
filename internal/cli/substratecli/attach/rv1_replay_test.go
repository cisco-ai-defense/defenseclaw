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

package attach

import (
	"strings"
	"testing"
	"time"
)

// RV1 P3-1: after the actor restarted, the relay greets a resumed input
// with no received count (a fresh session); the keys typed for the old
// prompt are counted, never replayed into the new agent.
func TestReplayNotIntoAFreshSession(t *testing.T) {
	r, s, o := suspendRig(t)
	o.KeyReplay = KeyReplayOn
	run := r.start(o)
	waitFor(t, "screen 1", func() bool { return strings.Contains(r.out.String(), "screen:1") })
	s.down.Store(true)
	r.typ("DROP\r")
	waitFor(t, "reconnecting line", func() bool { return strings.Contains(r.errb.String(), "reconnecting") })
	r.typ("blind")
	waitFor(t, "outage count", func() bool { return strings.Contains(r.errb.String(), "5 typed character(s) held") })
	s.mu.Lock()
	s.received = map[string]int64{} // the actor restarted
	s.mu.Unlock()
	s.down.Store(false)
	waitFor(t, "screen 2", func() bool { return strings.Contains(r.out.String(), "screen:2") })
	time.Sleep(100 * time.Millisecond)
	r.typ("\x1d")
	r.wait(run)
	if strings.Contains(relayInputs(r), "blind") || strings.Contains(r.errb.String(), "typed while disconnected") {
		t.Fatalf("keys replayed into a fresh session: inputs %q, stderr %q", relayInputs(r), r.errb.String())
	}
}

// RV1 P2-2: the relay counts more than this launcher did (a chunk reported
// unsent arrived; its reply was lost): those bytes are not replayed.
func TestReplayDropsUnsentBytesTheRelayReceived(t *testing.T) {
	now := time.Unix(1000, 0)
	a := &attacher{}
	a.outage.addUnsent([]byte("git push --force\r"), now)
	a.outage.addTyped([]byte("ls\r"), now)
	got := int64(100 + len("git push --force\r"))
	a.resumeHello("in-1", 100, &got)
	if b, n := a.outage.take(now); string(b) != "ls\r" || n != 3 {
		t.Fatalf("take = %q, %d; want only the keys typed during the outage", b, n)
	}
	// More arrived than is kept unsent: nothing lines up, nothing replays.
	a.outage.addUnsent([]byte("ab"), now)
	got = 105
	a.resumeHello("in-1", 100, &got)
	if b, _ := a.outage.take(now); b != nil {
		t.Fatalf("take = %q, want nothing", b)
	}
	// Fewer received: the rest may have reached the agent (counted, not replayed).
	got = 90
	a.resumeHello("in-1", 100, &got)
	if a.maybe.Load() != 10 {
		t.Fatalf("maybe = %d", a.maybe.Load())
	}
	// A fresh session (no count) spoils what is kept.
	a.outage.addTyped([]byte("x"), now)
	a.resumeHello("in-1", 100, nil)
	if b, n := a.outage.take(now); b != nil || n != 1 {
		t.Fatalf("fresh session: take = %q, %d", b, n)
	}
}
