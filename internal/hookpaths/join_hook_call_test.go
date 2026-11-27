// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

// TestJoinHookCallIsTheCallBeginWouldFind: a goroutine that found its open
// call joins it without finding it again (GAP-2197), and gets what
// BeginHookCall and CurrentHookCall answer: the same call with nothing to
// end inside it, a call of its own when none was found.
func TestJoinHookCallIsTheCallBeginWouldFind(t *testing.T) {
	if CurrentHookCall().call != nil {
		t.Fatal("test goroutine already runs a hook call")
	}
	outer, endOuter := BeginHookCall()
	if outer.call == nil {
		t.Fatal("BeginHookCall began no call")
	}
	joined, endJoined := JoinHookCall(outer)
	if joined.call != outer.call {
		t.Fatal("JoinHookCall(found) is not the open call")
	}
	if began, endBegan := BeginHookCall(); began.call != outer.call {
		t.Fatal("BeginHookCall inside the call found another call")
	} else {
		endBegan()
	}
	endJoined()
	if CurrentHookCall().call != outer.call {
		t.Fatal("ending a joined call ended the open call")
	}
	if FoundHookCall(outer).call != outer.call || FoundHookCall(Call{}).call != outer.call {
		t.Fatal("FoundHookCall is not the open call")
	}
	read, _ := ActionPrivateKeyReadBoundedIn(outer, "ls", "/", "/home/u", "")
	if read || CurrentHookCall().call != outer.call {
		t.Fatal("a private-key read in the joined call changed the open call")
	}
	endOuter()
	if CurrentHookCall().call != nil {
		t.Fatal("the call is still open after its end")
	}
	// No call found: JoinHookCall begins one and its end ends it, as
	// BeginHookCall does.
	own, endOwn := JoinHookCall(Call{})
	if own.call == nil || CurrentHookCall().call != own.call {
		t.Fatal("JoinHookCall(zero) began no call")
	}
	endOwn()
	if CurrentHookCall().call != nil {
		t.Fatal("JoinHookCall(zero) left its call open")
	}
	if FoundHookCall(Call{}).call != nil {
		t.Fatal("FoundHookCall(zero) found a call outside one")
	}
}
