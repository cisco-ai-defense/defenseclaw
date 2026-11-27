// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

// A kept Call reads what HookCallState and ShareBodyUnreadCauses read for the
// same call, with no call open, in an open call, nested and after its end
// (DET111-PERF-A: the gateway finds its call once per dispatch).
func TestPERFAKeptCallReadsAsTheCallReaders(t *testing.T) {
	same := func(t *testing.T, c Call, where string) {
		t.Helper()
		if got, want := c.State(), HookCallState(); got != want {
			t.Errorf("%s: kept State %+v, HookCallState %+v", where, got, want)
		}
		gb, gl := c.ShareBodyUnreadCauses()
		wb, wl := ShareBodyUnreadCauses()
		if gb != wb || gl != wl {
			t.Errorf("%s: kept causes (%v, %v), ShareBodyUnreadCauses (%v, %v)", where, gb, gl, wb, wl)
		}
	}
	none := CurrentHookCall()
	same(t, none, "no call")
	if none.State().open {
		t.Fatal("no call: the zero Call reads an open call")
	}
	c, end := BeginHookCall()
	if !c.State().open {
		t.Fatal("a begun call does not read open")
	}
	same(t, c, "open call")
	same(t, CurrentHookCall(), "found call")
	nested, endNested := BeginHookCall()
	if nested != c {
		t.Error("a nested begin keeps another call than the open one")
	}
	c.call.bodyUnread, c.call.bodyLinks = true, true
	same(t, nested, "nested call after a cause")
	endNested()
	same(t, c, "after the nested end")
	end()
	same(t, none, "after the end")
	if (CurrentHookCall() != Call{}) {
		t.Error("after the end a call is still found")
	}
}
