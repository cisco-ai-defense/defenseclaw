// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

// A hook call is found only by the goroutine that began it, also when the
// key is the locked OS thread (Windows): another goroutine finds none, a
// second HookCall on the same goroutine begins nothing, and the end closes it
// (rel-1-0-10:GAP-1293).
func TestGAP1293HookCallIsFoundOnlyByTheGoroutineThatBeganIt(t *testing.T) {
	if currentHookCall() != nil {
		t.Fatal("a call is open before HookCall")
	}
	end := HookCall()
	call := currentHookCall()
	if call == nil {
		t.Fatal("HookCall began no call the goroutine finds")
	}
	other := make(chan *hookCall)
	for range 8 {
		go func() { other <- currentHookCall() }()
	}
	for range 8 {
		if found := <-other; found != nil {
			t.Fatal("another goroutine found the call")
		}
	}
	nested := HookCall()
	if currentHookCall() != call {
		t.Fatal("a nested HookCall replaced the open call")
	}
	nested()
	if currentHookCall() != call {
		t.Fatal("the nested end closed the open call")
	}
	end()
	if currentHookCall() != nil {
		t.Fatal("the call is still open after its end")
	}
	// A new call after the end is a new call of the same goroutine.
	end = HookCall()
	defer end()
	if found := currentHookCall(); found == nil || found == call {
		t.Fatal("a HookCall after the end did not begin a new call")
	}
}
