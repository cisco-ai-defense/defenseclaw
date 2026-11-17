// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"testing"
)

// rel-1-0-10 GAP-1158 review: retire wrote the pending state only into a new
// marker. A retire over the marker of an earlier ok retire that was stopped
// while its writers ran (killed, a reboot) left the marker saying ok, and
// status read the install as retired. The marker says pending from the
// moment the writers may run until this retire ends ok.
func TestHookImageRetireOverAnOkMarkerSaysPendingWhileItsWritersRun(t *testing.T) {
	r := newRetireFixture(t)
	r.named = []map[string][]string{{}}
	steps := r.steps()
	steps.ReadMarker = func(path string) ([]byte, error) {
		node, ok := r.fs.get(path)
		if !ok {
			return nil, errors.New("not found")
		}
		return []byte(node.data), nil
	}
	state := func(marker string) any {
		t.Helper()
		node, ok := r.fs.get(marker)
		if !ok {
			t.Fatal("no marker")
		}
		var body map[string]any
		if err := json.Unmarshal([]byte(node.data), &body); err != nil {
			t.Fatalf("marker %q: %v", node.data, err)
		}
		return body["state"]
	}
	first := retireWindowsHookImages(steps)
	if !first.OK || first.Marker == "" {
		t.Fatalf("first retire = %+v, want ok", first)
	}
	// Run retire again; the state its writers would leave if it were stopped
	// there is the marker's state while they run.
	var during []any
	steps.ReconcileCodex = func() error { during = append(during, state(first.Marker)); return nil }
	steps.RestartGuardian = func() error { during = append(during, state(first.Marker)); return nil }
	r.scans = 0
	again := retireWindowsHookImages(steps)
	if !again.OK {
		t.Fatalf("second retire = %+v, want ok", again)
	}
	if len(during) != 2 || during[0] != "pending" || during[1] != "pending" {
		t.Fatalf("marker state while the writers ran = %v, want pending (a retire stopped there is not finished)", during)
	}
	if got := state(again.Marker); got != "ok" {
		t.Fatalf("marker state after the retire ended ok = %v, want ok", got)
	}
}
