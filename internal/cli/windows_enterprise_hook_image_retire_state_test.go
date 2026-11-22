// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// rel-1-0-10 GAP-1158: retire wrote bin\hooks\.retired and ended ok:false
// hook_image_retire_pending, and the marker read like a finished retire
// (status warned hook_image_retired; a no-op Setup /ensure kept it). The
// marker has to stay while retire is pending, since it is what makes the
// writers name the transition image, so it records how the last retire
// ended.
func TestHookImageRetireMarkerRecordsAPendingRetire(t *testing.T) {
	r := newRetireFixture(t)
	folder, _ := winpath.EnterpriseHookImageDigest(r.recorded["hook"])
	r.named = []map[string][]string{{folder: {`C:\Users\c\.kiro\hooks.json`}}}
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
	report := retireWindowsHookImages(steps)
	if report.OK || report.Reason != windowsHookImageRetirePending || report.Marker == "" {
		t.Fatalf("retire = %+v, want pending", report)
	}
	if got := state(report.Marker); got != "pending" {
		t.Fatalf("marker state after a pending retire = %v, want pending", got)
	}
	// The account converts: the next retire ends ok and says so.
	r.named = []map[string][]string{{}}
	r.scans = 0
	again := retireWindowsHookImages(steps)
	if !again.OK {
		t.Fatalf("second retire = %+v", again)
	}
	if got := state(again.Marker); got != "ok" {
		t.Fatalf("marker state after an ok retire = %v, want ok", got)
	}
	// A later retire that ends pending again records it.
	r.named = []map[string][]string{{folder: {`C:\Users\c\.kiro\hooks.json`}}}
	r.scans = 0
	if third := retireWindowsHookImages(steps); third.OK || state(third.Marker) != "pending" {
		t.Fatalf("third retire = %+v, state %v", third, state(third.Marker))
	}
}
