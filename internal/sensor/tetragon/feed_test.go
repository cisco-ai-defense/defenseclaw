// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package tetragon

import (
	"testing"
	"time"
)

// A controls event is blocked or would_block by the newer of the
// reconciler's own record and the last listing: a policy loaded enforcing
// after the listing (a new anchor set gives it a new name) is not reported
// as would_block, a demote is not reported as blocked, and an operator's
// set-mode the reconciler has not seen yet still comes from the listing.
func TestFeedPolicyModePrefersTheNewerSource(t *testing.T) {
	listed := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	own := map[string]struct {
		mode string
		at   time.Time
	}{
		"defenseclaw-controls-0000000a": {"enforce", listed.Add(5 * time.Second)}, // loaded after the listing
		"defenseclaw-controls-0000000b": {"monitor", listed.Add(2 * time.Second)}, // demoted after it
		"defenseclaw-controls-0000000c": {"enforce", listed.Add(-time.Minute)},    // an operator moved it since
		"defenseclaw-controls-0000000d": {"enforce", listed.Add(-time.Minute)},    // agrees
	}
	f := &feed{
		modes: map[string]string{
			"defenseclaw-controls-0000000b": "enforce",
			"defenseclaw-controls-0000000c": "monitor",
			"defenseclaw-controls-0000000d": "enforce",
			"defenseclaw-observe-0000000e":  "monitor",
		},
		listedAt: listed,
		own: func(name string) (string, time.Time, bool) {
			entry, ok := own[name]
			return entry.mode, entry.at, ok
		},
	}
	for name, want := range map[string]string{
		"defenseclaw-controls-0000000a": "enforce",
		"defenseclaw-controls-0000000b": "monitor",
		"defenseclaw-controls-0000000c": "monitor",
		"defenseclaw-controls-0000000d": "enforce",
		"defenseclaw-observe-0000000e":  "monitor",
		"defenseclaw-controls-0000000f": "",
	} {
		if got := f.policyMode(name); got != want {
			t.Errorf("%s: %q, want %q", name, got, want)
		}
	}
	f.own = nil
	if got := f.policyMode("defenseclaw-controls-0000000a"); got != "" {
		t.Fatalf("without the reconciler the listing decides: %q", got)
	}
}
