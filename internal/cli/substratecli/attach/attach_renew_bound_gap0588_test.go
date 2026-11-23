// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package attach

import (
	"strconv"
	"strings"
	"testing"
)

// GAP-0588: renews that keep ending at once are bounded: after
// maxQuickRenews of them the next end takes the reconnect path, with its
// line and backoff.
func TestQuickRenewsAreBoundedGAP0588(t *testing.T) {
	r := newRig(t, nil)
	run := r.start(r.options())
	for i := 1; i <= maxQuickRenews+1; i++ {
		waitFor(t, "screen "+strconv.Itoa(i), func() bool { return strings.Contains(r.out.String(), "screen:"+strconv.Itoa(i)) })
		if strings.Contains(r.errb.String(), lostMsg) {
			t.Fatalf("renew %d was reported as a loss: %q", i, r.errb.String())
		}
		r.typ("EXPIRE\r")
	}
	waitFor(t, "the reconnect line", func() bool { return strings.Contains(r.errb.String(), lostMsg) })
	waitFor(t, "screen after the reconnect", func() bool {
		return strings.Contains(r.out.String(), "screen:"+strconv.Itoa(maxQuickRenews+2))
	})
	r.typ("\x1d")
	got := r.wait(run)
	if got.err != nil || !got.res.Detached || got.res.Renewals != maxQuickRenews || got.res.Reconnects != maxQuickRenews+1 {
		t.Fatalf("%+v %v", got.res, got.err)
	}
}
