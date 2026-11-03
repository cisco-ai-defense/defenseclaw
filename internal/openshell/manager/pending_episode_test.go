// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// A recovery may finish while the daemon is not asked about the sandbox.
// The first refusal of a later busy window must start a new episode.
func TestReviewerProbeStaleEpisodeIsNotStuck(t *testing.T) {
	now := time.Unix(1_760_000_000, 0)
	m := &Manager{now: func() time.Time { return now }}
	get := func() string {
		var e *sandboxapi.Error
		if err := m.pendingRefusal("vs10c-x", openshell.PhaseError, false); !errors.As(err, &e) {
			t.Fatalf("refusal = %#v", err)
		}
		return e.Error()
	}
	if got := get(); !strings.Contains(got, "is busy") {
		t.Fatalf("first: %q", got)
	}
	now = now.Add(2 * time.Hour)
	if got := get(); strings.Contains(got, "is stuck") {
		t.Fatalf("FALSE STUCK on the first refusal of a new episode: %q", got)
	}
}
