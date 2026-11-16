// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sensor

import (
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/procprobe"
)

// An unattributed finding on Linux or macOS names that system's owner
// source, not Windows mechanisms; Windows keeps its own (GAP-0092).
func TestUnattributedReasonNamesThePlatformOwnerSources(t *testing.T) {
	previous := ownerGOOS
	t.Cleanup(func() { ownerGOOS = previous })
	at := time.Unix(1_760_000_000, 0)
	processes := []procprobe.Process{{PID: 30, Name: "mcp-server-fetch"}}
	for goos, want := range map[string]string{
		"linux":   "owning uid",
		"darwin":  "owning uid",
		"windows": "Win32_Process owner",
	} {
		ownerGOOS = goos
		got := resolverFor(OwnerLookups{}, processes, at).resolve(refsFor(processes, []int{30}, at), nil)
		if got.Attribution != AttributionUnattributed || !strings.Contains(got.Reason, want) {
			t.Errorf("%s: reason %q (%s), want it to name %q", goos, got.Reason, got.Attribution, want)
		}
		if goos != "windows" && strings.Contains(got.Reason, "Win32_Process") {
			t.Errorf("%s: reason %q names a Windows mechanism", goos, got.Reason)
		}
	}
}
