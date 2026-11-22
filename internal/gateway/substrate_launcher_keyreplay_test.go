// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"strings"
	"testing"
)

// B3.1: the launcher settings carry substrate.launcher.key_replay, read
// live, so an admin's off switch applies to the next attach; with no live
// reader the default is ask.
func TestLauncherSettingsReportKeyReplayLive(t *testing.T) {
	mode := "off"
	f := newSubstrateFixture(t, func(c *SubstrateConfig) { c.KeyReplay = func() string { return mode } })
	get := func() string {
		rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/launcher", "p-alice", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("launcher settings: %d %s", rec.Code, rec.Body)
		}
		return rec.Body.String()
	}
	if b := get(); !strings.Contains(b, `"key_replay":"off"`) {
		t.Fatalf("admin off not reported: %s", b)
	}
	mode = "on"
	if b := get(); !strings.Contains(b, `"key_replay":"on"`) {
		t.Fatalf("live change not reported: %s", b)
	}
	g := newSubstrateFixture(t)
	rec := g.do(t, g.admin, http.MethodGet, "/api/v1/substrate/launcher", "p-alice", "")
	if !strings.Contains(rec.Body.String(), `"key_replay":"ask"`) {
		t.Fatalf("default not ask: %s", rec.Body)
	}
}
