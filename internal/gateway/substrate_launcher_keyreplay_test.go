// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

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
