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
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// B2: substrate.files.push / .sync off refuse the upload of a push or a
// sync batch (read live); the first copy of a run is not affected.
func TestPushDisabledPUTRefused(t *testing.T) {
	push, sync := false, true
	var reached atomic.Int32
	f := newSubstrateFixture(t, func(c *SubstrateConfig) {
		c.FilesPush = func() bool { return push }
		c.FilesSync = func() bool { return push && sync }
	})
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer relay.Close()
	f.api.substrateState().cfg.Relays = &dialRelay{addr: strings.TrimPrefix(relay.URL, "http://")}
	put := func(op string) (int, string) {
		req := httptest.NewRequest(http.MethodPut, "/api/v1/substrate/actors/eng-web/alice-1/attach/files", bytes.NewReader([]byte("x")))
		req.Header.Set("Authorization", "Bearer p-alice")
		req.Header.Set("Content-Type", "application/x-tar")
		req.Header.Set("X-DefenseClaw-Client", "dc-launcher/1")
		if op != "" {
			req.Header.Set("X-DefenseClaw-Op", op)
		}
		rec := httptest.NewRecorder()
		f.admin.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	if c, _ := put(""); c != http.StatusNoContent {
		t.Fatalf("first copy refused with push off: %d", c)
	}
	if c, b := put("push"); c != http.StatusForbidden || !strings.Contains(b, "push_disabled") {
		t.Fatalf("push with push off: %d %s", c, b)
	}
	if c, b := put("sync"); c != http.StatusForbidden || !strings.Contains(b, "sync_disabled") {
		t.Fatalf("sync with push off: %d %s", c, b)
	}
	if reached.Load() != 1 {
		t.Fatalf("relay reached %d times, want 1", reached.Load())
	}
	push = true
	if c, _ := put("push"); c != http.StatusNoContent {
		t.Fatalf("push after the switch went on: %d", c)
	}
	sync = false
	if c, b := put("sync"); c != http.StatusForbidden || !strings.Contains(b, "sync_disabled") {
		t.Fatalf("sync with sync off: %d %s", c, b)
	}
	rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/launcher", "p-alice", "")
	if !strings.Contains(rec.Body.String(), `"files":{"push":true,"sync":false}`) {
		t.Fatalf("launcher settings: %s", rec.Body)
	}
}
