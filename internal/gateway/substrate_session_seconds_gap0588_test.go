// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

// GAP-0588: a terminal WebSocket learns from the gateway how long its
// session token lives, so the launcher renews before the relay ends it. A
// relay cannot set that header itself.
func TestAttachUpgradeSaysTheSessionSecondsGAP0588(t *testing.T) {
	for _, tc := range []struct {
		name    string
		left    time.Duration
		atMost  int
		atLeast int
	}{
		{"sign-in ends in 20 s", 20 * time.Second, 20, 18},
		{"sign-in ends in 2 h", 2 * time.Hour, int(substrateAttachSessionTTL / time.Second), int(substrateAttachSessionTTL/time.Second) - 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := alice
			p.Expires = time.Now().Add(tc.left)
			f := newSubstrateFixture(t, func(sc *SubstrateConfig) { sc.People = fakePeople{"p-alice": p} })
			up := websocket.Upgrader{}
			rl := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if _, err := f.sessions.Verify(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")); err != nil {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				// A relay that claims a longer session: dropped.
				c, err := up.Upgrade(w, r, http.Header{relay.SessionSecondsHeader: {"99999"}})
				if err != nil {
					return
				}
				_ = c.Close()
			}))
			defer rl.Close()
			f.api.substrateState().cfg.Relays = &dialRelay{addr: strings.TrimPrefix(rl.URL, "http://")}
			srv := httptest.NewServer(f.admin)
			defer srv.Close()
			u := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/v1/substrate/actors/eng-web/alice-1/attach"
			c, resp, err := websocket.DefaultDialer.Dial(u, http.Header{"Authorization": {"Bearer p-alice"}})
			if err != nil {
				t.Fatalf("dial: %v (%v)", err, resp)
			}
			defer c.Close()
			vals := resp.Header.Values(relay.SessionSecondsHeader)
			if len(vals) != 1 {
				t.Fatalf("session seconds header %q, want one value", vals)
			}
			n, err := strconv.Atoi(vals[0])
			if err != nil || n > tc.atMost || n < tc.atLeast {
				t.Fatalf("session seconds %q, want in [%d, %d]", vals[0], tc.atLeast, tc.atMost)
			}
		})
	}
}
