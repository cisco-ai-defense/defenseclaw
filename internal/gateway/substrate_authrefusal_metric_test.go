// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The substrate fixture (substrate_listener_test.go) is not built on Windows.

//go:build !windows

package gateway

import (
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
)

// GAP-0408: the metric counts every refusal by listener and closed reason;
// the verifier's message (attacker text) never reaches the log, the row or
// a label, and an unknown reason is "other".
func TestSubstrateAuthRefusedMetricAndWindowGAP0408(t *testing.T) {
	var mu sync.Mutex
	counts := map[string]int{}
	f := newSubstrateFixture(t, func(c *SubstrateConfig) {
		c.People = canaryPeople{}
		c.OnAuthRefused = func(listener, reason string) {
			mu.Lock()
			counts[listener+"/"+reason]++
			mu.Unlock()
		}
	})
	store, logger := testStoreAndLogger(t)
	f.api.store, f.api.logger = store, logger
	st := f.api.substrateState()
	log := &lockedBuffer{}
	var clock sync.Mutex
	now := time.Date(2026, 11, 17, 16, 0, 0, 0, time.UTC)
	st.logOut = log
	st.now = func() time.Time { clock.Lock(); defer clock.Unlock(); return now }

	for range 50 {
		f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/actors", "x."+authCanary+".y", "")
	}
	clock.Lock()
	now = now.Add(substrateAccessWindow)
	clock.Unlock()
	f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/actors", "x."+authCanary+".y", "")
	f.do(t, f.actor, http.MethodPost, substrateRelayTask, "tok-stale", `{"exit_code":0}`)
	waitAuthRefusalRows(t, store, 3)

	mu.Lock()
	if counts["admin/algorithm"] != 51 || counts["actor/actor_uid_mismatch"] != 1 || len(counts) != 2 {
		t.Errorf("metric counts %v, want admin/algorithm 51 and actor/actor_uid_mismatch 1", counts)
	}
	mu.Unlock()
	rows := authRefusalRows(t, store)
	var admin []string
	for _, e := range rows {
		if strings.Contains(e.Details, authCanary) {
			t.Errorf("row carries token or verifier text: %s", e.Details)
		}
		if strings.Contains(e.Details, `"listener":"admin"`) {
			admin = append(admin, e.Details)
		}
	}
	if len(admin) != 2 || !strings.Contains(admin[0]+admin[1], `"count":1,`) || !strings.Contains(admin[0]+admin[1], `"count":50,`) {
		t.Errorf("admin rows %v, want 2 (count 1, then count 50 after the window)", admin)
	}
	if strings.Contains(log.String(), authCanary) || strings.Count(log.String(), "admin listener refused a token: algorithm") != 2 {
		t.Errorf("log:\n%s", log.String())
	}
	if got := substrateAuthReason(identity.Reason("x-" + authCanary)); got != "other" {
		t.Errorf("unknown reason label %q", got)
	}
	for in, want := range map[string]string{"127.0.0.1:1": "loopback", "10.1.2.3:4": "private", "[fe80::1]:5": "link_local",
		"8.8.8.8:53": "public", "garbage": "unknown", "[::ffff:192.168.1.1]:9": "private"} {
		if got := substrateClientClass(in); got != want {
			t.Errorf("client class of %s = %s, want %s", in, got, want)
		}
	}
}

// lockedBuffer is a log the async row writer and the test share.
type lockedBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}
