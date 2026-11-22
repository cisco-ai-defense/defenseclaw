// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The substrate fixture (substrate_listener_test.go) is not built on Windows.

//go:build !windows

package gateway

import (
	"net/http"
	"strings"
	"testing"
)

// GAP-0424: an administrator's read of other people's agents (list --all,
// one agent by name) writes one substrate audit row naming who looked and
// at what; a person's own reads write none.
func TestSubstrateAdminReadOfOthersIsAuditedGAP0424(t *testing.T) {
	f := newSubstrateFixture(t)
	store, logger := testStoreAndLogger(t)
	f.api.store, f.api.logger = store, logger
	rows := func() []string {
		t.Helper()
		events, err := store.ListEvents(200)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, e := range events {
			if strings.Contains(e.Details, `"event":"admin_read"`) {
				out = append(out, e.Details)
			}
		}
		return out
	}
	for _, path := range []string{"/api/v1/substrate/actors?all=1", "/api/v1/substrate/actors/eng-web/alice-1"} {
		if rec := f.do(t, f.admin, http.MethodGet, path, "p-alice", ""); rec.Code != http.StatusOK {
			t.Fatalf("alice %s: %d %s", path, rec.Code, rec.Body)
		}
	}
	if got := rows(); len(got) != 0 {
		t.Fatalf("a person's own reads were audited as admin reads: %v", got)
	}
	if rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/actors?all=1", "p-admin", ""); rec.Code != http.StatusOK {
		t.Fatalf("admin list: %d %s", rec.Code, rec.Body)
	}
	if rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/actors/eng-web/alice-1", "p-admin", ""); rec.Code != http.StatusOK {
		t.Fatalf("admin get: %d %s", rec.Code, rec.Body)
	}
	got := rows()
	if len(got) != 2 {
		t.Fatalf("%d admin_read rows, want 2 (list --all, one agent): %v", len(got), got)
	}
	all := strings.Join(got, "\n")
	for _, want := range []string{`"view":"actors"`, `"count":2`, `"view":"actor"`, `"actor":"eng-web/alice-1"`,
		`"admin_id":"https://idp.example#root"`, `"source":"substrate"`, `GET /api/v1/substrate/actors`} {
		if !strings.Contains(all, want) {
			t.Errorf("admin_read rows have no %s:\n%s", want, all)
		}
	}
	if strings.Contains(all, "p-admin") {
		t.Errorf("a row carries the bearer token:\n%s", all)
	}
}
