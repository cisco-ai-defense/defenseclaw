// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSubstrateAttachUploadIsNotHeldToTheAdminJSONGate
// (substrate-1:GAP-0134): with the default limits, the launcher's workspace
// upload (PUT attach/files, a 2 MiB application/x-tar body) passes the admin
// listener whole to the relay, instead of 415 from the JSON content-type gate
// or 413 from the 1 MiB admin body cap. The client tag is still required,
// and the other admin routes keep the JSON gate.
func TestSubstrateAttachUploadIsNotHeldToTheAdminJSONGate(t *testing.T) {
	var got int64
	f := newSubstrateFixture(t)
	relaySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer relaySrv.Close()
	f.api.substrateState().cfg.Relays = &dialRelay{addr: strings.TrimPrefix(relaySrv.URL, "http://")}
	put := func(size int, client string) int {
		req := httptest.NewRequest(http.MethodPut, "/api/v1/substrate/actors/eng-web/alice-1/attach/files", bytes.NewReader(make([]byte, size)))
		req.Header.Set("Authorization", "Bearer p-alice")
		req.Header.Set("Content-Type", "application/x-tar")
		if client != "" {
			req.Header.Set("X-DefenseClaw-Client", client)
		}
		rec := httptest.NewRecorder()
		f.admin.ServeHTTP(rec, req)
		return rec.Code
	}
	if c := put(2<<20, "dc-launcher/1"); c != http.StatusOK || got != 2<<20 {
		t.Fatalf("2 MiB tar upload: status %d, relay read %d bytes", c, got)
	}
	if c := put(1024, ""); c != http.StatusForbidden {
		t.Fatalf("upload without the client tag: %d", c)
	}
	if rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/actors", "p-alice", `{}`, "Content-Type", "application/x-tar"); rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("non-JSON create: %d", rec.Code)
	}
}
