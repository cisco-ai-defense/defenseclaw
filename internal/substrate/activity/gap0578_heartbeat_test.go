// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package activity

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

// The Recorder sends its heartbeat on an empty flush when Replica is set,
// and nothing without it.
func TestGAP0578RecorderHeartbeat(t *testing.T) {
	store := &Store{}
	srv := &leader.Server{IsLeader: func() bool { return true }}
	Serve(srv, store)
	hs := httptest.NewServer(srv)
	defer hs.Close()
	client := &leader.Client{BaseURL: hs.URL, HTTP: hs.Client(), Retry: time.Second}
	if err := (&Recorder{Leader: client}).Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(store.replicas) != 0 {
		t.Fatalf("a recorder without a replica name sent a heartbeat: %v", store.replicas)
	}
	if err := (&Recorder{Leader: client, Replica: "gw-a"}).Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.replicas["gw-a"]; !ok {
		t.Fatal("an empty flush sent no heartbeat")
	}
}
