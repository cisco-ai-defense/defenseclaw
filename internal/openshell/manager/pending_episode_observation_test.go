// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package manager

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/stream"
)

func pendingVerdict(t *testing.T, m *Manager, name string) string {
	t.Helper()
	var e *sandboxapi.Error
	if err := m.pendingRefusal(name, openshell.PhaseError, false); !errors.As(err, &e) {
		t.Fatalf("pending refusal = %#v", err)
	}
	return e.Error()
}

func wantPendingVerdict(t *testing.T, m *Manager, name, want string) {
	t.Helper()
	if got := pendingVerdict(t, m, name); !strings.Contains(got, want) {
		t.Fatalf("pending refusal = %q, want %q", got, want)
	}
}

// A phase observed through Get or the watcher, and a gateway reconnect,
// each end the old episode even when a later delete is refused in Error.
func TestPendingEpisodeResetsOnRecoveryAndGatewayConnection(t *testing.T) {
	e := newEnv(t, nil)
	_, advance := e.fakeClock(time.Unix(1_760_000_000, 0))
	e.create(sandboxapi.CreateRequest{Name: "episodebox"})
	m := e.m
	wantPendingVerdict(t, m, "episodebox", "is busy")
	advance(pendingStuckAfter)
	if _, err := m.Get(t.Context(), "episodebox"); err != nil {
		t.Fatalf("Get after recovery: %v", err)
	}
	wantPendingVerdict(t, m, "episodebox", "is busy")
	advance(pendingStuckAfter)
	m.statusEvent(t.Context(), e.boxOf("episodebox"), &stream.Status{Phase: openshell.PhaseReady})
	wantPendingVerdict(t, m, "episodebox", "is busy")
	advance(pendingStuckAfter)
	m.forgetGateway(e.gw, errors.New("gateway connection closed"))
	wantPendingVerdict(t, m, "episodebox", "is busy")
	advance(pendingStuckAfter)
	if _, err := m.gateway(t.Context()); err != nil {
		t.Fatalf("new gateway connection: %v", err)
	}
	wantPendingVerdict(t, m, "episodebox", "is busy")
}

// A create rollback and deletion of a retained snapshot release the name.
// Its next use must not inherit the previous sandbox's episode.
func TestPendingEpisodeClearedOnReleasePaths(t *testing.T) {
	e := newEnv(t, nil)
	_, advance := e.fakeClock(time.Unix(1_760_000_000, 0))
	b, err := e.m.reserve("rollbackbox", e.project, "mount")
	if err != nil {
		t.Fatal(err)
	}
	wantPendingVerdict(t, e.m, "rollbackbox", "is busy")
	advance(pendingStuckAfter)
	e.m.release("rollbackbox", b)
	wantPendingVerdict(t, e.m, "rollbackbox", "is busy")

	e.create(sandboxapi.CreateRequest{Name: "retainbox"})
	e.deleteBox("retainbox", sandboxapi.DeleteRequest{KeepSnapshot: true})
	wantPendingVerdict(t, e.m, "retainbox", "is busy")
	advance(pendingStuckAfter)
	e.deleteBox("retainbox", sandboxapi.DeleteRequest{})
	wantPendingVerdict(t, e.m, "retainbox", "is busy")
}
