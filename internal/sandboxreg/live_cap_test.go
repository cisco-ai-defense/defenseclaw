// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package sandboxreg

import (
	"errors"
	"fmt"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

func capBind(n int) sandboxrelay.BindRequest {
	return sandboxrelay.BindRequest{V: 1, SandboxName: fmt.Sprintf("dc-cap-%03d", n), SandboxID: fmt.Sprintf("sbx-cap-%03d", n),
		BindingID: "sb_" + fmt.Sprintf("%032d", n)}
}

// One account's live registrations are what its sandboxes count in the
// fleet's active-sandbox gauge, and the gateway cannot check them against
// OpenShell: a made-up name bound and reported ready counted until the
// 1024-entry cap (GAP-0020). A bind, a restart or a lapsed lease's revival
// past MaxLivePerUID is refused; stopping one makes room, and another
// account is not affected.
func TestStoreCapsOneAccountsLiveRegistrations(t *testing.T) {
	s, clock, _ := newTestStore(t)
	var ids []string
	n := 0
	bindNext := func(uid int) (Registration, error) {
		t.Helper()
		r := pending(t)
		if err := s.Create(uid, r); err != nil {
			t.Fatal(err)
		}
		n++
		live, err := s.Bind(uid, r.ID, capBind(n))
		if err == nil && uid == 1001 {
			ids = append(ids, live.ID)
		}
		return live, err
	}
	for range MaxLivePerUID {
		if _, err := bindNext(1001); err != nil {
			t.Fatalf("bind %d of %d: %v", len(ids)+1, MaxLivePerUID, err)
		}
	}
	if _, err := bindNext(1001); !errors.Is(err, ErrTooManyLive) {
		t.Fatalf("bind past the cap: %v", err)
	}
	// Another account binds as before.
	if _, err := bindNext(1002); err != nil {
		t.Fatalf("another account's bind: %v", err)
	}
	// A stop makes room.
	if _, err := s.Report(1001, ids[0], false); err != nil {
		t.Fatal(err)
	}
	if _, err := bindNext(1001); err != nil {
		t.Fatalf("bind after a stop: %v", err)
	}
	// The restart of the stopped one would pass the cap.
	if _, err := s.Restart(1001, ids[0]); !errors.Is(err, ErrTooManyLive) {
		t.Fatalf("restart past the cap: %v", err)
	}
	// Every lease lapses; a new set binds, and a lapsed one does not revive
	// past the cap.
	clock.t = clock.t.Add(LiveLease + 1)
	for range MaxLivePerUID {
		if _, err := bindNext(1001); err != nil {
			t.Fatalf("bind after the leases lapsed: %v", err)
		}
	}
	if _, err := s.Report(1001, ids[1], true); !errors.Is(err, ErrTooManyLive) {
		t.Fatalf("revival of a lapsed lease past the cap: %v", err)
	}
	// A running report of a live one is unaffected.
	if _, err := s.Report(1001, ids[len(ids)-1], true); err != nil {
		t.Fatalf("running report of a live registration: %v", err)
	}
}
