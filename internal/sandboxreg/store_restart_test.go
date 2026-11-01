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

package sandboxreg

import (
	"errors"
	"os"
	"runtime"
	"testing"
	"time"
)

// GAP-0672, GAP-0673: every caller-driven path after a reported stop. A
// state report only moves a registration toward stopped; a start runs the
// sandbox under a new registration with its guest watched again, and the
// old registration authorizes nothing.
func TestStoreCallerPathsAfterAStop(t *testing.T) {
	type setup struct {
		s     *FileStore
		clock *testClock
		reg   Registration
	}
	stopped := func(t *testing.T) setup {
		t.Helper()
		s, clock, _ := newTestStore(t)
		r := pending(t)
		if err := s.CreateRun(1001, r, &Run{PolicyKey: "k1"}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Bind(1001, r.ID, bind(2)); err != nil {
			t.Fatal(err)
		}
		if err := s.MarkGuestSeen(1001, r.ID, clock.t); err != nil {
			t.Fatal(err)
		}
		clock.t = clock.t.Add(time.Minute)
		got, err := s.Report(1001, r.ID, false)
		if err != nil || got.State != StateStopped {
			t.Fatalf("stop: %+v %v", got, err)
		}
		return setup{s, clock, got}
	}
	stays := func(t *testing.T, st setup, want string) {
		t.Helper()
		got, ok, err := st.s.Get(1001, st.reg.ID)
		if err != nil || !ok || got.State != want {
			t.Fatalf("registration: %+v %v %v, want %s", got, ok, err, want)
		}
		live := 0
		all, _ := st.s.List(1001)
		for _, r := range all {
			if EffectiveState(r, st.clock.t) == StateLive {
				live++
			}
		}
		if live != 0 {
			t.Fatalf("%d live registrations, want none", live)
		}
	}

	t.Run("forged running report", func(t *testing.T) {
		st := stopped(t)
		if _, err := st.s.Report(1001, st.reg.ID, true); !errors.Is(err, ErrStopped) {
			t.Fatalf("running report: %v", err)
		}
		stays(t, st, StateStopped)
	})
	t.Run("replay after stop and gateway restart", func(t *testing.T) {
		st := stopped(t)
		reopened := NewFileStore(st.s.dir)
		reopened.Now = st.clock.now
		for range 3 {
			st.clock.t = st.clock.t.Add(time.Minute)
			if _, err := reopened.Report(1001, st.reg.ID, true); !errors.Is(err, ErrStopped) {
				t.Fatalf("replayed report: %v", err)
			}
		}
		st.s = reopened
		stays(t, st, StateStopped)
	})
	t.Run("synthetic bind of the stopped sandbox", func(t *testing.T) {
		st := stopped(t)
		other := pending(t)
		if err := st.s.Create(1001, other); err != nil {
			t.Fatal(err)
		}
		if _, err := st.s.Bind(1001, other.ID, bind(2)); !errors.Is(err, ErrInUse) {
			t.Fatalf("bind of a held sandbox: %v", err)
		}
		stays(t, st, StateStopped)
	})
	t.Run("another account's restart", func(t *testing.T) {
		st := stopped(t)
		if _, err := st.s.Restart(1002, st.reg.ID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("restart from another uid: %v", err)
		}
		stays(t, st, StateStopped)
	})
	t.Run("restart write failure", func(t *testing.T) {
		if runtime.GOOS == "windows" || os.Geteuid() == 0 {
			t.Skip("needs a directory the test cannot write")
		}
		st := stopped(t)
		if err := os.Chmod(st.s.dir, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(st.s.dir, 0o700) })
		if _, err := st.s.Restart(1001, st.reg.ID); err == nil {
			t.Fatal("restart stored nothing and reported success")
		}
		stays(t, st, StateStopped)
	})
	t.Run("start registers again", func(t *testing.T) {
		st := stopped(t)
		var gone []Registration
		st.s.OnGone = func(r Registration) { gone = append(gone, r) }
		st.clock.t = st.clock.t.Add(time.Minute)
		fresh, err := st.s.Restart(1001, st.reg.ID)
		if err != nil {
			t.Fatal(err)
		}
		if fresh.ID == st.reg.ID || !ValidID(fresh.ID) || fresh.State != StateLive ||
			!fresh.GuestWatch || !fresh.GuestSeenAt.IsZero() || !fresh.BoundAt.Equal(st.clock.t) ||
			fresh.SandboxID != st.reg.SandboxID || fresh.BindingID != st.reg.BindingID ||
			!fresh.CreatedAt.Equal(st.reg.CreatedAt) || !SessionStart(fresh).Equal(st.clock.t) {
			t.Fatalf("restarted registration: %+v", fresh)
		}
		if run, ok, _ := st.s.Run(1001, fresh.ID); !ok || run.PolicyKey != "k1" {
			t.Fatalf("run record did not move: %+v %v", run, ok)
		}
		old, _, _ := st.s.Get(1001, st.reg.ID)
		if old.State != StateRevoked || old.RevokedReason != ReasonRestarted {
			t.Fatalf("old registration: %+v", old)
		}
		if len(gone) != 1 || gone[0].ID != st.reg.ID {
			t.Fatalf("gone: %+v", gone)
		}
		if _, err := st.s.Report(1001, st.reg.ID, true); !errors.Is(err, ErrRevoked) {
			t.Fatalf("old registration report: %v", err)
		}
		// Stop and start once more: the sandbox ids pass on again.
		if _, err := st.s.Report(1001, fresh.ID, false); err != nil {
			t.Fatal(err)
		}
		again, err := st.s.Restart(1001, fresh.ID)
		if err != nil || again.SandboxID != st.reg.SandboxID {
			t.Fatalf("second restart: %+v %v", again, err)
		}
		// Deleting it tombstones the last one; the restarted tombstones are
		// the user's own and never retire the sandbox ids.
		if err := st.s.Deleted(1001, again.ID); err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{st.reg.ID, fresh.ID} {
			if err := st.s.Deleted(1001, id); err != nil {
				t.Fatal(err)
			}
		}
		u, _ := st.s.loadLocked(1001)
		if len(u.retired) != 0 {
			t.Fatalf("restarted tombstones retired %+v", u.retired)
		}
	})
	t.Run("pending does not restart", func(t *testing.T) {
		s, _, _ := newTestStore(t)
		r := pending(t)
		if err := s.Create(1001, r); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Restart(1001, r.ID); !errors.Is(err, ErrNotPending) {
			t.Fatalf("restart of a pending registration: %v", err)
		}
	})
}
