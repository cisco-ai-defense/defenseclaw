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
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

type testClock struct{ t time.Time }

func (c *testClock) now() time.Time { return c.t }

func newTestStore(t *testing.T) (*FileStore, *testClock, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "sandbox", "registrations")
	clock := &testClock{t: time.Unix(1_800_000_000, 0).UTC()}
	s := NewFileStore(dir)
	s.Now = clock.now
	return s, clock, dir
}

func pending(t *testing.T) Registration {
	t.Helper()
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	return Registration{ID: id, SubjectKey: DigestPrefix + "aa", Connector: "claudecode", WorkdirMode: "copy"}
}

func bind(n int) sandboxrelay.BindRequest {
	return sandboxrelay.BindRequest{
		V: 1, SandboxName: "dc-claude-" + string(rune('a'+n)), SandboxID: "sbx-" + string(rune('a'+n)),
		BindingID: "sb_" + strings.Repeat(string(rune('0'+n)), 32),
	}
}

func TestNewIDShape(t *testing.T) {
	seen := map[string]bool{}
	for range 64 {
		id, err := NewID()
		if err != nil || !ValidID(id) || len(id) != len(IDPrefix)+IDRandomChars || seen[id] {
			t.Fatalf("id %q err %v", id, err)
		}
		seen[id] = true
	}
	for _, bad := range []string{"", "reg-", "reg-AAAAAAAAAAAAAAAAAAAAAAAAAA", "reg-../../etc/passwd", "sr_" + strings.Repeat("a", 32)} {
		if ValidID(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

// Lookups are scoped to the caller's uid: another uid's id is not found,
// and every mutation through another uid fails as unknown.
func TestStoreScopesEveryLookupToTheUID(t *testing.T) {
	s, _, _ := newTestStore(t)
	r := pending(t)
	if err := s.Create(1001, r); err != nil {
		t.Fatal(err)
	}
	if got, ok, err := s.Get(1001, r.ID); err != nil || !ok || got.UID != 1001 || got.State != StatePending || got.V != RecordVersion {
		t.Fatalf("own get: %+v %v %v", got, ok, err)
	}
	if _, ok, err := s.Get(1002, r.ID); ok || err != nil {
		t.Fatalf("another uid found the registration: %v %v", ok, err)
	}
	if _, err := s.Bind(1002, r.ID, bind(1)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bind by another uid: %v", err)
	}
	if err := s.Revoke(1002, r.ID, "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoke by another uid: %v", err)
	}
	if err := s.Deleted(1002, r.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted by another uid: %v", err)
	}
	if regs, _ := s.List(1002); len(regs) != 0 {
		t.Fatalf("another uid lists %d", len(regs))
	}
}

// A registration tracks its sandbox's lifecycle (GAP-0505, GAP-0446): a
// stopped report makes it stopped until a running report, a daemon that
// stops reporting lets the lease lapse, a stop with a re-match's stop
// pending revokes it for good, and a bind must name the sandbox id.
func TestStoreReportTracksTheSandboxLifecycle(t *testing.T) {
	s, clock, _ := newTestStore(t)
	r := pending(t)
	if err := s.Create(1001, r); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Report(1001, r.ID, true); !errors.Is(err, ErrNotPending) {
		t.Fatalf("report of a pending registration: %v", err)
	}
	noID := bind(1)
	noID.SandboxID = ""
	if _, err := s.Bind(1001, r.ID, noID); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bind without a sandbox id: %v", err)
	}
	live, err := s.Bind(1001, r.ID, bind(1))
	if err != nil || EffectiveState(live, clock.t) != StateLive {
		t.Fatalf("bind: %+v %v", live, err)
	}
	if got, err := s.Report(1001, r.ID, false); err != nil || got.State != StateStopped || EffectiveState(got, clock.t) != StateStopped {
		t.Fatalf("stopped report: %+v %v", got, err)
	}
	clock.t = clock.t.Add(time.Minute)
	// A report only moves a registration toward stopped (GAP-0673).
	if got, err := s.Report(1001, r.ID, true); !errors.Is(err, ErrStopped) || got.State != StateStopped {
		t.Fatalf("running report after a reported stop: %+v %v", got, err)
	}
	live, err = s.Restart(1001, r.ID)
	if err != nil || live.State != StateLive || live.ID == r.ID || !live.SeenAt.Equal(clock.t) {
		t.Fatalf("restart: %+v %v", live, err)
	}
	// The daemon goes silent: the lease lapses, and a restarted store agrees.
	clock.t = clock.t.Add(LiveLease)
	reopened := NewFileStore(s.dir)
	reopened.Now = clock.now
	if got, _, _ := reopened.Get(1001, live.ID); EffectiveState(got, clock.t) != StateStopped {
		t.Fatalf("a registration past its lease is %q", EffectiveState(got, clock.t))
	}
	// A lapsed lease is a lost connection, not a stop: it runs on.
	if got, err := reopened.Report(1001, live.ID, true); err != nil || got.State != StateLive {
		t.Fatalf("running report after a lapsed lease: %+v %v", got, err)
	}
	// A revoked registration never comes back.
	if err := reopened.Revoke(1001, live.ID, ReasonPolicyChanged); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Report(1001, live.ID, true); !errors.Is(err, ErrRevoked) {
		t.Fatalf("a revoked registration came back: %v", err)
	}
	if _, err := reopened.Restart(1001, live.ID); !errors.Is(err, ErrRevoked) {
		t.Fatalf("a revoked registration restarted: %v", err)
	}
}

// A sandbox the daemon reports foreign revokes the registrations of the
// caller bound to it, and its ids never register again (GAP-0529).
func TestStoreRevokeSandboxRetiresAForeignSandbox(t *testing.T) {
	s, _, _ := newTestStore(t)
	forged, kept := pending(t), pending(t)
	for _, r := range []Registration{forged, kept} {
		if err := s.Create(1001, r); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Bind(1001, forged.ID, bind(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Bind(1001, kept.ID, bind(2)); err != nil {
		t.Fatal(err)
	}
	if got, err := s.RevokeSandbox(1002, bind(1).SandboxID, "", ReasonForeign); err != nil || len(got) != 0 {
		t.Fatalf("another uid revoked %+v %v", got, err)
	}
	got, err := s.RevokeSandbox(1001, bind(1).SandboxID, bind(1).SandboxName, ReasonForeign)
	if err != nil || len(got) != 1 || got[0].ID != forged.ID || got[0].State != StateRevoked || got[0].RevokedReason != ReasonForeign {
		t.Fatalf("revoke the foreign sandbox: %+v %v", got, err)
	}
	if r, _, _ := s.Get(1001, kept.ID); r.State != StateLive {
		t.Fatalf("another sandbox's registration: %+v", r)
	}
	again := pending(t)
	if err := s.Create(1001, again); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Bind(1001, again.ID, bind(1)); !errors.Is(err, ErrTombstoned) {
		t.Fatalf("the foreign sandbox registered again: %v", err)
	}
}

func TestStoreBindRevokeAndTombstones(t *testing.T) {
	s, clock, _ := newTestStore(t)
	r := pending(t)
	if err := s.Create(1001, r); err != nil {
		t.Fatal(err)
	}
	live, err := s.Bind(1001, r.ID, bind(1))
	if err != nil || live.State != StateLive || live.BindingID != bind(1).BindingID || !live.BoundAt.Equal(clock.t) {
		t.Fatalf("bind: %+v %v", live, err)
	}
	if _, err := s.Bind(1001, r.ID, bind(2)); !errors.Is(err, ErrNotPending) {
		t.Fatalf("second bind: %v", err)
	}
	other := pending(t)
	if err := s.Create(1001, other); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Bind(1001, other.ID, bind(1)); !errors.Is(err, ErrInUse) {
		t.Fatalf("binding id held by a live registration: %v", err)
	}
	if err := s.Revoke(1001, r.ID, "subject changed"); err != nil {
		t.Fatal(err)
	}
	if err := s.Revoke(1001, r.ID, "later"); err != nil {
		t.Fatal(err)
	}
	got, _, _ := s.Get(1001, r.ID)
	if got.State != StateRevoked || got.RevokedReason != "subject changed" || got.RevokedAt.IsZero() {
		t.Fatalf("tombstone: %+v", got)
	}
	// Neither the binding id nor the sandbox id of a tombstone registers
	// again.
	byBinding := bind(1)
	byBinding.SandboxID = "sbx-fresh"
	if _, err := s.Bind(1001, other.ID, byBinding); !errors.Is(err, ErrTombstoned) {
		t.Fatalf("tombstoned binding id: %v", err)
	}
	bySandbox := bind(3)
	bySandbox.SandboxID = bind(1).SandboxID
	if _, err := s.Bind(1001, other.ID, bySandbox); !errors.Is(err, ErrTombstoned) {
		t.Fatalf("tombstoned sandbox id: %v", err)
	}
	// Dropping a gateway revocation's tombstone retires its sandbox ids:
	// they still never register again, also after a restart.
	if err := s.Deleted(1001, r.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.Get(1001, r.ID); ok {
		t.Fatal("the tombstone was not dropped")
	}
	if _, err := s.Bind(1001, other.ID, byBinding); !errors.Is(err, ErrTombstoned) {
		t.Fatalf("retired binding id: %v", err)
	}
	reopened := NewFileStore(s.dir)
	reopened.Now = clock.now
	if _, err := reopened.Bind(1001, other.ID, bySandbox); !errors.Is(err, ErrTombstoned) {
		t.Fatalf("retired sandbox id after a restart: %v", err)
	}
}

func TestStoreBindReservesClaimedIDsAcrossAccountsAndRestart(t *testing.T) {
	s, _, dir := newTestStore(t)
	first := pending(t)
	if err := s.Create(1001, first); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Bind(1001, first.ID, bind(1)); err != nil {
		t.Fatal(err)
	}
	second := pending(t)
	if err := s.Create(1002, second); err != nil {
		t.Fatal(err)
	}
	for _, claim := range []sandboxrelay.BindRequest{
		{BindingID: bind(1).BindingID, SandboxID: bind(2).SandboxID, SandboxName: bind(2).SandboxName},
		{BindingID: bind(2).BindingID, SandboxID: bind(1).SandboxID, SandboxName: bind(2).SandboxName},
	} {
		if _, err := s.Bind(1002, second.ID, claim); !errors.Is(err, ErrInUse) {
			t.Fatalf("cross-account ID reuse = %v, want ErrInUse", err)
		}
	}
	restarted := NewFileStore(dir)
	if _, err := restarted.Bind(1002, second.ID, bind(1)); !errors.Is(err, ErrInUse) {
		t.Fatalf("ID reuse after restart = %v, want ErrInUse", err)
	}
}

// Deleted drops a pending entry, turns a live one into the user's own
// tombstone (or a policy_changed one while a stop is pending) and drops a
// tombstone; only the user's own tombstone frees its sandbox ids.
func TestStoreDeleted(t *testing.T) {
	s, _, _ := newTestStore(t)
	r := pending(t)
	if err := s.Create(1001, r); err != nil {
		t.Fatal(err)
	}
	if err := s.Deleted(1001, r.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.Get(1001, r.ID); ok {
		t.Fatal("pending entry kept")
	}

	live := pending(t)
	if err := s.CreateRun(1001, live, &Run{PolicyKey: "k"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Bind(1001, live.ID, bind(1)); err != nil {
		t.Fatal(err)
	}
	if err := s.Deleted(1001, live.ID); err != nil {
		t.Fatal(err)
	}
	got, ok, _ := s.Get(1001, live.ID)
	if !ok || got.State != StateRevoked || got.RevokedReason != ReasonDeleted {
		t.Fatalf("deleted live entry: %+v %v", got, ok)
	}
	if _, ok, _ := s.Run(1001, live.ID); ok {
		t.Fatal("a tombstone kept its run record")
	}
	next := pending(t)
	if err := s.Create(1001, next); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Bind(1001, next.ID, bind(1)); !errors.Is(err, ErrTombstoned) {
		t.Fatalf("a deleted live sandbox registers again: %v", err)
	}
	if err := s.Deleted(1001, live.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Bind(1001, next.ID, bind(1)); err != nil {
		t.Fatalf("the user's own tombstone dropped: %v", err)
	}
}

func TestStorePolicyRevocationKeepsFinalLifecycleWindow(t *testing.T) {
	s, clock, _ := newTestStore(t)
	r := pending(t)
	if err := s.Create(1001, r); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Bind(1001, r.ID, bind(1)); err != nil {
		t.Fatal(err)
	}
	if err := s.Revoke(1001, r.ID, ReasonPolicyChanged); err != nil {
		t.Fatal(err)
	}
	if err := s.Deleted(1001, r.ID); err != nil {
		t.Fatal(err)
	}
	if got, ok, err := s.Get(1001, r.ID); err != nil || !ok || got.State != StateRevoked {
		t.Fatalf("final lifecycle window lost: %+v %t %v", got, ok, err)
	}
	clock.t = clock.t.Add(RevokedTelemetryWindow + time.Second)
	if err := s.Deleted(1001, r.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.Get(1001, r.ID); ok {
		t.Fatal("expired lifecycle tombstone remained")
	}
}

// Run records survive a restart, are per uid and bounded, and go with
// their registration.
func TestStoreRunRecords(t *testing.T) {
	s, clock, dir := newTestStore(t)
	r := pending(t)
	run := &Run{Flags: sandboxrelay.RunFlags{Safe: true}, RepoOverlay: []byte("network: {}"), PolicyKey: "sha256:k", FloorDigest: "sha256:f"}
	if err := s.CreateRun(1001, r, run); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.Run(1002, r.ID); ok {
		t.Fatal("another uid read the run record")
	}
	reopened := NewFileStore(dir)
	reopened.Now = clock.now
	got, ok, err := reopened.Run(1001, r.ID)
	if err != nil || !ok || !got.Flags.Safe || string(got.RepoOverlay) != "network: {}" || got.PolicyKey != "sha256:k" {
		t.Fatalf("run after a restart: %+v %v %v", got, ok, err)
	}
	update, _, _ := reopened.Get(1001, r.ID)
	update.Profile = "engineering"
	got.StopAt, got.StopText = clock.t, "stop"
	if err := reopened.UpdateRun(1001, update, &got); err != nil {
		t.Fatal(err)
	}
	if after, _, _ := reopened.Run(1001, r.ID); after.StopText != "stop" || !after.Flags.Safe {
		t.Fatalf("updated run: %+v", after)
	}
	// A revoked registration keeps only the stop it was revoked with
	// (GAP-0623): its daemon is told that text; the run inputs go.
	if err := reopened.Revoke(1001, r.ID, ReasonPolicyChanged); err != nil {
		t.Fatal(err)
	}
	if kept, ok, _ := NewFileStore(dir).Run(1001, r.ID); !ok || kept.StopText != "stop" || kept.Flags.Safe || len(kept.RepoOverlay) != 0 || kept.PolicyKey != "" {
		t.Fatalf("a registration revoked by a stop kept %+v", kept)
	}
	plain := pending(t)
	if err := reopened.CreateRun(1001, plain, &Run{Flags: sandboxrelay.RunFlags{Safe: true}}); err != nil {
		t.Fatal(err)
	}
	if err := reopened.Revoke(1001, plain.ID, "x"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := reopened.Run(1001, plain.ID); ok {
		t.Fatal("a revoked registration without a stop kept its run record")
	}

	if err := s.CreateRun(1003, pending(t), &Run{UserPack: make([]byte, MaxRunBytes)}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an oversized run record: %v", err)
	}
	s.runLimit = 1 << 20
	big := &Run{UserPack: make([]byte, 64<<10), RepoOverlay: make([]byte, 16<<10)}
	full := false
	for range (1<<20)/(80<<10) + 2 {
		if err := s.CreateRun(1004, pending(t), big); errors.Is(err, ErrFull) {
			full = true
			break
		} else if err != nil {
			t.Fatal(err)
		}
	}
	if !full {
		t.Fatal("run records are not bounded per uid")
	}
	if err := s.CreateRun(1005, pending(t), big); err != nil {
		t.Fatalf("another uid is held up by a full one: %v", err)
	}
	clock.t = clock.t.Add(PendingTTL)
	if err := s.CreateRun(1004, pending(t), big); err != nil {
		t.Fatalf("expired pending entries still hold run budget: %v", err)
	}
}

// GAP-0636: a first start prepares its image and MicroVM disk between the
// resolve and the bind, about seven minutes on a cold computer; the pending
// registration must still bind then.
func TestStorePendingSurvivesAColdImageBuild(t *testing.T) {
	s, clock, _ := newTestStore(t)
	r := pending(t)
	if err := s.Create(1001, r); err != nil {
		t.Fatal(err)
	}
	clock.t = clock.t.Add(10 * time.Minute)
	if live, err := s.Bind(1001, r.ID, bind(1)); err != nil || live.State != StateLive {
		t.Fatalf("bind after a 10 minute image build: %+v %v", live, err)
	}
}

func TestStorePendingExpires(t *testing.T) {
	s, clock, _ := newTestStore(t)
	r := pending(t)
	if err := s.Create(1001, r); err != nil {
		t.Fatal(err)
	}
	clock.t = clock.t.Add(PendingTTL)
	if _, err := s.Bind(1001, r.ID, bind(1)); !errors.Is(err, ErrExpired) {
		t.Fatalf("bind after the TTL: %v", err)
	}
	got, ok, _ := s.Get(1001, r.ID)
	if !ok || !PendingExpired(got, clock.t) {
		t.Fatalf("expired entry is kept to answer expired: %+v %v", got, ok)
	}
	// Long after expiry a write drops it.
	clock.t = clock.t.Add(expiredPendingKeep)
	if err := s.Create(1001, pending(t)); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.Get(1001, r.ID); ok {
		t.Fatal("an expired pending entry outlived its keep window")
	}
}

// A restarted gateway reads the same registrations back, with the files
// private to the service account.
func TestStoreSurvivesARestart(t *testing.T) {
	s, clock, dir := newTestStore(t)
	r := pending(t)
	if err := s.Create(1001, r); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Bind(1001, r.ID, bind(1)); err != nil {
		t.Fatal(err)
	}
	revoked := pending(t)
	if err := s.Create(1002, revoked); err != nil {
		t.Fatal(err)
	}
	if err := s.Revoke(1002, revoked.ID, "regrouped"); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		for path, want := range map[string]os.FileMode{dir: 0o700, filepath.Join(dir, "1001.json"): 0o600} {
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != want {
				t.Fatalf("%s mode %v err %v, want %v", path, info.Mode().Perm(), err, want)
			}
		}
	}
	reopened := NewFileStore(dir)
	reopened.Now = clock.now
	got, ok, err := reopened.Get(1001, r.ID)
	if err != nil || !ok || got.State != StateLive || got.BindingID != bind(1).BindingID {
		t.Fatalf("reload: %+v %v %v", got, ok, err)
	}
	all, err := reopened.ListAll()
	if err != nil || len(all) != 2 {
		t.Fatalf("list all: %d %v", len(all), err)
	}
	tomb, _, _ := reopened.Get(1002, revoked.ID)
	if tomb.State != StateRevoked {
		t.Fatalf("tombstone after reload: %+v", tomb)
	}
	if err := reopened.Purge(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("purge left the store: %v", err)
	}
}

// A file that names another uid, is malformed or is readable by others
// fails closed for that uid.
func TestStoreFailsClosedOnAForeignFile(t *testing.T) {
	s, _, dir := newTestStore(t)
	r := pending(t)
	if err := s.Create(1001, r); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "1001.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(){
		"another uid": func() {
			_ = os.WriteFile(path, []byte(strings.Replace(string(data), `"uid":1001`, `"uid":1002`, 1)), 0o600)
		},
		"malformed": func() { _ = os.WriteFile(path, []byte(`{"v":1,"registrations":[`), 0o600) },
	}
	if runtime.GOOS != "windows" {
		cases["readable by others"] = func() { _ = os.WriteFile(path, data, 0o600); _ = os.Chmod(path, 0o644) }
	}
	for name, corrupt := range cases {
		t.Run(name, func(t *testing.T) {
			corrupt()
			fresh := NewFileStore(dir)
			if _, _, err := fresh.Get(1001, r.ID); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("get: %v", err)
			}
		})
	}
}

// Past the cap the oldest tombstones go first (the user's own deleted
// ones before the gateway's, whose sandbox ids are retired), then expired
// pending entries; live entries are never evicted.
func TestStoreEvictsTombstonesBeforeRefusing(t *testing.T) {
	s, clock, _ := newTestStore(t)
	s.limit = 3
	var ids []string
	for i := range 3 {
		r := pending(t)
		ids = append(ids, r.ID)
		if err := s.Create(1001, r); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Bind(1001, r.ID, bind(i+1)); err != nil {
			t.Fatal(err)
		}
		clock.t = clock.t.Add(time.Second)
	}
	if err := s.Create(1001, pending(t)); !errors.Is(err, ErrFull) {
		t.Fatalf("all live: %v", err)
	}
	if err := s.Revoke(1001, ids[1], "x"); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(1001, pending(t)); err != nil {
		t.Fatalf("a tombstone is evictable: %v", err)
	}
	if _, ok, _ := s.Get(1001, ids[1]); ok {
		t.Fatal("the tombstone was not the one evicted")
	}
	for _, id := range []string{ids[0], ids[2]} {
		if _, ok, _ := s.Get(1001, id); !ok {
			t.Fatalf("live %s evicted", id)
		}
	}
}

func TestStoreUpdateRewritesOnlyTheMatch(t *testing.T) {
	s, _, _ := newTestStore(t)
	r := pending(t)
	r.Profile, r.ProfileMatch, r.Provisional = "offline-floor", MatchDefaultLookupFailed, true
	if err := s.Create(1001, r); err != nil {
		t.Fatal(err)
	}
	update := r
	update.Profile, update.ProfileMatch, update.Provisional, update.FactsDigest = "contractors", MatchGroup, false, DigestPrefix+"bb"
	update.SubjectKey, update.State, update.UID = DigestPrefix+"forged", StateLive, 1002
	if err := s.Update(1001, update); err != nil {
		t.Fatal(err)
	}
	got, _, _ := s.Get(1001, r.ID)
	if got.Profile != "contractors" || got.Provisional || got.FactsDigest != DigestPrefix+"bb" ||
		got.SubjectKey != r.SubjectKey || got.State != StatePending || got.UID != 1001 {
		t.Fatalf("update: %+v", got)
	}
	if err := s.Update(1002, update); !errors.Is(err, ErrNotFound) {
		t.Fatalf("update through another uid: %v", err)
	}
}

func TestDecisionStore(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sandbox", "decisions")
	s := NewFileDecisionStore(dir)
	reg := pending(t).ID
	d := Decision{Registration: reg, Kind: sandboxrelay.DecisionEgressAllow, Host: "api.example.com",
		Scope: sandboxrelay.DecisionScopeAlways, Actor: DecisionActor{UID: 7, PrincipalHash: DigestPrefix + "cc"}}
	if err := s.Add(1001, d); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(1001, d); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(1001, Decision{Registration: reg, Kind: "operator", Host: "x", Scope: "always"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown kind: %v", err)
	}
	if err := s.Add(1001, Decision{Registration: reg, Kind: sandboxrelay.DecisionEgressBlock, Host: "evil.example/../x", Scope: "always"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("malformed host: %v", err)
	}
	got, err := s.List(1001, reg)
	if err != nil || len(got) != 1 || got[0].Actor.UID != 1001 || !strings.HasPrefix(got[0].ID, DecisionIDPrefix) {
		t.Fatalf("list: %+v %v", got, err)
	}
	if other, _ := s.List(1002, ""); len(other) != 0 {
		t.Fatalf("another uid sees %d decisions", len(other))
	}
	reopened := NewFileDecisionStore(dir)
	if again, err := reopened.List(1001, ""); err != nil || len(again) != 1 {
		t.Fatalf("reload: %+v %v", again, err)
	}
	if err := reopened.Purge(); err != nil {
		t.Fatal(err)
	}
}

func FuzzValidBind(f *testing.F) {
	f.Add("sb_"+strings.Repeat("a", 32), "dc-claude-1", "sbx-1")
	f.Add("sb_../", "../../x", "\x00")
	f.Fuzz(func(t *testing.T, binding, name, id string) {
		b := sandboxrelay.BindRequest{BindingID: binding, SandboxName: name, SandboxID: id}
		if ValidBind(b) != nil {
			return
		}
		for _, v := range []string{binding, name, id} {
			if strings.ContainsAny(v, "/\\\x00 \n") {
				t.Fatalf("accepted %q", v)
			}
		}
	})
}

// An evicted gateway tombstone retires its sandbox ids; the user's own
// deleted tombstones are evicted before it.
func TestStoreEvictionRetiresGatewayTombstones(t *testing.T) {
	s, clock, _ := newTestStore(t)
	s.limit = 3
	var ids []string
	for i := range 3 {
		r := pending(t)
		ids = append(ids, r.ID)
		if err := s.Create(1001, r); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Bind(1001, r.ID, bind(i+1)); err != nil {
			t.Fatal(err)
		}
		clock.t = clock.t.Add(time.Second)
	}
	if err := s.Revoke(1001, ids[0], "subject_changed"); err != nil {
		t.Fatal(err)
	}
	if err := s.Deleted(1001, ids[1]); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(1001, pending(t)); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.Get(1001, ids[0]); !ok {
		t.Fatal("the gateway tombstone went before the user's own")
	}
	if _, ok, _ := s.Get(1001, ids[1]); ok {
		t.Fatal("the user's deleted tombstone was kept")
	}
	// ids[2] live, ids[0] a gateway tombstone, one pending: the tombstone
	// goes, and its sandbox is retired.
	if err := s.Create(1001, pending(t)); err != nil {
		t.Fatal(err)
	}
	regs, _ := s.List(1001)
	var open string
	for _, r := range regs {
		if r.State == StatePending {
			open = r.ID
		}
	}
	if _, ok, _ := s.Get(1001, ids[0]); ok {
		t.Fatal("the gateway tombstone was not evicted")
	}
	if _, err := s.Bind(1001, open, bind(1)); !errors.Is(err, ErrTombstoned) {
		t.Fatalf("an evicted gateway tombstone's sandbox registers again: %v", err)
	}
}

// GAP-0367: every relayed hook call reads its registration, and the store
// wrote a uid's file (an fsync, which on macOS flushes the whole disk cache
// and took seconds while the audit log was busy) holding the lock those
// reads take. A read now returns the stored records while a write is still
// on disk, and sees the write's records once it is stored.
func TestFileStoreReadsDoNotWaitForAWrite(t *testing.T) {
	s, _, _ := newTestStore(t)
	r := pending(t)
	if err := s.Create(7, r); err != nil {
		t.Fatal(err)
	}
	inWrite, finish := make(chan struct{}), make(chan struct{})
	saved := storeFileWrite
	t.Cleanup(func() { storeFileWrite = saved })
	storeFileWrite = func(dir, path string, v any) error {
		close(inWrite)
		<-finish
		return saved(dir, path, v)
	}
	revoked := make(chan error, 1)
	go func() { revoked <- s.Revoke(7, r.ID, "test") }()
	<-inWrite
	read := make(chan Registration, 1)
	go func() {
		got, _, _ := s.Get(7, r.ID)
		read <- got
	}()
	select {
	case got := <-read:
		if got.State != StatePending {
			t.Fatalf("read during the write = %s, want the stored pending record", got.State)
		}
	case <-time.After(2 * time.Second):
		close(finish)
		t.Fatal("a read waited for the write to reach the disk")
	}
	close(finish)
	if err := <-revoked; err != nil {
		t.Fatal(err)
	}
	if got, _, _ := s.Get(7, r.ID); got.State != StateRevoked {
		t.Fatalf("read after the write = %s, want revoked", got.State)
	}
}

// Admission must not observe a live registration after a stop or revoke has
// started but before its durable file replacement has completed.
func TestFileStoreAdmissionWaitsForAuthorityWithdrawal(t *testing.T) {
	for _, tc := range []struct {
		name     string
		withdraw func(*FileStore, Registration) error
		want     string
	}{
		{"stop report", func(s *FileStore, r Registration) error { _, err := s.Report(7, r.ID, false); return err }, StateStopped},
		{"revoke sandbox", func(s *FileStore, r Registration) error {
			_, err := s.RevokeSandbox(7, bind(1).SandboxID, "", "test")
			return err
		}, StateRevoked},
		{"revoke registration", func(s *FileStore, r Registration) error { return s.Revoke(7, r.ID, "test") }, StateRevoked},
		{"deleted sandbox", func(s *FileStore, r Registration) error { return s.Deleted(7, r.ID) }, StateRevoked},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, _ := newTestStore(t)
			r := pending(t)
			if err := s.Create(7, r); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Bind(7, r.ID, bind(1)); err != nil {
				t.Fatal(err)
			}
			entered, finish := make(chan struct{}), make(chan struct{})
			saved := storeFileWrite
			t.Cleanup(func() { storeFileWrite = saved })
			storeFileWrite = func(dir, path string, v any) error {
				close(entered)
				<-finish
				return saved(dir, path, v)
			}
			written := make(chan error, 1)
			go func() { written <- tc.withdraw(s, r) }()
			<-entered
			started := make(chan struct{})
			read := make(chan Registration, 1)
			go func() {
				close(started)
				got, _, _, _, _ := s.GetWithRun(7, r.ID)
				read <- got
			}()
			<-started
			select {
			case got := <-read:
				close(finish)
				<-written
				t.Fatalf("admission saw %s while authority withdrawal was in flight", got.State)
			case <-time.After(100 * time.Millisecond):
			}
			close(finish)
			if err := <-written; err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-read:
				if got.State != tc.want {
					t.Fatalf("after withdrawal = %s, want %s", got.State, tc.want)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("admission remained blocked after withdrawal completed")
			}
		})
	}
}
