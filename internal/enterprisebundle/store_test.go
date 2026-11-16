// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	root := t.TempDir()
	// Version directories are read-only; open them up before TempDir removes them.
	t.Cleanup(func() { _ = removeTree(root) })
	s := NewStore(filepath.Join(root, "etc", BundlesDirName), filepath.Join(root, "lifecycle"))
	clock := time.Date(2026, 10, 12, 10, 0, 0, 0, time.UTC)
	s.Now = func() time.Time { clock = clock.Add(time.Second); return clock }
	return s
}

func testBundleID(n int) string { return fmt.Sprintf("b-01JA%022d", n) }

func storeBundle() *Bundle {
	return &Bundle{Manifest: []byte(`{"m":1}`), Signature: []byte(`{"s":1}`), Files: map[string][]byte{
		ConfigName:                            []byte("config_version: 9\n"),
		"policies/guardrail/strict/pack.yaml": []byte("name: strict\n"),
	}}
}

func TestStoreProtectsPrivateDirectoryAndAtomicFiles(t *testing.T) {
	s := testStore(t)
	var directories, files []string
	s.EnsurePrivateDirectory = func(path string) error {
		directories = append(directories, path)
		return os.MkdirAll(path, 0o700)
	}
	s.PublishPrivateFile = func(path string) error {
		files = append(files, path)
		_, err := os.Lstat(path)
		return err
	}
	r, err := s.Receive(testBundleID(88), 1, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.saveState(State{}); err != nil {
		t.Fatal(err)
	}
	if want := []string{s.receiptsDir(), s.LifecycleDir}; !reflect.DeepEqual(directories, want) {
		t.Fatalf("protected directories = %q, want %q", directories, want)
	}
	if want := []string{s.receiptPath(r.ReceiptID), s.StatePath()}; !reflect.DeepEqual(files, want) {
		t.Fatalf("protected files = %q, want %q", files, want)
	}
	var stageDirectories, stageFiles []string
	s.EnsureStageDirectory = func(_, path string) error {
		stageDirectories = append(stageDirectories, path)
		return os.MkdirAll(path, 0o700)
	}
	s.PublishStageFile = func(path string) error {
		stageFiles = append(stageFiles, path)
		_, err := os.Lstat(path)
		return err
	}
	staging, err := s.Stage(r, storeBundle())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(stageDirectories, staging) ||
		!slices.Contains(stageDirectories, filepath.Join(staging, "policies", "guardrail", "strict")) {
		t.Fatalf("staging directories did not use the protected creator: %q", stageDirectories)
	}
	if len(stageFiles) != len(storeBundle().Files)+2 {
		t.Fatalf("staging files did not use the protected publisher: %q", stageFiles)
	}
}

func TestStageCallsDirectoryCreatorOncePerPath(t *testing.T) {
	s := testStore(t)
	r, err := s.Receive(testBundleID(89), 1, "")
	if err != nil {
		t.Fatal(err)
	}
	created := make(map[string]bool)
	s.EnsureStageDirectory = func(_, path string) error {
		if created[path] {
			return os.ErrExist // model a creator that requires a new requested path
		}
		created[path] = true
		return os.MkdirAll(path, 0o700)
	}
	staging, err := s.Stage(r, storeBundle())
	if err != nil {
		t.Fatal(err)
	}
	if !created[staging] || !created[filepath.Join(staging, "policies", "guardrail", "strict")] || len(created) != 2 {
		t.Fatalf("directory creator calls = %v, want root and nested parent once each", created)
	}
}

func digestOf(s string) string { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:]) }

// applyThrough runs a receipt for bundle n, version v, up to state stop.
func applyThrough(t *testing.T, s *Store, n int, v uint64, stop string) *Receipt {
	t.Helper()
	r, err := s.Receive(testBundleID(n), v, "")
	if err != nil {
		t.Fatal(err)
	}
	if stop == StateReceived {
		return r
	}
	if _, err := s.Stage(r, storeBundle()); err != nil {
		t.Fatal(err)
	}
	if err := s.Advance(r, StateVerified, func(r *Receipt) {
		r.TenantID, r.DeviceGroup, r.SignerKeyID, r.Principal = "t1", "eng", "k1", "control-plane:t1/alice"
		r.ManifestSHA256 = digestOf(r.ReceiptID)
	}); err != nil {
		t.Fatal(err)
	}
	if stop == StateVerified {
		return r
	}
	if _, err := s.Promote(r); err != nil {
		t.Fatal(err)
	}
	if stop == StateStaged {
		return r
	}
	if err := s.Advance(r, StateApplied, func(r *Receipt) {
		r.EffectivePolicyDigest, r.ConfigGeneration, r.AppliedAt = "sha256:"+digestOf(r.ReceiptID+"p"), 40+v, "2026-10-12T10:00:00.000Z"
	}); err != nil {
		t.Fatal(err)
	}
	if stop == StateApplied {
		return r
	}
	if _, err := s.Confirm(r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestReceiptTransitionsMoveOneStepOrFail(t *testing.T) {
	order := []string{StateReceived, StateVerified, StateStaged, StateApplied, StateConfirmed}
	for i, from := range order {
		for j, to := range append(order, StateFailed, "bogus") {
			err := CheckTransition(from, to)
			allowed := from != StateConfirmed && (to == StateFailed || j == i+1)
			if (err == nil) != allowed {
				t.Errorf("%s -> %s: err %v, allowed %v", from, to, err, allowed)
			}
		}
	}
	for _, to := range order {
		if CheckTransition(StateFailed, to) == nil || CheckTransition("bogus", to) == nil {
			t.Fatalf("a failed or unknown receipt moved to %s", to)
		}
	}
}

func TestStoreConfirmRotatesCurrentAndLastGoodAndCollectsOldVersions(t *testing.T) {
	s := testStore(t)
	first := applyThrough(t, s, 1, 3, StateConfirmed)
	second := applyThrough(t, s, 2, 4, StateConfirmed)
	third := applyThrough(t, s, 3, 9, StateConfirmed)

	st, err := s.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	if st.Current.BundleID != third.BundleID || st.LastGood.BundleID != second.BundleID || st.Floor != 9 {
		t.Fatalf("state = %+v / %+v floor %d", st.Current, st.LastGood, st.Floor)
	}
	if c := st.Confirmed(); c.BundleID != third.BundleID || c.Version != 9 || c.ManifestSHA256 != third.ManifestSHA256 {
		t.Fatalf("confirmed = %+v", c)
	}
	if _, err := os.Stat(s.VersionDir(first.Dir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the version before last_good was kept: %v", err)
	}
	for _, r := range []*Receipt{second, third} {
		if _, err := os.Stat(filepath.Join(s.VersionDir(r.Dir), "policies/guardrail/strict/pack.yaml")); err != nil {
			t.Fatalf("version dir of %s: %v", r.BundleID, err)
		}
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(filepath.Join(s.VersionDir(third.Dir), ConfigName))
		dir, _ := os.Stat(s.VersionDir(third.Dir))
		if info.Mode().Perm() != 0o444 || dir.Mode().Perm() != 0o555 {
			t.Fatalf("version dir is not read-only: %v %v", info.Mode(), dir.Mode())
		}
	}
	if entries, _ := filepath.Glob(filepath.Join(s.BundlesDir, stagingPrefix+"*")); len(entries) != 0 {
		t.Fatalf("staging left behind: %v", entries)
	}
	got, err := s.Summary()
	if err != nil || got.State != StateConfirmed || got.BundleID != third.BundleID || got.CurrentBundleID != "" ||
		got.ConfirmedAt == "" || got.EffectivePolicyDigest != third.EffectivePolicyDigest || got.ConfigGeneration != 49 {
		t.Fatalf("summary = %+v, %v", got, err)
	}
}

func TestStoreFailureKeepsTheLastGoodBundleAndFloor(t *testing.T) {
	s := testStore(t)
	good := applyThrough(t, s, 1, 5, StateConfirmed)
	bad := applyThrough(t, s, 2, 6, StateVerified)
	if err := s.Fail(bad, CodeDigestMismatch, "digest \x1b[31mmismatch\n"+strings.Repeat("x", 600)); err != nil {
		t.Fatal(err)
	}
	if err := s.Advance(bad, StateStaged, nil); err == nil {
		t.Fatal("a failed receipt moved on")
	}
	if len(bad.ErrorMessage) > MaxErrorMessage || strings.ContainsAny(bad.ErrorMessage, "\x1b\n") {
		t.Fatalf("message not bounded: %q", bad.ErrorMessage[:40])
	}
	if _, err := os.Stat(s.stagingPath(bad.ReceiptID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staging of a failed bundle kept: %v", err)
	}
	st, _ := s.LoadState()
	if st.Current.BundleID != good.BundleID || st.Floor != 5 {
		t.Fatalf("a failed bundle changed the state: %+v", st)
	}
	got, _ := s.Summary()
	if got.State != StateConfirmed || got.BundleID != good.BundleID {
		t.Fatalf("summary = %+v", got)
	}
	// The same bundle may be retried after a failure.
	retry := applyThrough(t, s, 2, 6, StateConfirmed)
	if st, _ := s.LoadState(); st.Current.BundleID != retry.BundleID || st.LastGood.BundleID != good.BundleID {
		t.Fatalf("retry state = %+v", st)
	}
	// The confirmed bundle delivered again gets a receipt of its own; the
	// confirmed receipt stays, and the block names the bundle that enforces.
	again, err := s.Receive(retry.BundleID, 6, "")
	if err != nil || again.ReceiptID == retry.ReceiptID || again.BundleID != retry.BundleID {
		t.Fatalf("re-delivered receipt = %+v, %v", again, err)
	}
	if err := s.Fail(again, CodeVersionNotNewer, "the manifest differs from the confirmed bundle"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Summary(); got.State != StateConfirmed || got.BundleID != retry.BundleID || got.Version != 6 {
		t.Fatalf("summary after a re-delivery = %+v", got)
	}
	if receipts, _ := s.Receipts(); !containsReceipt(receipts, retry.ReceiptID, StateConfirmed) {
		t.Fatal("the confirmed receipt was replaced")
	}
}

func TestRefusedReplayPreservesEnforcingReceipt(t *testing.T) {
	s := testStore(t)
	v1 := applyThrough(t, s, 1, 1, StateConfirmed)
	v2 := applyThrough(t, s, 2, 2, StateConfirmed)
	replay, err := s.Receive(v1.BundleID, 1, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Fail(replay, CodeVersionNotNewer, "older version"); err != nil {
		t.Fatal(err)
	}
	secondReplay, err := s.Receive(v1.BundleID, 1, "")
	if err != nil || secondReplay.ReceiptID == replay.ReceiptID {
		t.Fatalf("second refusal receipt = %+v, %v", secondReplay, err)
	}
	if err := s.Fail(secondReplay, CodeVersionNotNewer, "older version again"); err != nil {
		t.Fatal(err)
	}
	receipts, err := s.Receipts()
	if err != nil || !containsReceipt(receipts, replay.ReceiptID, StateFailed) {
		t.Fatalf("refusal missing: %v", err)
	}
	got, err := s.Summary()
	if err != nil || got.BundleID != v2.BundleID || got.State != StateConfirmed {
		t.Fatalf("summary = %+v, %v", got, err)
	}
	public, err := enterprisestatus.ReadPublicReceipt(s.PublicReceiptPath())
	if err != nil || public.ReceiptID != v2.ReceiptID || public.State != StateConfirmed || public.LastRefusal == nil || public.LastRefusal.ReceiptID != secondReplay.ReceiptID || public.LastRefusal.ErrorCode != string(CodeVersionNotNewer) {
		t.Fatalf("public = %+v, %v", public, err)
	}
}

func TestPrunedReceiptIDIsNotReusedWhileAuditEventRemains(t *testing.T) {
	s := testStore(t)
	id := testBundleID(85)
	first, err := s.Receive(id, 9, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Fail(first, CodeSignatureInvalid, "bad signature"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(s.receiptPath(first.ReceiptID)); err != nil {
		t.Fatal(err)
	}
	second, err := s.Receive(id, 9, "")
	if err != nil {
		t.Fatal(err)
	}
	if second.ReceiptID == first.ReceiptID {
		t.Fatal("a later delivery reused a receipt ID still present in the audit spool")
	}
}

func TestStagedFailureReplacesEnforcingReceipt(t *testing.T) {
	s := testStore(t)
	good := applyThrough(t, s, 1, 1, StateConfirmed)
	bad := applyThrough(t, s, 2, 2, StateStaged)
	if err := s.Fail(bad, CodeApplyFailed, "apply failed"); err != nil {
		t.Fatal(err)
	}
	last, refusal, err := s.Latest()
	if err != nil || last == nil || last.ReceiptID != bad.ReceiptID || refusal != nil {
		t.Fatalf("latest = %+v %+v %v", last, refusal, err)
	}
	public, err := enterprisestatus.ReadPublicReceipt(s.PublicReceiptPath())
	if err != nil || public.ReceiptID != bad.ReceiptID || public.State != StateFailed || public.CurrentBundleID != good.BundleID {
		t.Fatalf("public = %+v, %v", public, err)
	}
}

func TestSettleEndsInterruptedRunsAndFinishesAConfirmCut(t *testing.T) {
	s := testStore(t)
	good := applyThrough(t, s, 1, 2, StateConfirmed)
	received := applyThrough(t, s, 2, 3, StateReceived)
	if _, err := s.Stage(received, storeBundle()); err != nil {
		t.Fatal(err)
	}
	verified := applyThrough(t, s, 3, 4, StateVerified)
	staged := applyThrough(t, s, 4, 5, StateStaged)
	applied := applyThrough(t, s, 5, 6, StateApplied)
	if err := os.WriteFile(filepath.Join(s.LifecycleDir, "."+StateFileName+".123.tmp"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := s.Settle()
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Interrupted) != 3 || len(report.Completed) != 0 || len(report.Unconfirmed) != 1 || report.Unconfirmed[0].ReceiptID != applied.ReceiptID {
		t.Fatalf("report = %+v", report)
	}
	receipts, _ := s.Receipts()
	for _, r := range receipts {
		want := StateFailed
		switch r.ReceiptID {
		case good.ReceiptID:
			want = StateConfirmed
		case applied.ReceiptID:
			want = StateApplied
		}
		if r.State != want || (want == StateFailed && r.ErrorCode != CodeInterrupted) {
			t.Fatalf("%s: %s %s, want %s", r.ReceiptID, r.State, r.ErrorCode, want)
		}
	}
	for _, gone := range []string{s.stagingPath(received.ReceiptID), s.stagingPath(verified.ReceiptID), s.VersionDir(staged.Dir),
		filepath.Join(s.LifecycleDir, "."+StateFileName+".123.tmp")} {
		if _, err := os.Stat(gone); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s was not removed: %v", gone, err)
		}
	}
	for _, kept := range []string{s.VersionDir(good.Dir), s.VersionDir(applied.Dir)} {
		if _, err := os.Stat(kept); err != nil {
			t.Fatalf("%s was removed: %v", kept, err)
		}
	}

	// A run that wrote bundle-state.json and stopped before the receipt:
	// the next settle confirms the receipt from the state, which carries the
	// proof fields Confirm copied from that receipt.
	st, _ := s.LoadState()
	ref := &Ref{BundleID: applied.BundleID, Version: applied.Version, ManifestSHA256: applied.ManifestSHA256, Dir: applied.Dir,
		SignerKeyID: applied.SignerKeyID, EffectivePolicyDigest: applied.EffectivePolicyDigest, ConfigGeneration: applied.ConfigGeneration,
		ConfirmedAt: "2026-10-12T11:00:00.000Z"}
	if err := s.saveState(State{Current: ref, LastGood: st.Current, Floor: 6}); err != nil {
		t.Fatal(err)
	}
	report, err = s.Settle()
	if err != nil || len(report.Completed) != 1 || len(report.Unconfirmed) != 0 {
		t.Fatalf("second settle = %+v, %v", report, err)
	}
	if got, _ := s.Summary(); got.State != StateConfirmed || got.BundleID != applied.BundleID || got.ConfirmedAt != ref.ConfirmedAt {
		t.Fatalf("summary = %+v", got)
	}
}

// Unsettled lists, read-only, what Settle would finish: the receipts no
// run finished. Status reports them as a pending transaction (GAP-0028).
func TestUnsettledListsUnfinishedReceiptsWithoutSettling(t *testing.T) {
	s := testStore(t)
	if got, err := s.Unsettled(); err != nil || len(got) != 0 || UnsettledMessage(got, "ensure") != "" {
		t.Fatalf("empty store: %v, %v", got, err)
	}
	applyThrough(t, s, 1, 2, StateConfirmed)
	if got, err := s.Unsettled(); err != nil || len(got) != 0 {
		t.Fatalf("confirmed only: %v, %v", got, err)
	}
	applied := applyThrough(t, s, 2, 3, StateApplied)
	staged, err := s.Receive(testBundleID(3), 4, "agent:crash-v4")
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Unsettled()
	if err != nil || len(got) != 2 || got[0].ReceiptID != staged.ReceiptID || got[1].ReceiptID != applied.ReceiptID {
		t.Fatalf("unsettled = %+v, %v", got, err)
	}
	message := UnsettledMessage(got, "defenseclaw-gateway enterprise linux ensure")
	for _, want := range []string{staged.ReceiptID, "delivery agent:crash-v4", "is received", "1 older unfinished", "enterprise linux ensure"} {
		if !strings.Contains(message, want) {
			t.Fatalf("message %q lacks %q", message, want)
		}
	}
	if rc := receiptByID(t, s, staged.ReceiptID); rc.State != StateReceived {
		t.Fatalf("Unsettled changed the receipt: %+v", rc)
	}
	if _, err := s.Settle(); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Unsettled(); err != nil || len(got) != 1 || got[0].ReceiptID != applied.ReceiptID {
		t.Fatalf("after settle (applied stays for the caller): %+v, %v", got, err)
	}
}

func receiptByID(t *testing.T, s *Store, id string) *Receipt {
	t.Helper()
	receipts, err := s.Receipts()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range receipts {
		if r.ReceiptID == id {
			return r
		}
	}
	t.Fatalf("no receipt %s", id)
	return nil
}

func TestStoreRefusesAStateThatWouldLowerTheFloor(t *testing.T) {
	s := testStore(t)
	if err := os.MkdirAll(s.LifecycleDir, 0o700); err != nil {
		t.Fatal(err)
	}
	ok := `{"schema_version":1,"current":{"bundle_id":"` + testBundleID(1) + `","version":4,"manifest_sha256":"` + digestOf("x") +
		`","dir":"` + VersionDirName(4, testBundleID(1)) + `"},"floor":4}`
	for name, body := range map[string]string{
		"truncated":       ok[:40],
		"no schema":       `{"floor":3}`,
		"floor below":     strings.Replace(ok, `"floor":4`, `"floor":2`, 1),
		"dir mismatch":    strings.Replace(ok, VersionDirName(4, testBundleID(1)), "../etc", 1),
		"bad manifest id": strings.Replace(ok, digestOf("x"), "abc", 1),
	} {
		if err := os.WriteFile(s.StatePath(), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := s.LoadState(); err == nil {
			t.Fatalf("%s: state accepted", name)
		}
		if _, err := s.Settle(); err == nil {
			t.Fatalf("%s: settle ran on an unreadable state", name)
		}
	}
	if err := os.WriteFile(s.StatePath(), []byte(ok), 0o600); err != nil {
		t.Fatal(err)
	}
	if st, err := s.LoadState(); err != nil || st.Confirmed().Version != 4 {
		t.Fatalf("valid state: %+v, %v", st, err)
	}
}

func TestReceiptVersionDirectoryNameIsFoundAndCollected(t *testing.T) {
	s := testStore(t)
	name := VersionDirNameForReceipt(1, testBundleID(1), "b-01M4VBXHT0DS0QNK83AKADPAK8")
	if !IsVersionDirName(name) {
		t.Fatalf("receipt-specific version directory %q was not recognized", name)
	}
	if got := VersionDirsNamed([]byte(filepath.Join(s.VersionDir(name), "policies", "rule.yaml")), s.BundlesDir); len(got) != 1 || got[0] != name {
		t.Fatalf("config references resolved to %q, want %q", got, name)
	}
	if err := os.MkdirAll(s.VersionDir(name), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.gc(State{}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.VersionDir(name)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unheld immutable version directory was not collected: %v", err)
	}
}

func TestReceiptsArePrunedAndUnreadableBundlesGetAReceipt(t *testing.T) {
	s := testStore(t)
	open := applyThrough(t, s, 1, 1, StateReceived)
	for i := 0; i < MaxReceipts+5; i++ {
		r, err := s.Receive("", 0, "")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(r.ReceiptID, "r-") || r.BundleID != "" {
			t.Fatalf("unreadable bundle receipt = %+v", r)
		}
		if err := s.Fail(r, CodeArchiveInvalid, "not a gzip stream"); err != nil {
			t.Fatal(err)
		}
	}
	receipts, _ := s.Receipts()
	if len(receipts) != MaxReceipts+1 {
		t.Fatalf("kept %d receipts, want %d (the unfinished one is never pruned)", len(receipts), MaxReceipts+1)
	}
	found := false
	for _, r := range receipts {
		found = found || r.ReceiptID == open.ReceiptID
	}
	if !found {
		t.Fatal("the unfinished receipt was pruned")
	}
	if got, _ := s.Summary(); got != nil {
		t.Fatalf("summary = %+v", got)
	}
}

func TestStageRefusesPathsOutsideTheBundle(t *testing.T) {
	s := testStore(t)
	r := applyThrough(t, s, 1, 1, StateReceived)
	b := storeBundle()
	b.Files["../escape.yaml"] = []byte("x")
	if _, err := s.Stage(r, b); err == nil {
		t.Fatal("a path outside the bundle was staged")
	}
	if _, err := os.Stat(filepath.Join(s.BundlesDir, "..", "escape.yaml")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("file written outside the store: %v", err)
	}
}

func TestStorePromotedTreeHasServiceGroupReadOnlyModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix mode bits and group ownership do not describe Windows ACLs; the Windows bundle ACL tests cover that platform")
	}
	s := testStore(t)
	const serviceGID = 4242
	owned := map[string][2]int{}
	s.SealVersion = func(root string) error {
		return SealVersionForGroup(root, serviceGID, func(path string, uid, gid int) error {
			owned[path] = [2]int{uid, gid}
			return nil
		})
	}
	r := applyThrough(t, s, 7, 7, StateReceived)
	staging, err := s.Stage(r, storeBundle())
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(staging); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("private staging directory: %v, %v", info, err)
	}
	if err := s.Advance(r, StateVerified, nil); err != nil {
		t.Fatal(err)
	}
	version, err := s.Promote(r)
	if err != nil {
		t.Fatal(err)
	}
	if r.State != StateStaged || r.Dir != VersionDirNameForReceipt(7, r.BundleID, r.ReceiptID) {
		t.Fatalf("promoted receipt: %+v", r)
	}
	err = filepath.WalkDir(version, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		want := os.FileMode(0o640)
		if entry.IsDir() {
			want = 0o750
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode().Perm() != want {
			t.Errorf("%s mode %04o, want %04o", path, info.Mode().Perm(), want)
		}
		staged := strings.Replace(path, version, staging, 1)
		if got := owned[staged]; got != [2]int{0, serviceGID} {
			t.Errorf("%s owner call %v, want root:%d", path, got, serviceGID)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{s.LifecycleDir, s.receiptsDir()} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o700 {
			t.Fatalf("private lifecycle directory %s: %v, %v", path, info, err)
		}
	}
	if info, err := os.Stat(s.receiptPath(r.ReceiptID)); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("private receipt: %v, %v", info, err)
	}
}

// The status block of every receipt state validates against the closed
// lifecycle-result schema (also checked in enterprisestatus).
func TestReceiptStatusFieldsMatchTheResultBlock(t *testing.T) {
	r := &Receipt{BundleID: testBundleID(2), Version: 3, State: StateFailed, ErrorCode: CodeInterrupted}
	got := r.Status(&Ref{BundleID: testBundleID(1), Version: 2})
	want := &enterprisestatus.BundleState{BundleID: testBundleID(2), Version: 3, State: StateFailed, ErrorCode: "interrupted",
		CurrentBundleID: testBundleID(1), CurrentVersion: 2}
	if !reflect.DeepEqual(*got, *want) {
		t.Fatalf("status = %+v", got)
	}
}

// The bundle block names the receipt it reports (receipt_id): the file name
// of the public receipt a management agent forwards.
func TestReceiptStatusNamesItsReceipt(t *testing.T) {
	r := &Receipt{ReceiptID: "r-01JA0000000000000000000009", BundleID: testBundleID(2), Version: 3, State: StateConfirmed}
	if got := r.Status(nil); got.ReceiptID != r.ReceiptID {
		t.Fatalf("receipt_id = %q, want %q", got.ReceiptID, r.ReceiptID)
	}
}

// With no receipt left (pruned), the summary of the current bundle names
// the receipt that promoted it, from its version directory name. A legacy
// directory name carries no receipt id, so none is reported.
func TestSummaryOfTheCurrentBundleNamesItsConfirmedReceipt(t *testing.T) {
	id := testBundleID(4)
	for name, tc := range map[string]struct{ dir, want string }{
		"receipt directory": {VersionDirNameForReceipt(4, id, "r-01JA0000000000000000000004"), "r-01JA0000000000000000000004"},
		"legacy directory":  {VersionDirName(4, id), ""},
	} {
		t.Run(name, func(t *testing.T) {
			s := testStore(t)
			if err := s.saveState(State{Current: &Ref{BundleID: id, Version: 4, ManifestSHA256: digestOf(id), Dir: tc.dir}, Floor: 4}); err != nil {
				t.Fatal(err)
			}
			got, err := s.Summary()
			if err != nil || got == nil || got.ReceiptID != tc.want || got.State != StateConfirmed {
				t.Fatalf("summary = %+v, %v; want receipt_id %q", got, err, tc.want)
			}
		})
	}
}

// A repeated delivery of the current bundle reports the current confirmed
// receipt, also when a newer delivery failed after staging and is the
// latest receipt Summary reports, and after the confirmed receipt was
// pruned.
func TestCurrentSummaryReportsTheConfirmedReceiptPastANewerFailure(t *testing.T) {
	s := testStore(t)
	if got, err := s.CurrentSummary(); err != nil || got != nil {
		t.Fatalf("no current bundle: %+v, %v", got, err)
	}
	v1 := applyThrough(t, s, 1, 1, StateConfirmed)
	v2 := applyThrough(t, s, 2, 2, StateStaged)
	if err := s.Fail(v2, CodeApplyFailed, "the gateway did not adopt it"); err != nil {
		t.Fatal(err)
	}
	if latest, err := s.Summary(); err != nil || latest == nil || latest.ReceiptID != v2.ReceiptID || latest.State != StateFailed {
		t.Fatalf("summary = %+v, %v; want the failed v2 receipt", latest, err)
	}
	got, err := s.CurrentSummary()
	if err != nil || got == nil || got.ReceiptID != v1.ReceiptID || got.BundleID != v1.BundleID || got.State != StateConfirmed ||
		got.CurrentBundleID != "" || got.ConfirmedAt == "" {
		t.Fatalf("current summary = %+v, %v; want the confirmed v1 receipt %s", got, err, v1.ReceiptID)
	}
	if err := os.Remove(s.receiptPath(v1.ReceiptID)); err != nil {
		t.Fatal(err)
	}
	got, err = s.CurrentSummary()
	if err != nil || got == nil || got.ReceiptID != v1.ReceiptID || got.BundleID != v1.BundleID || got.State != StateConfirmed {
		t.Fatalf("current summary after prune = %+v, %v; want receipt_id %s", got, err, v1.ReceiptID)
	}
}

// The state's record of the confirmed bundle keeps the delivery_id and
// restart_required its receipt reported, so a repeated delivery reports them
// also after that receipt was pruned.
func TestCurrentSummaryAfterPruneKeepsDeliveryIDAndRestartRequired(t *testing.T) {
	s := testStore(t)
	v1 := applyThrough(t, s, 1, 1, StateApplied)
	v1.DeliveryID, v1.RestartRequired = "acme-agent:d-000913", true
	if _, err := s.Confirm(v1); err != nil {
		t.Fatal(err)
	}
	for _, stage := range []string{"confirmed receipt", "after prune"} {
		if stage == "after prune" {
			if err := os.Remove(s.receiptPath(v1.ReceiptID)); err != nil {
				t.Fatal(err)
			}
		}
		got, err := s.CurrentSummary()
		if err != nil || got == nil || got.ReceiptID != v1.ReceiptID || got.DeliveryID != v1.DeliveryID || !got.RestartRequired {
			t.Fatalf("%s: current summary = %+v, %v; want receipt %s, delivery_id %s, restart_required", stage, got, err, v1.ReceiptID, v1.DeliveryID)
		}
	}

	st, err := s.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	st.Current.DeliveryID = "agent 7"
	if err := s.saveState(st); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadState(); err == nil || !strings.Contains(err.Error(), "delivery_id") {
		t.Fatalf("a state with a bad current delivery_id loaded: %v", err)
	}
}

// A process killed while it rewrites bundle-state.json leaves either the old
// or the new state, never a torn or empty one; settle removes the temp file.
func TestBundleStateSurvivesAKillDuringTheWrite(t *testing.T) {
	if dir := os.Getenv("DC_BUNDLE_STATE_CRASH_DIR"); dir != "" {
		s := NewStore(filepath.Join(dir, "bundles"), dir)
		for v := uint64(2); ; v++ {
			id := testBundleID(int(v))
			ref := &Ref{BundleID: id, Version: v, ManifestSHA256: digestOf(id), Dir: VersionDirName(v, id)}
			if err := s.saveState(State{Current: ref, Floor: v}); err != nil {
				fmt.Println("error", err)
				os.Exit(3)
			}
			if v == 2 {
				fmt.Println("ready")
			}
		}
	}
	dir := t.TempDir()
	s := NewStore(filepath.Join(dir, "bundles"), dir)
	id := testBundleID(1)
	if err := s.saveState(State{Current: &Ref{BundleID: id, Version: 1, ManifestSHA256: digestOf(id), Dir: VersionDirName(1, id)}, Floor: 1}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		cmd := exec.Command(os.Args[0], "-test.run=^TestBundleStateSurvivesAKillDuringTheWrite$", "-test.count=1")
		cmd.Env = append(os.Environ(), "DC_BUNDLE_STATE_CRASH_DIR="+dir)
		out, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		line, _ := bufio.NewReader(out).ReadString('\n')
		if strings.TrimSpace(line) != "ready" {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			t.Fatalf("writer did not start: %q", line)
		}
		time.Sleep(time.Duration(5+rand.IntN(40)) * time.Millisecond)
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		st, err := s.LoadState()
		if err != nil || st.Current == nil || st.Floor != st.Current.Version || st.Current.Version < 1 {
			t.Fatalf("after kill %d: state %+v, %v", i, st, err)
		}
	}
	if _, err := s.Settle(); err != nil {
		t.Fatal(err)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".*.tmp")); len(left) != 0 {
		t.Fatalf("temp files left after settle: %v", left)
	}
}

func containsReceipt(receipts []*Receipt, id, state string) bool {
	for _, r := range receipts {
		if r.ReceiptID == id && r.State == state {
			return true
		}
	}
	return false
}

// A bundle delivered again while its applied receipt waits for settle gets a
// receipt of its own and its own version directory, leaving the installed
// config's directory intact; a confirm never lowers the floor.
func TestStoreKeepsAnAppliedBundleAndTheFloorOnARetry(t *testing.T) {
	s := testStore(t)
	applyThrough(t, s, 1, 4, StateConfirmed)
	applied := applyThrough(t, s, 5, 6, StateApplied)

	again, err := s.Receive(applied.BundleID, applied.Version, "")
	if err != nil {
		t.Fatal(err)
	}
	if again.ReceiptID == applied.ReceiptID || !strings.HasPrefix(again.ReceiptID, "r-") {
		t.Fatalf("redelivery took receipt id %s", again.ReceiptID)
	}
	if _, err := s.Stage(again, storeBundle()); err != nil {
		t.Fatal(err)
	}
	if err := s.Advance(again, StateVerified, func(r *Receipt) { r.ManifestSHA256 = applied.ManifestSHA256 }); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Promote(again); err != nil || again.Dir == applied.Dir {
		t.Fatalf("retry did not get a fresh version directory: %v, %s", err, again.Dir)
	}
	if _, err := os.Stat(filepath.Join(s.VersionDir(applied.Dir), ConfigName)); err != nil {
		t.Fatalf("applied version directory lost its config: %v", err)
	}
	if report, err := s.Settle(); err != nil || len(report.Unconfirmed) != 1 || report.Unconfirmed[0].ReceiptID != applied.ReceiptID {
		t.Fatalf("settle = %+v, %v", report, err)
	}

	older := applyThrough(t, s, 7, 3, StateApplied)
	var refusal *Error
	if _, err := s.Confirm(older); !errors.As(err, &refusal) || refusal.Code != CodeVersionNotNewer {
		t.Fatalf("confirm below the floor: %v", err)
	}
	if st, _ := s.LoadState(); st.Floor != 4 || st.Current.BundleID != testBundleID(1) {
		t.Fatalf("state after a refused confirm = %+v", st)
	}
	st := State{Current: &Ref{BundleID: testBundleID(1), Version: 4}, Floor: 9}
	if got := st.Confirmed().Version; got != 9 {
		t.Fatalf("confirmed version = %d, want the floor 9", got)
	}
}
