// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/fsnotify/fsnotify"
)

// GAP-0045: a loop that rewrote only the Hermes hooks block in place reached
// a repair at the interval pass, 71 s later: the watch loop ignored every
// Write to a shared agent config. GAP-0044: an in-place overwrite of the
// scoped token right after a pass fell in the settle window and waited 24 s.
// A Write the writer policy or the settle window drops now counts when the
// file no longer holds what the last pass left there, and a pass's own tail
// (same bytes) is still dropped.
func TestEnterpriseHookWatchOwnedFileChangedSeesInPlaceRewrites(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "config.yaml")
	token := filepath.Join(dir, ".hook-hermes.token")
	other := filepath.Join(dir, "state.db")
	write := func(path, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(config, "hooks:\n  pre_tool_call:\n  - command: defenseclaw\n")
	write(token, "issued\n")
	write(other, "x")
	exclusive := map[string]struct{}{token: {}}
	shared := map[string]struct{}{config: {}}
	snapshot := map[string]string{}
	takeEnterpriseHookOwnedSnapshot(snapshot, exclusive, shared, enterprisehooks.OwnedFileFingerprint)
	changed := func(path string) bool {
		return enterpriseHookWatchOwnedFileChanged(path, exclusive, shared, snapshot, enterprisehooks.OwnedFileFingerprint)
	}

	// The writer policy still drops a shared Write; the content check is what lets it through.
	if enterpriseHookWatchOwnedEventActionable(fsnotify.Event{Name: config, Op: fsnotify.Write}, exclusive, shared) {
		t.Fatal("a shared-writer Write became actionable by policy alone")
	}
	if changed(config) || changed(token) {
		t.Fatal("files as the pass left them read as changed (the pass's own tail)")
	}
	write(config, "hooks: {}\n")
	if !changed(config) {
		t.Fatal("an in-place rewrite of the shared agent config was not seen (GAP-0045)")
	}
	if runtime.GOOS != "windows" {
		// Windows fingerprints metadata, so only there a rewrite of the
		// same bytes counts as a change.
		write(config, "hooks:\n  pre_tool_call:\n  - command: defenseclaw\n")
		if changed(config) {
			t.Fatal("a rewrite back to the same bytes read as changed")
		}
	}
	write(token, "lane-made-longer\n")
	if !changed(token) {
		t.Fatal("an in-place token overwrite was not seen (GAP-0044)")
	}
	if changed(other) {
		t.Fatal("an unowned file counted")
	}
	// An owned file the last pass did not fingerprint counts as changed.
	added := filepath.Join(dir, ".hookcfg.hermes")
	exclusive[added] = struct{}{}
	if !changed(added) {
		t.Fatal("an owned file without a snapshot did not count")
	}
	// The next pass's snapshot takes in what it left.
	takeEnterpriseHookOwnedSnapshot(snapshot, exclusive, shared, enterprisehooks.OwnedFileFingerprint)
	if changed(token) || changed(added) {
		t.Fatal("a fresh snapshot still reads changed")
	}
}

// GAP-0030: while a Hermes repair kept failing, each pass wrote the
// allowlist backup receipt and its rollback removed it again; the receipt's
// Create|Remove armed the next pass a second later, so the repair backoff
// never applied (34 passes in 34 s). An exclusive-writer Create, Remove or
// Rename in the settle window that left the file as the pass found it and
// left it is that pass's own tail; a change made during or after the pass
// still reconciles, and shared agent configs are never judged this way.
func TestEnterpriseHookWatchDropsAPassOwnMadeAndDroppedReceipt(t *testing.T) {
	dir := t.TempDir()
	receipt := filepath.Join(dir, "connector_backups", "hermes", "shell-hooks-allowlist.json.json")
	script := filepath.Join(dir, "hooks", "hermes-hook.sh")
	config := filepath.Join(dir, "config.yaml")
	for _, path := range []string{script, config} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("v1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	exclusive := map[string]struct{}{receipt: {}, script: {}}
	shared := map[string]struct{}{config: {}}
	found := map[string]string{}
	left := map[string]string{}
	// The pass found the receipt absent and, after its rollback, left it absent.
	takeEnterpriseHookOwnedSnapshot(found, exclusive, shared, enterprisehooks.OwnedFileFingerprint)
	takeEnterpriseHookOwnedSnapshot(left, exclusive, shared, enterprisehooks.OwnedFileFingerprint)
	now := time.Now()
	settleUntil := now.Add(2 * time.Second)
	tail := func(path string, op fsnotify.Op, at time.Time) bool {
		return enterpriseHookWatchExclusiveTailUnchanged(at, settleUntil, fsnotify.Event{Name: path, Op: op}, exclusive, found, left, enterprisehooks.OwnedFileFingerprint)
	}
	for _, op := range []fsnotify.Op{fsnotify.Create, fsnotify.Remove, fsnotify.Create | fsnotify.Remove} {
		if !tail(receipt, op, now) {
			t.Fatalf("the pass's own made-and-dropped receipt (%s) armed another pass (GAP-0030)", op)
		}
	}
	if tail(receipt, fsnotify.Create, settleUntil.Add(time.Millisecond)) {
		t.Fatal("an event after the settle window was judged a tail")
	}
	if tail(config, fsnotify.Create, now) {
		t.Fatal("a shared agent config replacement was judged a tail")
	}
	// A pass that changed the file (made the receipt and kept it) still reconciles.
	if err := os.MkdirAll(filepath.Dir(receipt), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(receipt, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	takeEnterpriseHookOwnedSnapshot(left, exclusive, shared, enterprisehooks.OwnedFileFingerprint)
	if tail(receipt, fsnotify.Create, now) {
		t.Fatal("a receipt the pass created and kept was judged unchanged")
	}
	// A tamper after the pass (the hook script removed in the window) still reconciles.
	if err := os.Remove(script); err != nil {
		t.Fatal(err)
	}
	if tail(script, fsnotify.Remove, now) {
		t.Fatal("a hook script removed after the pass was judged the pass's tail")
	}
	// A file the pass did not fingerprint before is not judged.
	added := filepath.Join(dir, "hooks", ".hookcfg.hermes")
	exclusive[added] = struct{}{}
	if tail(added, fsnotify.Create, now) {
		t.Fatal("an owned file without a found fingerprint was judged a tail")
	}
}
