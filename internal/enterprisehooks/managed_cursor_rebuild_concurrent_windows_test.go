// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"golang.org/x/sys/windows"
)

// A Cursor guard rebuild snapshots its artifacts when the transaction starts,
// but Cursor and administrators do not take the DefenseClaw lock. Each write
// is a compare-and-swap that publishes only over the file the rebuild read.
// When another writer changed a file in between, the newer file is kept, the
// rebuild undoes its other writes and starts again from what is on disk: an
// administrator's hooks.json edit is kept with the registration merged into
// it, a changed file DefenseClaw owns is rebuilt, an edit that is not JSON
// stops the rebuild, and an undo never puts a preimage back over a newer save.
func TestWindowsCursorMachineGuardRebuildKeepsConcurrentChanges(t *testing.T) {
	const hook = `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`
	adminHooks := []byte(`{"version":1,"hooks":{"adminEvent":[{"type":"command","command":"admin-concurrent-hook"}]}}`)
	type files struct{ hooks, adapter, state, receipt []byte }
	read := func(t *testing.T, paths windowsCursorPaths) files {
		t.Helper()
		var result files
		for path, target := range map[string]*[]byte{paths.Hooks: &result.hooks, paths.Adapter: &result.adapter, paths.State: &result.state, paths.Receipt: &result.receipt} {
			data, err := os.ReadFile(path)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
			*target = data
		}
		return result
	}
	write := func(t *testing.T, path string, data []byte) {
		t.Helper()
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// beforeWrite runs edit once, just before the rebuild re-reads path.
	beforeWrite := func(t *testing.T, path string, edit func()) {
		t.Helper()
		previous := windowsCursorManagedGuardRebuildBeforeWrite
		done := false
		windowsCursorManagedGuardRebuildBeforeWrite = func(target string) {
			if !done && strings.EqualFold(target, path) {
				done = true
				edit()
			}
		}
		t.Cleanup(func() { windowsCursorManagedGuardRebuildBeforeWrite = previous })
	}
	failOpen := func(t *testing.T, paths windowsCursorPaths) {
		data, err := os.ReadFile(paths.Hooks)
		if err != nil {
			t.Fatal(err)
		}
		var document map[string]any
		if err := json.Unmarshal(data, &document); err != nil {
			t.Fatal(err)
		}
		events, _ := document["hooks"].(map[string]any)
		for _, raw := range events {
			entries, _ := raw.([]any)
			for _, entry := range entries {
				if hookEntry, ok := entry.(map[string]any); ok && hookEntry["failClosed"] == true {
					hookEntry["failClosed"] = false
				}
			}
		}
		edited, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		write(t, paths.Hooks, edited)
	}
	hooksDamage := []struct {
		name  string
		apply func(t *testing.T, paths windowsCursorPaths)
	}{
		{"hooks.json missing", func(t *testing.T, paths windowsCursorPaths) {
			if err := os.Remove(paths.Hooks); err != nil {
				t.Fatal(err)
			}
		}},
		{"hooks.json replaced", func(t *testing.T, paths windowsCursorPaths) {
			write(t, paths.Hooks, []byte(`{"version":1,"hooks":{"operatorEvent":[{"type":"command","command":"operator-hook"}]}}`))
		}},
		{"registration fails open", failOpen},
		{"hooks.json not JSON", func(t *testing.T, paths windowsCursorPaths) {
			write(t, paths.Hooks, []byte("{ not json"))
		}},
	}
	for _, enrolled := range []bool{false, true} {
		for _, hooksCase := range hooksDamage {
			for _, removeAdapter := range []bool{false, true} {
				name := map[bool]string{false: "empty", true: "Alice"}[enrolled] + "/" + hooksCase.name +
					map[bool]string{false: "/adapter intact", true: "/adapter missing"}[removeAdapter]
				t.Run("administrator edit is kept/"+name, func(t *testing.T) {
					paths := installWindowsCursorStandaloneGuardForTest(t, hook, enrolled)
					targetsBefore, _, err := ReadWindowsCursorManagedPolicyTargets()
					if err != nil {
						t.Fatal(err)
					}
					hooksCase.apply(t, paths)
					if removeAdapter {
						if err := os.Remove(paths.Adapter); err != nil {
							t.Fatal(err)
						}
					}
					beforeWrite(t, paths.Hooks, func() { write(t, paths.Hooks, adminHooks) })
					restored, err := RestoreWindowsCursorManagedAdapter(hook)
					if err != nil || !restored {
						t.Fatalf("rebuild: restored=%t err=%v", restored, err)
					}
					hooksAfter, err := os.ReadFile(paths.Hooks)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Contains(hooksAfter, []byte("admin-concurrent-hook")) {
						t.Fatalf("the rebuild discarded the administrator's concurrent hooks.json edit: %s", hooksAfter)
					}
					if err := connector.VerifyWindowsCursorEnterpriseHooks(hooksAfter, paths.Adapter, "closed"); err != nil {
						t.Fatalf("rebuilt registration is not the closed guard: %v", err)
					}
					targets, active, err := ReadWindowsCursorManagedPolicyTargets()
					if err != nil || !active || !slices.Equal(targets, targetsBefore) {
						t.Fatalf("rebuilt guard: active=%t targets=%v (want %v) err=%v", active, targets, targetsBefore, err)
					}
				})
			}
		}
	}

	t.Run("administrator attribute change is kept", func(t *testing.T) {
		paths := installWindowsCursorStandaloneGuardForTest(t, hook, true)
		hooksDamage[1].apply(t, paths)
		beforeWrite(t, paths.Hooks, func() {
			pointer, err := windows.UTF16PtrFromString(paths.Hooks)
			if err != nil {
				t.Fatal(err)
			}
			attributes, err := windows.GetFileAttributes(pointer)
			if err != nil {
				t.Fatal(err)
			}
			if err := windows.SetFileAttributes(pointer, attributes|windows.FILE_ATTRIBUTE_NOT_CONTENT_INDEXED); err != nil {
				t.Fatal(err)
			}
		})
		if restored, err := RestoreWindowsCursorManagedAdapter(hook); err != nil || !restored {
			t.Fatalf("rebuild: restored=%t err=%v", restored, err)
		}
		pointer, err := windows.UTF16PtrFromString(paths.Hooks)
		if err != nil {
			t.Fatal(err)
		}
		attributes, err := windows.GetFileAttributes(pointer)
		if err != nil {
			t.Fatal(err)
		}
		if attributes&windows.FILE_ATTRIBUTE_NOT_CONTENT_INDEXED == 0 {
			t.Fatal("the rebuild put back the snapshot's attributes over the administrator's concurrent change")
		}
		if _, active, err := ReadWindowsCursorManagedPolicyTargets(); err != nil || !active {
			t.Fatalf("rebuilt guard: active=%t err=%v", active, err)
		}
	})

	t.Run("administrator edit that is not JSON stops the rebuild", func(t *testing.T) {
		paths := installWindowsCursorStandaloneGuardForTest(t, hook, true)
		for _, path := range []string{paths.Hooks, paths.Adapter} {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}
		before := read(t, paths)
		partial := []byte(`{"version":1,"hooks":{"adminEvent":[`)
		beforeWrite(t, paths.Hooks, func() { write(t, paths.Hooks, partial) })
		if restored, err := RestoreWindowsCursorManagedAdapter(hook); err == nil || restored {
			t.Fatalf("rebuild over a concurrent invalid edit: restored=%t err=%v", restored, err)
		}
		after := read(t, paths)
		if !bytes.Equal(after.hooks, partial) {
			t.Fatalf("the rebuild replaced the administrator's concurrent hooks.json: %q", after.hooks)
		}
		if !bytes.Equal(after.adapter, before.adapter) || !bytes.Equal(after.state, before.state) || !bytes.Equal(after.receipt, before.receipt) {
			t.Fatal("a stopped rebuild left a partly rebuilt guard")
		}
	})

	// swapHook runs edit around the rebuild's swaps of path: before reports a
	// call before the swap, after one after it. edit returns whether it ran.
	swapHook := func(t *testing.T, path string, edit func(request windowsCursorManagedSwap, before bool) bool) {
		t.Helper()
		swap := windowsCursorManagedFileSwap
		windowsCursorManagedFileSwap = func(request windowsCursorManagedSwap) (windowsCursorManagedSwapResult, error) {
			if !strings.EqualFold(request.path, path) {
				return swap(request)
			}
			edit(request, true)
			result, err := swap(request)
			edit(request, false)
			return result, err
		}
		t.Cleanup(func() { windowsCursorManagedFileSwap = swap })
	}
	damaged := func(t *testing.T) (windowsCursorPaths, files) {
		t.Helper()
		paths := installWindowsCursorStandaloneGuardForTest(t, hook, true)
		for _, path := range []string{paths.Hooks, paths.Adapter} {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}
		return paths, read(t, paths)
	}
	requireRebuiltWithAdminHook := func(t *testing.T, paths windowsCursorPaths) {
		t.Helper()
		hooksAfter, err := os.ReadFile(paths.Hooks)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(hooksAfter, []byte("admin-concurrent-hook")) {
			t.Fatalf("the rebuild discarded the administrator's concurrent hooks.json edit: %s", hooksAfter)
		}
		if err := connector.VerifyWindowsCursorEnterpriseHooks(hooksAfter, paths.Adapter, "closed"); err != nil {
			t.Fatalf("rebuilt registration is not the closed guard: %v", err)
		}
		if _, active, err := ReadWindowsCursorManagedPolicyTargets(); err != nil || !active {
			t.Fatalf("rebuilt guard: active=%t err=%v", active, err)
		}
	}

	t.Run("an edit between the last read and the swap is kept", func(t *testing.T) {
		paths, _ := damaged(t)
		done := false
		swapHook(t, paths.Hooks, func(_ windowsCursorManagedSwap, before bool) bool {
			if before && !done {
				done = true
				write(t, paths.Hooks, adminHooks)
			}
			return done
		})
		if restored, err := RestoreWindowsCursorManagedAdapter(hook); err != nil || !restored {
			t.Fatalf("rebuild: restored=%t err=%v", restored, err)
		}
		requireRebuiltWithAdminHook(t, paths)
	})

	t.Run("an edit made after the hooks.json swap is kept and the rebuild starts again", func(t *testing.T) {
		paths, _ := damaged(t)
		done := false
		swapHook(t, paths.Hooks, func(_ windowsCursorManagedSwap, before bool) bool {
			if !before && !done {
				done = true
				// The administrator saves over the rebuilt file before the
				// rebuild validates it.
				write(t, paths.Hooks, adminHooks)
			}
			return done
		})
		if restored, err := RestoreWindowsCursorManagedAdapter(hook); err != nil || !restored {
			t.Fatalf("rebuild overtaken by a concurrent edit: restored=%t err=%v", restored, err)
		}
		requireRebuiltWithAdminHook(t, paths)
	})

	t.Run("an undo puts a preimage back only over the rebuild's bytes", func(t *testing.T) {
		paths := installWindowsCursorStandaloneGuardForTest(t, hook, true)
		ours := []byte(`{"version":1,"hooks":{"stop":[]}}`)
		for _, preimageExisted := range []bool{true, false} {
			if preimageExisted {
				write(t, paths.Hooks, []byte(`{"version":1,"hooks":{}}`))
			} else if err := os.Remove(paths.Hooks); err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
			preimage, err := readWindowsCursorSharedHooks(paths.Hooks)
			if err != nil {
				t.Fatal(err)
			}
			publish := func() safefile.SharedFileWrite {
				t.Helper()
				written, err := publishWindowsCursorManagedHooks(preimage, func(safefile.SharedFile) (safefile.SharedEdit, error) {
					return safefile.SharedEdit{Data: ours}, nil
				})
				if err != nil || !written.Written {
					t.Fatalf("publish: written=%t err=%v", written.Written, err)
				}
				return written
			}
			written := publish()
			if err := undoWindowsCursorManagedHooks(written, nil); err != nil {
				t.Fatalf("undo over the rebuild's own bytes: %v", err)
			}
			if now, err := readWindowsCursorSharedHooks(paths.Hooks); err != nil || !now.Same(preimage) {
				t.Fatalf("undo did not put the preimage back: %+v err=%v", now, err)
			}
			written = publish()
			// The administrator saves after the rebuild wrote.
			write(t, paths.Hooks, adminHooks)
			if err := undoWindowsCursorManagedHooks(written, nil); !errors.Is(err, errWindowsCursorManagedConcurrentChange) {
				t.Fatalf("undo over a newer save: %v", err)
			}
			if now := read(t, paths); !bytes.Equal(now.hooks, adminHooks) {
				t.Fatalf("undo discarded a newer save (preimage existed %t): %q", preimageExisted, now.hooks)
			}
		}
	})

	t.Run("a concurrent change to an owned artifact is rebuilt", func(t *testing.T) {
		paths, _ := damaged(t)
		concurrent := []byte("exit 0\r\n")
		beforeWrite(t, paths.Adapter, func() { write(t, paths.Adapter, concurrent) })
		if restored, err := RestoreWindowsCursorManagedAdapter(hook); err != nil || !restored {
			t.Fatalf("rebuild over a concurrent adapter: restored=%t err=%v", restored, err)
		}
		after := read(t, paths)
		if bytes.Equal(after.adapter, concurrent) || after.hooks == nil {
			t.Fatalf("the rebuild kept a changed adapter: adapter=%q hooks=%q", after.adapter, after.hooks)
		}
		if _, active, err := ReadWindowsCursorManagedPolicyTargets(); err != nil || !active {
			t.Fatalf("rebuilt guard: active=%t err=%v", active, err)
		}
	})

	t.Run("a writer that never stops: the rebuild gives up and keeps the last save", func(t *testing.T) {
		paths, before := damaged(t)
		saves := 0
		var last []byte
		swapHook(t, paths.Hooks, func(request windowsCursorManagedSwap, before bool) bool {
			if before && bytes.Contains(request.data, []byte("EncodedCommand")) {
				saves++
				last = []byte(fmt.Sprintf(`{"version":1,"hooks":{"adminEvent":[{"type":"command","command":"admin-save-%d"}]}}`, saves))
				write(t, paths.Hooks, last)
			}
			return true
		})
		restored, err := RestoreWindowsCursorManagedAdapter(hook)
		if err == nil || restored || !errors.Is(err, errWindowsCursorManagedConcurrentChange) {
			t.Fatalf("rebuild against a writer that never stops: restored=%t err=%v", restored, err)
		}
		if saves != windowsCursorManagedGuardRebuildAttempts {
			t.Fatalf("the rebuild made %d attempts, want %d", saves, windowsCursorManagedGuardRebuildAttempts)
		}
		after := read(t, paths)
		if !bytes.Equal(after.hooks, last) {
			t.Fatalf("the rebuild did not keep the last save: %q", after.hooks)
		}
		if after.adapter != nil || !bytes.Equal(after.state, before.state) || !bytes.Equal(after.receipt, before.receipt) {
			t.Fatal("a stopped rebuild left a partly rebuilt guard")
		}
	})
}
