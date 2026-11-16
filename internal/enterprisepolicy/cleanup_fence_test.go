// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// The guardian's cleanup fence is taken in GuardRemoval: it must wrap every
// kind of removal (a JSON rewrite, a Hermes rewrite, a plugin moved aside),
// never run when there is nothing to remove, and a refusal must leave the
// hook in place and reported.
func TestCleanupGuardsEveryRemovalAndOnlyThen(t *testing.T) {
	type fixture struct {
		req     GuardRequest
		path    string
		removed func() bool
	}
	cursor := func(t *testing.T) fixture {
		req := guardRequest(t, "cursor", config.ForeignHooksRemove)
		path := filepath.Join(req.Home, ".cursor", "hooks.json")
		writeFile(t, path, `{"version": 1, "hooks": {"preToolUse": [`+ownedCursorEntry+`, {"command": "./rewrite.sh"}]}}`)
		return fixture{req, path, func() bool { return !strings.Contains(readFile(t, path), "rewrite.sh") }}
	}
	hermes := func(t *testing.T) fixture {
		req, script := hermesGuardRequest(t, config.ForeignHooksRemove)
		path := filepath.Join(req.Home, ".hermes", "config.yaml")
		writeFile(t, path, hermesConfig(script, hermesRewriteEntry))
		return fixture{req, path, func() bool { return !strings.Contains(readFile(t, path), "rewrite-tool-input.sh") }}
	}
	plugin := func(t *testing.T) fixture {
		req := guardRequest(t, "opencode", config.ForeignHooksRemove)
		req.AccountHome = req.Home
		path := filepath.Join(req.Home, ".config", "opencode", "plugins", "mutate.mjs")
		writeFile(t, path, "export default {}")
		return fixture{req, path, func() bool { _, err := os.Lstat(path); return os.IsNotExist(err) }}
	}
	for name, build := range map[string]func(*testing.T) fixture{"json": cursor, "hermes": hermes, "plugin dir": plugin} {
		t.Run(name, func(t *testing.T) {
			f := build(t)
			calls := 0
			f.req.GuardRemoval = func(paths []string, remove func() error) error {
				calls++
				if f.removed() {
					t.Error("the removal ran before its guard")
				}
				if len(paths) != 1 || paths[0] != f.path {
					t.Errorf("guarded paths %v, want [%s]", paths, f.path)
				}
				err := remove()
				if !f.removed() {
					t.Error("the removal did not run inside its guard")
				}
				return err
			}
			result, err := CleanUserForeignHooks(f.req, time.Now())
			if err != nil || len(result.Removed) == 0 || !f.removed() || calls != 1 {
				t.Fatalf("cleanup with the guard granted: calls=%d result=%+v err=%v", calls, result, err)
			}

			// Nothing left to remove: the guard never runs.
			calls = 0
			if _, err := CleanUserForeignHooks(f.req, time.Now()); err != nil || calls != 0 {
				t.Fatalf("a clean config ran the guard %d times: %v", calls, err)
			}

			// Refused: the hook stays, reported, and the error surfaces.
			g := build(t)
			refused := errors.New("fence unavailable")
			g.req.GuardRemoval = func([]string, func() error) error { return refused }
			result, err = CleanUserForeignHooks(g.req, time.Now())
			if !errors.Is(err, refused) || len(result.Removed) != 0 || len(result.Reported) == 0 || g.removed() {
				t.Fatalf("a refused guard must leave the hook in place: result=%+v err=%v", result, err)
			}
			if result.BackupDir != "" {
				t.Fatalf("a refused removal left a backup: %s", result.BackupDir)
			}

			// A guard that returns without running the removal and without
			// an error still leaves the hook in place, reported.
			h := build(t)
			h.req.GuardRemoval = func([]string, func() error) error { return nil }
			result, err = CleanUserForeignHooks(h.req, time.Now())
			if !errors.Is(err, errRemovalRefused) || len(result.Removed) != 0 || len(result.Reported) == 0 || h.removed() {
				t.Fatalf("a guard that skipped the removal: result=%+v err=%v", result, err)
			}

			// The removal ran but the guard's commit failed: the hook is gone,
			// so it is reported removed, and the error surfaces.
			k := build(t)
			commitErr := errors.New("ledger commit failed")
			k.req.GuardRemoval = func(_ []string, remove func() error) error { return errors.Join(remove(), commitErr) }
			result, err = CleanUserForeignHooks(k.req, time.Now())
			if !errors.Is(err, commitErr) || len(result.Removed) == 0 || !k.removed() {
				t.Fatalf("a removal whose commit failed: result=%+v err=%v", result, err)
			}
		})
	}
}

// Each removal is its own guarded interval: the guard is let go before the
// cleanup reads anything else, whether the next read is a later source, a
// redirected home or the next plugin of the same directory. A slow source
// read after a removal therefore never runs under the fence.
func TestCleanupReadsNothingWhileARemovalIsGuarded(t *testing.T) {
	type fixture struct {
		req       GuardRequest
		redirects []EnvRedirect
		paths     []string
		roots     []string
	}
	cursorHomes := func(t *testing.T) fixture {
		req := guardRequest(t, "cursor", config.ForeignHooksRemove)
		other := t.TempDir()
		first := filepath.Join(req.Home, ".cursor", "hooks.json")
		second := filepath.Join(other, ".cursor", "hooks.json")
		for _, path := range []string{first, second} {
			writeFile(t, path, `{"version": 1, "hooks": {"preToolUse": [`+ownedCursorEntry+`, {"command": "./rewrite.sh"}]}}`)
		}
		return fixture{req, []EnvRedirect{{Homes: []string{other}}}, []string{first, second}, []string{req.Home, other}}
	}
	plugins := func(t *testing.T) fixture {
		req := guardRequest(t, "opencode", config.ForeignHooksRemove)
		req.AccountHome = req.Home
		dir := filepath.Join(req.Home, ".config", "opencode", "plugins")
		first, second := filepath.Join(dir, "a-mutate.mjs"), filepath.Join(dir, "b-mutate.mjs")
		for _, path := range []string{first, second} {
			writeFile(t, path, "export default {}")
		}
		return fixture{req, nil, []string{first, second}, []string{req.Home}}
	}
	for name, build := range map[string]func(*testing.T) fixture{"later home": cursorHomes, "next plugin": plugins} {
		t.Run(name, func(t *testing.T) {
			f := build(t)
			guarded := false
			readsWhileGuarded, readsAfterFirst := 0, 0
			var guardedPaths []string
			previous := guardScanReadHook
			t.Cleanup(func() { guardScanReadHook = previous })
			guardScanReadHook = func(path string) {
				inFixture := false
				for _, root := range f.roots {
					if strings.HasPrefix(path, root) {
						inFixture = true
					}
				}
				if !inFixture {
					return
				}
				if guarded {
					readsWhileGuarded++
				}
				if len(guardedPaths) > 0 {
					readsAfterFirst++
				}
			}
			f.req.GuardRemoval = func(paths []string, remove func() error) error {
				guarded = true
				defer func() { guarded = false }()
				guardedPaths = append(guardedPaths, paths...)
				return remove()
			}
			result, err := CleanUserForeignHooksWithRedirects(f.req, f.redirects, time.Now())
			if err != nil || len(result.Removed) != 2 {
				t.Fatalf("cleanup: result=%+v err=%v", result, err)
			}
			if len(guardedPaths) != 2 || guardedPaths[0] == guardedPaths[1] {
				t.Fatalf("each removal must be guarded on its own, got %v", guardedPaths)
			}
			for _, path := range f.paths {
				if guardedPaths[0] != path && guardedPaths[1] != path {
					t.Fatalf("guarded %v, want %v", guardedPaths, f.paths)
				}
			}
			if readsAfterFirst == 0 {
				t.Fatal("the fixture must make the cleanup read on after its first removal")
			}
			if readsWhileGuarded != 0 {
				t.Fatalf("the cleanup read %d time(s) while a removal was guarded", readsWhileGuarded)
			}
		})
	}
}
