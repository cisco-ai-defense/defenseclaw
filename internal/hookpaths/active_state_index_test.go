// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func resetActiveStateIndex(t *testing.T) {
	t.Helper()
	activeStateIndex.Lock()
	activeStateIndex.byRoot = nil
	activeStateIndex.Unlock()
	t.Cleanup(func() {
		activeStateIndex.Lock()
		activeStateIndex.byRoot = nil
		activeStateIndex.Unlock()
	})
}

func activeStateIndexFixture(t *testing.T, cacheFiles int) (home, cwd string) {
	t.Helper()
	root := t.TempDir()
	home, cwd = filepath.Join(root, "home"), filepath.Join(root, "project")
	cache := filepath.Join(home, ".defenseclaw", "cache")
	for _, dir := range []string{cache, filepath.Join(home, ".defenseclaw", "hooks"), cwd} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{
		filepath.Join(home, ".defenseclaw", "config.yaml"),
		filepath.Join(home, ".defenseclaw", "hooks", "hook.sh"),
	} {
		if err := os.WriteFile(file, []byte("state\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < cacheFiles; i++ {
		if err := os.WriteFile(filepath.Join(cache, fmt.Sprintf("entry-%04d", i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return home, cwd
}

// GAP-1409 review loop 2: a call that writes a project file and names many
// ordinary hard links walks the active state at most once, not once per word.
func TestGAP1409OrdinaryHardlinksShareOneStateIndex(t *testing.T) {
	resetActiveStateIndex(t)
	home, cwd := activeStateIndexFixture(t, 200)
	var words []string
	for i := 0; i < 64; i++ {
		name := fmt.Sprintf("file-%02d", i)
		if err := os.WriteFile(filepath.Join(cwd, name), []byte("ordinary\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(filepath.Join(cwd, name), filepath.Join(cwd, name+".link")); err != nil {
			t.Fatal(err)
		}
		words = append(words, name+".link")
	}
	before := activeStateIndexWalks.Load()
	command := "cat " + strings.Join(words, " ") + " > report.txt"
	if ActionStateTargetMention(command, cwd, home) {
		t.Fatal("ordinary hard links were treated as active state")
	}
	for _, word := range words {
		if mapped, same := ResolveActiveStateHardlinkTarget(filepath.Join(cwd, word), home); same {
			t.Fatalf("ordinary hard link %s mapped to %s", word, mapped)
		}
	}
	if walks := activeStateIndexWalks.Load() - before; walks != 1 {
		t.Fatalf("active state walked %d times for one request, want 1", walks)
	}
	// The shared index still maps a real alias of the active config.
	alias := filepath.Join(cwd, "config-alias")
	if err := os.Link(filepath.Join(home, ".defenseclaw", "config.yaml"), alias); err != nil {
		t.Fatal(err)
	}
	if mapped, same := ResolveActiveStateHardlinkTarget(alias, home); !same ||
		mapped != filepath.Join(home, ".defenseclaw", "config.yaml") {
		t.Fatalf("active config hard link mapped=%q same=%t", mapped, same)
	}
	if !ActionStateTargetMention("printf changed >> config-alias", cwd, home) {
		t.Fatal("active config hard link is no longer a state target")
	}
}

// The walk is bounded by entries and time. Named state files and hooks are
// indexed before the large cache, so a bounded walk still covers them.
func TestGAP1409ActiveStateIndexIsBounded(t *testing.T) {
	resetActiveStateIndex(t)
	home, cwd := activeStateIndexFixture(t, 64)
	entries := activeStateIndexEntries
	activeStateIndexEntries = len(activeStateFiles) + 8
	t.Cleanup(func() { activeStateIndexEntries = entries })
	configAlias, hookAlias, lateAlias := filepath.Join(cwd, "config-alias"), filepath.Join(cwd, "hook-alias"), filepath.Join(cwd, "late-alias")
	for target, alias := range map[string]string{
		filepath.Join(home, ".defenseclaw", "config.yaml"):         configAlias,
		filepath.Join(home, ".defenseclaw", "hooks", "hook.sh"):    hookAlias,
		filepath.Join(home, ".defenseclaw", "cache", "entry-0063"): lateAlias,
	} {
		if err := os.Link(target, alias); err != nil {
			t.Fatal(err)
		}
	}
	if _, same := ResolveActiveStateHardlinkTarget(configAlias, home); !same {
		t.Fatal("bounded index lost the active config")
	}
	if _, same := ResolveActiveStateHardlinkTarget(hookAlias, home); !same {
		t.Fatal("bounded index lost the installed hook")
	}
	if files := activeStateIdentities(mustResolve(t, filepath.Join(home, ".defenseclaw"))); len(files) > activeStateIndexEntries {
		t.Fatalf("index holds %d files over the %d entry bound", len(files), activeStateIndexEntries)
	}
	if _, same := ResolveActiveStateHardlinkTarget(lateAlias, home); same {
		t.Fatal("walk did not stop at the entry bound")
	}

	resetActiveStateIndex(t)
	budget := activeStateIndexBudget
	activeStateIndexBudget = -time.Second
	t.Cleanup(func() { activeStateIndexBudget = budget })
	start := time.Now()
	if _, same := ResolveActiveStateHardlinkTarget(configAlias, home); same {
		t.Fatal("expired walk budget still indexed files")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("expired walk budget took %s", elapsed)
	}
}

// A cached identity is confirmed against the current name: once the config
// is replaced, an alias of the old file is no longer active state.
func TestGAP1409ActiveStateIndexConfirmsCurrentFile(t *testing.T) {
	resetActiveStateIndex(t)
	home, cwd := activeStateIndexFixture(t, 0)
	config := filepath.Join(home, ".defenseclaw", "config.yaml")
	alias := filepath.Join(cwd, "config-alias")
	if err := os.Link(config, alias); err != nil {
		t.Fatal(err)
	}
	if _, same := ResolveActiveStateHardlinkTarget(alias, home); !same {
		t.Fatal("active config alias not mapped")
	}
	replacement := config + ".new"
	if err := os.WriteFile(replacement, []byte("replaced\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, config); err != nil {
		t.Fatal(err)
	}
	if mapped, same := ResolveActiveStateHardlinkTarget(alias, home); same {
		t.Fatalf("alias of the replaced config still mapped to %s", mapped)
	}
}

func mustResolve(t *testing.T, value string) string {
	t.Helper()
	resolved, ok := ResolveWriteTarget(value)
	if !ok {
		t.Fatalf("cannot resolve %s", value)
	}
	return resolved
}
