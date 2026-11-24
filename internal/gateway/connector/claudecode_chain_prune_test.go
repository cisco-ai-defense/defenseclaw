// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// GAP-1075: every guard publish made a new chain-<n> folder (guard + approved
// copy, about 4.8 MB) and none was ever removed; a guard digest an older
// folder already held was written again. A publish now reuses a folder that
// holds the same digest and prunes the chain-* folders nothing names, keeping
// the newest one and the one the previous record named (a rollback).

type chainPublisher struct {
	t        *testing.T
	dir      string
	source   string
	launcher string
	settings string
}

func newChainPublisher(t *testing.T) *chainPublisher {
	t.Helper()
	p := &chainPublisher{
		t:        t,
		dir:      filepath.Join(t.TempDir(), "claude-code-chain"),
		source:   filepath.Join(t.TempDir(), windowsHookGuardBinaryName),
		launcher: filepath.Join(t.TempDir(), windowsHookBinaryName),
		settings: filepath.Join(t.TempDir(), "settings.json"),
	}
	oldDir, oldSource, oldProbe, oldSettings := claudeChainDir, claudeChainSource, claudeChainProbe, ClaudeCodeSettingsPathOverride
	claudeChainDir = func() string { return p.dir }
	claudeChainSource = func(string) string { return p.source }
	claudeChainProbe = func(string, string) error { return nil }
	ClaudeCodeSettingsPathOverride = p.settings
	t.Cleanup(func() {
		claudeChainDir, claudeChainSource, claudeChainProbe, ClaudeCodeSettingsPathOverride = oldDir, oldSource, oldProbe, oldSettings
	})
	return p
}

// publish installs a guard with body and returns the generation folder name
// the record points to. Every folder is then aged, as one from an earlier day.
func (p *chainPublisher) publish(body string) string {
	p.t.Helper()
	if err := os.WriteFile(p.source, []byte(body), 0o600); err != nil {
		p.t.Fatal(err)
	}
	if err := ensureClaudeChain(p.launcher); err != nil {
		p.t.Fatal(err)
	}
	guard, _ := claudeChainFor(p.launcher)
	p.age()
	return filepath.Base(filepath.Dir(guard))
}

func (p *chainPublisher) age() {
	old := time.Now().Add(-48 * time.Hour)
	for _, name := range p.folders() {
		_ = os.Chtimes(filepath.Join(p.dir, name), old, old)
	}
}

func (p *chainPublisher) folders() []string {
	entries, _ := os.ReadDir(p.dir)
	var out []string
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "chain-") {
			out = append(out, e.Name())
		}
	}
	return out
}

func TestClaudeCodeChainReusesAFolderHoldingTheSameGuard(t *testing.T) {
	p := newChainPublisher(t)
	first := p.publish("MZ guard 1.0.10")
	p.publish("MZ guard 1.0.11")
	again := p.publish("MZ guard 1.0.10")
	if again != first {
		t.Fatalf("a guard an earlier folder holds got a new folder %s, want %s", again, first)
	}
	if got := p.folders(); len(got) != 2 {
		t.Fatalf("round trip left %d chain folders: %v", len(got), got)
	}
}

func TestClaudeCodeChainPrunesFoldersNothingNames(t *testing.T) {
	p := newChainPublisher(t)
	var gens []string
	for _, v := range []string{"1", "2", "3", "4", "5"} {
		gens = append(gens, p.publish("MZ guard "+v))
	}
	// The newest and the one the previous record named stay; nothing else.
	want := map[string]bool{gens[4]: true, gens[3]: true}
	got := p.folders()
	if len(got) != len(want) {
		t.Fatalf("chain folders after 5 publishes = %v, want %v", got, want)
	}
	for _, name := range got {
		if !want[name] {
			t.Fatalf("unexpected chain folder %s in %v", name, got)
		}
	}
	// The recorded pair is whole.
	guard, approved := claudeChainFor(p.launcher)
	for _, path := range []string{guard, approved} {
		if body, err := os.ReadFile(path); err != nil || string(body) != "MZ guard 5" {
			t.Fatalf("recorded file %s = %q: %v", path, body, err)
		}
	}
}

func TestClaudeCodeChainKeepsAFolderTheSettingsNameAndAFreshOne(t *testing.T) {
	p := newChainPublisher(t)
	named := p.publish("MZ guard 1")
	if err := os.WriteFile(p.settings, []byte(`{"hooks":{"PreToolUse":[{"hooks":[{"command":"C:\\x\\`+named+`\\defenseclaw-hook-guard.exe"}]}]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	p.publish("MZ guard 2")
	p.publish("MZ guard 3")
	fresh := filepath.Join(p.dir, "chain-freshone") // another process is publishing it now
	if err := os.MkdirAll(fresh, 0o700); err != nil {
		t.Fatal(err)
	}
	stray := filepath.Join(p.dir, "not-a-chain")
	if err := os.MkdirAll(stray, 0o700); err != nil {
		t.Fatal(err)
	}
	p.publish("MZ guard 4")
	for _, keep := range []string{named, "chain-freshone", "not-a-chain"} {
		if _, err := os.Stat(filepath.Join(p.dir, keep)); err != nil {
			t.Errorf("%s was removed: %v", keep, err)
		}
	}
	// 2 is older than the previous record and unnamed: pruned.
	if got := p.folders(); len(got) != 4 { // named, previous, newest, fresh
		t.Fatalf("chain folders = %v", got)
	}
}
