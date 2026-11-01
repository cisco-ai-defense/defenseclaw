// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// gap0017CLICopy writes a skill-only plugin the way "defenseclaw plugin
// install" leaves it in Claude Code's cache: the whole plugin folder at
// cache/<name>, with skills/<skill> and .git/<...> sub-folders.
func gap0017CLICopy(t *testing.T, dir string) {
	t.Helper()
	for _, sub := range []string{".claude-plugin", filepath.Join("skills", "helper"), filepath.Join(".git", "modules", "notes"), "notes"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		filepath.Join(".claude-plugin", "plugin.json"):    `{"name":"r105sub","version":"1.0.0"}`,
		filepath.Join("skills", "helper", "SKILL.md"):     "---\nname: helper\ndescription: Format notes.\n---\nFormat notes.\n",
		filepath.Join("notes", "README.md"):               "notes\n",
		filepath.Join(".git", "modules", "notes", "HEAD"): "ref: refs/heads/main\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// GAP-0017: the watcher read the sub-folders of a plugin the CLI copied into
// Claude Code's cache (cache/<name>/skills/helper, and the install staging
// folder's <name>/{skills,notes,.git}) as <marketplace>/<plugin>/<version>
// plugins, blocked each for a missing manifest and listed skills@<name>
// blocked. The copy is one plugin; staging is the CLI's own; a marketplace
// version folder is still a plugin.
func TestCLIPluginCopyInClaudeCacheIsOnePlugin(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Guardrail.Connector = "claudecode"
	cache := filepath.Join(t.TempDir(), ".claude", "plugins", "cache")
	copied := filepath.Join(cache, "r105sub")
	stage := filepath.Join(cache, ".dclaw-stage-r105sub-k7telux", "r105sub")
	version := filepath.Join(cache, "mkt", "plug", "1.0.0")
	gap0017CLICopy(t, copied)
	gap0017CLICopy(t, stage)
	if err := os.MkdirAll(version, 0o700); err != nil {
		t.Fatal(err)
	}
	w := New(cfg, nil, []string{cache}, store, logger, nil, nil)

	var targets []string
	for _, evt := range w.enumerateTargets() {
		targets = append(targets, evt.Name+"="+evt.Path)
	}
	slices.Sort(targets)
	want := []string{"plug@mkt=" + version, "r105sub=" + copied}
	if !slices.Equal(targets, want) {
		t.Fatalf("rescan targets %v, want %v", targets, want)
	}

	if evt := w.classifyEvent(copied); evt.Type != InstallPlugin || evt.Name != "r105sub" {
		t.Fatalf("classifyEvent(copy) = %s %q, want plugin r105sub", evt.Type, evt.Name)
	}
	for _, sub := range []string{"skills", filepath.Join("skills", "helper"), ".git"} {
		if !w.inClaudePluginStaging(filepath.Join(stage, sub), 0) {
			t.Errorf("%s of the install staging folder is not staging", sub)
		}
	}

	w.queueExistingClaudePlugins(context.Background(), cache, 0)
	var queued []string
	for path := range w.pending {
		queued = append(queued, path)
	}
	slices.Sort(queued)
	if want := []string{version, copied}; !slices.Equal(queued, want) {
		t.Fatalf("queued %v, want %v", queued, want)
	}
}

// GAP-0017 live: the CLI stages the copy in cache/.dclaw-stage-<name>-*/<name>
// and renames it to cache/<name>. The watcher admits cache/<name> once, as
// plugin <name>, and none of its sub-folders.
func TestLiveWatcherAdmitsCLIPluginCopyAsOnePlugin(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Guardrail.Connector = "claudecode"
	cache := filepath.Join(t.TempDir(), ".claude", "plugins", "cache")
	if err := os.MkdirAll(cache, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg.AssetPolicy.Plugin.Allowed = append(cfg.AssetPolicy.Plugin.Allowed,
		config.AssetPolicyRule{Name: "r105sub", Reason: "pre-approved"})

	var mu sync.Mutex
	seen := map[string]string{}
	w := New(cfg, nil, []string{cache}, store, logger, nil, func(r AdmissionResult) {
		mu.Lock()
		seen[r.Event.Name] = r.Event.Path
		mu.Unlock()
	})
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- w.Run(ctx) }()
	time.Sleep(500 * time.Millisecond)

	stageDir := filepath.Join(cache, ".dclaw-stage-r105sub-k7telux")
	stage := filepath.Join(stageDir, "r105sub")
	gap0017CLICopy(t, stage)
	time.Sleep(time.Second)
	copied := filepath.Join(cache, "r105sub")
	if err := os.Rename(stage, copied); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(stageDir); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		_, ok := seen["r105sub"]
		mu.Unlock()
		if ok {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(2 * time.Second) // let any sub-folder admission land too
	cancel()
	<-errCh
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 || seen["r105sub"] != copied {
		t.Fatalf("admissions = %v, want only r105sub=%s", seen, copied)
	}
}
