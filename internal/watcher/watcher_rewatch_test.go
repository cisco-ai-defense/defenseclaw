package watcher

import (
	"context"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// GAP-2469: a watched plugin folder that moved away (to quarantine) and is
// re-created at the same path is watched again, so a plugin written into the
// new folder reaches admission.
func TestWatcherRewatchesFolderRecreatedAfterMove(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	cfg.Guardrail.Connector = "hermes"
	t.Setenv("HERMES_BUNDLED_PLUGINS", "")
	root := filepath.Join(filepath.Dir(skillDir), "plugins")
	pending := filepath.Join(root, "web", "pending")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg.AssetPolicy.Plugin.Allowed = append(cfg.AssetPolicy.Plugin.Allowed, config.AssetPolicyRule{Name: "web/pending", Reason: "pre-approved"})
	var mu sync.Mutex
	admitted := 0
	w := New(cfg, nil, []string{root}, store, logger, nil, func(r AdmissionResult) {
		if r.Event.Name == "web/pending" {
			mu.Lock()
			admitted++
			mu.Unlock()
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- w.Run(ctx) }()
	defer func() { cancel(); <-errCh }()

	settle := func() { time.Sleep(600 * time.Millisecond) }
	settle()
	if err := os.MkdirAll(pending, 0o700); err != nil { // watched, nothing to admit
		t.Fatal(err)
	}
	settle()
	if err := os.Rename(pending, filepath.Join(filepath.Dir(skillDir), "moved")); err != nil {
		t.Fatal(err)
	}
	settle()
	if err := os.Mkdir(pending, 0o700); err != nil {
		t.Fatal(err)
	}
	settle()
	if err := os.WriteFile(filepath.Join(pending, "plugin.yaml"), []byte("name: pending\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := admitted
		mu.Unlock()
		if n > 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("plugin written into the re-created web/pending got no admission")
}

// GAP-1315: a skill root replaced while the watcher runs is watched again,
// and the skill the new folder holds, and one added to it later, get an
// install verdict instead of only a rescan baseline.
func TestWatcherAdmitsSkillsOfReplacedRoot(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	for _, name := range []string{"moved-in", "added-later"} {
		cfg.AssetPolicy.Skill.Allowed = append(cfg.AssetPolicy.Skill.Allowed, config.AssetPolicyRule{Name: name, Reason: "pre-approved"})
	}
	admitted := make(chan string, 8)
	w := New(cfg, []string{skillDir}, nil, store, logger, nil, func(r AdmissionResult) { admitted <- r.Event.Name })
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- w.Run(ctx) }()
	defer func() { cancel(); <-errCh }()
	time.Sleep(500 * time.Millisecond)

	replacement := filepath.Join(filepath.Dir(skillDir), "skills.new")
	if err := os.MkdirAll(filepath.Join(replacement, "moved-in"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(replacement, "moved-in", "SKILL.md"), []byte("# moved in\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(skillDir, filepath.Join(filepath.Dir(skillDir), "skills.old")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, skillDir); err != nil {
		t.Fatal(err)
	}
	wait := func(name string) {
		t.Helper()
		deadline := time.After(5 * time.Second)
		for {
			select {
			case got := <-admitted:
				if got == name {
					return
				}
			case <-deadline:
				t.Fatalf("skill %s in the replaced root got no admission", name)
			}
		}
	}
	wait("moved-in")
	added := filepath.Join(skillDir, "added-later")
	if err := os.Mkdir(added, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(added, "SKILL.md"), []byte("# added later\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wait("added-later")
}
