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
