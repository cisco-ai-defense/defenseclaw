package watcher

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// GAP-2464: the watcher quarantines a category plugin under its category, so
// two plugins with one folder name in different categories get their own
// quarantine slots and "plugin restore <category>/<name>" can find them.
func TestWatcherQuarantineKeepsPluginCategory(t *testing.T) {
	cfg, store, logger, skillDir := setupQuarantineProvenanceTestEnv(t)
	cfg.Guardrail.Connector = "hermes"
	root := filepath.Join(filepath.Dir(skillDir), "plugins")
	w := New(cfg, nil, []string{root}, store, logger, nil, nil)
	for _, category := range []string{"web", "memx"} {
		path := filepath.Join(root, category, "dup")
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "plugin.yaml"), []byte("name: dup\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		w.quarantineAsset(context.Background(), InstallEvent{
			Type: InstallPlugin, Name: category + "/dup", Path: path,
			Connector: "hermes", Timestamp: time.Now().UTC(),
		})
		want := filepath.Join(cfg.QuarantineDir, "plugins", "hermes", category, "dup", "plugin.yaml")
		if _, err := os.Stat(want); err != nil {
			t.Fatalf("%s/dup not quarantined at %s: %v", category, want, err)
		}
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("%s source still exists: %v", path, err)
		}
	}
}
