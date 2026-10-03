package watcher

import (
	"os"
	"path/filepath"
	"testing"
)

func pluginEventNames(events []InstallEvent) map[string]string {
	got := map[string]string{}
	for _, evt := range events {
		got[evt.Name] = evt.Path
	}
	return got
}

// GAP-2449: a category folder in a Hermes plugin root is a folder of plugins,
// not a plugin. The live path admits each plugin in it by its "plugin list"
// id instead of scanning (and quarantining) the folder, and an empty folder
// is watched until a plugin lands in it.
func TestLivePluginEventsExpandCategoryAndWaitOnEmptyFolder(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	cfg.Guardrail.Connector = "hermes"
	t.Setenv("HERMES_BUNDLED_PLUGINS", "")
	home := filepath.Dir(skillDir)
	user := filepath.Join(home, "plugins")
	bundled := filepath.Join(home, "hermes-agent", "plugins")
	write := func(dir string, files ...string) {
		t.Helper()
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if err := os.WriteFile(filepath.Join(dir, f), []byte("name: x\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	write(filepath.Join(user, "platforms", "demo"), "plugin.yaml", "__init__.py")
	write(filepath.Join(bundled, "platforms", "a2a"), "plugin.yaml")
	write(filepath.Join(user, "flat"), "__init__.py")
	w := New(cfg, nil, []string{user, bundled}, store, logger, nil, nil)

	if got := pluginEventNames(w.pendingInstallEvents(filepath.Join(user, "platforms"))); len(got) != 1 ||
		got["platforms/demo"] != filepath.Join(user, "platforms", "demo") {
		t.Fatalf("user category folder events = %v, want platforms/demo", got)
	}
	if got := pluginEventNames(w.pendingInstallEvents(filepath.Join(bundled, "platforms"))); len(got) != 1 ||
		got["a2a"] == "" {
		t.Fatalf("bundled platforms events = %v, want a2a", got)
	}
	// A flat plugin without a manifest is still one plugin for the scanner.
	if got := pluginEventNames(w.pendingInstallEvents(filepath.Join(user, "flat"))); len(got) != 1 || got["flat"] == "" {
		t.Fatalf("flat plugin events = %v, want flat", got)
	}

	web := filepath.Join(user, "web")
	write(web)
	if events := w.pendingInstallEvents(web); len(events) != 0 {
		t.Fatalf("empty folder events = %v, want none (watched, not admitted)", events)
	}
	nested := filepath.Join(web, "later")
	write(nested)
	if queued, ok := w.waitingPluginEvent(nested); !ok || queued != nested {
		t.Fatalf("new folder in waiting category = %q, %v; want %q", queued, ok, nested)
	}
	if events := w.pendingInstallEvents(nested); len(events) != 0 {
		t.Fatalf("nested folder without manifest events = %v, want none", events)
	}
	write(nested, "plugin.yaml")
	queued, ok := w.waitingPluginEvent(filepath.Join(nested, "plugin.yaml"))
	if !ok || queued != nested {
		t.Fatalf("manifest in waiting folder = %q, %v; want %q", queued, ok, nested)
	}
	if got := pluginEventNames(w.pendingInstallEvents(queued)); len(got) != 1 || got["web/later"] != nested {
		t.Fatalf("nested plugin events = %v, want web/later", got)
	}
	// A file beside the plugins of a category folder re-admits none of them.
	write(web, "README.md")
	if queued, ok := w.waitingPluginEvent(filepath.Join(web, "README.md")); ok {
		t.Fatalf("file in category folder queued %q", queued)
	}
}

// GAP-2462: category folders that already exist when the watcher starts are
// watched like live-created ones, so a plugin added to them later reaches
// admission after a gateway restart.
func TestWatcherStartWaitsOnExistingCategoryFolders(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	cfg.Guardrail.Connector = "hermes"
	t.Setenv("HERMES_BUNDLED_PLUGINS", "")
	home := filepath.Dir(skillDir)
	user := filepath.Join(home, "plugins")
	bundled := filepath.Join(home, "hermes-agent", "plugins")
	write := func(dir string, files ...string) {
		t.Helper()
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if err := os.WriteFile(filepath.Join(dir, f), []byte("name: x\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	write(filepath.Join(user, "web"))
	write(filepath.Join(user, "memx", "later"))
	write(filepath.Join(user, "flat"), "__init__.py")
	write(filepath.Join(user, "manifested"), "plugin.yaml")
	write(filepath.Join(bundled, "platforms", "a2a"), "plugin.yaml")
	w := New(cfg, nil, []string{user, bundled}, store, logger, nil, nil)
	var watched []string
	w.addWatch = func(dir string) { watched = append(watched, dir) }
	w.watchExistingPluginFolders(user)
	w.watchExistingPluginFolders(bundled)

	for _, dir := range []string{
		filepath.Join(user, "web"), filepath.Join(user, "memx"),
		filepath.Join(user, "memx", "later"), filepath.Join(bundled, "platforms"),
	} {
		if _, ok := w.pluginWaiting[dir]; !ok {
			t.Errorf("%s not watched at start (watched %v)", dir, watched)
		}
	}
	for _, dir := range []string{
		filepath.Join(user, "flat"), filepath.Join(user, "manifested"),
		filepath.Join(bundled, "platforms", "a2a"),
	} {
		if _, ok := w.pluginWaiting[dir]; ok {
			t.Errorf("plugin %s watched as a category folder", dir)
		}
	}
	post := filepath.Join(user, "web", "post")
	write(post, "plugin.yaml")
	if queued, ok := w.waitingPluginEvent(post); !ok || queued != post {
		t.Fatalf("new plugin in pre-existing category = %q, %v; want %q", queued, ok, post)
	}
	if got := pluginEventNames(w.pendingInstallEvents(post)); got["web/post"] != post {
		t.Fatalf("events = %v, want web/post", got)
	}
	bundledNew := filepath.Join(bundled, "platforms", "fresh")
	write(bundledNew, "plugin.yaml")
	if queued, ok := w.waitingPluginEvent(bundledNew); !ok || queued != bundledNew {
		t.Fatalf("new bundled platform plugin = %q, %v; want %q", queued, ok, bundledNew)
	}
}
